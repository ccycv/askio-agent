#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture_network="askio_redis_valkey_smoke"
binary_volume="askio_redis_valkey_binary_smoke"
runner_image="askio/redis-valkey-runner:smoke"
fixture_password="askio-fixture-pass"
redis_image="${ASKIO_MIGRATION_REDIS_IMAGE:-redis:7.4}"
valkey_image="${ASKIO_MIGRATION_VALKEY_IMAGE:-valkey/valkey:8.1}"
builder_image="golang@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253"
containers=(askio-redis-source-smoke askio-redis-target-smoke askio-valkey-source-smoke askio-valkey-target-smoke)

cleanup() {
  docker stop "${containers[@]}" >/dev/null 2>&1 || true
  docker network rm "${fixture_network}" >/dev/null 2>&1 || true
  docker volume rm "${binary_volume}" >/dev/null 2>&1 || true
  docker image rm "${runner_image}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

case "${redis_image}" in redis:7.2|redis:7.4|redis:8.2) ;; *) echo "unsupported Redis fixture image ${redis_image}" >&2; exit 1 ;; esac
case "${valkey_image}" in valkey/valkey:7.2|valkey/valkey:8.1|valkey/valkey:9.1) ;; *) echo "unsupported Valkey fixture image ${valkey_image}" >&2; exit 1 ;; esac
for container in "${containers[@]}"; do
  if docker container inspect "${container}" >/dev/null 2>&1; then
    echo "refusing to reuse existing Redis/Valkey fixture container ${container}" >&2
    exit 1
  fi
done
if docker network inspect "${fixture_network}" >/dev/null 2>&1 || docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing Redis/Valkey fixture network or volume" >&2
  exit 1
fi

docker build --tag "${runner_image}" --file "${repository_root}/scripts/fixtures/redis-valkey-runner.Dockerfile" "${repository_root}/scripts/fixtures"
docker volume create "${binary_volume}" >/dev/null
docker run --rm \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_volume}:/out" \
  --workdir /src \
  "${builder_image}" \
  go test -c -o /out/migration.test ./internal/migration

docker network create "${fixture_network}" >/dev/null
docker run --detach --rm --name askio-redis-source-smoke --network "${fixture_network}" --tmpfs /data:rw,mode=0700 "${redis_image}" redis-server --appendonly no --save "3600 1" --requirepass "${fixture_password}" >/dev/null
docker run --detach --rm --name askio-redis-target-smoke --network "${fixture_network}" --tmpfs /data:rw,mode=0700 "${redis_image}" redis-server --appendonly yes --save "" --requirepass "${fixture_password}" >/dev/null
docker run --detach --rm --name askio-valkey-source-smoke --network "${fixture_network}" --tmpfs /data:rw,mode=0700 "${valkey_image}" valkey-server --appendonly yes --save "" --requirepass "${fixture_password}" >/dev/null
docker run --detach --rm --name askio-valkey-target-smoke --network "${fixture_network}" --tmpfs /data:rw,mode=0700 "${valkey_image}" valkey-server --appendonly no --save "3600 1" --requirepass "${fixture_password}" >/dev/null

for container in "${containers[@]}"; do
  ready=0
  cli=redis-cli
  if [[ "${container}" == askio-valkey-* ]]; then cli=valkey-cli; fi
  for _attempt in {1..90}; do
    if docker exec "${container}" "${cli}" -a "${fixture_password}" --no-auth-warning ping 2>/dev/null | grep -qx PONG; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "${ready}" -ne 1 ]]; then
    docker logs "${container}"
    exit 1
  fi
done

run_engine() {
  local engine="$1"
  local source_container="askio-${engine}-source-smoke"
  local target_container="askio-${engine}-target-smoke"
  docker run --rm \
    --network "${fixture_network}" \
    --volume "${binary_volume}:/work:ro" \
    --env ASKIO_MIGRATION_REDIS_INTEGRATION=disposable-redis-valkey-cycle \
    --env ASKIO_MIGRATION_REDIS_ENGINE="${engine}" \
    --env ASKIO_MIGRATION_REDIS_SOURCE_PORT=16379 \
    --env ASKIO_MIGRATION_REDIS_TARGET_PORT=26379 \
    --env ASKIO_MIGRATION_REDIS_PASSWORD="${fixture_password}" \
    --env ASKIO_MIGRATION_REDIS_HOST=127.0.0.1 \
    "${runner_image}" \
    sh -c "socat TCP-LISTEN:16379,bind=127.0.0.1,reuseaddr,fork TCP:${source_container}:6379 & socat TCP-LISTEN:26379,bind=127.0.0.1,reuseaddr,fork TCP:${target_container}:6379 & exec /work/migration.test -test.v -test.run '^TestRedisValkeyOfflineMigrationCycle$'"
}

run_engine redis
run_engine valkey
