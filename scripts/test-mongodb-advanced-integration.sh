#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner_container="askio-mongodb-runner-smoke"
source_container="askio-mongodb-source-smoke"
target_container="askio-mongodb-target-smoke"
binary_volume="askio_mongodb_binary_smoke"

cleanup() {
  docker stop "${source_container}" "${target_container}" "${runner_container}" >/dev/null 2>&1 || true
  for _attempt in {1..20}; do
    if ! docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
      break
    fi
    if docker volume rm "${binary_volume}" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
}
trap cleanup EXIT

for fixture_container in "${runner_container}" "${source_container}" "${target_container}"; do
  if docker container inspect "${fixture_container}" >/dev/null 2>&1; then
    echo "refusing to reuse existing MongoDB fixture container ${fixture_container}" >&2
    exit 1
  fi
done
if docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing MongoDB fixture volume" >&2
  exit 1
fi

docker volume create "${binary_volume}" >/dev/null
docker run --rm \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_volume}:/out" \
  --workdir /src \
  golang:1.22.12-bookworm \
  go test -c -o /out/migration.test ./internal/migration

docker run --detach --rm \
  --name "${runner_container}" \
  --volume "${binary_volume}:/work:ro" \
  mongo:8 sleep infinity >/dev/null
docker run --detach --rm \
  --name "${source_container}" \
  --network "container:${runner_container}" \
  --tmpfs /data/db:rw,uid=999,gid=999,mode=0700 \
  mongo:8 mongod --replSet askioRS --bind_ip 127.0.0.1 --port 27017 >/dev/null
docker run --detach --rm \
  --name "${target_container}" \
  --network "container:${runner_container}" \
  --tmpfs /data/db:rw,uid=999,gid=999,mode=0700 \
  mongo:8 mongod --replSet askioTargetRS --bind_ip 127.0.0.1 --port 27018 >/dev/null

for fixture_port in 27017 27018; do
  ready=0
  for _attempt in {1..90}; do
    if docker exec "${runner_container}" mongosh --quiet --port "${fixture_port}" --eval 'quit(db.adminCommand({ping: 1}).ok === 1 ? 0 : 1)' >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ "${ready}" -ne 1 ]]; then
    docker logs "${source_container}" || true
    docker logs "${target_container}" || true
    exit 1
  fi
done

docker exec "${runner_container}" mongosh --quiet --port 27017 --eval \
  'quit(rs.initiate({_id: "askioRS", members: [{_id: 0, host: "127.0.0.1:27017"}]}).ok === 1 ? 0 : 1)' >/dev/null
docker exec "${runner_container}" mongosh --quiet --port 27018 --eval \
  'quit(rs.initiate({_id: "askioTargetRS", members: [{_id: 0, host: "127.0.0.1:27018"}]}).ok === 1 ? 0 : 1)' >/dev/null
for fixture_port in 27017 27018; do
  primary=0
  for _attempt in {1..90}; do
    if docker exec "${runner_container}" mongosh --quiet --port "${fixture_port}" --eval \
      'quit(db.adminCommand({hello: 1}).isWritablePrimary === true ? 0 : 1)' >/dev/null 2>&1; then
      primary=1
      break
    fi
    sleep 1
  done
  if [[ "${primary}" -ne 1 ]]; then
    docker logs "${source_container}" || true
    docker logs "${target_container}" || true
    exit 1
  fi
done

for fixture_port in 27017 27018; do
  docker exec "${runner_container}" mongosh --quiet --port "${fixture_port}" --eval \
    'const admin=db.getSiblingDB("admin"); if (!admin.getUser("root")) admin.createUser({user:"root",pwd:"fixture-pass",roles:[{role:"root",db:"admin"}]});' >/dev/null
done

docker exec \
  --env ASKIO_MIGRATION_MONGODB_INTEGRATION=disposable-same-major-cycle \
  --env ASKIO_MIGRATION_MONGODB_SOURCE_PORT=27017 \
  --env ASKIO_MIGRATION_MONGODB_TARGET_PORT=27018 \
  --env ASKIO_MIGRATION_MONGODB_PASSWORD=fixture-pass \
  "${runner_container}" \
  /work/migration.test -test.v -test.run '^TestMongoDB(Offline|Advanced)MigrationCycle$'
