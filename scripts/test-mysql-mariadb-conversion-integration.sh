#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_mysql_container="askio-mysql-conversion-smoke"
source_mariadb_container="askio-mariadb-conversion-smoke"
fixture_network="askio_mysql_conversion_smoke"
binary_volume="askio_mysql_conversion_binary_smoke"
runner_image="askio/mysql-conversion-runner:smoke"
fixture_password="askio-fixture-pass"
mysql_image="${ASKIO_MIGRATION_MYSQL_IMAGE:-mysql:8.4}"
mariadb_image="${ASKIO_MIGRATION_MARIADB_IMAGE:-mariadb:11.4}"

case "${mysql_image}" in
  mysql:8.0|mysql:8.4) ;;
  *) echo "unsupported MySQL fixture image ${mysql_image}" >&2; exit 1 ;;
esac
case "${mariadb_image}" in
  mariadb:10.11|mariadb:11.4) ;;
  *) echo "unsupported MariaDB fixture image ${mariadb_image}" >&2; exit 1 ;;
esac

cleanup() {
  docker stop "${source_mysql_container}" "${source_mariadb_container}" >/dev/null 2>&1 || true
  docker network rm "${fixture_network}" >/dev/null 2>&1 || true
  docker volume rm "${binary_volume}" >/dev/null 2>&1 || true
  docker image rm "${runner_image}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for container in "${source_mysql_container}" "${source_mariadb_container}"; do
  if docker container inspect "${container}" >/dev/null 2>&1; then
    echo "refusing to reuse existing MySQL/MariaDB fixture container ${container}" >&2
    exit 1
  fi
done
if docker network inspect "${fixture_network}" >/dev/null 2>&1 || docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing MySQL/MariaDB fixture network or volume" >&2
  exit 1
fi

docker build --tag "${runner_image}" --file "${repository_root}/scripts/fixtures/mysql-conversion-runner.Dockerfile" "${repository_root}/scripts/fixtures"
docker volume create "${binary_volume}" >/dev/null
docker run --rm \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_volume}:/out" \
  --workdir /src \
  golang:1.22-bookworm \
  go test -c -o /out/migration.test ./internal/migration

docker network create "${fixture_network}" >/dev/null
docker run --detach --rm \
  --name "${source_mysql_container}" \
  --network "${fixture_network}" \
  --env MYSQL_ROOT_PASSWORD="${fixture_password}" \
  --env MYSQL_ROOT_HOST=% \
  --tmpfs /var/lib/mysql:rw,uid=999,gid=999,mode=0700 \
  "${mysql_image}" >/dev/null
docker run --detach --rm \
  --name "${source_mariadb_container}" \
  --network "${fixture_network}" \
  --env MARIADB_ROOT_PASSWORD="${fixture_password}" \
  --env MARIADB_ROOT_HOST=% \
  --tmpfs /var/lib/mysql:rw,uid=999,gid=999,mode=0700 \
  "${mariadb_image}" >/dev/null

for container in "${source_mysql_container}" "${source_mariadb_container}"; do
  ready=0
  for _attempt in {1..90}; do
    admin_command=mysqladmin
    if [[ "${container}" == "${source_mariadb_container}" ]]; then admin_command=mariadb-admin; fi
    if docker exec "${container}" sh -c "${admin_command} ping --silent -h127.0.0.1 -uroot -p'${fixture_password}'" >/dev/null 2>&1; then
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

run_direction() {
  local source_engine="$1"
  local target_engine="$2"
  local source_port target_port
  if [[ "${source_engine}" == "mysql" ]]; then source_port=13306; else source_port=13307; fi
  if [[ "${target_engine}" == "mysql" ]]; then target_port=13306; else target_port=13307; fi

  docker run --rm \
    --network "${fixture_network}" \
    --volume "${binary_volume}:/work:ro" \
    --env ASKIO_MIGRATION_MYSQL_INTEGRATION=disposable-conversion-cycle \
    --env ASKIO_MIGRATION_MYSQL_SOURCE_ENGINE="${source_engine}" \
    --env ASKIO_MIGRATION_MYSQL_TARGET_ENGINE="${target_engine}" \
    --env ASKIO_MIGRATION_MYSQL_SOURCE_PORT="${source_port}" \
    --env ASKIO_MIGRATION_MYSQL_TARGET_PORT="${target_port}" \
    --env ASKIO_MIGRATION_MYSQL_PASSWORD="${fixture_password}" \
    --env ASKIO_MIGRATION_MYSQL_HOST=127.0.0.1 \
    --env ASKIO_MIGRATION_MYSQL_SSL_MODE=disable \
    "${runner_image}" \
    sh -c "socat TCP-LISTEN:13306,bind=127.0.0.1,reuseaddr,fork TCP:${source_mysql_container}:3306 & socat TCP-LISTEN:13307,bind=127.0.0.1,reuseaddr,fork TCP:${source_mariadb_container}:3306 & exec /work/migration.test -test.v -test.run '^TestMySQLOfflineMigrationCycle$'"
}

run_direction mysql mariadb
run_direction mariadb mysql
