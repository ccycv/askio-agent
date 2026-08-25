#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_container="askio-pg-source-smoke"
target_container="askio-pg-target-smoke"
source_socket_volume="askio_pg_source_socket_smoke"
target_socket_volume="askio_pg_target_socket_smoke"
binary_volume="askio_pg_binary_smoke"

cleanup() {
  # Both containers are --rm, so stopping removes only these exact fixtures.
  docker stop "${source_container}" "${target_container}" >/dev/null 2>&1 || true
  # Docker Desktop may return from stop before the volume mount is fully
  # released. Retry only the fixture-owned volumes so repeated smoke runs do
  # not leave a socket volume behind.
  for fixture_volume in "${source_socket_volume}" "${target_socket_volume}" "${binary_volume}"; do
    for _attempt in {1..20}; do
      if ! docker volume inspect "${fixture_volume}" >/dev/null 2>&1; then
        break
      fi
      if docker volume rm "${fixture_volume}" >/dev/null 2>&1; then
        break
      fi
      sleep 0.1
    done
  done
}
trap cleanup EXIT

if docker container inspect "${source_container}" >/dev/null 2>&1 ||
  docker container inspect "${target_container}" >/dev/null 2>&1; then
  echo "refusing to reuse existing PostgreSQL fixture containers" >&2
  exit 1
fi
if docker volume inspect "${source_socket_volume}" >/dev/null 2>&1 ||
  docker volume inspect "${target_socket_volume}" >/dev/null 2>&1 ||
  docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing PostgreSQL fixture volumes" >&2
  exit 1
fi

docker volume create "${binary_volume}" >/dev/null
docker run --rm \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_volume}:/out" \
  --workdir /src \
  golang:1.22-bookworm \
  go test -c -o /out/migration.test ./internal/migration

docker volume create "${source_socket_volume}" >/dev/null
docker volume create "${target_socket_volume}" >/dev/null
docker run --detach --rm \
  --name "${source_container}" \
  --env POSTGRES_PASSWORD=fixture-pass \
  --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
  --volume "${source_socket_volume}:/var/run/postgresql" \
  postgres:16 -c listen_addresses= >/dev/null
docker run --detach --rm \
  --name "${target_container}" \
  --env POSTGRES_PASSWORD=fixture-pass \
  --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
  --volume "${target_socket_volume}:/var/run/postgresql" \
  postgres:16 -c listen_addresses= >/dev/null

for container in "${source_container}" "${target_container}"; do
  ready=0
  for _attempt in {1..60}; do
    if docker exec "${container}" pg_isready -U postgres >/dev/null 2>&1; then
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

docker run --rm \
  --volume "${binary_volume}:/work:ro" \
  --volume "${source_socket_volume}:/sockets/source" \
  --volume "${target_socket_volume}:/sockets/target" \
  --env ASKIO_MIGRATION_POSTGRES_INTEGRATION=disposable-postgres-16 \
  --env ASKIO_MIGRATION_POSTGRES_SOURCE_SOCKET=/sockets/source \
  --env ASKIO_MIGRATION_POSTGRES_TARGET_SOCKET=/sockets/target \
  --env ASKIO_MIGRATION_POSTGRES_PASSWORD=fixture-pass \
  postgres:16 \
  /work/migration.test -test.v -test.run '^TestPostgresOfflineMigrationCycle$'
