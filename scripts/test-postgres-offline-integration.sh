#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_container="askio-pg-source-smoke"
target_container="askio-pg-target-smoke"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/askio-pg-offline.XXXXXX")"
source_socket_directory="${fixture_root}/source-socket"
target_socket_directory="${fixture_root}/target-socket"
binary_directory="${fixture_root}/binary"
mkdir "${source_socket_directory}" "${target_socket_directory}" "${binary_directory}"
chmod 0777 "${source_socket_directory}" "${target_socket_directory}" "${binary_directory}"

cleanup() {
  # Both containers are --rm, so stopping removes only these exact fixtures.
  docker stop "${source_container}" "${target_container}" >/dev/null 2>&1 || true
  # The exact mktemp-owned paths avoid Docker named-volume capacity coupling.
  rm "${binary_directory}/migration.test" >/dev/null 2>&1 || true
  rmdir "${source_socket_directory}" "${target_socket_directory}" "${binary_directory}" "${fixture_root}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if docker container inspect "${source_container}" >/dev/null 2>&1 ||
  docker container inspect "${target_container}" >/dev/null 2>&1; then
  echo "refusing to reuse existing PostgreSQL fixture containers" >&2
  exit 1
fi

docker run --rm \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_directory}:/out" \
  --workdir /src \
  golang:1.22-bookworm \
  go test -c -o /out/migration.test ./internal/migration

docker run --detach --rm \
  --name "${source_container}" \
  --env POSTGRES_PASSWORD=fixture-pass \
  --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
  --volume "${source_socket_directory}:/var/run/postgresql" \
  postgres:14 -c listen_addresses= >/dev/null
docker run --detach --rm \
  --name "${target_container}" \
  --env POSTGRES_PASSWORD=fixture-pass \
  --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
  --volume "${target_socket_directory}:/var/run/postgresql" \
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
  --volume "${binary_directory}:/work:ro" \
  --volume "${source_socket_directory}:/sockets/source" \
  --volume "${target_socket_directory}:/sockets/target" \
  --env ASKIO_MIGRATION_POSTGRES_INTEGRATION=disposable-postgres-14-to-16 \
  --env ASKIO_MIGRATION_POSTGRES_SOURCE_SOCKET=/sockets/source \
  --env ASKIO_MIGRATION_POSTGRES_TARGET_SOCKET=/sockets/target \
  --env ASKIO_MIGRATION_POSTGRES_PASSWORD=fixture-pass \
  postgres:16 \
  /work/migration.test -test.v -test.run '^TestPostgres(Offline|MultiDatabase)MigrationCycle$'
