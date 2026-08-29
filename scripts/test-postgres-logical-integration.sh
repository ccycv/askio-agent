#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary_volume="askio_pg_logical_binary_smoke"
certificate_volume="askio_pg_logical_cert_smoke"
postgres_majors=(14 15 16 17)

source_container() { printf 'askio-pg-logical-source-%s' "$1"; }
target_container() { printf 'askio-pg-logical-target-%s' "$1"; }
fixture_network() { printf 'askio-pg-logical-network-%s' "$1"; }

cleanup() {
  for major in "${postgres_majors[@]}"; do
    docker stop "$(source_container "${major}")" "$(target_container "${major}")" >/dev/null 2>&1 || true
    docker network rm "$(fixture_network "${major}")" >/dev/null 2>&1 || true
  done
  docker volume rm "${binary_volume}" "${certificate_volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for major in "${postgres_majors[@]}"; do
  if docker container inspect "$(source_container "${major}")" >/dev/null 2>&1 ||
    docker container inspect "$(target_container "${major}")" >/dev/null 2>&1 ||
    docker network inspect "$(fixture_network "${major}")" >/dev/null 2>&1; then
    echo "refusing to reuse an existing PostgreSQL ${major} logical fixture" >&2
    exit 1
  fi
done
if docker volume inspect "${binary_volume}" >/dev/null 2>&1 || docker volume inspect "${certificate_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing PostgreSQL logical fixture volumes" >&2
  exit 1
fi

docker volume create "${binary_volume}" >/dev/null
docker run --rm \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_volume}:/out" \
  --workdir /src \
  golang:1.22.12-bookworm \
  /usr/local/go/bin/go test -c -o /out/migration.test ./internal/migration

docker volume create "${certificate_volume}" >/dev/null
source_sans="DNS:$(source_container 14),DNS:$(source_container 15),DNS:$(source_container 16),DNS:$(source_container 17)"
docker run --rm \
  --user root \
  --env SOURCE_SANS="${source_sans}" \
  --volume "${certificate_volume}:/certs" \
  alpine:3.20 sh -ec '
    apk add --no-cache openssl >/dev/null
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Askio disposable PostgreSQL CA" -keyout /certs/ca.key -out /certs/source-ca.crt >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -subj "/CN=askio-pg-logical-source" -addext "subjectAltName=${SOURCE_SANS}" -keyout /certs/server.key -out /certs/server.csr >/dev/null 2>&1
    openssl x509 -req -days 2 -in /certs/server.csr -CA /certs/source-ca.crt -CAkey /certs/ca.key -CAcreateserial -copy_extensions copy -out /certs/server.crt >/dev/null 2>&1
    rm /certs/ca.key /certs/server.csr /certs/source-ca.srl
    chown 999:999 /certs/server.key /certs/server.crt /certs/source-ca.crt
    chmod 0600 /certs/server.key
    chmod 0644 /certs/server.crt /certs/source-ca.crt
  '

for major in "${postgres_majors[@]}"; do
  echo "PostgreSQL ${major} lower-downtime integration"
  source_name="$(source_container "${major}")"
  target_name="$(target_container "${major}")"
  network_name="$(fixture_network "${major}")"
  docker network create "${network_name}" >/dev/null
  docker run --detach --rm \
    --name "${source_name}" \
    --network "${network_name}" \
    --env POSTGRES_PASSWORD=fixture-pass \
    --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
    --volume "${certificate_volume}:/certs:ro" \
    "postgres:${major}" \
    -c listen_addresses='*' \
    -c wal_level=logical \
    -c max_replication_slots=8 \
    -c max_wal_senders=8 \
    -c ssl=on \
    -c ssl_cert_file=/certs/server.crt \
    -c ssl_key_file=/certs/server.key >/dev/null
  docker run --detach --rm \
    --name "${target_name}" \
    --network "${network_name}" \
    --env POSTGRES_PASSWORD=fixture-pass \
    --tmpfs /var/lib/postgresql/data:rw,uid=999,gid=999,mode=0700 \
    --volume "${binary_volume}:/work:ro" \
    --volume "${certificate_volume}:/var/lib/askio-migrations/certs:ro" \
    "postgres:${major}" -c listen_addresses='*' >/dev/null

  for container in "${source_name}" "${target_name}"; do
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

  docker exec \
    --env ASKIO_MIGRATION_POSTGRES_LOGICAL_INTEGRATION=disposable-postgres-logical \
    --env ASKIO_MIGRATION_POSTGRES_LOGICAL_SOURCE_HOST="${source_name}" \
    --env ASKIO_MIGRATION_POSTGRES_LOGICAL_TARGET_HOST=127.0.0.1 \
    --env ASKIO_MIGRATION_POSTGRES_LOGICAL_PASSWORD=fixture-pass \
    --env ASKIO_MIGRATION_POSTGRES_LOGICAL_CA_PATH=/var/lib/askio-migrations/certs/source-ca.crt \
    "${target_name}" /work/migration.test -test.v -test.run '^TestPostgresLogicalLowerDowntimeCycle$'

  docker stop "${source_name}" "${target_name}" >/dev/null
  docker network rm "${network_name}" >/dev/null
done
