#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
binary_volume="askio_file_capacity_binary_smoke"

cleanup() {
  docker volume rm "${binary_volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing file-capacity fixture volume" >&2
  exit 1
fi

docker volume create "${binary_volume}" >/dev/null
docker run --rm \
  --env CGO_ENABLED=0 \
  --volume "${repository_root}:/src:ro" \
  --volume "${binary_volume}:/out" \
  --workdir /src \
  golang:1.22-bookworm \
  go test -c -o /out/migration.test ./internal/migration

docker run --rm \
  --tmpfs /capacity:rw,size=24m,mode=0700 \
  --volume "${binary_volume}:/work:ro" \
  --env ASKIO_MIGRATION_CAPACITY_INTEGRATION=disposable-tmpfs \
  --env ASKIO_MIGRATION_CAPACITY_ROOT=/capacity \
  golang:1.22-bookworm \
  /work/migration.test -test.v -test.run '^TestFileSyncDiskExhaustionStopsBeforeTransferOrTargetMutation$'
