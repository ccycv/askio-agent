#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container_name="askio-compose-dind-smoke"
binary_volume="askio_compose_binary_smoke"

cleanup() {
  docker stop "${container_name}" >/dev/null 2>&1 || true
  docker volume rm "${binary_volume}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if docker container inspect "${container_name}" >/dev/null 2>&1; then
  echo "refusing to reuse existing Compose fixture container" >&2
  exit 1
fi
if docker volume inspect "${binary_volume}" >/dev/null 2>&1; then
  echo "refusing to reuse existing Compose fixture volume" >&2
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

# Privilege is confined to this disposable nested daemon. The test needs the
# daemon and the agent's /run path in the same Linux mount namespace.
docker run --detach --rm --privileged \
  --name "${container_name}" \
  --volume "${binary_volume}:/work:ro" \
  docker:29-dind >/dev/null

ready=0
for _attempt in {1..90}; do
  if docker exec "${container_name}" docker info >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  docker logs "${container_name}"
  exit 1
fi

docker exec "${container_name}" docker pull redis:7.4-alpine >/dev/null
image="$(docker exec "${container_name}" docker image inspect --format '{{index .RepoDigests 0}}' redis:7.4-alpine)"
if [[ "${image}" != *@sha256:* ]]; then
  echo "fixture image did not resolve to a repository digest" >&2
  exit 1
fi

docker exec \
  --env ASKIO_MIGRATION_COMPOSE_INTEGRATION=disposable-dind \
  --env ASKIO_MIGRATION_COMPOSE_IMAGE="${image}" \
  "${container_name}" \
  /work/migration.test -test.v -test.run '^TestComposeRuntimeSecretLifecycle$'
