#!/usr/bin/env bash
# Run scripts/release-build.sh inside a digest-pinned Go builder image, the
# builder Askio records in backend/config/agent-release.json ("builderImage").
#
#   scripts/release-build-docker.sh
#
# Environment (all optional):
#   BUILDER_IMAGE     image@sha256 reference (default: the pinned golang 1.22.12 image)
#   OUT_DIR           host output directory (default: bin/docker)
#   HOST_GOMODCACHE   host module cache to mount read-only instead of letting
#                     the container download modules (they are checked against
#                     go.sum either way)
#
# The source is mounted read-only and the build runs as the calling user.
set -euo pipefail
export LC_ALL=C

die() { echo "release-build-docker: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

BUILDER_IMAGE="${BUILDER_IMAGE:-golang@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253}"
[[ "${BUILDER_IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]] || die "BUILDER_IMAGE must be pinned by digest"
OUT_DIR="${OUT_DIR:-bin/docker}"
command -v docker >/dev/null 2>&1 || die "docker is required"

[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || die "working tree is dirty; commit first"
commit="$(git rev-parse HEAD)"
epoch="$(git log -1 --format=%ct HEAD)"

mkdir -p "${OUT_DIR}"
out="$(cd "${OUT_DIR}" && pwd)"

mounts=(-v "${ROOT}:/src:ro" -v "${out}:/out")
env_args=(-e HOME=/tmp -e GOCACHE=/tmp/gocache -e OUT_DIR=/out
  -e RELEASE_COMMIT="${commit}" -e SOURCE_DATE_EPOCH="${epoch}" -e RELEASE_TREE=clean
  -e RELEASE_BUILDER="${RELEASE_BUILDER:-local-docker}" -e BUILDER_IMAGE="${BUILDER_IMAGE}")
if [[ -n "${HOST_GOMODCACHE:-}" ]]; then
  mounts+=(-v "${HOST_GOMODCACHE}:/gomodcache:ro")
  env_args+=(-e GOMODCACHE=/gomodcache -e GOPROXY=off)
else
  env_args+=(-e GOMODCACHE=/tmp/gomodcache)
fi

docker run --rm --user "$(id -u):$(id -g)" "${mounts[@]}" "${env_args[@]}" -w /src "${BUILDER_IMAGE}" \
  ./scripts/release-build.sh
