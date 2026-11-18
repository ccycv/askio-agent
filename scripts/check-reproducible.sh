#!/usr/bin/env bash
# Prove the release build is reproducible: export HEAD twice with `git archive`
# into two different directories, build each with scripts/release-build.sh and
# its own empty GOCACHE, and require byte-identical artifacts. Optionally also
# require equality with an artifact built elsewhere (e.g. by `make release`).
#
#   scripts/check-reproducible.sh [ARTIFACT_TO_MATCH]
#
# Only committed content (HEAD) is built. Prints both SHA-256 values.
set -euo pipefail
export LC_ALL=C

die() { echo "check-reproducible: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
compare_with="${1:-}"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

commit="$(git rev-parse HEAD)"
epoch="$(git log -1 --format=%ct HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "check-reproducible: note: working tree is dirty; only HEAD ${commit} is built" >&2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/askio-repro.XXXXXX")"
cleanup() { chmod -R u+w "${work}" 2>/dev/null || true; rm -rf "${work}"; }
trap cleanup EXIT

hashes=()
for n in 1 2; do
  # Different directory names and depths, so any leaked path would show up.
  src="${work}/copy-${n}/$(printf 'src%.0s' $(seq 1 "${n}"))"
  mkdir -p "${src}" "${work}/gocache-${n}" "${work}/out-${n}"
  git archive --format=tar HEAD | tar -x -C "${src}"
  echo "check-reproducible: build ${n} in ${src}"
  ( cd "${src}" && \
    GOCACHE="${work}/gocache-${n}" OUT_DIR="${work}/out-${n}" \
    RELEASE_COMMIT="${commit}" SOURCE_DATE_EPOCH="${epoch}" \
    RELEASE_BUILDER="${RELEASE_BUILDER:-local}-repro-${n}" \
    ./scripts/release-build.sh >/dev/null )
  hashes+=("$(sha256_of "${work}/out-${n}/askio-monitor-linux-amd64")")
  echo "check-reproducible: build ${n} sha256 ${hashes[$((n - 1))]}"
done

[[ "${hashes[0]}" == "${hashes[1]}" ]] || die "builds differ: ${hashes[0]} != ${hashes[1]}"
cmp -s "${work}/out-1/askio-monitor-linux-amd64" "${work}/out-2/askio-monitor-linux-amd64" || die "builds differ byte-wise"
# Manifests differ only in the builder id we set on purpose.
diff <(jq 'del(.builder.id)' "${work}/out-1/askio-monitor-linux-amd64.provenance.json") \
     <(jq 'del(.builder.id)' "${work}/out-2/askio-monitor-linux-amd64.provenance.json") >/dev/null \
  || die "manifests differ beyond the builder id"

if [[ -n "${compare_with}" ]]; then
  [[ -f "${compare_with}" ]] || die "${compare_with} not found"
  other="$(sha256_of "${compare_with}")"
  [[ "${other}" == "${hashes[0]}" ]] || die "${compare_with} sha256 ${other} != clean builds ${hashes[0]}"
  echo "check-reproducible: ${compare_with} sha256 ${other} matches"
fi

echo "check-reproducible: PASS commit ${commit} sha256 ${hashes[0]}"
