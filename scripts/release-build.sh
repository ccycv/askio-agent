#!/usr/bin/env bash
# Build the Linux amd64 askio-monitor release candidate and write its
# provenance manifest beside it. Builds nothing else, publishes nothing.
#
#   scripts/release-build.sh            # from a clean git checkout
#
# Outputs (OUT_DIR defaults to ./bin):
#   askio-monitor-linux-amd64                  the artifact
#   askio-monitor-linux-amd64.sha256           "<sha256>  askio-monitor-linux-amd64"
#   askio-monitor-linux-amd64.provenance.json  the provenance manifest
#
# Environment (all optional):
#   OUT_DIR              output directory (default: bin)
#   REQUIRED_GO_VERSION  toolchain the build must use (default: go1.22.12)
#   RELEASE_COMMIT       40-hex source revision; required when building an
#                        exported source tree that has no .git metadata
#   SOURCE_DATE_EPOCH    commit time in Unix seconds (default: HEAD's commit time)
#   RELEASE_TREE         without .git metadata only: "exported" (default) or
#                        "clean" when the caller verified a clean checkout
#   RELEASE_ALLOW_DIRTY  set to 1 to build a dirty tree for local experiments;
#                        the manifest then says tree "dirty" and the embedded
#                        commit ends in "-dirty", so it can never pass as a release
#   RELEASE_BUILDER      builder identity recorded in the manifest (default: local)
#   BUILDER_IMAGE        digest-pinned builder image, when building in one
#
# See docs/RELEASE.md.
set -euo pipefail
umask 022
export LC_ALL=C

die() { echo "release-build: $*" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

command -v go >/dev/null 2>&1 || die "go is not on PATH"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

ARTIFACT_NAME="askio-monitor-linux-amd64"
MAIN_PACKAGE="./cmd/askio-monitor"
VERSION_PACKAGE="github.com/askio-cloud/askio-monitor/internal/version"
OUT_DIR="${OUT_DIR:-bin}"
REQUIRED_GO_VERSION="${REQUIRED_GO_VERSION:-go1.22.12}"
RELEASE_BUILDER="${RELEASE_BUILDER:-local}"
BUILDER_IMAGE="${BUILDER_IMAGE:-}"

# --- Version: the VERSION file is the single source --------------------------
[[ -f VERSION ]] || die "VERSION file is missing"
version="$(cat VERSION)"
[[ "$(wc -c < VERSION | tr -d ' ')" == "$(( ${#version} + 1 ))" ]] \
  || die "VERSION must be one line ending in a single newline"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "VERSION '${version}' is not MAJOR.MINOR.PATCH"

# --- Source identity ------------------------------------------------------------
in_git=0
if git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  && [[ "$(git rev-parse --show-toplevel)" == "$(pwd -P)" ]]; then
  in_git=1
fi

tag=""
if [[ "${in_git}" == 1 ]]; then
  head_commit="$(git rev-parse HEAD)"
  commit="${RELEASE_COMMIT:-${head_commit}}"
  [[ "${commit}" == "${head_commit}" ]] || die "RELEASE_COMMIT ${commit} is not HEAD ${head_commit}"
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    tree="dirty"
  else
    tree="clean"
  fi
  source_date_epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}"
  [[ "${source_date_epoch}" == "$(git log -1 --format=%ct HEAD)" ]] \
    || die "SOURCE_DATE_EPOCH must be HEAD's commit time"
  # A release tag is optional (tagging is the owner's decision), but if HEAD
  # carries v* tags they must all name this version.
  while IFS= read -r t; do
    [[ -z "${t}" ]] && continue
    [[ "${t}" == "v${version}" ]] || die "HEAD is tagged ${t} but VERSION is ${version}"
    tag="${t}"
  done < <(git tag --points-at HEAD --list 'v*')
else
  commit="${RELEASE_COMMIT:-}"
  [[ -n "${commit}" ]] || die "not a git checkout: set RELEASE_COMMIT and SOURCE_DATE_EPOCH"
  source_date_epoch="${SOURCE_DATE_EPOCH:-}"
  [[ -n "${source_date_epoch}" ]] || die "not a git checkout: set SOURCE_DATE_EPOCH"
  # A wrapper that verified a clean checkout itself (scripts/release-build-docker.sh)
  # may say so; otherwise the tree is an export such as `git archive` output.
  tree="${RELEASE_TREE:-exported}"
fi
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || die "commit '${commit}' is not a full 40-hex revision"
[[ "${source_date_epoch}" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH '${source_date_epoch}' is not an integer"

embedded_commit="${commit}"
case "${tree}" in
  clean|exported) ;;
  dirty)
    [[ "${RELEASE_ALLOW_DIRTY:-0}" == 1 ]] || die "working tree is dirty; commit first (or RELEASE_ALLOW_DIRTY=1 for a non-release experiment)"
    embedded_commit="${commit}-dirty"
    ;;
  *) die "RELEASE_TREE must be clean or exported" ;;
esac
export SOURCE_DATE_EPOCH="${source_date_epoch}"
commit_time="$(date -u -d "@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
  || date -u -r "${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)"

# --- Toolchain and pinned build environment -----------------------------------
# GOTOOLCHAIN=local stops go.mod from switching toolchains behind our back.
export GOTOOLCHAIN=local
go_version="$(go env GOVERSION)"
[[ "${go_version}" == "${REQUIRED_GO_VERSION}" ]] \
  || die "toolchain is ${go_version}; the release toolchain is ${REQUIRED_GO_VERSION}"
host_platform="$(go env GOHOSTOS)/$(go env GOHOSTARCH)"

export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
export GOFLAGS=-mod=readonly GOEXPERIMENT=
unset GOARM GO386 GOMIPS GOMIPS64 GOPPC64 GOWASM 2>/dev/null || true

ldflags="-s -w -buildid= -X ${VERSION_PACKAGE}.Version=${version} -X ${VERSION_PACKAGE}.Commit=${embedded_commit} -X ${VERSION_PACKAGE}.GoVersion=${go_version}"
build_flags=(-trimpath -buildvcs=false)

go mod verify >/dev/null || die "go mod verify failed"

mkdir -p "${OUT_DIR}"
artifact="${OUT_DIR}/${ARTIFACT_NAME}"
rm -f "${artifact}" "${artifact}.sha256" "${artifact}.provenance.json"
go build "${build_flags[@]}" -ldflags "${ldflags}" -o "${artifact}.tmp" "${MAIN_PACKAGE}"
mv -f "${artifact}.tmp" "${artifact}"
chmod 0755 "${artifact}"

# --- ELF identity: 64-bit, little-endian, x86-64 --------------------------------
elf_header="$(od -An -tx1 -N20 "${artifact}" | tr -d ' \n')"
[[ "${elf_header:0:12}" == "7f454c460201" ]] || die "artifact is not a 64-bit little-endian ELF"
[[ "${elf_header:36:4}" == "3e00" ]] || die "artifact ELF machine is not x86-64"

artifact_sha256="$(sha256_of "${artifact}")"
artifact_size="$(wc -c < "${artifact}" | tr -d ' ')"
printf '%s  %s\n' "${artifact_sha256}" "${ARTIFACT_NAME}" > "${artifact}.sha256"

# The manifest is written without jq (the pinned golang builder image has
# none). Every interpolated value is checked against a character set that
# needs no JSON escaping, so the output is valid JSON by construction.
json_safe() {
  [[ "$2" =~ ^[A-Za-z0-9\ ._:/@=+-]*$ ]] || die "manifest value $1 has characters outside the safe set: $2"
  printf '%s' "$2"
}
json_string_or_null() {
  if [[ -z "$2" ]]; then printf 'null'; else printf '"%s"' "$(json_safe "$1" "$2")"; fi
}
module="$(go list -m)"
go_mod_sha256="$(sha256_of go.mod)"
go_sum_sha256="$(sha256_of go.sum)"
{
  printf '{\n'
  printf '  "schema": "askio-monitor.release-provenance.v1",\n'
  printf '  "status": "candidate",\n'
  printf '  "artifact": {\n'
  printf '    "name": "%s",\n' "$(json_safe name "${ARTIFACT_NAME}")"
  printf '    "sha256": "%s",\n' "$(json_safe sha256 "${artifact_sha256}")"
  printf '    "size": %s,\n' "$(json_safe size "${artifact_size}")"
  printf '    "os": "linux",\n'
  printf '    "arch": "amd64",\n'
  printf '    "format": "ELF 64-bit LSB executable, x86-64, statically linked"\n'
  printf '  },\n'
  printf '  "version": "%s",\n' "$(json_safe version "${version}")"
  printf '  "source": {\n'
  printf '    "module": "%s",\n' "$(json_safe module "${module}")"
  printf '    "commit": "%s",\n' "$(json_safe commit "${commit}")"
  printf '    "embeddedCommit": "%s",\n' "$(json_safe embeddedCommit "${embedded_commit}")"
  printf '    "tree": "%s",\n' "$(json_safe tree "${tree}")"
  printf '    "tag": %s,\n' "$(json_string_or_null tag "${tag}")"
  printf '    "sourceDateEpoch": %s,\n' "$(json_safe sourceDateEpoch "${source_date_epoch}")"
  printf '    "commitTime": "%s",\n' "$(json_safe commitTime "${commit_time}")"
  printf '    "goModSha256": "%s",\n' "$(json_safe goModSha256 "${go_mod_sha256}")"
  printf '    "goSumSha256": "%s"\n' "$(json_safe goSumSha256 "${go_sum_sha256}")"
  printf '  },\n'
  printf '  "build": {\n'
  printf '    "goVersion": "%s",\n' "$(json_safe goVersion "${go_version}")"
  printf '    "package": "%s",\n' "$(json_safe package "${MAIN_PACKAGE}")"
  printf '    "flags": ["-trimpath", "-buildvcs=false"],\n'
  printf '    "ldflags": "%s",\n' "$(json_safe ldflags "${ldflags}")"
  printf '    "env": {"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOFLAGS": "%s", "GOTOOLCHAIN": "local"}\n' "$(json_safe GOFLAGS "${GOFLAGS}")"
  printf '  },\n'
  printf '  "builder": {\n'
  printf '    "id": "%s",\n' "$(json_safe builder "${RELEASE_BUILDER}")"
  printf '    "hostPlatform": "%s",\n' "$(json_safe hostPlatform "${host_platform}")"
  printf '    "image": %s\n' "$(json_string_or_null image "${BUILDER_IMAGE}")"
  printf '  },\n'
  printf '  "promotion": "Not promoted. Promotion requires recorded owner authorization: see docs/RELEASE.md."\n'
  printf '}\n'
} > "${artifact}.provenance.json"

echo "release-build: ${artifact}"
echo "release-build: version ${version} commit ${embedded_commit} ${go_version} tree ${tree}"
echo "release-build: sha256 ${artifact_sha256} size ${artifact_size}"
