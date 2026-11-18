#!/usr/bin/env bash
# Verify an askio-monitor release artifact against its provenance manifest.
#
#   scripts/verify-release.sh [options] BINARY
#
# Options:
#   --manifest PATH   manifest to check against (default: BINARY.provenance.json)
#   --source DIR      also check the manifest against a source checkout: VERSION,
#                     go.mod/go.sum digests, HEAD commit, and every module the
#                     binary embeds against DIR/go.sum
#   --run             execute BINARY --version and require the exact expected
#                     line (directly on linux/amd64, else in a linux/amd64
#                     container: VERIFY_DOCKER_IMAGE, default debian:bookworm-slim)
#   --skip-buildinfo  skip the `go version -m` checks (for hosts without Go)
#
# Always checked: manifest schema and fields, artifact SHA-256 and size, the
# .sha256 sidecar if present, and the ELF header (64-bit, little-endian,
# x86-64). With Go on PATH: toolchain version, -trimpath, CGO_ENABLED=0,
# GOOS/GOARCH/GOAMD64, no VCS stamping, module path.
#
# Exits non-zero on the first mismatch. It verifies; it never publishes.
set -euo pipefail
export LC_ALL=C

fail() { echo "verify-release: FAIL: $*" >&2; exit 1; }
ok() { echo "verify-release: ok   $*"; }
note() { echo "verify-release: note $*"; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

manifest="" source_dir="" run=0 skip_buildinfo=0 binary=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) manifest="${2:?--manifest needs a path}"; shift 2 ;;
    --source) source_dir="${2:?--source needs a directory}"; shift 2 ;;
    --run) run=1; shift ;;
    --skip-buildinfo) skip_buildinfo=1; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    -*) fail "unknown option $1" ;;
    *) [[ -z "${binary}" ]] || fail "only one BINARY"; binary="$1"; shift ;;
  esac
done
[[ -n "${binary}" ]] || fail "usage: verify-release.sh [--manifest PATH] [--source DIR] [--run] [--skip-buildinfo] BINARY"
[[ -f "${binary}" && ! -L "${binary}" ]] || fail "${binary} is not a regular file"
manifest="${manifest:-${binary}.provenance.json}"
[[ -f "${manifest}" ]] || fail "manifest ${manifest} not found"
command -v jq >/dev/null 2>&1 || fail "jq is required"

m() { jq -er "$1" "${manifest}" 2>/dev/null || fail "manifest field $1 is missing or invalid"; }

# --- Manifest shape -------------------------------------------------------------
[[ "$(m .schema)" == "askio-monitor.release-provenance.v1" ]] || fail "unknown manifest schema"
version="$(m .version)"
commit="$(m .source.commit)"
embedded_commit="$(m .source.embeddedCommit)"
tree="$(m .source.tree)"
go_version="$(m .build.goVersion)"
expected_sha256="$(m .artifact.sha256)"
expected_size="$(m .artifact.size)"
ldflags="$(m .build.ldflags)"
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "manifest version '${version}' is not MAJOR.MINOR.PATCH"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || fail "manifest commit is not a full revision"
[[ "${expected_sha256}" =~ ^[0-9a-f]{64}$ ]] || fail "manifest sha256 is malformed"
[[ "${expected_size}" =~ ^[0-9]+$ ]] || fail "manifest size is malformed"
[[ "$(m .artifact.os)/$(m .artifact.arch)" == "linux/amd64" ]] || fail "manifest platform is not linux/amd64"
case "${tree}" in
  clean|exported) [[ "${embedded_commit}" == "${commit}" ]] || fail "embedded commit differs from source commit" ;;
  dirty) fail "manifest records a dirty source tree; this build is not a release candidate" ;;
  *) fail "manifest source tree '${tree}' is unknown" ;;
esac
vp="github.com/askio-cloud/askio-monitor/internal/version"
expected_ldflags="-s -w -buildid= -X ${vp}.Version=${version} -X ${vp}.Commit=${commit} -X ${vp}.GoVersion=${go_version}"
[[ "${ldflags}" == "${expected_ldflags}" ]] || fail "manifest ldflags differ from the release recipe"
[[ "$(jq -c '.build.flags' "${manifest}")" == '["-trimpath","-buildvcs=false"]' ]] || fail "manifest build flags differ from the release recipe"
[[ "$(jq -c '.build.env' "${manifest}")" == '{"CGO_ENABLED":"0","GOOS":"linux","GOARCH":"amd64","GOAMD64":"v1","GOFLAGS":"-mod=readonly","GOTOOLCHAIN":"local"}' ]] \
  || fail "manifest build environment differs from the release recipe"
ok "manifest ${manifest}: version ${version}, commit ${commit}, ${go_version}, tree ${tree}"

# --- Artifact digest, size and sidecar ------------------------------------------
actual_sha256="$(sha256_of "${binary}")"
[[ "${actual_sha256}" == "${expected_sha256}" ]] || fail "sha256 ${actual_sha256} != manifest ${expected_sha256}"
actual_size="$(wc -c < "${binary}" | tr -d ' ')"
[[ "${actual_size}" == "${expected_size}" ]] || fail "size ${actual_size} != manifest ${expected_size}"
ok "sha256 ${actual_sha256} size ${actual_size}"
if [[ -f "${binary}.sha256" ]]; then
  [[ "$(cat "${binary}.sha256")" == "${expected_sha256}  $(m .artifact.name)" ]] || fail "${binary}.sha256 disagrees with the manifest"
  ok "sidecar ${binary}.sha256"
fi

# --- ELF identity ---------------------------------------------------------------
elf_header="$(od -An -tx1 -N20 "${binary}" | tr -d ' \n')"
[[ "${elf_header:0:12}" == "7f454c460201" ]] || fail "not a 64-bit little-endian ELF"
[[ "${elf_header:36:4}" == "3e00" ]] || fail "ELF machine is not x86-64"
ok "ELF 64-bit LSB x86-64"

# --- Go build info ----------------------------------------------------------------
buildinfo=""
if [[ "${skip_buildinfo}" == 1 ]]; then
  note "build info not checked (--skip-buildinfo)"
elif ! command -v go >/dev/null 2>&1; then
  fail "go is not on PATH; install it or pass --skip-buildinfo"
else
  buildinfo="$(go version -m "${binary}")" || fail "go version -m could not read build info"
  first="$(printf '%s\n' "${buildinfo}" | head -1)"
  [[ "${first##*: }" == "${go_version}" ]] || fail "binary toolchain '${first##*: }' != manifest ${go_version}"
  setting() { printf '%s\n' "${buildinfo}" | awk -F'\t' -v k="$1" '$2 == "build" && index($3, k "=") == 1 { print substr($3, length(k) + 2) }'; }
  [[ "$(setting -trimpath)" == "true" ]] || fail "binary was not built with -trimpath"
  [[ "$(setting CGO_ENABLED)" == "0" ]] || fail "binary was not built with CGO_ENABLED=0"
  [[ "$(setting GOOS)/$(setting GOARCH)" == "linux/amd64" ]] || fail "binary build platform is not linux/amd64"
  [[ "$(setting GOAMD64)" == "v1" ]] || fail "binary GOAMD64 is not v1"
  [[ "$(setting -buildmode)" == "exe" ]] || fail "binary build mode is not exe"
  [[ -z "$(printf '%s\n' "${buildinfo}" | awk -F'\t' '$2 == "build" && $3 ~ /^vcs\./')" ]] || fail "binary carries VCS stamping (expected -buildvcs=false)"
  [[ "$(printf '%s\n' "${buildinfo}" | awk -F'\t' '$2 == "mod" { print $3 }')" == "$(m .source.module)" ]] || fail "binary main module differs from manifest"
  ok "build info: ${go_version}, -trimpath, CGO_ENABLED=0, linux/amd64 v1, no VCS stamp"
fi

# --- Source checkout ----------------------------------------------------------------
if [[ -n "${source_dir}" ]]; then
  [[ -f "${source_dir}/VERSION" && -f "${source_dir}/go.sum" ]] || fail "--source ${source_dir} is not an askio-agent checkout"
  [[ "$(cat "${source_dir}/VERSION")" == "${version}" ]] || fail "source VERSION differs from manifest"
  [[ "$(sha256_of "${source_dir}/go.mod")" == "$(m .source.goModSha256)" ]] || fail "source go.mod digest differs from manifest"
  [[ "$(sha256_of "${source_dir}/go.sum")" == "$(m .source.goSumSha256)" ]] || fail "source go.sum digest differs from manifest"
  if git -C "${source_dir}" rev-parse HEAD >/dev/null 2>&1; then
    [[ "$(git -C "${source_dir}" rev-parse HEAD)" == "${commit}" ]] || fail "source HEAD differs from manifest commit"
  else
    note "source has no git metadata; HEAD not compared"
  fi
  if [[ -n "${buildinfo}" ]]; then
    deps=0
    while IFS=$'\t' read -r path ver sum; do
      [[ -n "${path}" ]] || continue
      grep -qxF "${path} ${ver} ${sum}" "${source_dir}/go.sum" || fail "embedded module ${path} ${ver} ${sum} is not in go.sum"
      deps=$((deps + 1))
    done < <(printf '%s\n' "${buildinfo}" | awk -F'\t' '$2 == "dep" { print $3 "\t" $4 "\t" $5 }')
    ok "source: VERSION, go.mod, go.sum, HEAD; ${deps} embedded modules found in go.sum"
  else
    ok "source: VERSION, go.mod, go.sum, HEAD"
  fi
fi

# --- Execute --version ------------------------------------------------------------
if [[ "${run}" == 1 ]]; then
  expected_line="askio-monitor version ${version} (commit ${embedded_commit}, ${go_version}, linux/amd64)"
  if [[ "$(uname -s)/$(uname -m)" == "Linux/x86_64" ]]; then
    actual_line="$("${binary}" --version)"
  else
    command -v docker >/dev/null 2>&1 || fail "--run needs a linux/amd64 host or docker"
    image="${VERIFY_DOCKER_IMAGE:-debian:bookworm-slim}"
    dir="$(cd "$(dirname "${binary}")" && pwd)"
    actual_line="$(docker run --rm --network none --platform linux/amd64 -v "${dir}:/work:ro" "${image}" "/work/$(basename "${binary}")" --version)"
  fi
  [[ "${actual_line}" == "${expected_line}" ]] || fail "--version printed '${actual_line}', expected '${expected_line}'"
  ok "--version: ${actual_line}"
else
  note "--version not executed (pass --run on linux/amd64 or with docker)"
fi

echo "verify-release: PASS ${binary}"
