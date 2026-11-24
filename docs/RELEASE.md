# Releasing askio-monitor

This document covers how an `askio-monitor` build becomes a release candidate, how that candidate is verified, and how a candidate may be promoted into the binary Askio production serves. Promotion is never automatic. It needs the project owner's explicit, recorded authorization for one exact digest.

## Roles

- **Owner.** The Askio project owner decides every merge, release, tag, artifact promotion and enrollment. Each of these decisions is separate. Approving one does not approve the next.
- **Release preparer.** Anyone else, including automation and AI sessions. They may build candidates, run the checks below and write evidence. They never promote, tag, publish or enroll anything.
- **CI** (`.github/workflows/ci.yml`). It builds and verifies with a read-only token. It does not upload artifacts, tag, release or deploy.

## Version

- The `VERSION` file at the repository root is the only version source. It holds one `MAJOR.MINOR.PATCH` line.
- Release builds embed it with `-ldflags -X`. The in-source default in `internal/version/version.go` must equal it, and `TestDefaultVersionMatchesVERSIONFile` enforces this, so a plain `go build` also reports the right version.
- Bump `VERSION` in a pull request for every source change since the last promoted release. Two different binaries must never report the same version. The backend compares the version verbatim:
  - the heartbeat `agent_version`;
  - the migration enrollment check against `AGENT_RELEASE_VERSION`;
  - the installers' and agent-update script's version checks.
- `0.4.39` is the last promoted version: source `50b8bbd…`, SHA-256 `9e577e73…`. `0.4.40` is a candidate that has not been promoted ([notes](releases/0.4.40.md)). `main` has changed since then: the remote inventory switch was added. The next candidate is therefore `0.4.41` ([notes](releases/0.4.41.md)).
- Git tags are optional, and creating one is the owner's decision. If `HEAD` carries any `v*` tag, `scripts/release-build.sh` requires it to be exactly `v<VERSION>`.

## `--version` output contract

```text
askio-monitor version 0.4.40 (commit <40-hex source revision>, go1.22.12, linux/amd64)
```

The line begins with exactly `askio-monitor version <VERSION>`, as every earlier release did. These consumers in the Askio repository rely on it:

| Consumer | How it reads the output |
| --- | --- |
| `backend/config/install-scripts/agent-install.sh`, `agent-host-install.sh` and their `public/` copies (`verify_binary_version`) | `grep -Fq "$BINARY_VERSION"` over the whole output |
| `backend/apps/api/src/routes/operations-agent-update.ts` (generated update script) | `grep -Fq "$EXPECTED_VERSION"`. The script also interpolates the output into a hand-built JSON string. |
| `scripts/smoke/verify-public-agent-artifact.sh` | Glob match `*"askio-monitor version ${AGENT_VERSION}"*` |

The build details therefore go on the **same line**, in parentheses. The line never contains a newline, quote or backslash. A multi-line output would break the agent-update result JSON. `TestLineKeepsParsedPrefixAndIsOneSafeLine` and `TestVersionFlagPrintsOneCompatibleLine` guard this contract. The heartbeat, User-Agent (`askio-monitor/<VERSION>`) and `--package-version` default still carry the plain version.

## Build recipe

| Setting | Value |
| --- | --- |
| Toolchain | `go1.22.12`, either the official go.dev tarball or the builder image `golang@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253` (the one in Askio's `agent-release.json`). `GOTOOLCHAIN=local`. |
| Environment | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOFLAGS=-mod=readonly`, plus `SOURCE_DATE_EPOCH` set to the commit time |
| Flags | `-trimpath -buildvcs=false` |
| ldflags | `-s -w -buildid= -X …/internal/version.Version=<VERSION> -X …/internal/version.Commit=<commit> -X …/internal/version.GoVersion=go1.22.12` |
| Package | `./cmd/askio-monitor` |

This is ADR-010's recipe with two additions: `-buildvcs=false` and the `-X` version flags. `-buildvcs=false` keeps the bytes the same whether or not `.git` is present. The commit is embedded explicitly instead.

Commands:

```sh
make release                # bin/askio-monitor-linux-amd64 (+ .sha256, .provenance.json); clean tree required
make verify-release         # scripts/verify-release.sh --source . bin/askio-monitor-linux-amd64
make reproducibility-check  # two more builds from `git archive HEAD`, fresh GOCACHE each; all must match
make release-docker         # same build inside the pinned builder image -> bin/docker/
```

`make release` refuses a dirty tree. It also refuses any toolchain other than `go1.22.12` and a `VERSION` that is not `MAJOR.MINOR.PATCH`. `RELEASE_ALLOW_DIRTY=1` exists only for experiments. Such a build embeds `<commit>-dirty`, its manifest says `"tree": "dirty"`, and `verify-release.sh` rejects it.

The macOS host can cross-build the release, and the result is byte-identical. It cannot compile or test `internal/agent` for darwin. Run the tests on Linux, as CI does.

## Provenance manifest

`bin/askio-monitor-linux-amd64.provenance.json` (schema `askio-monitor.release-provenance.v1`) records:

| Field | Meaning |
| --- | --- |
| `artifact.sha256`, `artifact.size` | Digest and byte size of the binary |
| `version` | `VERSION` at build time |
| `source.commit`, `source.embeddedCommit`, `source.tree`, `source.tag` | Source revision, the value embedded in the binary, `clean` or `exported` (a `git archive` copy), and the `v*` tag if any |
| `source.sourceDateEpoch`, `source.commitTime` | Commit time used as `SOURCE_DATE_EPOCH` |
| `source.goModSha256`, `source.goSumSha256` | Digests of `go.mod` and `go.sum` |
| `build.goVersion`, `build.flags`, `build.ldflags`, `build.env`, `build.package` | The exact recipe |
| `builder.id`, `builder.hostPlatform`, `builder.image` | Who built it: `local`, `github-actions` or a docker builder, with the image digest |
| `status`, `promotion` | Always `candidate` and "not promoted". The manifest is never an authorization. |

The manifest holds no wall-clock time, hostname or user name. Two builds of one commit on the same kind of builder give identical manifests.

`scripts/verify-release.sh [--source DIR] [--run] [--skip-buildinfo] BINARY` checks the following:

- **Always:** the manifest schema; the recipe fields, which must equal the release recipe; that the tree is not dirty; the SHA-256 and size; the `.sha256` sidecar; and the ELF header (64-bit, little-endian, x86-64).
- **With Go installed:** `go version -m`. This covers the toolchain version, `-trimpath`, `CGO_ENABLED=0`, `linux/amd64` `GOAMD64=v1`, the absence of a VCS stamp, and the module path. Go omits `-ldflags` from build info under `-trimpath`, so the embedded version is checked by `--run`.
- **`--source DIR`:** `VERSION`, the `go.mod` and `go.sum` digests and `HEAD`. It also checks that every module embedded in the binary appears in `go.sum`.
- **`--run`:** executes `BINARY --version` and requires the exact expected line. It runs natively on linux/amd64; elsewhere it uses `docker --platform linux/amd64`.

## Candidate qualification

Do all of this before asking the owner to authorize a promotion:

1. The candidate commit is on `main`, or is an exact commit the owner named, and CI is green for it.
2. `VERSION` is bumped relative to the last promoted release.
3. From a clean checkout of that commit:
   - `make release`;
   - `make verify-release` plus `--run` on linux/amd64;
   - `make reproducibility-check`;
   - `make release-docker`, which must be `cmp`-identical to `bin/askio-monitor-linux-amd64`.
   CI runs the same steps on every pull request.
4. Write down the candidate's version, commit, artifact SHA-256 and manifest SHA-256, together with the evidence above, in `docs/releases/<version>.md` (for example [0.4.40](releases/0.4.40.md)). That file also holds the tag plan; the tag itself waits for the owner.

A merge commit or squash commit is a new commit. Its build embeds a different commit and so has a different digest. Evidence from a pull request's head proves the recipe. It does not prove the digest that gets promoted. Qualify the commit that will actually be promoted.

## Promotion authorization

**Promotion** means replacing the artifact production serves, `backend/config/agent-binaries/askio-monitor` in the Askio repository (`ccycv/askio`). The release metadata that must move with it in the same Askio pull request is pinned by `backend/apps/api/src/routes/agent-release-artifact.test.ts`:

- `backend/config/agent-release.json`: `version`, `sha256`, `sourceRevision`, `goVersion`, `builderImage` and `migrationServiceUnitSha256`;
- `BINARY_VERSION` and `BINARY_SHA256` in `backend/config/install-scripts/agent-install.sh` and `agent-host-install.sh`, and in their byte-identical `public/` copies;
- `supabase/functions/_shared/agent-release.ts`: `AGENT_RELEASE_VERSION` and `AGENT_RELEASE_SHA256`;
- `src/hooks/useOperationsAgents.ts`: `LATEST_AGENT_VERSION`.

No promotion happens without an **authorization record**. It is a statement by the owner, in their own words, posted where it cannot be edited silently, for example as a comment on the Askio promotion pull request. It must contain all of the following:

```yaml
authorization:
  action: promote askio-monitor to backend/config/agent-binaries/askio-monitor
  authorized_by: <owner's name and GitHub login>
  authorized_at: <UTC timestamp, e.g. 2026-11-20T14:05:00Z>
  version: 0.4.40
  source_commit: <40-hex commit the candidate was built from>
  artifact_sha256: <64-hex SHA-256 of the binary>
  manifest_sha256: <64-hex SHA-256 of the provenance manifest>
  rollback_to: <previous promoted version and SHA-256, e.g. 0.4.39 9e577e73...>
  scope: promotion only; does not enable any VULNERABILITY_* flag or enroll any host
```

The record works under these rules:

- **One authorization covers one digest.** A rebuild that produces a different SHA-256, for any reason, needs a new authorization.
- **It must match the bytes.** Whoever carries out the promotion first rebuilds or fetches the candidate. They confirm that `scripts/verify-release.sh --source <checkout of source_commit> --run` passes and that the SHA-256 equals `artifact_sha256`. Only then do they copy it into the Askio repository.
- **It is linked and checked.** The Askio promotion pull request links the record. Its description repeats `version`, `source_commit` and `artifact_sha256`. A reviewer checks that these match the binary in the diff.
- **It does not authorize deployment or merge.** Merging the Askio pull request, and so publishing the binary through the backend release workflow, remains the owner's separate decision. After deployment, `scripts/smoke/verify-public-agent-artifact.sh` in the Askio repository must pass.
- **It does not authorize anything else.** It never authorizes enabling `VULNERABILITY_*` flags, enrolling hosts or opting any host in to inventory collection. Those follow [ENROLLMENT.md](ENROLLMENT.md).
- **Rollback.** Rolling back to `rollback_to` uses the same Askio files and is covered by the record that named it. Rolling back to any other digest needs a new record.
- **Nothing in this repository promotes.** Neither the agent repository nor its CI ever writes to the Askio repository, a registry or a release.

## Optional signing (not set up)

No signing keys exist and none are required today: the installers trust the SHA-256 pinned in the Askio repository. If the owner decides to add detached signatures, sign the binary and the manifest after qualification and before the authorization request. Publish the public key through a separate owner-approved change. A signature proves who built the file. It does not replace the authorization record.

minisign (offline key held by the owner):

```sh
minisign -G -p askio-monitor.pub -s askio-monitor.key            # once, by the owner; never commit the secret key
minisign -S -s askio-monitor.key -t "askio-monitor 0.4.40 <commit>" \
  -m bin/askio-monitor-linux-amd64 bin/askio-monitor-linux-amd64.provenance.json
minisign -V -p askio-monitor.pub -m bin/askio-monitor-linux-amd64          # verify (also the .provenance.json)
```

cosign (key pair, or keyless with an OIDC identity):

```sh
cosign generate-key-pair                                          # once, by the owner
cosign sign-blob --key cosign.key --bundle bin/askio-monitor-linux-amd64.sigstore.json bin/askio-monitor-linux-amd64
cosign verify-blob --key cosign.pub --bundle bin/askio-monitor-linux-amd64.sigstore.json bin/askio-monitor-linux-amd64
```

Keyless cosign writes an entry to the public Rekor transparency log. That would publish the digest, so it needs the owner's approval like any other publication.
