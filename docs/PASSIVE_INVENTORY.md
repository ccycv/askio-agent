# Passive vulnerability inventory (P1-03)

This internal capability collects installed-package observations only. It is disabled by default and is separate from existing audit, operations, remediation and migration dispatch. It does not install/update packages, restart services, acquire package-manager locks, invoke a shell, inspect application health or grant mutation authority.

## Release and source boundary

This change starts from source revision `50b8bbdae511942d5049e7240c7b1235d2bf8fef`, the source pinned by Askio's retained agent `0.4.39` release metadata (Linux amd64 artifact SHA-256 `9e577e732d2bd10e748b39a84349cb596b32cafd8a4f546dc61f9c8c07f34b17`). That source tree was already merged to agent remote main. The older primary local checkout was not the distributed source baseline. This PR does not replace an artifact, change the version, install an agent or enable enrollment. A future release must separately build, version, promote and qualify its artifact.

## Explicit enablement

An operator-managed host config must opt in:

```yaml
inventory:
  enabled: true
```

The collector requires direct `host` mode and a fixed HTTPS API URL with verified TLS. `tls_skip_verify`, gateway mode, URL credentials and query/fragment overrides are rejected for this capability. The backend must independently enable its feature and enroll the current agent. Neither remote monitor config nor a generic task can enable this loop. With the local option absent or false, no inventory polling or collection occurs.

## Protocol version 1

The only routes are authenticated POSTs to:

- `monitor-agent-inventory-claim`
- `monitor-agent-inventory-page`
- `monitor-agent-inventory-complete`

Claims advertise schema/protocol `1`, `vulnerability.inventory.dpkg.v1` and the collector version. The claim body supplies no tenant, project, server or agent authority. Backend-issued requests bind request, enrollment, generation, snapshot, server and agent identities and expire within 30 minutes. The agent checks configured server identity, configured agent identity when present, schema/capability, clocks and resource ceilings before collecting or uploading.

One capture is paginated after collection. Maximums are 10,000 packages, 250 packages/page, 40 pages, 262,144 wire bytes/page, 1,900,000 canonical capture bytes and 120,000 capture milliseconds. Completion includes ordered page digests, counts and capture metadata; even an empty/unsupported observation has one empty page. The backend derives tenant/project/receipt time and validates the complete assembled snapshot. Sending pages does not establish admission or completeness.

Hashes use SHA-256 over the ASCII protocol subset of Askio canonical JSON: recursively sorted map keys, integer numeric fields, no HTML escaping and no trailing newline. Unicode strings are refused rather than hashed differently between Go and Node. The digest for a page covers its entire envelope excluding only `pageDigest`; the capture digest covers capture metadata plus all packages in binary-name/architecture order. The Go-generated fixture at `internal/vulnerability/testdata/wire-v1.json` is shared with backend tests and verifies the exact canonical capture bytes and digests.

The daemon staggers initial polling by a stable server-derived offset. Polling is bounded to at most once/minute in the normal waiting path so coalesced advisory requests can be noticed; the backend owns the six-hour routine collection schedule. Polling frequency does not change inventory freshness or later action eligibility.

A transport retry uses the same bounded in-memory capture, pages and completion manifest. It never queries again per page. A process restart loses that pending buffer: the backend must refuse any conflicting digest for the old request, and a fresh request is needed after expiry. This implementation does not claim durable upload resumption across daemon restarts.

## Passive observations and limits

The native source uses fixed `/usr/bin/dpkg --admindir=/var/lib/dpkg --print-architecture` and `/usr/bin/dpkg-query --admindir=/var/lib/dpkg --show --showformat=...` commands, absolute executable paths and a clean fixed locale/environment. Executables must be root-owned regular files without group/other write permission. No discovered executable, payload argument, generic executor, privilege broker or shell fallback is available.

The package query runs once and is bounded to 30 seconds and 8 MiB stdout. stderr is bounded and never uploaded or logged. State fingerprints before and after the capture bind dpkg status bytes and file identity/mtime, the bounded dpkg updates directory, architecture metadata, OS release and boot identity. State reads are bounded; no package lock is acquired to manufacture stability. Like any attributed host observation, this cannot prove a compromised host truthful or rule out an adversarial change-and-restore entirely between observations.

Supported collection scope is Ubuntu 24.04 and Debian 13 on amd64. Each exact binary/architecture row retains its full dpkg revision and separate source name/version, including binNMU differences. Multiarch names are normalized without collapsing architectures or PHP branches. Installed, config-files, unpacked, half-configured and not-installed states are represented. Half-installed, trigger states, reinstreq, malformed rows, duplicates and exceeded limits yield incomplete evidence rather than a guessed installed state. The legacy audit collector remains unchanged.

Repository origin is **unknown** for every inventory-v1 row: dpkg's installed database alone does not authenticate official repository provenance. The separately negotiated [cached provenance capability](PASSIVE_PROVENANCE.md) can report attributed correspondence to a published payload when its complete bounded local chain verifies. Missing capability, unsupported OS/architecture, nonzero/timeout, output truncation, malformed rows or changed state remain explicit unsupported/failed/partial observations. Oversized captures discard rows with explicit partial/truncated metadata; they never silently claim a complete subset. Absence is usable only after backend validation of a complete, stable collection covering the package.

## Local checks

The target is Linux. Use the pinned Go 1.22.12 toolchain to run:

```sh
go test ./...
go test -race ./internal/vulnerability ./internal/api ./internal/config
go vet ./...
GOOS=linux GOARCH=amd64 go build -o /tmp/askio-monitor-p103 ./cmd/askio-monitor
```

Opt-in database/container migration drills in the existing suite remain separate; skipped integration cases are not new inventory acceptance. On the development macOS host, the retained baseline has unrelated non-Linux type/linker failures; Linux tests are run in a disposable digest-pinned Go container without host credentials or a Docker socket. No customer agent or production endpoint is exercised.
