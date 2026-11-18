# Passive inventory: enrollment qualification and first-host checklist

Passive vulnerability inventory ([PASSIVE_INVENTORY.md](PASSIVE_INVENTORY.md), [PASSIVE_PROVENANCE.md](PASSIVE_PROVENANCE.md)) is off by default. It must stay off until the owner separately authorizes three things: a promoted agent release ([RELEASE.md](RELEASE.md)), backend enablement with this host's enrollment, and this host's opt-in. This document records how the gate works in the agent today, how it is tested, and the checklist for the first host.

## How collection is gated

The agent collects and uploads only when **both** of these hold.

### Host opt-in

The operator-managed local config, `/etc/askio/monitor.conf` (root-owned, mode `0600`), contains:

```yaml
inventory:
  enabled: true
```

- **Where it is checked.** `inventoryOptedIn` in `internal/agent/inventory_loop.go`. `Daemon.Run` starts the inventory loop only if it returns true. `newInventoryPoller` returns no poller otherwise, so the loop exits at once even if something starts it.
- **Default.** The key is absent. `askio-monitor install` and `config.Save` never write it (`TestInventoryOptInIsNotSetByInstallerDefaults`).
- **What cannot set it.**
  - Remote monitor config (`monitor-agent-config`) is decoded into `model.RemoteConfig`, which has no inventory setting, and never into `config.Config`.
  - Pending actions and commands have no code path that changes `config.Config` at run time.
- **Validation.** `config.Normalized` refuses the opt-in unless the agent runs in direct `host` mode against a fixed `https` API URL with verified TLS. That rules out `tls_skip_verify`, gateway mode, credentials in the URL, and query or fragment overrides (`TestInventoryDefaultOffAndExplicitTLSHostOnly`).

### Backend enablement and enrollment

The agent cannot read the backend's flags. It sees them only through the answer to its claim:

| Backend state | Claim response | Agent behaviour |
| --- | --- | --- |
| `VULNERABILITY_INVENTORY_ENABLED` off | `404 INVENTORY_DISABLED` (every inventory route) | no collection, no page, no completion; next claim after 1 min (15 s – 1 min for `waiting`/`unsupported`) |
| On, agent not enrolled | `403 INVENTORY_NOT_ENROLLED` | same |
| On, enrollment changed | `409 INVENTORY_ENROLLMENT_CHANGED` | same |
| On, enrolled, nothing due | `200 waiting` | same |
| On, unsupported host | `200 unsupported` | same |
| On, enrolled, request due | `200 assigned` with a request | collects **only if** the request names this `server_id` and `agent_id`, uses schema 1 with a supported capability, is unexpired (at most 30 minutes), and has limits within the ceilings. Otherwise nothing is collected. |

Package-origin provenance is a further capability. The backend must also have `VULNERABILITY_PROVENANCE_ENABLED` on and must request that capability explicitly.

### Proof

`TestInventoryRequiresHostOptInAndBackendEnrollment` (`internal/agent/inventory_gate_test.go`) uses the real code paths:

- it writes a YAML config file, loads it with `config.Load` and builds the daemon with `NewDaemon`;
- it runs the real HTTPS API client, pinned to a test CA, and the real poller;
- the backend is emulated to answer the way Askio's `monitor-agent-inventory-*` routes do;
- a counting host fake makes collection observable.

The test runs every combination of three host states and eight backend states:

| Host opt-in | Backend | Inventory requests | Host observations | Pages / completions |
| --- | --- | --- | --- | --- |
| absent | any of 8 | **0** (no route contacted; the daemon loop returns at once) | 0 | 0 / 0 |
| `enabled: false` | any of 8 | **0** | 0 | 0 / 0 |
| `enabled: true` | disabled, not enrolled, enrollment changed, waiting, unsupported, assigned to another agent, assigned but expired | 1 claim, capabilities only, no host data | **0** | **0 / 0** |
| `enabled: true` | enabled, enrolled, assigned to this agent | 1 claim | > 0 | ≥ 1 / 1 (positive control) |

Existing tests cover the rest of the boundary:

- `internal/vulnerability`: `TestWaitingAndUnsupportedNeverCollect` and `TestWrongAssignmentAndNegotiationNeverCollect`;
- `internal/api`: `TestInventoryRefusesRedirectUnknownOversizeAndRawErrors`, which covers redirects, unknown fields, oversized responses and raw error bodies.

### Residual risks

These are known and accepted, and the checklist below covers them:

- **Anything with root on the host can edit `monitor.conf`.** That includes an Operations Platform task with shell enabled. The local opt-in is only as strong as control of that file. Backend enrollment is the independent second gate. The checklist records a digest of the config file at opt-in.
- **Opt-in before enablement causes a steady stream of claims.** An opted-in host whose backend gate is closed sends one capability-only claim about once a minute and gets `404` or `403` back. Opt in only after the backend has enrolled the host.
- **A restart drops an in-flight upload.** The backend refuses a conflicting recapture for the old request, and a new request follows its expiry (see PASSIVE_INVENTORY.md).

## First-host checklist

Every item marked **owner** is a separate decision by the Askio project owner, recorded with who, when and what. None of them is implied by another, and none is implied by merging any pull request.

### Preconditions

- [ ] **Owner:** agent release promoted per [RELEASE.md](RELEASE.md), version ≥ `0.4.40`, with its authorization record linked.
- [ ] Backend later-phase obligations met. These are listed in the Askio repository's `backend/packages/vulnerabilities/qualification/close08-handoff-2026-11-17.json` under `laterPhaseObligations`.
- [ ] **Owner:** the no-go on enabling `VULNERABILITY_INVENTORY_ENABLED` is lifted. Record it.
- [ ] **Owner:** first host chosen. It must be an owner-controlled, non-customer host running Ubuntu 24.04 or Debian 13 on amd64, the only qualified profiles. Record its `server_id` and `agent_id`.
- [ ] **Owner:** the host's operator consents to opt-in on that host. Record it.
- [ ] `VULNERABILITY_PROVENANCE_ENABLED` stays off for the first host unless the owner authorizes it separately.

### On the host, before enablement

- [ ] `sha256sum /usr/local/bin/askio-monitor` equals the authorized `artifact_sha256`.
- [ ] `askio-monitor --version` prints `askio-monitor version <promoted version> (commit <authorized commit>, go1.22.12, linux/amd64)`.
- [ ] `sudo grep -n '^inventory' /etc/askio/monitor.conf` prints nothing, so the host has not opted in.
- [ ] `sudo journalctl -u askio-monitor --since -1h | grep -i inventory` prints nothing.

### Backend (owner-authorized)

- [ ] Enable `VULNERABILITY_INVENTORY_ENABLED` only. Readiness must report the required inventory migration.
- [ ] Enroll exactly this agent, using the backend's enrollment procedure. Record the enrollment id.
- [ ] Confirm the backend receives **no** inventory claim from this host yet. The host has not opted in, and the gate test shows that zero requests follow.

### Host opt-in (owner-authorized)

- [ ] As root, add the `inventory: {enabled: true}` stanza to `/etc/askio/monitor.conf`.
- [ ] `sudo askio-monitor status --config /etc/askio/monitor.conf` exits 0. It validates the HTTPS, host-mode and verified-TLS requirements.
- [ ] Record `sha256sum /etc/askio/monitor.conf`. Record the digest only, never the file: it contains the agent token.
- [ ] `sudo systemctl restart askio-monitor`.

### Observe

- [ ] The first claim arrives 1–30 s after start. The delay is a stable offset derived from `server_id`.
- [ ] The backend issues an assignment, then receives the page(s) and the completion. A snapshot is recorded for this server only.
- [ ] The agent logs show no repeated `passive inventory cycle incomplete` warning. Any that appear are explained.
- [ ] The snapshot's package count matches `dpkg-query -W | wc -l` on the host, and the collection status is `complete`.
- [ ] Over the hold period, 24 h or whatever the owner chooses:
  - claims stay at most one per minute;
  - collection follows the backend's schedule;
  - host CPU and memory show no anomaly.

### Disable or roll back

Each of these closes a gate on its own. The gate test proves each one.

- **Host:** remove the stanza or set `enabled: false`, then restart. The host sends zero inventory requests.
- **Backend:** turn `VULNERABILITY_INVENTORY_ENABLED` off. Every claim returns `404`, so nothing is collected even on an opted-in host.
- **Enrollment:** retire it through the backend's retirement or deletion path.

### Record to keep

Keep a record with:

- the authorizations above, each with who, when and scope;
- `server_id`, `agent_id` and the enrollment id;
- the agent version, commit and SHA-256;
- the `monitor.conf` digest at opt-in;
- the first snapshot id and its package count;
- the hold-period observations;
- any rollback.
