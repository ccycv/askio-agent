# Passive inventory: enrollment qualification and first-host checklist

Passive vulnerability inventory ([PASSIVE_INVENTORY.md](PASSIVE_INVENTORY.md), [PASSIVE_PROVENANCE.md](PASSIVE_PROVENANCE.md)) is off by default. This document records how the gate works in the agent today, how it is tested, and the checklist for the first host.

> **Security change in 0.4.41.** Before 0.4.41, only the host's operator could turn collection on, by editing `/etc/askio/monitor.conf`. From 0.4.41, **the Askio backend can also turn collection on for an enrolled host** whose local config does not mention the setting. The backend does this through the `monitor-agent-config` response. An explicit local `inventory: {enabled: false}` is the hard opt-out: the backend cannot override it. Backend enrollment is still required before anything is collected. Hosts that must never be switched on remotely should set `enabled: false` before running 0.4.41.

## How collection is gated

The agent collects and uploads only when **both** of these hold: the host gate is open, and the backend has enabled the feature and enrolled this agent.

### Host gate

The host gate combines the operator-managed local config, `/etc/askio/monitor.conf` (root-owned, mode `0600`), with the backend's remote switch. The local key is tri-state:

| Local `inventory.enabled` | Remote switch in `monitor-agent-config` | Host gate | `askio-monitor status` |
| --- | --- | --- | --- |
| `false` (explicitly present) | anything | **closed**. This is a hard deny; the remote switch is ignored. | `local-off` |
| `true` | anything | open | `local-on` |
| absent | field missing, or `{"enabled": false}` | closed | `remote-off` |
| absent | `{"enabled": true}`, safe composition | open | `remote-on` |
| absent | `{"enabled": true}`, unsafe composition | **closed**. One warning is logged with the reason. | `remote-refused:<reason>` |

"Absent" means no `inventory` stanza, an empty stanza, or a stanza without `enabled`. The local settings are written like this:

```yaml
inventory:
  enabled: false   # hard opt-out: the backend can never turn collection on
```

```yaml
inventory:
  enabled: true    # local opt-in, independent of the remote switch
```

- **Where it is checked.** `effectiveInventory` in `internal/agent/inventory_loop.go`. `Daemon.Run` always starts `inventorySupervisor`. The supervisor idles while the gate is closed. It re-evaluates the gate at start and after every successful remote config poll.
  - When the gate opens, the supervisor starts the inventory loop. The first claim follows the usual stable 1–30 s offset.
  - When the gate closes, the supervisor cancels the loop's context and waits for it to exit. No further claim, page or completion is sent. An upload in flight is dropped, exactly as on a restart.
  - At most one loop runs at a time. `newInventoryPoller` re-checks the gate and returns no poller if it is closed.
- **Timing.** The remote switch takes effect within one config poll (`config_poll_interval_seconds`, default 60 s) in either direction.
- **Remote switch, wire format.** The backend adds `"inventory": {"enabled": true|false}` to `monitor-agent-config`, and only while `VULNERABILITY_INVENTORY_ENABLED` is on. It sends `true` only to the agent of a current enrollment whose assignment is enabled. The agent advertises nothing new for this.
- **Remote switch, safety conditions.** Remote ON is honoured only when all of the following hold. They are evaluated at run time by `config.InventoryRemoteRefusal`:

  | Condition | Refusal reason |
  | --- | --- |
  | direct `host` mode | `not_host_mode` |
  | no `gateway` stanza in the config | `gateway_configured` |
  | fixed `https` API URL with a host and no credentials, query or fragment | `api_url_not_fixed_https` |
  | verified TLS, so no `tls_skip_verify` | `tls_skip_verify` |

  A refusal is logged once each time the gate enters it: `WARN passive inventory remote enable refused category=inventory_remote_refused reason=<reason>`. Reason codes never contain config values or secrets.
- **Live polls only.** The remote switch is acted on only after this process has fetched it. A switch cached on disk by an earlier process is not honoured at start, so a restart cannot claim on a stale ON (`TestInventoryCachedRemoteSwitchNeedsLivePoll`). If a poll fails, the last switch fetched by this process stays in effect. `askio-monitor status` reads the cached switch, so before the daemon's first poll its answer can differ from what the daemon is doing.
- **Default.** The key is absent. `askio-monitor install` and `config.Save` never write it (`TestInventoryOptInIsNotSetByInstallerDefaults`). A default host therefore follows the remote switch.
- **What cannot set it.** Pending actions and commands have no code path that changes `config.Config` or the remote switch at run time. The remote switch is read only from the `inventory` field of `monitor-agent-config`.
- **Validation of the local opt-in.** `config.Normalized` refuses `enabled: true` unless the agent runs in direct `host` mode against a fixed `https` API URL with verified TLS. That rules out `tls_skip_verify`, gateway mode, credentials in the URL, and query or fragment overrides (`TestInventoryDefaultOffAndExplicitTLSHostOnly`). An explicit `false` or an absent key never fails loading.

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

The tests in `internal/agent/inventory_gate_test.go` use the real code paths:

- they write a YAML config file, load it with `config.Load` and build the daemon with `NewDaemon`;
- they run the real HTTPS API client, pinned to a test CA, the real remote config manager, the real config poll loop, the real supervisor and the real poller;
- the backend is emulated to answer the way Askio's `monitor-agent-config` and `monitor-agent-inventory-*` routes do;
- a counting host fake makes collection observable.

`TestInventoryRequiresHostOptInAndBackendEnrollment` runs every combination of three local states, three remote switch states (field missing, `false`, `true`) and eight backend states, 72 cases in all:

| Local | Remote switch | Backend | Inventory requests | Host observations | Pages / completions |
| --- | --- | --- | --- | --- | --- |
| absent | missing or `false` | any of 8 | **0** (no route contacted; the supervisor starts no loop) | 0 | 0 / 0 |
| `enabled: false` | any of 3 | any of 8 | **0** | 0 | 0 / 0 |
| `enabled: true`, or absent with remote `true` | | disabled, not enrolled, enrollment changed, waiting, unsupported, assigned to another agent, assigned but expired | 1 claim, capabilities only, no host data | **0** | **0 / 0** |
| `enabled: true`, or absent with remote `true` | | enabled, enrolled, assigned to this agent | 1 claim | > 0 | ≥ 1 / 1 (positive control) |

Each case also checks the `askio-monitor status` value.

The other gate tests:

- `TestInventoryRemoteOnRefusedOrDenied`: the remote switch says ON and the backend would assign this agent. There are four cases: local `false`, `tls_skip_verify`, a `gateway` stanza, and a plain `http` API URL. In each, at least three polls produce zero inventory requests and zero host observations. The status is `local-off` or `remote-refused:<reason>`. The refusal is logged exactly once, and the logs never contain the agent token.
- `TestInventoryRemoteSwitchTogglesWithinOnePoll`: runs OFF→ON→OFF→ON→OFF.
  - Claims start within one poll interval after ON.
  - Within one poll interval after OFF, the loop has exited. After that, no claim, page or completion arrives over ten loop periods.
- `TestInventoryLocalTrueIgnoresRemoteOff` and `TestInventoryCachedRemoteSwitchNeedsLivePoll`.
- `TestEffectiveInventoryTable`, plus `internal/config` `TestInventoryLocalIsTriStateInYAML` and `TestInventoryRemoteRefusalReasons`.

Existing tests cover the rest of the boundary:

- `internal/vulnerability`: `TestWaitingAndUnsupportedNeverCollect` and `TestWrongAssignmentAndNegotiationNeverCollect`;
- `internal/api`: `TestInventoryRefusesRedirectUnknownOversizeAndRawErrors`, which covers redirects, unknown fields, oversized responses and raw error bodies.

### Residual risks

These are known and accepted, and the checklist below covers them:

- **The backend can turn collection on for a default host.** From 0.4.41, a host without an explicit local `false` collects whenever the backend sends remote ON *and* has enrolled the agent. The host operator's consent is therefore an organizational control, recorded in the checklist, not one the agent enforces. Operators who require a local-only decision must set `inventory: {enabled: false}`, or set `true` to opt in locally.
- **Remote ON and enrollment are both backend decisions.** For a host without a local setting, the two gates are independent code paths in the backend, but both are under backend control. A compromised backend, or a compromised path to it, could open both. The agent's own protections still hold: verified TLS to a fixed HTTPS URL, request binding to this `server_id` and `agent_id`, expiry, resource ceilings, and no shell or package mutation.
- **The agent cannot detect every gateway-fronted host.** A host agent that reaches Askio through a gateway has `mode: host` and its `api_url` points at the gateway. The agent refuses remote ON only when the gateway is visible in its own config (`mode: gateway` or a `gateway` stanza). For other gateway-fronted hosts, it relies on two things: the backend not enrolling gateway-fronted hosts (the readiness `direct_host` check), and the gateway not proxying the inventory routes. Today the gateway proxies `monitor-agent-config` but not `monitor-agent-inventory-*`, so such a host's claims fail and nothing is collected.
- **Anything with root on the host can edit `monitor.conf`.** That includes an Operations Platform task with shell enabled. A local `false` or `true` is only as strong as control of that file. The checklist records a digest of the config file.
- **Opt-in before enablement causes a steady stream of claims.** A host whose host gate is open but whose backend gate is closed sends one capability-only claim about once a minute and gets `404` or `403` back. With the remote switch, the backend opens the host gate only for enrolled agents, so this mainly affects local `true`. Opt in locally only after the backend has enrolled the host.
- **A restart drops an in-flight upload.** The backend refuses a conflicting recapture for the old request, and a new request follows its expiry (see PASSIVE_INVENTORY.md).

## First-host checklist

Every item marked **owner** is a separate decision by the Askio project owner, recorded with who, when and what. None of them is implied by another, and none is implied by merging any pull request.

### Preconditions

- [ ] **Owner:** agent release promoted per [RELEASE.md](RELEASE.md), with its authorization record linked. The version must be ≥ `0.4.41` for the remote switch, or ≥ `0.4.40` for local opt-in only.
- [ ] Backend later-phase obligations met. These are listed in the Askio repository's `backend/packages/vulnerabilities/qualification/close08-handoff-2026-11-17.json` under `laterPhaseObligations`.
- [ ] **Owner:** the no-go on enabling `VULNERABILITY_INVENTORY_ENABLED` is lifted. Record it.
- [ ] **Owner:** first host chosen. It must be an owner-controlled, non-customer host running Ubuntu 24.04 or Debian 13 on amd64, the only qualified profiles. Record its `server_id` and `agent_id`.
- [ ] **Owner:** the host's operator consents to collection on that host, whether it is switched on remotely or locally. Record it. The agent does not enforce this consent when the local key is absent.
- [ ] `VULNERABILITY_PROVENANCE_ENABLED` stays off for the first host unless the owner authorizes it separately.

### On the host, before enablement

- [ ] `sha256sum /usr/local/bin/askio-monitor` equals the authorized `artifact_sha256`.
- [ ] `askio-monitor --version` prints `askio-monitor version <promoted version> (commit <authorized commit>, go1.22.12, linux/amd64)`.
- [ ] `sudo grep -n -A1 '^inventory' /etc/askio/monitor.conf` prints nothing for the remote path. If it prints `enabled: false`, the host has opted out and remote ON will be ignored.
- [ ] `sudo askio-monitor status --config /etc/askio/monitor.conf` reports `"inventory": "remote-off"`.
- [ ] `sudo journalctl -u askio-monitor --since -1h | grep -i 'passive inventory'` prints nothing.

### Backend (owner-authorized)

- [ ] Enable `VULNERABILITY_INVENTORY_ENABLED` only. Readiness must report the required inventory migration.
- [ ] Enroll exactly this agent, using the backend's enrollment procedure. Record the enrollment id.
- [ ] Before the assignment is enabled, confirm the backend receives **no** inventory claim from this host. The remote switch says `false` and the gate test shows that zero requests follow.

### Switch on (owner-authorized; choose one)

**Remote (0.4.41 and later, local key absent).**

- [ ] Record `sha256sum /etc/askio/monitor.conf`. Record the digest only, never the file: it contains the agent token.
- [ ] Enable the host's assignment in the backend. No restart is needed.
- [ ] Within one config poll, the agent logs `passive inventory started ... state=remote-on`, and `askio-monitor status` reports `remote-on`. If it reports `remote-refused:<reason>`, fix the reported composition (see the table above) or stop.

**Local.**

- [ ] As root, add the `inventory: {enabled: true}` stanza to `/etc/askio/monitor.conf`.
- [ ] `sudo askio-monitor status --config /etc/askio/monitor.conf` exits 0 and reports `local-on`. It validates the HTTPS, host-mode and verified-TLS requirements.
- [ ] Record `sha256sum /etc/askio/monitor.conf`.
- [ ] `sudo systemctl restart askio-monitor`.

### Observe

- [ ] The first claim arrives 1–30 s after the loop starts, which is at daemon start for a local opt-in or at the config poll that delivers remote ON. The delay is a stable offset derived from `server_id`.
- [ ] The backend issues an assignment, then receives the page(s) and the completion. A snapshot is recorded for this server only.
- [ ] The agent logs show no repeated `passive inventory cycle incomplete` warning. Any that appear are explained.
- [ ] The snapshot's package count matches `dpkg-query -W | wc -l` on the host, and the collection status is `complete`.
- [ ] Over the hold period, 24 h or whatever the owner chooses:
  - claims stay at most one per minute;
  - collection follows the backend's schedule;
  - host CPU and memory show no anomaly.

### Disable or roll back

Each of these closes a gate on its own. The gate test proves each one.

- **Host, hard opt-out:** set `enabled: false`, then restart. The host sends zero inventory requests whatever the backend says. Removing a local `true` stanza instead returns the host to the remote switch.
- **Remote switch:** disable the host's assignment, or turn the backend flag off, which omits the field. Within one config poll the loop is cancelled and no further claim is sent. This applies only to hosts without a local `true`.
- **Backend:** turn `VULNERABILITY_INVENTORY_ENABLED` off. Every claim returns `404`, so nothing is collected even on a locally opted-in host.
- **Enrollment:** retire it through the backend's retirement or deletion path.

### Record to keep

Keep a record with:

- the authorizations above, each with who, when and scope;
- `server_id`, `agent_id` and the enrollment id;
- the agent version, commit and SHA-256;
- the `monitor.conf` digest at switch-on, and whether collection was switched on remotely or locally;
- the first snapshot id and its package count;
- the hold-period observations;
- any rollback.
