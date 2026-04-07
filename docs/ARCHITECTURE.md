# askio-monitor — Architecture (developer notes)

This document explains how the Go agent is structured and how the main runtime loops interact.

> **Binary**: `askio-monitor` (`cmd/askio-monitor/main.go`)

## Runtime modes

The agent supports two modes via config (`internal/config/config.go`):

- **Host mode** (`mode: host`): run the monitoring agent on a target server.
- **Gateway mode** (`mode: gateway`): run an HTTPS reverse proxy that forwards host-agent traffic to the cloud API (`internal/gateway/*`).

## Host mode — Daemon loops

The main daemon is `internal/agent/daemon.go`.

`Daemon.Run()` starts 4 background loops + a monitor scheduler:

1. **Heartbeat loop** (`heartbeatLoop`)
   - Periodically calls `postHeartbeat`.
   - Sends resource telemetry (CPU/mem/disk/net/process) and capabilities.
   - Persists last heartbeat to file store: `data_dir/meta/last_heartbeat`.

2. **Config poll loop** (`configPollLoop`)
   - Calls `internal/config/remote.go` remote config manager.
   - Updates `Daemon.remoteConf` (monitors + pending commands/actions).
   - If `pending_action` exists, executes it (Operations Platform path).
   - Otherwise processes `pending_command` (legacy) or `pending_command_v2`.

3. **Discovery loop** (`discoveryLoop`)
   - On startup + every `discovery_poll_interval_seconds`.
   - Uses `internal/discovery/detector.go`:
     - systemd (`internal/discovery/systemd/*`)
     - docker (`internal/discovery/docker/*`)
     - process fallback (`internal/discovery/process/*`)
   - Posts discovery results to backend.

4. **Capabilities loop** (`capabilitiesLoop`)
   - Detects optional tools installed on host (best-effort).
   - Exposed under `detected_capabilities` in heartbeat.

5. **Scheduler loop** (`schedulerLoop`)
   - Maintains a set of active monitor goroutines based on the remote config.
   - Each monitor runs `monitorLoop` on its own interval.
   - Each tick calls `RunSingleCheck` and posts results.
   - If result is critical and remediation is enabled, triggers a playbook.

## Monitoring checks

Implemented under `internal/checks/*` and driven by `internal/agent/check_runner.go`.

Supported check types:

- `active_state` (`internal/checks/active_state.go`)
- `port` (`internal/checks/port.go`)
- `http` (`internal/checks/http.go`)

The monitor result model is in `internal/model/model.go`.

## Remediation

Remediation is deliberately deterministic.

Key packages:

- `internal/remediation/engine.go` – playbook engine.
- `internal/remediation/playbooks.go` – built-in playbook definitions.
- `internal/remediation/executor.go` – command execution abstraction.
- `internal/remediation/exec.go` – root/sudo execution implementation.
- `internal/remediation/redact.go` – output scrubbing.

Remediation execution is triggered from `Daemon.maybeRemediate()`.

## Operations Platform (actions)

The agent can execute server-driven actions via **remote config** `pending_action`.

Entry point:

- `internal/agent/operations_handler.go` → `operations.Runner`.

Runner:

- `internal/operations/runner.go`
  - supports `action_type`: `script`, `plan`, `playbook`, `ansible`
  - supports `execution_mode`: `live`, `dry_run`

Handlers:

- `internal/operations/default_registry.go` wires handlers into a registry.
- service ops: `internal/operations/handlers_service.go`
- package ops: `internal/operations/handlers_package.go`
- checks: `internal/operations/handlers_checks.go`
- **command.run**: `internal/operations/handlers_command.go`

See `docs/OPERATIONS.md` for handler specs.

## API / backend client

HTTP client:

- `internal/api/client.go`

Payload schemas are intentionally flexible (JSON maps) for forward-compat.
See `docs/BACKEND_INTEGRATION.md` for endpoint contract.

## Local state

The agent uses a small local store (`internal/store/*`) to cache:

- last good remote config
- queued results payloads (if backend is temporarily unavailable)
- last heartbeat
- cached operations results (to avoid re-execution)

Default path depends on EUID (`internal/config/config.go`):

- root → `/var/lib/askio-monitor`
- non-root → `${XDG_CACHE_HOME}/askio-monitor`
