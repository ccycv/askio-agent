# askio-monitor (Askio host agent)

Lightweight Go agent for:

- **Discovery** of systemd services + docker containers + common processes
- **Monitoring** (active state + optional port/HTTP checks)
- **Resource telemetry** in heartbeat (CPU/memory/disk/network/processes)
- **Safe remediation** via built-in, allowlisted playbooks
- **Operations Platform actions** (script/plan/playbook/ansible) including `command.run`
- **Native Askio Ops migration assessment** through the same daemon identity and heartbeat/task loop

Non-goals (v1): full metrics/log aggregation or “AI runs arbitrary commands”.

Migration support does not install or run a second public agent. A migration-enabled host uses this same `askio-monitor` daemon with an additional signed-task runner. Its optional root-owned typed broker independently verifies each backend-signed task envelope and has separate root-only replay/fencing state. The bounded V1 direct-transfer, PostgreSQL offline and same-major logical-replication, filesystem, Compose, validation, writer-fence, evidence, and cleanup primitives are implemented locally; production use remains disabled until Askio's independent security review, two-distinct-host drill, promoted Linux `amd64` artifact, and deployment gates are complete.

---

## Repository layout (high level)

- `cmd/askio-monitor/main.go` – binary entrypoint
- `internal/agent/*` – host agent daemon loops (heartbeat/config/discovery/check scheduler)
- `internal/discovery/*` – systemd/docker/process detectors
- `internal/checks/*` – monitoring checks (active_state/port/http)
- `internal/remediation/*` – playbooks + executor (root/sudo), redaction
- `internal/operations/*` – Operations Platform runner + handlers (service/package/check/command)
- `internal/migration/*` – signed migration tasks, read-only discovery, scoped primitives, and typed broker protocol
- `internal/gateway/*` – optional gateway reverse-proxy mode
- `internal/api/*` – HTTP client and payloads
- `packaging/*` – systemd unit + sudoers templates

---

## Build

```bash
go build -o ./bin/askio-monitor ./cmd/askio-monitor
./bin/askio-monitor --version
```

---

## Quick start (dev / local)

Create a config file (example):

```yaml
api_url: "http://localhost:9999/functions/v1"
server_id: "dev"
agent_token: "devtoken"
privilege_mode: "sudo"
data_dir: "./.askio-monitor-data"
log_level: "info"

operations:
  allow_shell: false
  allowlist: []
```

Run:

```bash
./bin/askio-monitor discover --config ./tmp-monitor.conf
./bin/askio-monitor start --config ./tmp-monitor.conf
```

---

## Install (on a server)

```bash
sudo ./askio-monitor install \
  --api-url "https://<backend>/functions/v1" \
  --server-id "<uuid>" \
  --token "<token>" \
  --mode sudo
```

Installer writes:
- `/etc/askio/monitor.conf`
- `/etc/systemd/system/askio-monitor.service`
- `/etc/sudoers.d/askio-monitor` (sudo mode)
- `/usr/local/bin/askio-monitor`

And runs:
- `systemctl daemon-reload`
- `systemctl enable --now askio-monitor`

---

## Documentation

Start here:

- **Architecture**: `docs/ARCHITECTURE.md`
- **Config**: `docs/CONFIG.md`
- **Backend contract** (edge functions/API): `docs/BACKEND_INTEGRATION.md`
- **Operations Platform** (pending_action, handlers, `command.run`): `docs/OPERATIONS.md`
- **Resource telemetry / heartbeat schema**: `docs/RESOURCES.md`
- **Remediation playbooks**: `docs/PLAYBOOKS.md`
- **Security**: `docs/SECURITY.md`
