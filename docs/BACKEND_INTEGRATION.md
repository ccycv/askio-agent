# Askio Monitor Agent — Backend Integration (v1)

This doc describes **exactly** what the Go agent (`askio-monitor`) expects from your backend so you can implement the server-side (edge functions/API + DB) in another tool.

## High-level flow

1) Agent runs on host.
2) Agent authenticates via **Bearer token**.
3) Agent periodically:
   - sends heartbeat (`POST monitor-agent-heartbeat`)
   - fetches remote config (`GET monitor-agent-config`)
   - runs checks and posts results (`POST monitor-agent-results`)
   - if remediation triggers, posts remediation logs (`POST monitor-agent-remediation-log`)

## Base URL

The agent takes an `api_url` from config, and calls paths relative to it.

Example:

```yaml
api_url: "https://<your-supabase-project>.supabase.co/functions/v1"
```

The agent will call:

- `POST {api_url}/monitor-agent-heartbeat`
- `GET  {api_url}/monitor-agent-config?server_id=<server_id>`
- `POST {api_url}/monitor-agent-results`
- `POST {api_url}/monitor-agent-remediation-log`
- `POST {api_url}/monitor-agent-discovered-services` (startup + every 6h by default)

## Authentication

Every request includes:

- `Authorization: Bearer <agent_token>`
- `User-Agent: askio-monitor/0.1`

You should validate:
- `agent_token` belongs to the host/server
- token is not revoked

## Content-Type

Requests with bodies are JSON:

- `Content-Type: application/json`


---

# Endpoint specs

## 0) Discovered services (auto)

### Request

`POST /monitor-agent-discovered-services`

Body:

```json
{
  "server_id": "<string>",
  "discovered_at": "2026-01-07T12:00:00Z",
  "services": [
    {
      "name": "nginx",
      "type": "systemd",
      "unit": "nginx.service",
      "pid": 1234,
      "state": "active/running"
    },
    {
      "name": "my-app",
      "type": "docker",
      "state": "Up 2 hours",
      "meta": {
        "container_id": "abc123",
        "image": "my-app:latest",
        "ports": "0.0.0.0:3000->3000/tcp"
      }
    }
  ]
}
```

### Response

Return any `2xx`. Body is ignored.

### Notes

- This is **informational**: it’s intended to populate your UI “Found services” list.
- Monitoring still depends on remote config returning monitors.


## 1) Heartbeat

### Request

`POST /monitor-agent-heartbeat`

Body (JSON):

```json
{
  "server_id": "<string>",
  "agent_version": "0.4.18",
  "go_version": "go1.xx.x",
  "hostname": "<string>",
  "pid": 1234,
  "timestamp": "2026-01-07T14:00:00Z",
  "privilege_mode": "sudo",
  "cpu_percent": 23.5,
  "memory_percent": 67.2,
  "memory": {
    "total_bytes": 0,
    "used_bytes": 0,
    "available_bytes": 0,
    "cached_bytes": 0,
    "used_percent": 0
  },

  "has_multiple_disks": false,
  "disk_used_percent_root": 12.3,
  "disks": [
    {
      "device": "/dev/sda1",
      "mountpoint": "/",
      "fs_type": "ext4",
      "total_bytes": 0,
      "used_bytes": 0,
      "used_percent": 0
    }
  ],

  "network_interfaces": [
    {"name":"eth0","mac":"..","is_up":true,"ipv4":["1.2.3.4"],"ipv6":[]}
  ],
  "network_counters": [
    {"name":"eth0","rx_bytes":123,"tx_bytes":456}
  ],

  "disk_latency": [
    {"device":"/dev/sda","read_latency_ms":12.4,"write_latency_ms":48.2,"read_iops":10.5,"write_iops":2.1}
  ],
  "disk_latency_avg": {"read_latency_ms":8.1,"write_latency_ms":3.2},

  "top_processes_cpu": [
    {"pid":1234,"name":"postgres","state":"R","cpu_percent":24.2,"rss_bytes":4200000000}
  ],
  "top_processes_mem": [
    {"pid":1234,"name":"postgres","state":"S","cpu_percent":1.0,"rss_bytes":4200000000}
  ],

  "capabilities": {
    "monitoring": true,
    "operations": true,
    "handlers": ["service.restart", "command.run"],
    "playbooks": ["systemd_restart"],
    "privilege_mode": "sudo",
    "operations_config": {
      "command_run": true,
      "command_run_shell": false,
      "command_run_allowlist": []
    }
  },

  "os_info": {
    "distro": "ubuntu",
    "version": "22.04",
    "arch": "amd64"
  }
}
```

Notes:
- `timestamp` is RFC3339.
- `cpu_percent` and `memory_percent` are optional; agent sends them when available.
- `detected_capabilities` is best-effort and may be empty.

See also: `docs/RESOURCES.md`.

### Response

Return any `2xx`. Body is ignored by the agent.

Recommended:

```json
{ "ok": true }
```

### Suggested backend behavior

- Upsert `monitor_agents.last_heartbeat`
- Set `monitor_agents.status = online`


---

## 2) Remote config

### Operations Platform extension: `pending_action`

Your backend may include an optional `pending_action` object in the config response.

Contract:
- If `pending_action` is present, the agent executes it **before** `pending_command`.
- The backend clears `pending_action` only after receiving `POST /operations-agent-result`.
- The agent does not cache `pending_action` locally (prevents re-execution on restart).

`pending_action` shape:

```json
{
  "run_id": "uuid-of-the-run",
  "action_id": "uuid-of-the-action",
  "action_name": "Install Nginx",
  "action_type": "script",
  "timeout_seconds": 300,
  "execution_mode": "live",
  "parameters": {"package": "nginx"},
  "enable_rollback": false,
  "script_content": "#!/bin/bash\napt-get install -y {{package}}\n",
  "rollback_script": "#!/bin/bash\napt-get remove -y {{package}}\n"
}
```

Supported `action_type`:
- `script`
- `plan`
- `playbook`
- `ansible`

Supported `execution_mode`:
- `live`
- `dry_run`

### `action_type: "ansible"`

When `action_type` is `ansible`, backend should include:

```json
{
  "action_type": "ansible",
  "ansible_playbook": {
    "content": "---\n- hosts: localhost\n  tasks: ...\n",
    "inventory": "[webservers]\nweb1.example.com\nweb2.example.com\n",
    "extra_vars": {"example": "value"}
  },
  "execution_mode": "live"
}
```

Agent behavior:
- writes `content` to a temp `.yml`
- if `inventory` is provided, writes it to a temp file and runs: `ansible-playbook <file> -i <inventory_file> --extra-vars '<json>'`
- otherwise runs locally: `ansible-playbook <file> -i localhost, -c local --extra-vars '<json>'`
- if `execution_mode=dry_run`, adds `--check`


### Request

`GET /monitor-agent-config?server_id=<server_id>`

No body.

### Response

Return `200` with JSON:

```json
{
  "fetched_at": "2026-01-07T12:00:00Z",
  "monitors": [
    {
      "id": "monitor-uuid",
      "service_name": "nginx",
      "service_type": "systemd",
      "systemd_unit": "nginx.service",

      "docker_container_id": "", 
      "process_match": "", 

      "check_types": ["active_state", "port", "http"],
      "check_interval_seconds": 60,
      "port": 80,
      "http_endpoint": "http://127.0.0.1/health",

      "enabled": true,

      "remediation_enabled": true,
      "remediation_policy": "reload_first",

      "allowed_playbook_ids": ["nginx_test_reload", "systemd_restart"],

      "additional_properties": {
        "any_extra": "values"
      }
    }
  ]
}
```

### Field semantics

- `service_type` is one of:
  - `systemd`
  - `docker`
  - `process`

- `check_types` values (array of strings):
  - `active_state`
  - `port`
  - `http`

- `remediation_policy` values:
  - `restart_only`
  - `reload_first`
  - `full`

### Agent behavior

- Agent polls this config every `config_poll_interval_seconds`.
- Agent caches the last good config locally (file store under `data_dir/config/remote_config_v1`).
- If remote config is temporarily unavailable, agent keeps using cached config.

### Optional commands (UI-triggered)

Your backend may include `pending_command` in one of two formats:

1) **Legacy string** (supported for backwards compatibility):
- `pending_command: "discover_services"`
- `pending_command: "run_playbook:<playbook_id>:<incident_id>:<monitor_id>"`

2) **New JSON object** (recommended for new capabilities):

```json
{
  "pending_command": {
    "type": "install_capability",
    "command_id": "<uuid>",
    "capability": "ansible",
    "script_b64": "<base64>",
    "timeout_seconds": 300,
    "execution_mode": "live"
  }
}
```

For legacy string commands, `command_id` may be included separately.

When the agent receives `pending_command: "discover_services"`, it will:
1) run discovery immediately
2) POST results to `/monitor-agent-discovered-services`

When the agent receives a remediation command:

- `pending_command: "run_playbook:<playbook_id>:<incident_id>:<monitor_id>"`

Supported built-in playbook IDs (v1):
- `systemd_restart`
- `systemd_reload`
- `systemd_reset_failed`
- `nginx_test_reload`
- `postgres_restart_verify`
- `docker_restart`

Common aliases (agent will normalize these):
- `restart_nginx` → `systemd_restart`
- `reload_nginx` → `nginx_test_reload`

Recommendation: keep your DB/UI using the built-in IDs to avoid drift.

It will:
1) find the referenced `monitor_id` in the `monitors` array
2) execute the allowlisted playbook (manual trigger)
3) POST the remediation run to `/monitor-agent-remediation-log` including `incident_id`

Notes:
- `monitor_id` must be present in the same config response, otherwise the agent cannot run the playbook.
- If `allowed_playbook_ids` is set for that monitor, `playbook_id` must be included there.

To avoid repeating the same command on restart, the agent does **not** persist command fields in its local cache.


---

## 3) Results submission

### Request

`POST /monitor-agent-results`

Body:

```json
{
  "server_id": "<string>",
  "results": [
    {
      "monitor_id": "monitor-uuid",
      "checked_at": "2026-01-07T12:00:00Z",
      "status": "ok",
      "latency_ms": 5,
      "details": {
        "active_state": { "unit": "nginx.service", "raw": "active" },
        "port": { "port": 80, "open": true, "latency_ms": 2 },
        "http": { "url": "http://127.0.0.1/health", "status_code": 200, "latency_ms": 15, "body_prefix": "OK" }
      },
      "active_state": "active",
      "service_name": "nginx",
      "service_type": "systemd"
    }
  ]
}
```

### `status` enum

- `ok`
- `warning`
- `critical`

### Response

Return any `2xx`. Body is ignored.

### Suggested backend behavior

- Insert into `monitor_results`
- Open or update incidents when `status != ok`


---

## 4) Remediation log submission

### Request

`POST /monitor-agent-remediation-log`

Body:

```json
{
  "server_id": "<string>",
  "monitor_id": "monitor-uuid",
  "incident_id": "optional-uuid",
  "playbook_id": "systemd_restart",
  "trigger": "auto",
  "success": true,
  "steps": [
    {
      "order": 1,
      "command": "sudo -n systemctl restart nginx.service --no-pager",
      "exit_code": 0,
      "output": "(redacted output)",
      "duration_ms": 1200
    }
  ],
  "verification": {
    "command": "sudo -n systemctl is-active nginx.service --no-pager",
    "output": "active",
    "success": true
  },
  "started_at": "2026-01-07T12:00:00Z",
  "finished_at": "2026-01-07T12:00:02Z"
}
```

### Playbook IDs (built-in v1)

- `systemd_restart`
- `systemd_reload`
- `systemd_reset_failed`
- `nginx_test_reload`
- `postgres_restart_verify`
- `docker_restart`

### Response

Return any `2xx`. Body is ignored.

### Suggested backend behavior

- Insert into `remediation_runs`
- Add an event to incident timeline


---

## 5) Command result submission

### Request

`POST /monitor-agent-command-result`

Body:

```json
{
  "command_id": "uuid-from-pending-command",
  "command_type": "install_capability",
  "status": "success",
  "output": "stdout/stderr combined",
  "error": "error message if failed",
  "exit_code": 0,
  "started_at": "2026-01-18T17:45:00Z",
  "finished_at": "2026-01-18T17:45:30Z",
  "duration_ms": 30000
}
```

### Response

Return any `2xx`. Body is ignored by the agent.

---

## 6) Operations result submission

### Request

`POST /operations-agent-result`

Body:

```json
{
  "run_id": "uuid-of-the-run",
  "server_id": "uuid-of-this-server",
  "status": "success",
  "step_results": [
    {
      "step_id": "step_1",
      "action": "package.install",
      "status": "success",
      "output": "...",
      "error": "",
      "started_at": "2026-01-16T12:00:00Z",
      "finished_at": "2026-01-16T12:00:05Z",
      "changed": true
    }
  ],
  "output": "Overall execution output",
  "error": "",
  "started_at": "2026-01-16T12:00:00Z",
  "finished_at": "2026-01-16T12:01:00Z"
}
```

### Response

Return any `2xx`. Body is ignored by the agent.

### Notes

- Backend should clear the pending action (`pending_action_run_id`) after receiving this result.
- If the backend is unavailable, the agent caches the result locally and retries on next config poll.



---

# Common integration errors / troubleshooting

## Error: `cannot unmarshal object into Go struct field ... check_types`

**Symptom (agent log):**

```
json: cannot unmarshal object into Go struct field MonitorConfig.monitors.check_types of type model.CheckType
```

**Cause:** Your backend returned `monitors[].check_types` with the wrong JSON shape.

✅ **Correct** (agent expects an array of strings):

```json
"check_types": ["active_state", "port", "http"]
```

❌ **Incorrect** (object/map):

```json
"check_types": {"active_state": true, "port": true}
```

❌ **Incorrect** (single object):

```json
"check_types": {"type": "active_state"}
```

**Fix:** Ensure `check_types` is always an array of strings.

## Error: `Unknown handler: command.run`

Cause:

- The agent did not include `command.run` in its handler registry.

Fix:

- Upgrade to agent **v0.4.18+** and confirm heartbeat `capabilities.handlers` includes `command.run`.
- If using `{cmd, shell:true}`, also ensure `operations.allow_shell: true` on the host.

## Quick verification (server-side)

Validate what the backend returns:

```bash
curl -sS -H "Authorization: Bearer <agent_token>" \
  "{api_url}/monitor-agent-config?server_id=<server_id>" \
  | jq '.monitors[0].check_types'
```

You should see output like:

```json
[
  "active_state",
  "port"
]
```


---

# Minimal backend validation rules (recommended)

Additionally for discovery endpoint:
- Require `server_id`, `discovered_at`, `services`.


1) Auth token must match `server_id`.
2) `server_id` must exist.
3) For `results`, each entry must contain:
   - `monitor_id`, `checked_at`, `status`, `latency_ms`, `details`
4) For `remediation-log`, require:
   - `server_id`, `monitor_id`, `playbook_id`, `trigger`, `success`, `steps`, `started_at`, `finished_at`


---

# Local development tips

## Quick manual agent tests

Create a local config file:

```yaml
api_url: "http://localhost:9999/functions/v1"
server_id: "dev"
agent_token: "devtoken"
privilege_mode: "sudo"
data_dir: "./.askio-monitor-data"
```

Run:

```bash
./bin/askio-monitor discover --config ./tmp-monitor.conf | jq

./bin/askio-monitor check --config ./tmp-monitor.conf \
  --monitor '{"id":"test","service_name":"containerd","service_type":"systemd","systemd_unit":"containerd.service","check_types":["active_state"],"check_interval_seconds":60,"enabled":true}' \
  | jq
```

## Mock server (what to implement)

If you want to quickly validate agent traffic, implement a small HTTP server that:
- accepts the POSTs above
- returns a static config JSON at `/monitor-agent-config`


---

# Changelog / Versioning

- Agent sends `agent_version: "0.1"` today.
- You can extend payloads later; keep server-side parsing tolerant (ignore unknown keys).
