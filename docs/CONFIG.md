# askio-monitor config

Default path: `/etc/askio/monitor.conf`

```yaml
mode: "host" # host|gateway

api_url: "https://<your-backend>/functions/v1"
server_id: "<uuid>"
agent_token: "<token>"

# TLS options (host mode)
# Use one of these when connecting to a self-signed gateway.
# Recommended: provide the gateway cert as a trusted CA.
# ca_cert_path: "/etc/askio/gateway-ca.crt"
# Fallback (less secure): disable TLS verification.
# tls_skip_verify: true

# root: agent runs as root, executes commands directly
# sudo: agent runs unprivileged (recommended), and executes remediation via `sudo -n`
privilege_mode: "sudo"

heartbeat_interval_seconds: 30
config_poll_interval_seconds: 60

# Auto-discovery reporting (startup + every 6 hours by default)
# discovery_poll_interval_seconds: 21600

log_level: "info"

# optional
# data_dir: "/var/lib/askio-monitor" # defaults based on whether running as root

# Operations Platform settings (optional)
# Controls the `command.run` operation handler.
operations:
  # If true, allows `{cmd: "...", shell: true}` which runs `/bin/bash -lc <cmd>`.
  # Default: false (recommended).
  allow_shell: false
  # Optional allowlist for `{exe,args}` mode. If empty, exe is not restricted.
  # Prefer absolute paths.
  allowlist: []
```

## Gateway mode

In gateway mode, the agent runs an HTTPS reverse proxy that accepts requests from host-agents and forwards them to the Askio Cloud API.

```yaml
mode: "gateway"

gateway:
  listen_addr: ":8443"
  tls_cert_path: "/etc/askio/gateway.crt"
  tls_key_path: "/etc/askio/gateway.key"
  token_hmac_key: "<random-secret>"  # used to validate per-host tokens

  cloud_api_url: "https://<your-backend>/functions/v1"
  cloud_agent_token: "<gateway-cloud-token>"

  # Optional but recommended so gateway heartbeats can be attributed in the dashboard.
  # If omitted, the agent will default it to the top-level server_id (if present).
  gateway_server_id: "<gateway-server-uuid>"

# optional
data_dir: "/var/lib/askio-monitor"
```

Host agents should point their `api_url` to the gateway URL, and use a per-host gateway token as `agent_token`.

## Remote config
The agent periodically calls:

`GET {api_url}/monitor-agent-config?server_id=<server_id>`

Expected JSON (agent-side):

```json
{
  "fetched_at": "2026-01-07T12:00:00Z",
  "monitors": [
    {
      "id": "monitor-uuid",
      "service_name": "nginx",
      "service_type": "systemd",
      "systemd_unit": "nginx.service",
      "check_types": ["active_state", "port", "http"],
      "check_interval_seconds": 60,
      "port": 80,
      "http_endpoint": "http://127.0.0.1/health",
      "enabled": true,
      "remediation_enabled": true,
      "remediation_policy": "reload_first",
      "allowed_playbook_ids": ["nginx_test_reload", "systemd_restart"]
    }
  ]
}
```

## Notes for developers

### Privilege mode

- `privilege_mode: sudo` (recommended): the agent runs unprivileged and uses `sudo -n` for allowlisted remediation commands.
- `privilege_mode: root`: executes directly.

### Operations + `command.run`

- `{exe,args}` mode does **not** use a shell.
- `{cmd, shell:true}` mode is **gated** by `operations.allow_shell: true`.

See `docs/OPERATIONS.md`.
