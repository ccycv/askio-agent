# Operations Platform (pending_action) — Developer docs

The agent supports a server-driven actions workflow via the **remote config** response (`GET /monitor-agent-config`) by including a `pending_action` field.

Implementation entry points:

- Agent side handler: `internal/agent/operations_handler.go`
- Runner: `internal/operations/runner.go`
- Handler registry: `internal/operations/default_registry.go`
- Individual handlers: `internal/operations/handlers_*.go`

## Flow summary

1. Backend returns a config payload that includes `pending_action`.
2. Agent executes the action (with timeouts).
3. Agent posts the result to `POST /operations-agent-result`.
4. Backend clears `pending_action` only after receiving the result.

Crash-safety:

- The agent **caches the result** locally if posting fails.
- If the same `run_id` appears again, the agent re-posts the cached result and **does not re-execute**.

## pending_action schema

The schema lives in `internal/model/model.go`.

Common fields:

- `run_id` (required)
- `action_id` (optional)
- `action_name` (optional)
- `action_type` (required): `script | plan | playbook | ansible`
- `timeout_seconds` (optional, default 300)
- `execution_mode` (optional): `live | dry_run` (default live)
- `parameters` (optional map)
- `enable_rollback` (optional)

## action_type: script

Fields:

- `script_content` (required)
- `rollback_script` (optional; used only if `enable_rollback=true`)

Behavior:

- Agent substitutes `{{key}}` placeholders using `parameters`.
- Executes with `/bin/bash <tempfile>`.

## action_type: plan

Fields:

- `action_plan.steps[]` (required)
- `action_plan.rollback[]` (optional)

Each step:

```json
{
  "id": "step_1",
  "action": "service.restart",
  "params": {"unit": "nginx.service"},
  "on_failure": "abort|continue|warn"
}
```

The runner:

- looks up `step.action` in the handler registry
- calls handler `Execute(ctx, params, mode)`

If a handler id is missing you will get:

```
Unknown handler: <id>
```

## action_type: playbook

This is a separate playbook structure (Operations Platform) distinct from remediation playbooks.

Fields:

- `playbook.steps[]` where each step is a shell string command

Implementation uses `/bin/bash -lc <command>`.

## action_type: ansible

Fields:

```json
{
  "ansible_playbook": {
    "content": "---\n- hosts: localhost\n  tasks: ...\n",
    "inventory": "optional inventory text",
    "extra_vars": {"k": "v"}
  }
}
```

Behavior:

- Writes playbook to a temp file
- If inventory is not supplied: runs local-only (`-i localhost, -c local`)
- `execution_mode=dry_run` adds `--check`

## Handler registry

Registry lives in `internal/operations/registry.go`.

Default registry constructor:

- `internal/operations/default_registry.go: DefaultRegistry(exec, cfg.Operations)`

### Built-in handler IDs

Service:

- `service.start`
- `service.stop`
- `service.restart`
- `service.reload`
- `service.status`
- `service.enable`
- `service.disable`

Package:

- `package.install`
- `package.remove`
- `package.upgrade`

Checks:

- `http.check`
- `port.check`

Command:

- `command.run`

## Handler: command.run

Implementation: `internal/operations/handlers_command.go`.

### Mode A (preferred): no-shell exec

```json
{
  "action": "command.run",
  "params": {
    "exe": "/usr/bin/pkill",
    "args": ["-9", "stress"],
    "timeout_seconds": 30
  }
}
```

Properties:

- Does not use a shell.
- If `config.operations.allowlist` is non-empty, `exe` must match.

### Mode B (gated): shell

```json
{
  "action": "command.run",
  "params": {
    "cmd": "ps aux | grep stress | awk '{print $2}' | xargs -r kill -9",
    "shell": true,
    "timeout_seconds": 30
  }
}
```

Behavior:

- Runs `/bin/bash -lc <cmd>`.
- Only allowed when `operations.allow_shell: true`.
- Default is **disabled**.

### Recommended replacement for pipelines

Prefer using `{exe,args}` and native tools, e.g.:

```json
{"exe":"pkill","args":["-9","stress"]}
```

## Capabilities reporting

On each heartbeat, `internal/agent/daemon.go` includes a `capabilities` object.

The following keys are provided to support UI gating:

```json
"capabilities": {
  "handlers": ["service.restart", "command.run", ...],
  "operations_config": {
    "command_run": true,
    "command_run_shell": false,
    "command_run_allowlist": []
  }
}
```

This allows the UI to:

- detect whether `command.run` exists
- show whether shell is enabled
- offer an “enable shell” action (implemented server-side via an explicit, user-approved script)
