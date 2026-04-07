# Security notes (v1)

## Privilege model
The agent supports two modes:

- `privilege_mode: root`
  - simplest
  - biggest blast radius

- `privilege_mode: sudo` (recommended)
  - agent runs as an unprivileged user (e.g. `askio-agent`)
  - remediation actions run through `sudo -n` and a strict allowlist

See `packaging/sudoers/askio-monitor`.

## Command execution

### Remediation

- No shell interpolation (no `sh -c`)
- Hard timeouts per step
- Output redaction before posting to backend

Implementation: `internal/remediation/*`.

### Operations Platform: `command.run`

The Operations Platform supports a handler registry (`internal/operations/*`).

`command.run` supports:

- `{exe,args}` mode: **no shell**, optionally restricted by an allowlist in config.
- `{cmd, shell:true}` mode: **shell execution** via `/bin/bash -lc`, gated behind `operations.allow_shell: true`.

Security posture:

- Default is safe: `operations.allow_shell` is **false** unless explicitly enabled.
- If you enable shell mode, treat the agent like a remote execution surface and ensure:
  - only trusted users can create actions,
  - you log all action payloads and outcomes,
  - you keep `sudoers` tight.

See `docs/OPERATIONS.md`.

## Network auth
- Uses bearer token in `Authorization: Bearer <token>`
- Consider rotating tokens and adding config signature on the backend.
