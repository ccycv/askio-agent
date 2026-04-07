# Remediation playbooks (v1)

Playbooks are **built-in** and executed by ID.

The agent will only run remediation when:
- `monitor.remediation_enabled = true`
- The chosen playbook is allowed for that monitor:
  - if `allowed_playbook_ids` is empty -> any applicable built-in playbook may run
  - if set -> playbook ID must be in the allowlist

## Built-ins

- `systemd_restart`
- `systemd_reload`
- `systemd_reset_failed`
- `nginx_test_reload`
- `postgres_restart_verify`
- `docker_restart`

## Variables
Some playbooks use variables:
- `{unit}` resolves to `monitor.systemd_unit` or `service_name + ".service"`
- `{container}` resolves to `monitor.docker_container_id` or `service_name`

## Safety notes
- No shell is used; commands are executed with `exec.CommandContext` and explicit args.
- In `sudo` mode, the executor uses `sudo -n` (never prompts).
- Command output is redacted before sending to backend.
