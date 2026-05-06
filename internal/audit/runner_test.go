package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type fakeExec struct {
	outputs map[string]remediation.ExecResult
	calls   []string
}

func (f *fakeExec) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (remediation.ExecResult, error) {
	key := command + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if out, ok := f.outputs[key]; ok {
		return out, nil
	}
	return remediation.ExecResult{ExitCode: 1, Output: "not found", Duration: time.Millisecond}, nil
}

func (f *fakeExec) Format(command string, args []string) string {
	return command + " " + strings.Join(args, " ")
}

func TestRunnerExecutesOnlyKnownReadOnlyAuditChecks(t *testing.T) {
	exec := &fakeExec{outputs: map[string]remediation.ExecResult{
		"cat /etc/ssh/sshd_config": {ExitCode: 0, Output: "PermitRootLogin yes\nPasswordAuthentication no\n", Duration: time.Millisecond},
	}}
	runner := NewRunner(exec)

	result := runner.Execute(context.Background(), model.PendingAuditJob{
		RunID:          "run-1",
		Target:         model.AuditTarget{AgentID: "agent-1", ServerID: "server-1"},
		RedactionRules: model.AuditRedactionRules{RedactPatterns: []string{"password"}, StoreRawOutput: true},
		Checks: []model.AuditCheckDefinition{
			auditCheck("check-1", "ssh_root_login", true, "high"),
			auditCheck("check-2", "unknown_check", true, "medium"),
			auditCheck("check-3", "ssh_password_auth", false, "high"),
		},
	}, "server-1")

	if result.RunID != "run-1" || result.ServerID != "server-1" || result.AgentID != "agent-1" {
		t.Fatalf("unexpected result identity: %#v", result)
	}
	if len(exec.calls) != 2 {
		t.Fatalf("expected only known read-only SSH command executions, got %v", exec.calls)
	}
	if len(result.Results) != 3 {
		t.Fatalf("expected 3 check results, got %d", len(result.Results))
	}
	if result.Results[0].Status != "fail" {
		t.Fatalf("expected root login fail, got %s", result.Results[0].Status)
	}
	if result.Results[1].Status != "not_applicable" {
		t.Fatalf("expected unknown check not_applicable, got %s", result.Results[1].Status)
	}
	if result.Results[2].Status != "unknown" || len(result.Results[2].Errors) == 0 {
		t.Fatalf("expected non-read-only check rejection, got %#v", result.Results[2])
	}
	raw := result.Results[0].RawResultJSON["commands"].([]commandOutput)[0].Output
	if strings.Contains(strings.ToLower(raw), "password") {
		t.Fatalf("expected password-like tokens to be redacted, got %q", raw)
	}
}

func TestRunnerNormalizesDiskAndLoginChecks(t *testing.T) {
	exec := &fakeExec{outputs: map[string]remediation.ExecResult{
		"df -P":                         {ExitCode: 0, Output: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100 95 5 95% /\n", Duration: time.Millisecond},
		"tail -n 500 /var/log/auth.log": {ExitCode: 0, Output: strings.Repeat("Failed password for root\n", 21), Duration: time.Millisecond},
	}}
	runner := NewRunner(exec)

	result := runner.Execute(context.Background(), model.PendingAuditJob{
		RunID: "run-2",
		Checks: []model.AuditCheckDefinition{
			auditCheck("check-1", "disk_usage_critical", true, "high"),
			auditCheck("check-2", "failed_login_spike", true, "high"),
		},
	}, "server-1")

	if result.Results[0].Status != "fail" {
		t.Fatalf("expected disk check fail, got %s", result.Results[0].Status)
	}
	if result.Results[0].Normalized["max_used_percent"] != 95 {
		t.Fatalf("expected max disk 95, got %#v", result.Results[0].Normalized)
	}
	if result.Results[1].Status != "fail" {
		t.Fatalf("expected failed login check fail, got %s", result.Results[1].Status)
	}
	if result.Results[1].Normalized["failed_login_count"] != 21 {
		t.Fatalf("expected 21 failed logins, got %#v", result.Results[1].Normalized)
	}
}

func TestNormalizeLinuxCheckFixtures(t *testing.T) {
	fixtures := []struct {
		name       string
		checkKey   string
		outputs    []commandOutput
		wantStatus string
		wantField  string
		wantValue  any
	}{
		{
			name:       "ssh root login enabled",
			checkKey:   "ssh_root_login",
			outputs:    outputs(out("sshd_effective_config", 0, "permitrootlogin yes\n")),
			wantStatus: "fail",
		},
		{
			name:       "ssh root login disabled",
			checkKey:   "ssh_root_login",
			outputs:    outputs(out("sshd_effective_config", 0, "permitrootlogin no\n")),
			wantStatus: "pass",
		},
		{
			name:       "ssh password auth enabled",
			checkKey:   "ssh_password_auth",
			outputs:    outputs(out("sshd_effective_config", 0, "passwordauthentication yes\n")),
			wantStatus: "fail",
		},
		{
			name:       "ssh password auth disabled",
			checkKey:   "ssh_password_auth",
			outputs:    outputs(out("sshd_effective_config", 0, "passwordauthentication no\n")),
			wantStatus: "pass",
		},
		{
			name:       "ssh weak ciphers manual evidence collected",
			checkKey:   "ssh_weak_ciphers_manual",
			outputs:    outputs(out("sshd_config", 0, "Ciphers aes256-gcm@openssh.com\n")),
			wantStatus: "warning",
		},
		{
			name:       "sudo users evidence collected",
			checkKey:   "sudo_users",
			outputs:    outputs(out("sudo_group", 0, "sudo:x:27:root,deploy\n")),
			wantStatus: "warning",
		},
		{
			name:       "wheel users evidence collected",
			checkKey:   "sudo_users",
			outputs:    outputs(out("sudo_group", 2, ""), out("wheel_group", 0, "wheel:x:10:root,admin\n")),
			wantStatus: "warning",
		},
		{
			name:       "inactive users evidence collected",
			checkKey:   "inactive_users_manual",
			outputs:    outputs(out("passwd", 0, "root:x:0:0:root:/root:/bin/bash\n")),
			wantStatus: "warning",
		},
		{
			name:       "missing mfa manual evidence",
			checkKey:   "missing_mfa_manual",
			outputs:    nil,
			wantStatus: "not_applicable",
		},
		{
			name:       "public ssh listener",
			checkKey:   "public_ssh",
			outputs:    socketOutputs("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"),
			wantStatus: "fail",
		},
		{
			name:       "private ssh listener",
			checkKey:   "public_ssh",
			outputs:    socketOutputs("tcp LISTEN 0 4096 127.0.0.1:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"),
			wantStatus: "pass",
		},
		{
			name:       "public postgresql listener",
			checkKey:   "public_postgresql",
			outputs:    socketOutputs("tcp LISTEN 0 4096 0.0.0.0:5432 0.0.0.0:* users:((\"postgres\",pid=2,fd=3))"),
			wantStatus: "fail",
		},
		{
			name:       "public mysql listener",
			checkKey:   "public_mysql",
			outputs:    socketOutputs("tcp LISTEN 0 4096 0.0.0.0:3306 0.0.0.0:* users:((\"mysqld\",pid=3,fd=3))"),
			wantStatus: "fail",
		},
		{
			name:       "public redis listener",
			checkKey:   "public_redis",
			outputs:    socketOutputs("tcp LISTEN 0 4096 [::]:6379 [::]:* users:((\"redis\",pid=4,fd=3))"),
			wantStatus: "fail",
		},
		{
			name:       "rhel public redis listener",
			checkKey:   "public_redis",
			outputs:    socketOutputs("tcp LISTEN 0 511 *:6379 *:* users:((\"redis-server\",pid=123,fd=6))"),
			wantStatus: "fail",
		},
		{
			name:       "docker socket detected",
			checkKey:   "public_docker_socket",
			outputs:    outputs(out("docker_socket", 0, "srw-rw---- 1 root docker 0 May 5 10:00 /var/run/docker.sock\n")),
			wantStatus: "fail",
		},
		{
			name:       "unexpected ports evidence collected",
			checkKey:   "unexpected_listening_ports",
			outputs:    socketOutputs("tcp LISTEN 0 4096 0.0.0.0:8080 0.0.0.0:* users:((\"app\",pid=5,fd=3))"),
			wantStatus: "warning",
		},
		{
			name:       "pending security updates",
			checkKey:   "pending_security_updates",
			outputs:    outputs(out("apt_upgradable", 0, "Listing...\nopenssl/jammy-security 3.0.2 amd64 [upgradable from: 3.0.1]\n")),
			wantStatus: "warning",
		},
		{
			name:       "dnf security updates",
			checkKey:   "pending_security_updates",
			outputs:    outputs(out("apt_upgradable", 1, ""), out("dnf_updates", 100, "Security: RHSA-2026:1001 Important/Sec. kernel.x86_64 5.14.0-1.el9 updates\n")),
			wantStatus: "warning",
		},
		{
			name:       "no pending security updates",
			checkKey:   "pending_security_updates",
			outputs:    outputs(out("apt_upgradable", 0, "Listing...\n")),
			wantStatus: "pass",
		},
		{
			name:       "reboot required",
			checkKey:   "reboot_required",
			outputs:    outputs(out("reboot_required", 0, "")),
			wantStatus: "warning",
		},
		{
			name:       "reboot not required",
			checkKey:   "reboot_required",
			outputs:    outputs(out("reboot_required", 1, "")),
			wantStatus: "pass",
		},
		{
			name:       "unsupported os evidence collected",
			checkKey:   "unsupported_os_version",
			outputs:    outputs(out("os_release", 0, "PRETTY_NAME=\"Ubuntu 24.04.4 LTS\"\n")),
			wantStatus: "warning",
		},
		{
			name:       "unattended upgrades disabled",
			checkKey:   "unattended_upgrades_disabled",
			outputs:    outputs(out("unattended_upgrades", 1, "disabled\n")),
			wantStatus: "fail",
		},
		{
			name:       "unattended upgrades enabled",
			checkKey:   "unattended_upgrades_disabled",
			outputs:    outputs(out("unattended_upgrades", 0, "enabled\n")),
			wantStatus: "pass",
		},
		{
			name:       "time sync disabled",
			checkKey:   "time_sync_disabled",
			outputs:    outputs(out("timedatectl", 0, "System clock synchronized: no\nNTP service: inactive\n")),
			wantStatus: "fail",
		},
		{
			name:       "time sync enabled",
			checkKey:   "time_sync_disabled",
			outputs:    outputs(out("timedatectl", 0, "System clock synchronized: yes\nNTP service: active\n")),
			wantStatus: "pass",
		},
		{
			name:       "askio agent active",
			checkKey:   "askio_agent_offline",
			outputs:    outputs(out("askio_monitor_status", 0, "active\n")),
			wantStatus: "pass",
		},
		{
			name:       "askio agent inactive is offline",
			checkKey:   "askio_agent_offline",
			outputs:    outputs(out("askio_monitor_status", 3, "inactive\n")),
			wantStatus: "fail",
		},
		{
			name:       "failed systemd services",
			checkKey:   "failed_systemd_services",
			outputs:    outputs(out("failed_systemd", 0, "UNIT LOAD ACTIVE SUB DESCRIPTION\nbad.service loaded failed failed Bad service\n1 loaded units listed.\n")),
			wantStatus: "warning",
		},
		{
			name:       "no failed systemd services",
			checkKey:   "failed_systemd_services",
			outputs:    outputs(out("failed_systemd", 0, "0 loaded units listed.\n")),
			wantStatus: "pass",
		},
		{
			name:       "auth log missing",
			checkKey:   "auth_log_missing",
			outputs:    outputs(out("auth_log", 1, "")),
			wantStatus: "warning",
		},
		{
			name:       "auth log readable",
			checkKey:   "auth_log_missing",
			outputs:    outputs(out("auth_log", 0, "")),
			wantStatus: "pass",
		},
		{
			name:       "rhel secure log readable",
			checkKey:   "auth_log_missing",
			outputs:    outputs(out("auth_log", 1, ""), out("secure_log", 0, "")),
			wantStatus: "pass",
		},
		{
			name:       "sshd journal readable",
			checkKey:   "auth_log_missing",
			outputs:    outputs(out("auth_log", 1, ""), out("secure_log", 1, ""), out("sshd_journal", 0, "May 06 host sshd[1]: Server listening on 0.0.0.0 port 22.\n")),
			wantStatus: "pass",
		},
		{
			name:       "failed login spike",
			checkKey:   "failed_login_spike",
			outputs:    outputs(out("auth_log_tail", 0, strings.Repeat("authentication failure\n", 20))),
			wantStatus: "fail",
			wantField:  "failed_login_count",
			wantValue:  20,
		},
		{
			name:       "rhel failed login spike",
			checkKey:   "failed_login_spike",
			outputs:    outputs(out("auth_log_tail", 1, ""), out("secure_log_tail", 0, strings.Repeat("Failed password for root from 1.2.3.4 port 22 ssh2\n", 20))),
			wantStatus: "fail",
			wantField:  "failed_login_count",
			wantValue:  20,
		},
		{
			name:       "failed login evidence unavailable",
			checkKey:   "failed_login_spike",
			outputs:    outputs(out("auth_log_tail", 1, ""), out("secure_log_tail", 1, ""), out("sshd_journal_tail", 1, "")),
			wantStatus: "unknown",
			wantField:  "failed_login_count",
			wantValue:  0,
		},
		{
			name:       "low failed login count",
			checkKey:   "failed_login_spike",
			outputs:    outputs(out("auth_log_tail", 0, "Failed password for invalid user\n")),
			wantStatus: "pass",
			wantField:  "failed_login_count",
			wantValue:  1,
		},
		{
			name:       "disk usage critical",
			checkKey:   "disk_usage_critical",
			outputs:    outputs(out("disk_usage", 0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100 91 9 91% /\n")),
			wantStatus: "fail",
			wantField:  "max_used_percent",
			wantValue:  91,
		},
		{
			name:       "disk usage healthy",
			checkKey:   "disk_usage_critical",
			outputs:    outputs(out("disk_usage", 0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/root 100 40 60 40% /\n")),
			wantStatus: "pass",
			wantField:  "max_used_percent",
			wantValue:  40,
		},
		{
			name:       "backup not detected review evidence",
			checkKey:   "backup_not_detected",
			outputs:    outputs(out("cron_daily", 0, "logrotate\napt-compat\n")),
			wantStatus: "warning",
		},
		{
			name:       "backup older than threshold evidence",
			checkKey:   "backup_older_than_threshold",
			outputs:    outputs(out("backup_dirs", 0, "2026-04-01 00:00 /var/backups/app.sql\n")),
			wantStatus: "warning",
		},
		{
			name:       "restore test manual evidence",
			checkKey:   "restore_test_missing_manual",
			outputs:    nil,
			wantStatus: "not_applicable",
		},
		{
			name:       "tls certificate evidence",
			checkKey:   "tls_certificate_expiring",
			outputs:    outputs(out("certbot_certificates", 0, "Certificate Name: askio.cloud\nExpiry Date: 2026-06-01\n")),
			wantStatus: "warning",
		},
		{
			name:       "weak tls manual evidence",
			checkKey:   "weak_tls_manual",
			outputs:    outputs(out("nginx_config_test", 0, "ssl_protocols TLSv1.2 TLSv1.3;\n")),
			wantStatus: "warning",
		},
		{
			name:       "dns unknown ip external evidence",
			checkKey:   "dns_points_unknown_ip",
			outputs:    nil,
			wantStatus: "not_applicable",
		},
		{
			name:       "cloudflare proxy external evidence",
			checkKey:   "cloudflare_proxy_disabled",
			outputs:    nil,
			wantStatus: "not_applicable",
		},
		{
			name:       "origin exposed manual evidence",
			checkKey:   "origin_exposed_manual",
			outputs:    nil,
			wantStatus: "not_applicable",
		},
	}

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			status, confidence, normalized := normalizeCheck(fixture.checkKey, fixture.outputs)
			if status != fixture.wantStatus {
				t.Fatalf("expected status %s, got %s with normalized %#v", fixture.wantStatus, status, normalized)
			}
			if confidence <= 0 || confidence > 1 {
				t.Fatalf("expected confidence within 0..1, got %f", confidence)
			}
			if normalized["summary"] == "" {
				t.Fatalf("expected normalized summary, got %#v", normalized)
			}
			if fixture.wantField != "" && normalized[fixture.wantField] != fixture.wantValue {
				t.Fatalf("expected normalized %s=%#v, got %#v", fixture.wantField, fixture.wantValue, normalized)
			}
		})
	}
}

func TestCommandRegistryCoversThirtyReadOnlyAuditChecks(t *testing.T) {
	expected := []string{
		"ssh_root_login",
		"ssh_password_auth",
		"ssh_weak_ciphers_manual",
		"sudo_users",
		"inactive_users_manual",
		"missing_mfa_manual",
		"public_ssh",
		"public_postgresql",
		"public_mysql",
		"public_redis",
		"public_docker_socket",
		"unexpected_listening_ports",
		"pending_security_updates",
		"reboot_required",
		"unsupported_os_version",
		"unattended_upgrades_disabled",
		"time_sync_disabled",
		"askio_agent_offline",
		"failed_systemd_services",
		"auth_log_missing",
		"failed_login_spike",
		"disk_usage_critical",
		"backup_not_detected",
		"backup_older_than_threshold",
		"restore_test_missing_manual",
		"tls_certificate_expiring",
		"weak_tls_manual",
		"dns_points_unknown_ip",
		"cloudflare_proxy_disabled",
		"origin_exposed_manual",
	}
	registry := commandRegistry()
	if len(registry) != len(expected) {
		t.Fatalf("expected %d registered checks, got %d", len(expected), len(registry))
	}
	for _, checkKey := range expected {
		specs, ok := registry[checkKey]
		if !ok {
			t.Fatalf("missing registry entry for %s", checkKey)
		}
		for _, spec := range specs {
			formatted := spec.Command + " " + strings.Join(spec.Args, " ")
			if strings.Contains(formatted, "systemctl restart") ||
				strings.Contains(formatted, "apt install") ||
				strings.Contains(formatted, "apt upgrade") ||
				strings.Contains(formatted, "ufw allow") ||
				strings.Contains(formatted, "ufw enable") ||
				strings.Contains(formatted, "rm -rf") ||
				strings.Contains(formatted, "chmod ") ||
				strings.Contains(formatted, "chown ") ||
				strings.Contains(formatted, "sed -i") {
				t.Fatalf("registry command for %s is not read-only: %s", checkKey, formatted)
			}
		}
	}
}

func auditCheck(id string, key string, readOnly bool, severity string) model.AuditCheckDefinition {
	return model.AuditCheckDefinition{
		ID:       id,
		CheckKey: key,
		Name:     key,
		Severity: severity,
		ReadOnly: readOnly,
	}
}

func out(name string, exitCode int, output string) commandOutput {
	return commandOutput{Name: name, ExitCode: exitCode, Output: output}
}

func outputs(items ...commandOutput) []commandOutput {
	return items
}

func socketOutputs(output string) []commandOutput {
	return outputs(out("listening_sockets", 0, output+"\n"))
}
