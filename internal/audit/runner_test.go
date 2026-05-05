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

func auditCheck(id string, key string, readOnly bool, severity string) model.AuditCheckDefinition {
	return model.AuditCheckDefinition{
		ID:       id,
		CheckKey: key,
		Name:     key,
		Severity: severity,
		ReadOnly: readOnly,
	}
}
