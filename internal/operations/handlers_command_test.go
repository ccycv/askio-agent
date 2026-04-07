package operations

import (
	"context"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type fakeExec struct{}

func (fakeExec) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (remediation.ExecResult, error) {
	return remediation.ExecResult{ExitCode: 0, Output: "ok"}, nil
}
func (fakeExec) Format(command string, args []string) string { return command }

func TestCommandRunHandler_ShellDisabled(t *testing.T) {
	h := commandRunHandler{exec: StepExec{Exec: fakeExec{}}, cfg: &config.OperationsConfig{AllowShell: false}}
	r := h.Execute(context.Background(), map[string]any{"cmd": "echo hi", "shell": true}, ExecutionModeLive)
	if r.Status != "failed" {
		t.Fatalf("expected failed, got %s", r.Status)
	}
}

func TestCommandRunHandler_ExeAllowlist(t *testing.T) {
	h := commandRunHandler{exec: StepExec{Exec: fakeExec{}}, cfg: &config.OperationsConfig{AllowShell: false, Allowlist: []string{"/usr/bin/pkill"}}}
	r := h.Execute(context.Background(), map[string]any{"exe": "/usr/bin/kill", "args": []any{"-9", "123"}}, ExecutionModeLive)
	if r.Status != "failed" {
		t.Fatalf("expected failed, got %s", r.Status)
	}

	r2 := h.Execute(context.Background(), map[string]any{"exe": "/usr/bin/pkill", "args": []any{"-9", "stress"}, "timeout_seconds": 5}, ExecutionModeDryRun)
	if r2.Status != "success" {
		t.Fatalf("expected success, got %s", r2.Status)
	}
}

func TestCommandRunHandler_TimeoutParsing(t *testing.T) {
	if _, err := parseInt("10"); err != nil {
		t.Fatal(err)
	}
	if _, err := parseInt("xx"); err == nil {
		t.Fatalf("expected error")
	}

	h := commandRunHandler{exec: StepExec{Exec: fakeExec{}}, cfg: &config.OperationsConfig{AllowShell: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r := h.Execute(ctx, map[string]any{"cmd": "echo hi", "shell": true, "timeout_seconds": "1"}, ExecutionModeDryRun)
	if r.Status != "success" {
		t.Fatalf("expected success, got %s", r.Status)
	}
}

