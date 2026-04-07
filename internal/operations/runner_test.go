package operations

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

type fakeHandler struct{}

func (fakeHandler) ID() string { return "service.start" }

func (fakeHandler) Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult {
	return HandlerResult{Status: "success", Output: "ok", Changed: !mode.IsDryRun()}
}

// Note: we don't need a real executor for this test because it's dry_run.

func TestRunnerPlanDryRun(t *testing.T) {
	reg := NewRegistry(fakeHandler{})
	r := NewRunner(StepExec{Exec: nil}, reg)

	res := r.Execute(context.Background(), RunOptions{ServerID: "srv"}, model.PendingAction{
		RunID:         "run",
		ActionName:    "test",
		ActionType:    "plan",
		ExecutionMode: "dry_run",
		TimeoutSeconds: 30,
		ActionPlan: &model.ActionPlan{Version: "1.0", Steps: []model.PlanStep{{ID: "s1", Action: "service.start", Params: map[string]any{"name": "nginx"}, OnFailure: "abort"}}},
	})

	if res.Status != "success" {
		t.Fatalf("expected success, got %s (err=%s)", res.Status, res.Error)
	}
	if len(res.StepResults) != 1 {
		t.Fatalf("expected 1 step, got %d", len(res.StepResults))
	}
	if res.StepResults[0].Changed {
		t.Fatalf("expected changed=false in dry run")
	}
	if res.FinishedAt.Before(res.StartedAt) {
		t.Fatalf("finished_at before started_at")
	}
	_ = time.Second
}

func TestRunnerAnsibleDryRun(t *testing.T) {
	reg := NewRegistry(fakeHandler{})
	r := NewRunner(StepExec{Exec: nil}, reg)

	res := r.Execute(context.Background(), RunOptions{ServerID: "srv"}, model.PendingAction{
		RunID:          "run",
		ActionName:     "install_mariadb",
		ActionType:     "ansible",
		ExecutionMode:  "dry_run",
		TimeoutSeconds: 30,
		AnsiblePlaybook: &model.AnsiblePlaybook{
			Content: "---\n- hosts: localhost\n  tasks: []\n",
			ExtraVars: map[string]any{
				"foo": "bar",
			},
		},
	})

	if res.Status != "success" {
		t.Fatalf("expected success, got %s (err=%s)", res.Status, res.Error)
	}
	if len(res.StepResults) != 1 {
		t.Fatalf("expected 1 step, got %d", len(res.StepResults))
	}
	if res.StepResults[0].Action != "ansible" {
		t.Fatalf("expected action=ansible, got %s", res.StepResults[0].Action)
	}
	if res.StepResults[0].Changed {
		t.Fatalf("expected changed=false in dry run")
	}
}

func TestRunnerAnsibleDryRun_WithInventory(t *testing.T) {
	reg := NewRegistry(fakeHandler{})
	r := NewRunner(StepExec{Exec: nil}, reg)

	res := r.Execute(context.Background(), RunOptions{ServerID: "srv"}, model.PendingAction{
		RunID:          "run",
		ActionName:     "install_mariadb",
		ActionType:     "ansible",
		ExecutionMode:  "dry_run",
		TimeoutSeconds: 30,
		AnsiblePlaybook: &model.AnsiblePlaybook{
			Content:   "---\n- hosts: all\n  tasks: []\n",
			Inventory: "[webservers]\nweb1.example.com\n",
			ExtraVars: map[string]any{"foo": "bar"},
		},
	})

	if res.Status != "success" {
		t.Fatalf("expected success, got %s (err=%s)", res.Status, res.Error)
	}
	if len(res.StepResults) != 1 {
		t.Fatalf("expected 1 step, got %d", len(res.StepResults))
	}
	out := res.StepResults[0].Output
	if out == "" {
		t.Fatalf("expected output")
	}
	if !strings.Contains(out, "askio-inv-run") {
		t.Fatalf("expected inventory temp file in output, got: %s", out)
	}
	if strings.Contains(out, "-c local") {
		t.Fatalf("did not expect -c local when inventory provided")
	}
}
