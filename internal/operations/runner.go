package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type Runner struct {
	Exec StepExec
	Reg  *Registry
}

func NewRunner(exec StepExec, reg *Registry) *Runner {
	return &Runner{Exec: exec, Reg: reg}
}

type RunOptions struct {
	ServerID string
	DataDir  string
}

// Execute runs a PendingAction and returns a result payload.
//
// Crash-safety: the caller should persist the result and retry posting if needed.
func (r *Runner) Execute(ctx context.Context, opt RunOptions, a model.PendingAction) model.OperationsAgentResult {
	started := time.Now().UTC()
	res := model.OperationsAgentResult{
		RunID:     a.RunID,
		ServerID:  opt.ServerID,
		Status:    "failed",
		StartedAt: started,
	}

	mode := ExecutionMode(a.ExecutionMode)
	if mode != ExecutionModeLive && mode != ExecutionModeDryRun {
		mode = ExecutionModeLive
	}

	timeout := time.Duration(a.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	ctx2, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var out bytes.Buffer
	writeLine := func(format string, args ...any) {
		out.WriteString(fmt.Sprintf(format, args...))
		out.WriteString("\n")
	}

	writeLine("action=%s type=%s mode=%s", a.ActionName, a.ActionType, mode)
	if mode.IsDryRun() {
		writeLine("[DRY RUN] no commands will be executed")
	}

	switch a.ActionType {
	case "script":
		r.execScript(ctx2, opt, a, mode, &res, &out)
	case "plan":
		r.execPlan(ctx2, opt, a, mode, &res, &out)
	case "playbook":
		r.execPlaybook(ctx2, opt, a, mode, &res, &out)
	case "ansible":
		r.execAnsible(ctx2, opt, a, mode, &res, &out)
	default:
		res.Error = fmt.Sprintf("unknown action_type: %s", a.ActionType)
		res.FinishedAt = time.Now().UTC()
		res.Output = out.String()
		return res
	}

	if errors.Is(ctx2.Err(), context.DeadlineExceeded) {
		res.Status = "failed"
		res.Error = fmt.Sprintf("Execution timed out after %d seconds", int(timeout.Seconds()))
	}
	res.FinishedAt = time.Now().UTC()
	res.Output = out.String()
	return res
}

func (r *Runner) execScript(ctx context.Context, opt RunOptions, a model.PendingAction, mode ExecutionMode, res *model.OperationsAgentResult, out *bytes.Buffer) {
	if strings.TrimSpace(a.ScriptContent) == "" {
		res.Error = "script_content is required"
		return
	}

	script := substituteParams(a.ScriptContent, a.Parameters)

	if mode.IsDryRun() {
		res.Status = "success"
		res.StepResults = []model.OperationsStepResult{{
			StepID:     "script",
			Action:     "script",
			Status:     "success",
			Output:     "[DRY RUN]\n" + script,
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
			Changed:    false,
		}}
		return
	}

	file := filepath.Join(os.TempDir(), fmt.Sprintf("askio-action-%s.sh", a.RunID))
	_ = os.WriteFile(file, []byte(script), 0o700)

	stepStart := time.Now().UTC()
	exRes, err := r.Exec.Exec.Run(ctx, "/bin/bash", []string{file}, int(time.Until(stepStart.Add(5 * time.Minute)).Seconds()))
	stepEnd := time.Now().UTC()

	step := model.OperationsStepResult{
		StepID:     "script",
		Action:     "script",
		StartedAt:  stepStart,
		FinishedAt: stepEnd,
		Changed:    err == nil,
	}

	step.Output = remediation.Redact(exRes.Output)
	if err != nil {
		step.Status = "failed"
		step.Error = err.Error()
		res.StepResults = append(res.StepResults, step)
		res.Status = "failed"
		res.Error = err.Error()

		if a.EnableRollback && strings.TrimSpace(a.RollbackScript) != "" {
			rollback := substituteParams(a.RollbackScript, a.Parameters)
			rbFile := filepath.Join(os.TempDir(), fmt.Sprintf("askio-action-%s-rollback.sh", a.RunID))
			_ = os.WriteFile(rbFile, []byte(rollback), 0o700)
			rbRes, rbErr := r.Exec.Exec.Run(ctx, "/bin/bash", []string{rbFile}, 300)
			out.WriteString("rollback_output:\n")
			out.WriteString(remediation.Redact(rbRes.Output))
			out.WriteString("\n")
			if rbErr != nil {
				out.WriteString("rollback_error: " + rbErr.Error() + "\n")
			}
		}
		return
	}

	step.Status = "success"
	res.StepResults = append(res.StepResults, step)
	res.Status = "success"
}

func (r *Runner) execPlan(ctx context.Context, opt RunOptions, a model.PendingAction, mode ExecutionMode, res *model.OperationsAgentResult, out *bytes.Buffer) {
	if a.ActionPlan == nil {
		res.Error = "action_plan is required"
		return
	}
	steps := a.ActionPlan.Steps
	results := make([]model.OperationsStepResult, 0, len(steps))
	overall := "success"
	var firstErr string

	for _, s := range steps {
		stepStart := time.Now().UTC()
		rr := model.OperationsStepResult{StepID: s.ID, Action: s.Action, StartedAt: stepStart}

		h, ok := r.Reg.Get(s.Action)
		if !ok {
			rr.Status = "failed"
			rr.Error = "Unknown handler: " + s.Action
			rr.FinishedAt = time.Now().UTC()
			results = append(results, rr)
			overall = "failed"
			if firstErr == "" {
				firstErr = rr.Error
			}
			if strings.ToLower(s.OnFailure) == "abort" {
				break
			}
			continue
		}

		hr := h.Execute(ctx, s.Params, mode)
		rr.Status = hr.Status
		rr.Output = hr.Output
		rr.Changed = hr.Changed
		if hr.Error != nil {
			rr.Error = hr.Error.Error()
		}
		rr.FinishedAt = time.Now().UTC()
		results = append(results, rr)

		if rr.Status == "failed" {
			if strings.ToLower(s.OnFailure) == "warn" {
				overall = "partial"
			} else {
				overall = "failed"
			}
			if firstErr == "" {
				firstErr = rr.Error
			}
			if strings.ToLower(s.OnFailure) == "abort" {
				break
			}
		}
	}

	res.StepResults = results
	res.Status = overall
	res.Error = firstErr

	if overall == "failed" && a.EnableRollback && len(a.ActionPlan.Rollback) > 0 {
		out.WriteString("rollback:\n")
		for i := len(a.ActionPlan.Rollback) - 1; i >= 0; i-- {
			rb := a.ActionPlan.Rollback[i]
			out.WriteString("- " + rb.Action + "\n")
			if mode.IsDryRun() {
				continue
			}
			h, ok := r.Reg.Get(rb.Action)
			if !ok {
				out.WriteString("  rollback handler missing\n")
				continue
			}
			hr := h.Execute(ctx, rb.Params, mode)
			if hr.Error != nil {
				out.WriteString("  rollback error: " + hr.Error.Error() + "\n")
			}
		}
	}
}

func (r *Runner) execPlaybook(ctx context.Context, opt RunOptions, a model.PendingAction, mode ExecutionMode, res *model.OperationsAgentResult, out *bytes.Buffer) {
	if a.Playbook == nil {
		res.Error = "playbook is required"
		return
	}

	results := []model.OperationsStepResult{}
	overall := "success"
	var firstErr string

	for idx, s := range a.Playbook.Steps {
		id := s.ID
		if id == "" {
			id = fmt.Sprintf("step_%d", idx+1)
		}
		stepStart := time.Now().UTC()
		rr := model.OperationsStepResult{StepID: id, Action: "command.run", StartedAt: stepStart}

		if mode.IsDryRun() {
			rr.Status = "success"
			rr.Output = "[DRY RUN] " + s.Command
			rr.Changed = false
			rr.FinishedAt = time.Now().UTC()
			results = append(results, rr)
			continue
		}

		cmd, args := "/bin/bash", []string{"-lc", s.Command}
		tm := time.Duration(s.TimeoutSeconds) * time.Second
		if tm <= 0 {
			tm = 30 * time.Second
		}
		exRes, err := r.Exec.Run(ctx, cmd, args, tm)
		rr.Output = remediation.Redact(exRes.Output)
		rr.Changed = err == nil
		rr.FinishedAt = time.Now().UTC()
		if err != nil {
			rr.Status = "failed"
			rr.Error = err.Error()
			results = append(results, rr)
			overall = "failed"
			if firstErr == "" {
				firstErr = rr.Error
			}
			if strings.ToLower(s.FailAction) != "continue" {
				break
			}
			continue
		}
		rr.Status = "success"
		results = append(results, rr)
	}

	// Verification command
	if overall == "success" && strings.TrimSpace(a.Playbook.VerificationCommand) != "" {
		vr := model.OperationsStepResult{StepID: "verify", Action: "command.run", StartedAt: time.Now().UTC()}
		if mode.IsDryRun() {
			vr.Status = "success"
			vr.Output = "[DRY RUN] " + a.Playbook.VerificationCommand
			vr.Changed = false
			vr.FinishedAt = time.Now().UTC()
			results = append(results, vr)
		} else {
			exRes, err := r.Exec.Run(ctx, "/bin/bash", []string{"-lc", a.Playbook.VerificationCommand}, 30*time.Second)
			vr.Output = remediation.Redact(exRes.Output)
			vr.Changed = false
			vr.FinishedAt = time.Now().UTC()
			if err != nil {
				vr.Status = "failed"
				vr.Error = err.Error()
				overall = "failed"
				if firstErr == "" {
					firstErr = vr.Error
				}
			} else {
				vr.Status = "success"
			}
			results = append(results, vr)
		}
	}

	res.StepResults = results
	res.Status = overall
	res.Error = firstErr

	// Rollback
	if overall == "failed" && a.EnableRollback && len(a.Playbook.RollbackSteps) > 0 {
		out.WriteString("rollback:\n")
		for _, rb := range a.Playbook.RollbackSteps {
			out.WriteString("- " + rb.Command + "\n")
			if mode.IsDryRun() {
				continue
			}
			_, _ = r.Exec.Run(ctx, "/bin/bash", []string{"-lc", rb.Command}, 30*time.Second)
		}
	}
}

func (r *Runner) execAnsible(ctx context.Context, opt RunOptions, a model.PendingAction, mode ExecutionMode, res *model.OperationsAgentResult, out *bytes.Buffer) {
	if a.AnsiblePlaybook == nil {
		res.Error = "ansible_playbook is required"
		return
	}
	if strings.TrimSpace(a.AnsiblePlaybook.Content) == "" {
		res.Error = "ansible_playbook.content is required"
		return
	}

	extraJSON, err := json.Marshal(a.AnsiblePlaybook.ExtraVars)
	if err != nil {
		res.Error = fmt.Sprintf("marshal extra_vars: %v", err)
		return
	}

	playbookFile := filepath.Join(os.TempDir(), fmt.Sprintf("askio-action-%s.yml", a.RunID))
	args := []string{playbookFile}

	if inv := strings.TrimSpace(a.AnsiblePlaybook.Inventory); inv != "" {
		invFile := filepath.Join(os.TempDir(), fmt.Sprintf("askio-inv-%s", a.RunID))
		_ = os.WriteFile(invFile, []byte(inv), 0o600)
		args = append(args, "-i", invFile)
	} else {
		// Backward compatible default: local-only execution.
		args = append(args, "-i", "localhost,", "-c", "local")
	}

	args = append(args, "--extra-vars", string(extraJSON))
	if mode.IsDryRun() {
		args = append(args, "--check")

		res.Status = "success"
		res.StepResults = []model.OperationsStepResult{{
			StepID:     "ansible",
			Action:     "ansible",
			Status:     "success",
			Output:     "[DRY RUN] ansible-playbook " + strings.Join(args, " "),
			StartedAt:  time.Now().UTC(),
			FinishedAt: time.Now().UTC(),
			Changed:    false,
		}}
		return
	}

	_ = os.WriteFile(playbookFile, []byte(a.AnsiblePlaybook.Content), 0o600)

	stepStart := time.Now().UTC()
	stepTimeout := time.Duration(a.TimeoutSeconds) * time.Second
	if stepTimeout <= 0 {
		stepTimeout = 5 * time.Minute
	}
	exRes, exErr := r.Exec.Exec.Run(ctx, "ansible-playbook", args, int(time.Until(stepStart.Add(stepTimeout)).Seconds()))
	stepEnd := time.Now().UTC()

	step := model.OperationsStepResult{
		StepID:     "ansible",
		Action:     "ansible",
		StartedAt:  stepStart,
		FinishedAt: stepEnd,
		Changed:    exErr == nil && !mode.IsDryRun(),
		Output:     remediation.Redact(exRes.Output),
	}
	if exErr != nil {
		step.Status = "failed"
		step.Error = exErr.Error()
		res.StepResults = append(res.StepResults, step)
		res.Status = "failed"
		res.Error = exErr.Error()
		return
	}
	step.Status = "success"
	res.StepResults = append(res.StepResults, step)
	res.Status = "success"
}

func substituteParams(s string, params map[string]any) string {
	out := s
	for k, v := range params {
		out = strings.ReplaceAll(out, "{{"+k+"}}", fmt.Sprint(v))
	}
	return out
}

// PersistedRunKey returns a stable store key for an action run.
func PersistedRunKey(runID string) string { return "ops_result_" + runID }

func MarshalResult(r model.OperationsAgentResult) ([]byte, error) {
	return json.Marshal(r)
}
