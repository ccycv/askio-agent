package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/operations"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

const (
	bucketOps = "ops"
)

// handlePendingAction executes a pending action, posts the result, and persists
// the result locally if posting fails.
func (d *Daemon) handlePendingAction(ctx context.Context, a *model.PendingAction) {
	if a == nil {
		return
	}

	// If we already have a cached result for this run_id, try posting it again and do NOT re-execute.
	if b, ok, err := d.store.Get(ctx, bucketOps, operations.PersistedRunKey(a.RunID)); err == nil && ok {
		var cached model.OperationsAgentResult
		if err := json.Unmarshal(b, &cached); err == nil {
			d.logger.Info("pending_action: retry posting cached result", "run_id", a.RunID)
			if err := d.api.PostOperationsResult(ctx, cached); err != nil {
				d.logger.Warn("pending_action: post cached result failed", "run_id", a.RunID, "err", err)
				return
			}
			_ = d.store.Delete(ctx, bucketOps, operations.PersistedRunKey(a.RunID))
			return
		}
	}

	// Execute action.
	d.logger.Info("pending_action starting", "run_id", a.RunID, "action_id", a.ActionID, "type", a.ActionType, "mode", a.ExecutionMode)

	exec := d.remEngExec()
	runner := operations.NewRunner(
		operations.StepExec{Exec: exec},
		operations.DefaultRegistry(exec, d.cfg.Operations),
	)

	res := runner.Execute(ctx, operations.RunOptions{ServerID: d.cfg.ServerID, DataDir: d.cfg.DataDir}, *a)

	// Post result with small retry.
	postCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := d.api.PostOperationsResult(postCtx, res); err != nil {
		d.logger.Warn("pending_action: post result failed, caching", "run_id", a.RunID, "err", err)
		b, _ := json.Marshal(res)
		_ = d.store.Put(context.Background(), bucketOps, operations.PersistedRunKey(a.RunID), b)
		return
	}

	d.logger.Info("pending_action finished", "run_id", a.RunID, "status", res.Status)
}

// remEngExec returns the executor backing the remediation engine.
// This is a little hacky because the remediation engine holds it privately.
// For now we rebuild a new runner using the same privilege_mode configured in cfg.
func (d *Daemon) remEngExec() remediation.Executor {
	// The remediation.Engine doesn't expose its executor; build a fresh one using same privilege mode.
	exec, err := remediation.NewExecutor(d.cfg.PrivilegeMode)
	if err != nil {
		d.logger.Warn("failed to create executor", slog.Any("err", err))
		return remediation.RootExecutor{}
	}
	return exec
}

func (d *Daemon) validatePendingAction(a *model.PendingAction) error {
	if a == nil {
		return nil
	}
	if a.RunID == "" {
		return fmt.Errorf("pending_action.run_id is required")
	}
	if a.ActionType == "" {
		return fmt.Errorf("pending_action.action_type is required")
	}
	if a.ActionType == "ansible" {
		if a.AnsiblePlaybook == nil {
			return fmt.Errorf("pending_action.ansible_playbook is required for action_type=ansible")
		}
	}
	return nil
}
