package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/audit"
	"github.com/askio-cloud/askio-monitor/internal/model"
)

const bucketAudit = "audit"

func auditResultKey(runID string) string {
	return "result_" + runID
}

func (d *Daemon) handlePendingAuditJob(ctx context.Context, job *model.PendingAuditJob) {
	if job == nil {
		return
	}

	if b, ok, err := d.store.Get(ctx, bucketAudit, auditResultKey(job.RunID)); err == nil && ok {
		var cached model.AuditAgentResult
		if err := json.Unmarshal(b, &cached); err == nil {
			d.logger.Info("pending_audit_job: retry posting cached result", "run_id", job.RunID)
			if err := d.api.PostAuditResult(ctx, cached); err != nil {
				d.logger.Warn("pending_audit_job: post cached result failed", "run_id", job.RunID, "err", err)
				return
			}
			_ = d.store.Delete(ctx, bucketAudit, auditResultKey(job.RunID))
			return
		}
	}

	d.logger.Info("pending_audit_job starting", "run_id", job.RunID, "checks", len(job.Checks), "bundle_version", job.BundleVersion)
	exec := d.remEngExec()
	runner := audit.NewRunner(exec)
	result := runner.Execute(ctx, *job, d.cfg.ServerID)

	postCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := d.api.PostAuditResult(postCtx, result); err != nil {
		d.logger.Warn("pending_audit_job: post result failed, caching", "run_id", job.RunID, "err", err)
		b, _ := json.Marshal(result)
		_ = d.store.Put(context.Background(), bucketAudit, auditResultKey(job.RunID), b)
		return
	}

	d.logger.Info("pending_audit_job finished", "run_id", job.RunID, "checks", len(result.Results))
}
