package agent

import (
	"context"
	"errors"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

func (d *Daemon) handleCommand(ctx context.Context, cmd Command) {
	switch cmd.Kind {
	case "discover_services":
		_ = d.postDiscovery(ctx)
	case "run_playbook":
		d.runPlaybookCommand(ctx, cmd)
	default:
		d.logger.Warn("unhandled command", "command", cmd.Raw)
	}
}

func (d *Daemon) runPlaybookCommand(ctx context.Context, cmd Command) {
	// Find the monitor in the current remote config snapshot.
	monitors := d.snapshotMonitors()
	var m model.MonitorConfig
	found := false
	for _, mm := range monitors {
		if mm.ID == cmd.MonitorID {
			m = mm
			found = true
			break
		}
	}
	if !found {
		d.logger.Warn("run_playbook: monitor not found", "monitor_id", cmd.MonitorID, "playbook", cmd.PlaybookID, "incident_id", cmd.IncidentID)
		return
	}

	ctx2, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	d.logger.Info("run_playbook starting", "monitor_id", m.ID, "service", m.ServiceName, "playbook", cmd.PlaybookID, "incident_id", cmd.IncidentID)

	run, err := d.remEng.Run(ctx2, m, cmd.PlaybookID, "manual")
	if err != nil {
		if errors.Is(err, remediation.ErrPlaybookNotAllowed) {
			d.logger.Warn("run_playbook not allowed", "monitor_id", m.ID, "playbook", cmd.PlaybookID)
			return
		}
		d.logger.Warn("run_playbook failed", "monitor_id", m.ID, "playbook", cmd.PlaybookID, "err", err, "supported_playbooks", d.remEng.IDs())
		return
	}

	run.ServerID = d.cfg.ServerID
	run.IncidentID = cmd.IncidentID

	if err := d.api.PostRemediationLog(ctx2, run); err != nil {
		d.logger.Warn("post remediation log failed", "monitor_id", m.ID, "playbook", cmd.PlaybookID, "err", err)
		return
	}

	d.logger.Info("run_playbook finished", "monitor_id", m.ID, "playbook", cmd.PlaybookID, "success", run.Success)
}
