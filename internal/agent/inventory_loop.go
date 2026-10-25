package agent

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/vulnerability"
)

// Explicit local opt-in is required; neither remote config nor an arbitrary
// task/action can enable this collector. Backend enrollment remains a separate gate.
func (d *Daemon) inventoryLoop(ctx context.Context) {
	offset := sha256.Sum256([]byte(d.cfg.ServerID))
	timer := time.NewTimer(time.Duration(offset[0]%30+1) * time.Second)
	defer timer.Stop()
	poller := &vulnerability.Poller{Client: d.api, Collector: vulnerability.NewCollector(), ServerID: d.cfg.ServerID, AgentID: d.cfg.AgentID}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next, e := poller.RunOnce(ctx)
		if e != nil && ctx.Err() == nil {
			d.logger.Warn("passive inventory cycle incomplete", "category", "inventory_unavailable")
		}
		delay := time.Until(next)
		if delay < 15*time.Second {
			delay = 15 * time.Second
		}
		if delay > 6*time.Hour {
			delay = 6 * time.Hour
		}
		timer.Reset(delay)
	}
}
