package agent

import (
	"context"
	"crypto/sha256"
	"time"

	cfgpkg "github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/vulnerability"
)

// inventoryOptedIn is the host gate for passive inventory: the operator-managed
// local config must say `inventory: {enabled: true}`. Nothing else sets it:
// the installer never writes it, and neither remote monitor config nor a
// pending action/command maps onto Config. The backend gate (feature enabled
// and this agent enrolled) is separate and is enforced by the claim response.
func inventoryOptedIn(cfg cfgpkg.Config) bool {
	return cfg.Inventory != nil && cfg.Inventory.Enabled
}

// newInventoryPoller returns nil unless the host has opted in, so no inventory
// route can be reached without the local opt-in even if a caller forgets to
// check it first.
func (d *Daemon) newInventoryPoller(collector *vulnerability.Collector) *vulnerability.Poller {
	if !inventoryOptedIn(d.cfg) {
		return nil
	}
	return &vulnerability.Poller{Client: d.api, Collector: collector, ServerID: d.cfg.ServerID, AgentID: d.cfg.AgentID}
}

// Explicit local opt-in is required; neither remote config nor an arbitrary
// task/action can enable this collector. Backend enrollment remains a separate gate.
func (d *Daemon) inventoryLoop(ctx context.Context) {
	poller := d.newInventoryPoller(vulnerability.NewCollector())
	if poller == nil {
		return
	}
	offset := sha256.Sum256([]byte(d.cfg.ServerID))
	timer := time.NewTimer(time.Duration(offset[0]%30+1) * time.Second)
	defer timer.Stop()
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
