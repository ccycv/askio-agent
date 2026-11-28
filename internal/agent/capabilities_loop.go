package agent

import (
	"context"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/selfupdate"
)

func (d *Daemon) capabilitiesLoop(ctx context.Context) {
	// Re-check every 5 minutes.
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		d.refreshDetectedCapabilities()
		d.refreshSelfUpdate(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) refreshDetectedCapabilities() {
	caps := detectCapabilities()
	d.mu.Lock()
	d.detectedCapabilities = caps
	d.mu.Unlock()
}

func (d *Daemon) snapshotDetectedCapabilities() map[string]bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.detectedCapabilities == nil {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(d.detectedCapabilities))
	for k, v := range d.detectedCapabilities {
		out[k] = v
	}
	return out
}

// refreshSelfUpdate re-checks how this agent could replace its own binary.
// It only reads the host (and asks sudo -n -l), so it runs with the other
// capability checks instead of on every heartbeat.
func (d *Daemon) refreshSelfUpdate(ctx context.Context) {
	if d.migrationRunner != nil {
		return
	}
	probe := selfupdate.DefaultProbe(d.cfg.DataDir, true)
	if d.selfUpdateProbe != nil {
		probe = *d.selfUpdateProbe
	}
	report := selfupdate.Detect(ctx, probe)
	d.mu.Lock()
	d.selfUpdate = &report
	d.mu.Unlock()
}

func (d *Daemon) snapshotSelfUpdate() *selfupdate.Report {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.selfUpdate == nil {
		return nil
	}
	report := *d.selfUpdate
	return &report
}
