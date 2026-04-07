package agent

import (
	"context"
	"time"
)

func (d *Daemon) capabilitiesLoop(ctx context.Context) {
	// Re-check every 5 minutes.
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		d.refreshDetectedCapabilities()
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
