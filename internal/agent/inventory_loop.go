package agent

import (
	"context"
	"crypto/sha256"
	"time"

	cfgpkg "github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/vulnerability"
)

// Effective passive-inventory states, as reported by `askio-monitor status`.
const (
	inventoryLocalOn          = "local-on"
	inventoryLocalOff         = "local-off"
	inventoryRemoteOn         = "remote-on"
	inventoryRemoteOff        = "remote-off"
	inventoryRemoteRefusedPfx = "remote-refused:"
)

// inventoryDecision is the host half of the passive-inventory gate. The
// backend half (feature enabled and this agent enrolled) is separate and is
// enforced by every claim response, whatever this decision says.
type inventoryDecision struct {
	On      bool
	Status  string
	Refusal string // set only for remote-refused
}

// effectiveInventory combines the operator-managed local setting with the
// backend's remote switch:
//
//   - local `inventory.enabled: false` -> OFF, always; remote is ignored (hard deny);
//   - local `inventory.enabled: true`  -> ON (validated at load by config.Normalized);
//   - local key absent                 -> follow remote `inventory.enabled`;
//     missing field or false is OFF, and true is honoured only when
//     config.InventoryRemoteRefusal finds the composition safe (direct host
//     mode, no gateway stanza, fixed HTTPS API URL, verified TLS).
//
// remote is the inventory object from monitor-agent-config, or nil when the
// backend did not send one.
func effectiveInventory(cfg cfgpkg.Config, remote *model.RemoteInventory) inventoryDecision {
	switch cfg.InventoryLocal() {
	case cfgpkg.InventoryLocalOff:
		return inventoryDecision{Status: inventoryLocalOff}
	case cfgpkg.InventoryLocalOn:
		return inventoryDecision{On: true, Status: inventoryLocalOn}
	}
	if remote == nil || !remote.Enabled {
		return inventoryDecision{Status: inventoryRemoteOff}
	}
	if reason := cfg.InventoryRemoteRefusal(); reason != "" {
		return inventoryDecision{Status: inventoryRemoteRefusedPfx + reason, Refusal: reason}
	}
	return inventoryDecision{On: true, Status: inventoryRemoteOn}
}

// inventoryOptedIn reports whether the host gate is open for the given local
// config and remote switch.
func inventoryOptedIn(cfg cfgpkg.Config, remote *model.RemoteInventory) bool {
	return effectiveInventory(cfg, remote).On
}

// currentInventoryDecision evaluates the gate against the remote switch most
// recently fetched by this process. A remote switch cached on disk by an
// earlier process is deliberately not honoured: remote ON takes effect only
// after a live config poll.
func (d *Daemon) currentInventoryDecision() inventoryDecision {
	d.mu.RLock()
	remote := d.liveRemoteInventory
	d.mu.RUnlock()
	return effectiveInventory(d.cfg, remote)
}

// newInventoryPoller returns nil unless the host gate is open right now, so no
// inventory route can be reached without it even if a caller forgets to check.
func (d *Daemon) newInventoryPoller(collector *vulnerability.Collector) *vulnerability.Poller {
	if !d.currentInventoryDecision().On {
		return nil
	}
	return &vulnerability.Poller{Client: d.api, Collector: collector, ServerID: d.cfg.ServerID, AgentID: d.cfg.AgentID}
}

// wakeInventory asks the supervisor to re-evaluate the gate. It never blocks.
func (d *Daemon) wakeInventory() {
	select {
	case d.inventoryWake <- struct{}{}:
	default:
	}
}

func (d *Daemon) recordInventoryState(status string, running bool) {
	d.invMu.Lock()
	d.invStatus, d.invRunning = status, running
	d.invMu.Unlock()
}

func (d *Daemon) setInventoryPoller(p *vulnerability.Poller) {
	d.invMu.Lock()
	d.invPoller = p
	d.invMu.Unlock()
}

// inventoryStatusReport is the heartbeat's inventory_status: the gate status,
// whether the loop runs, and what its last cycle did (stage, reason code,
// counts and durations), so a host that never completes an inventory can be
// diagnosed from the backend. Nil until the gate has been evaluated.
func (d *Daemon) inventoryStatusReport() map[string]any {
	d.invMu.Lock()
	status, running, poller := d.invStatus, d.invRunning, d.invPoller
	d.invMu.Unlock()
	if status == "" {
		return nil
	}
	report := map[string]any{"gate": status, "running": running}
	if poller != nil {
		if last, ok := poller.LastCycle(); ok {
			report["last_cycle"] = last
		}
		if progress, ok := poller.Progress(); ok {
			report["in_progress"] = progress
		}
	}
	return report
}

// inventoryState reports the last evaluated gate status and whether the
// inventory loop is running.
func (d *Daemon) inventoryState() (string, bool) {
	d.invMu.Lock()
	defer d.invMu.Unlock()
	return d.invStatus, d.invRunning
}

// inventorySupervisor owns the inventory loop's lifecycle. It re-evaluates the
// gate at start and after every remote config poll: it starts the loop when
// the gate opens and, when it closes, cancels the loop's context and waits for
// it to exit, so no further claim, page or completion is sent. An in-flight
// upload is dropped, as on a restart. At most one loop runs at a time.
func (d *Daemon) inventorySupervisor(ctx context.Context) {
	var cancel context.CancelFunc
	var done chan struct{}
	halt := func() {
		if cancel == nil {
			return
		}
		cancel()
		<-done
		cancel, done = nil, nil
		d.setInventoryPoller(nil)
	}
	last := ""
	defer func() {
		halt()
		d.recordInventoryState(last, false)
	}()
	for {
		decision := d.currentInventoryDecision()
		if decision.Refusal != "" && decision.Status != last {
			// Logged once per transition into a refusal; reason codes carry no config values.
			d.logger.Warn("passive inventory remote enable refused", "category", "inventory_remote_refused", "reason", decision.Refusal)
		}
		last = decision.Status
		switch {
		case decision.On && cancel == nil:
			if poller := d.newInventoryPoller(d.inventoryCollector); poller != nil {
				d.setInventoryPoller(poller)
				loopCtx, stop := context.WithCancel(ctx)
				finished := make(chan struct{})
				cancel, done = stop, finished
				d.logger.Info("passive inventory started", "category", "inventory_state", "state", decision.Status)
				go func() {
					defer close(finished)
					d.inventoryLoop(loopCtx, poller)
				}()
			}
		case !decision.On && cancel != nil:
			halt()
			d.logger.Info("passive inventory stopped", "category", "inventory_state", "state", decision.Status)
		}
		d.recordInventoryState(decision.Status, cancel != nil)
		select {
		case <-ctx.Done():
			return
		case <-d.inventoryWake:
		}
	}
}

// inventoryTiming bounds the loop's schedule. Tests shorten it.
type inventoryTiming struct {
	first    func(serverID string) time.Duration
	min, max time.Duration
}

var defaultInventoryTiming = inventoryTiming{first: stableInventoryOffset, min: 15 * time.Second, max: 6 * time.Hour}

// stableInventoryOffset staggers the first claim by 1-30 s derived from server_id.
func stableInventoryOffset(serverID string) time.Duration {
	offset := sha256.Sum256([]byte(serverID))
	return time.Duration(offset[0]%30+1) * time.Second
}

// inventoryLoop runs one poller until ctx is cancelled. Only the supervisor
// starts it, and only with a poller that newInventoryPoller issued.
func (d *Daemon) inventoryLoop(ctx context.Context, poller *vulnerability.Poller) {
	if poller == nil {
		return
	}
	timing := d.invTiming
	timer := time.NewTimer(timing.first(d.cfg.ServerID))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return
		}
		next, e := poller.RunOnce(ctx)
		if e != nil && ctx.Err() == nil {
			d.logger.Warn("passive inventory cycle incomplete", "category", "inventory_unavailable")
		}
		delay := time.Until(next)
		if delay < timing.min {
			delay = timing.min
		}
		if delay > timing.max {
			delay = timing.max
		}
		timer.Reset(delay)
	}
}
