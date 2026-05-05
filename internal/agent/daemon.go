package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/api"
	cfgpkg "github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/discovery"
	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/operations"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
	"github.com/askio-cloud/askio-monitor/internal/store"
	"github.com/askio-cloud/askio-monitor/internal/version"
)

const (
	bucketQueue = "queue"
	bucketMeta  = "meta"
	keyLastHB   = "last_heartbeat"
)

type Daemon struct {
	logger *slog.Logger
	cfg    cfgpkg.Config
	api    *api.Client
	store  store.Store

	remEng *remediation.Engine

	mu                   sync.RWMutex
	remoteConf           model.RemoteConfig
	detectedCapabilities map[string]bool
}

func NewDaemon(logger *slog.Logger, cfg cfgpkg.Config) (*Daemon, error) {
	apiClient, err := api.New(api.Options{
		BaseURL:       cfg.APIURL,
		Token:         cfg.AgentToken,
		TLSSkipVerify: cfg.TLSSkipVerify,
		CACertPath:    cfg.CACertPath,
	})
	if err != nil {
		return nil, err
	}

	st, err := store.OpenFileStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	exec, err := remediation.NewExecutor(cfg.PrivilegeMode)
	if err != nil {
		return nil, err
	}

	d := &Daemon{
		logger:               logger,
		cfg:                  cfg,
		api:                  apiClient,
		store:                st,
		remEng:               remediation.NewEngine(logger, exec),
		detectedCapabilities: detectCapabilities(),
	}

	// Load cached remote config.
	mgr := cfgpkg.NewRemoteConfigManager(apiClient, st)
	if cached, ok, err := mgr.LoadCached(context.Background()); err == nil && ok {
		d.remoteConf = cached
	} else if err != nil {
		logger.Warn("failed to load cached remote config", "err", err)
	}

	return d, nil
}

func (d *Daemon) Close() error {
	if d.store != nil {
		return d.store.Close()
	}
	return nil
}

func (d *Daemon) Run(ctx context.Context) error {
	d.logger.Info("askio-monitor starting", "server_id", d.cfg.ServerID, "mode", d.cfg.PrivilegeMode, "data_dir", d.cfg.DataDir)
	defer d.Close()

	wg := &sync.WaitGroup{}
	wg.Add(4)
	go func() {
		defer wg.Done()
		d.heartbeatLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		d.configPollLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		d.discoveryLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		d.capabilitiesLoop(ctx)
	}()

	err := d.schedulerLoop(ctx)
	wg.Wait()
	return err
}

func (d *Daemon) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(d.cfg.HeartbeatInterval())
	defer ticker.Stop()

	for {
		_ = d.postHeartbeat(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) postHeartbeat(ctx context.Context) error {
	cpuPercent, _ := getSystemCPUPercent(800 * time.Millisecond)
	memPercent, _ := getSystemMemoryPercent()
	memBreakdown, _ := getSystemMemoryBreakdown()
	disks, hasMultiDisks, rootDiskPct, _ := getDiskUsage()
	nics, _ := getNetworkInterfaces()
	netCounters, _ := getNetworkCounters()
	deviceBases := map[string]bool{}
	for _, dsk := range disks {
		deviceBases[blockDeviceBase(dsk.Device)] = true
	}
	sampled, _ := sampleHostResources(800*time.Millisecond, deviceBases)

	caps := d.snapshotDetectedCapabilities()

	payload := map[string]any{
		"server_id":              d.cfg.ServerID,
		"agent_version":          version.Version,
		"go_version":             runtime.Version(),
		"hostname":               hostnameSafe(),
		"pid":                    os.Getpid(),
		"timestamp":              time.Now().UTC(),
		"privilege_mode":         string(d.cfg.PrivilegeMode),
		"cpu_percent":            cpuPercent,
		"memory_percent":         memPercent,
		"memory":                 memBreakdown,
		"has_multiple_disks":     hasMultiDisks,
		"disk_used_percent_root": rootDiskPct,
		"disks":                  disks,
		"network_interfaces":     nics,
		"network_counters":       netCounters,
		"disk_latency": func() any {
			if sampled != nil {
				return sampled.Disk
			}
			return nil
		}(),
		"disk_latency_avg": func() any {
			if sampled != nil {
				return sampled.DiskAvg
			}
			return nil
		}(),
		"top_processes_cpu": func() any {
			if sampled != nil {
				return sampled.TopCPU
			}
			return nil
		}(),
		"top_processes_mem": func() any {
			if sampled != nil {
				return sampled.TopMem
			}
			return nil
		}(),
		"os_info":               detectOS(),
		"detected_capabilities": caps,
		"capabilities": map[string]any{
			"audit":          true,
			"audit_config":   map[string]any{"mode": "read_only", "frameworks": []string{"nis2"}, "bundle_version": "2026.05"},
			"monitoring":     true,
			"operations":     true,
			"handlers":       operations.DefaultRegistry(d.remEngExec(), d.cfg.Operations).IDs(),
			"playbooks":      d.remEng.IDs(),
			"privilege_mode": string(d.cfg.PrivilegeMode),
			"operations_config": map[string]any{
				"command_run":       true,
				"command_run_shell": d.cfg.Operations != nil && d.cfg.Operations.AllowShell,
				"command_run_allowlist": func() any {
					if d.cfg.Operations == nil {
						return []string{}
					}
					return d.cfg.Operations.Allowlist
				}(),
			},
		},
	}

	ctx2, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := d.api.PostHeartbeat(ctx2, payload); err != nil {
		d.logger.Warn("heartbeat failed", "err", err)
		return err
	}

	b, _ := json.Marshal(payload)
	_ = d.store.Put(context.Background(), bucketMeta, keyLastHB, b)
	return nil
}

func hostnameSafe() string {
	h, _ := os.Hostname()
	return h
}

func (d *Daemon) configPollLoop(ctx context.Context) {
	mgr := cfgpkg.NewRemoteConfigManager(d.api, d.store)
	interval := d.cfg.ConfigPollInterval()

	// Add jitter so multiple agents don't all poll at once.
	if j := time.Duration(rand.Intn(5000)) * time.Millisecond; j > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(j):
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastCommandKey string

	for {
		rc, err := mgr.PollOnce(ctx, d.cfg.ServerID)
		if err != nil {
			d.logger.Warn("config poll failed", "err", err)
		} else {
			d.mu.Lock()
			d.remoteConf = rc
			d.mu.Unlock()

			d.logger.Info("config updated", "monitors", len(rc.Monitors), "fetched_at", rc.FetchedAt, "pending_command", rc.PendingCommand.Legacy)

			// Operations Platform: pending_action has priority.
			if rc.PendingAction != nil {
				if err := d.validatePendingAction(rc.PendingAction); err != nil {
					d.logger.Warn("invalid pending_action", "err", err)
				} else {
					go d.handlePendingAction(ctx, rc.PendingAction)
				}
				// Do not process pending_command in same poll cycle.
				goto wait
			}

			if rc.PendingAuditJob != nil {
				if err := validatePendingAuditJob(rc.PendingAuditJob); err != nil {
					d.logger.Warn("invalid pending_audit_job", "err", err)
				} else {
					go d.handlePendingAuditJob(ctx, rc.PendingAuditJob)
				}
				goto wait
			}

			// UI-driven command support.
			if rc.PendingCommand.V2 != nil {
				d.logger.Info("received pending_command_v2",
					"type", rc.PendingCommand.V2.Type,
					"command_id", rc.PendingCommand.V2.CommandID,
					"server_id", rc.PendingCommand.V2.ServerID,
					"capability", rc.PendingCommand.V2.Capability,
					"timeout_seconds", rc.PendingCommand.V2.TimeoutSeconds,
					"execution_mode", rc.PendingCommand.V2.ExecutionMode,
				)
				go d.handlePendingCommandV2(ctx, rc.PendingCommand.V2)
				goto wait
			}
			cmd, hasCmd, parseErr := ParsePendingCommand(rc.PendingCommand.Legacy)
			if parseErr != nil {
				d.logger.Warn("invalid pending_command", "pending_command", rc.PendingCommand.Legacy, "err", parseErr)
			} else if hasCmd {
				cmdKey := rc.PendingCommand.Legacy + ":" + rc.CommandID
				if rc.CommandID == "" {
					// fallback de-dupe: if no command id is provided, use fetched_at.
					cmdKey = rc.PendingCommand.Legacy + ":" + rc.FetchedAt.UTC().Format(time.RFC3339Nano)
				}
				if cmdKey != lastCommandKey {
					lastCommandKey = cmdKey
					d.logger.Info("received pending_command", "command", cmd.Raw, "command_id", rc.CommandID)
					go d.handleCommand(ctx, cmd)
				}
			}
		}

	wait:

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func validatePendingAuditJob(job *model.PendingAuditJob) error {
	if job == nil {
		return nil
	}
	if job.RunID == "" {
		return fmt.Errorf("pending_audit_job.run_id is required")
	}
	if job.BundleVersion == "" {
		return fmt.Errorf("pending_audit_job.bundle_version is required")
	}
	if len(job.Checks) == 0 {
		return fmt.Errorf("pending_audit_job.checks is required")
	}
	for _, check := range job.Checks {
		if check.CheckKey == "" {
			return fmt.Errorf("pending_audit_job check_key is required")
		}
		if !check.ReadOnly {
			return fmt.Errorf("pending_audit_job check %s is not read-only", check.CheckKey)
		}
	}
	return nil
}

func (d *Daemon) discoveryLoop(ctx context.Context) {
	interval := d.cfg.DiscoveryPollInterval()

	// run once soon after start
	_ = d.postDiscovery(ctx)

	// jitter
	if j := time.Duration(rand.Intn(5000)) * time.Millisecond; j > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(j):
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		_ = d.postDiscovery(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) postDiscovery(ctx context.Context) error {
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	det := discovery.NewDetector(d.logger)
	svcs, err := det.Detect(ctx2)
	if err != nil {
		d.logger.Warn("discovery failed", "err", err)
		return err
	}
	payload := map[string]any{
		"server_id":     d.cfg.ServerID,
		"discovered_at": time.Now().UTC(),
		"services":      svcs,
	}
	if err := d.api.PostDiscoveredServices(ctx2, payload); err != nil {
		d.logger.Warn("post discovered services failed", "err", err)
		return err
	}
	return nil
}

func (d *Daemon) schedulerLoop(ctx context.Context) error {
	active := map[string]context.CancelFunc{}

	rebuild := func(monitors []model.MonitorConfig) {
		want := map[string]model.MonitorConfig{}
		for _, m := range monitors {
			if !m.Enabled {
				continue
			}
			if m.ID == "" {
				// Defensive: ignore invalid monitors.
				continue
			}
			want[m.ID] = m
		}

		// Stop removed.
		for id, cancel := range active {
			if _, ok := want[id]; !ok {
				cancel()
				delete(active, id)
			}
		}

		// Start new.
		for id, m := range want {
			if _, ok := active[id]; ok {
				continue
			}
			mctx, cancel := context.WithCancel(ctx)
			active[id] = cancel
			go d.monitorLoop(mctx, m)
		}
	}

	rebuild(d.snapshotMonitors())

	poll := time.NewTicker(10 * time.Second)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			for _, cancel := range active {
				cancel()
			}
			return nil
		case <-poll.C:
			rebuild(d.snapshotMonitors())
		}
	}
}

func (d *Daemon) snapshotMonitors() []model.MonitorConfig {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]model.MonitorConfig, 0, len(d.remoteConf.Monitors))
	out = append(out, d.remoteConf.Monitors...)
	return out
}

func (d *Daemon) monitorLoop(ctx context.Context, m model.MonitorConfig) {
	interval := m.Interval()

	if j := time.Duration(rand.Intn(3000)) * time.Millisecond; j > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(j):
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		d.runMonitorOnce(ctx, m)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) runMonitorOnce(ctx context.Context, m model.MonitorConfig) {
	ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	res, err := RunSingleCheck(ctx2, d.logger, m)
	if err != nil {
		d.logger.Warn("monitor check failed", "monitor", m.ID, "err", err)
		return
	}

	payload := map[string]any{
		"server_id": d.cfg.ServerID,
		"results":   []model.CheckResult{res},
	}
	if err := d.api.PostResults(ctx2, payload); err != nil {
		d.logger.Warn("post results failed", "monitor", m.ID, "err", err)
		_ = d.enqueuePayload(context.Background(), payload)
	}

	if res.Status == model.StatusCritical {
		d.maybeRemediate(ctx2, m)
	}
}

func (d *Daemon) enqueuePayload(ctx context.Context, payload map[string]any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	k := fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Intn(1000))
	return d.store.Put(ctx, bucketQueue, k, b)
}

func (d *Daemon) maybeRemediate(ctx context.Context, m model.MonitorConfig) {
	if !m.RemediationEnabled {
		return
	}

	pbID := ""
	switch m.ServiceType {
	case model.ServiceTypeSystemd:
		switch m.RemediationPolicy {
		case model.RemediationPolicyReloadFirst:
			if m.ServiceName == "nginx" {
				pbID = "nginx_test_reload"
			} else {
				pbID = "systemd_reload"
			}
		case model.RemediationPolicyFull:
			pbID = "systemd_reset_failed"
		default:
			pbID = "systemd_restart"
		}
	case model.ServiceTypeDocker:
		pbID = "docker_restart"
	default:
		return
	}

	run, err := d.remEng.Run(ctx, m, pbID, "auto")
	if err != nil {
		if errors.Is(err, remediation.ErrPlaybookNotAllowed) {
			d.logger.Warn("remediation playbook not allowed", "monitor", m.ID, "playbook", pbID)
			return
		}
		d.logger.Warn("remediation run failed", "monitor", m.ID, "playbook", pbID, "err", err)
		return
	}
	run.ServerID = d.cfg.ServerID
	if err := d.api.PostRemediationLog(ctx, run); err != nil {
		d.logger.Warn("post remediation log failed", "monitor", m.ID, "err", err)
	}
}
