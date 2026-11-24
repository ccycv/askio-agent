package agent

// Enrollment qualification for passive inventory.
//
// Collection and upload must never happen unless BOTH gates are open:
//  1. host gate (effectiveInventory): local inventory.enabled: true, or the key
//     absent and the backend's remote switch (monitor-agent-config
//     "inventory": {"enabled": true}) on a safe composition. A local
//     inventory.enabled: false is a hard deny the remote switch cannot override;
//  2. backend: VULNERABILITY_INVENTORY_ENABLED is on AND this agent is enrolled,
//     which the agent observes only as an "assigned" claim bound to it.
//
// These tests drive the real daemon construction (NewDaemon from a YAML config
// loaded with config.Load), the real HTTPS API client, the real remote config
// manager and the real poller against an emulated backend that answers the way
// Askio's monitor-agent-config and monitor-agent-inventory routes do. The host
// collector is a counting fake, so "collection ran" is observable without
// reading this machine's packages.

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/vulnerability"
)

const (
	gateServerID = "22222222-2222-4222-8222-222222222222"
	gateAgentID  = "33333333-3333-4333-8333-333333333333"
	gateOtherID  = "77777777-7777-4777-8777-777777777777"
)

// gateHost counts every observation the collector makes of the host.
type gateHost struct{ calls atomic.Int32 }

func (h *gateHost) Platform(context.Context) (vulnerability.OS, *string, error) {
	h.calls.Add(1)
	boot := "88888888-8888-4888-8888-888888888888"
	return vulnerability.OS{ID: "ubuntu", VersionID: "24.04", Architecture: "amd64"}, &boot, nil
}
func (h *gateHost) State(context.Context) (string, error) {
	h.calls.Add(1)
	return "stable", nil
}
func (h *gateHost) Packages(context.Context) (vulnerability.QueryResult, error) {
	h.calls.Add(1)
	exit := 0
	return vulnerability.QueryResult{Output: []byte{}, ExitCode: &exit}, nil
}

// gateBackend emulates Askio's inventory routes for one backend state, and
// monitor-agent-config with a switchable remote inventory field.
type gateBackend struct {
	server     *httptest.Server
	mu         sync.Mutex
	hits       map[string]int // inventory routes only
	claims     [][]byte
	remote     string // "absent", "false" or "true"
	configHits int
}

func (b *gateBackend) setRemote(remote string) {
	b.mu.Lock()
	b.remote = remote
	b.mu.Unlock()
}

func (b *gateBackend) configCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.configHits
}

func (b *gateBackend) count(route string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hits[route]
}

func (b *gateBackend) total() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.hits {
		n += c
	}
	return n
}

func gateRequest(mutate func(*vulnerability.Request)) *vulnerability.Request {
	issued := time.Now().UTC().Add(-time.Minute)
	r := vulnerability.Request{
		SchemaVersion: vulnerability.SchemaVersion, Capability: vulnerability.Capability,
		RequestID: "11111111-1111-4111-8111-111111111111", EnrollmentID: "44444444-4444-4444-8444-444444444444",
		GenerationID: "55555555-5555-4555-8555-555555555555", SnapshotID: "66666666-6666-4666-8666-666666666666",
		ServerID: gateServerID, AgentID: gateAgentID,
		IssuedAt: issued.Format(time.RFC3339Nano), ExpiresAt: issued.Add(30 * time.Minute).Format(time.RFC3339Nano),
		Limits: vulnerability.DefaultLimits(),
	}
	if mutate != nil {
		mutate(&r)
	}
	return &r
}

// backendStates are what an opted-in agent can be told by the backend.
// Only "enabled-enrolled-assigned" opens the backend gate.
var backendStates = []struct {
	name   string
	status int
	body   func() any
}{
	{"feature-disabled", 404, func() any { return map[string]string{"error": "INVENTORY_DISABLED"} }},
	{"enabled-not-enrolled", 403, func() any { return map[string]string{"error": "INVENTORY_NOT_ENROLLED"} }},
	{"enabled-enrollment-changed", 409, func() any { return map[string]string{"error": "INVENTORY_ENROLLMENT_CHANGED"} }},
	{"enabled-enrolled-waiting", 200, func() any {
		return vulnerability.Assignment{Status: "waiting", NextPollAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	}},
	{"enabled-unsupported", 200, func() any {
		return vulnerability.Assignment{Status: "unsupported", NextPollAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	}},
	{"enabled-assigned-to-other-agent", 200, func() any {
		return vulnerability.Assignment{Status: "assigned", Request: gateRequest(func(r *vulnerability.Request) { r.AgentID = gateOtherID }), NextPollAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	}},
	{"enabled-assigned-expired", 200, func() any {
		return vulnerability.Assignment{Status: "assigned", Request: gateRequest(func(r *vulnerability.Request) {
			issued := time.Now().UTC().Add(-40 * time.Minute)
			r.IssuedAt, r.ExpiresAt = issued.Format(time.RFC3339Nano), issued.Add(30*time.Minute).Format(time.RFC3339Nano)
		}), NextPollAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	}},
	{"enabled-enrolled-assigned", 200, func() any {
		return vulnerability.Assignment{Status: "assigned", Request: gateRequest(nil), NextPollAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}
	}},
}

// remoteStates are what monitor-agent-config can say about inventory.
var remoteStates = []string{"absent", "false", "true"}

func newGateBackend(t *testing.T, status int, body func() any) *gateBackend {
	return newGateBackendTLS(t, status, body, true)
}

func newGateBackendTLS(t *testing.T, status int, body func() any, useTLS bool) *gateBackend {
	t.Helper()
	b := &gateBackend{hits: map[string]int{}, remote: "absent"}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := strings.TrimPrefix(r.URL.Path, "/functions/v1/")
		if route == "monitor-agent-config" {
			b.mu.Lock()
			b.configHits++
			remote := b.remote
			b.mu.Unlock()
			resp := map[string]any{"fetched_at": time.Now().UTC().Format(time.RFC3339Nano), "monitors": []any{}}
			switch remote {
			case "false":
				resp["inventory"] = map[string]bool{"enabled": false}
			case "true":
				resp["inventory"] = map[string]bool{"enabled": true}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if !strings.HasPrefix(route, "monitor-agent-inventory-") {
			http.NotFound(w, r)
			return
		}
		data, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.hits[route]++
		if route == "monitor-agent-inventory-claim" {
			b.claims = append(b.claims, data)
		}
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if route != "monitor-agent-inventory-claim" {
			// Page and completion are accepted only to observe that they were sent.
			fmt.Fprint(w, `{}`)
			return
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body())
	})
	if useTLS {
		b.server = httptest.NewTLSServer(handler)
	} else {
		b.server = httptest.NewServer(handler)
	}
	t.Cleanup(b.server.Close)
	return b
}

// syncBuffer collects daemon logs across goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type gateDaemonOptions struct {
	stanza     string // inventory stanza
	extra      string // further YAML, e.g. a gateway stanza
	skipVerify bool   // tls_skip_verify instead of pinning the test CA
	logs       *syncBuffer
}

// newGateDaemon writes an operator config file with the given inventory
// stanza, loads it the way `askio-monitor start` does and builds the daemon.
func newGateDaemon(t *testing.T, backend *gateBackend, inventoryStanza string) *Daemon {
	return newGateDaemonWith(t, backend, gateDaemonOptions{stanza: inventoryStanza})
}

func newGateDaemonWith(t *testing.T, backend *gateBackend, opts gateDaemonOptions) *Daemon {
	t.Helper()
	dir := t.TempDir()
	lines := []string{
		"api_url: " + backend.server.URL + "/functions/v1",
		"server_id: " + gateServerID,
		"agent_id: " + gateAgentID,
		"agent_token: synthetic-agent-token",
		"privilege_mode: sudo",
		"config_poll_interval_seconds: 1",
		"data_dir: " + filepath.Join(dir, "data"),
	}
	if opts.skipVerify {
		lines = append(lines, "tls_skip_verify: true")
	} else if backend.server.Certificate() != nil {
		caPath := filepath.Join(dir, "backend-ca.pem")
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.server.Certificate().Raw})
		if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, "ca_cert_path: "+caPath)
	}
	lines = append(lines, opts.stanza, opts.extra)
	cfgPath := filepath.Join(dir, "monitor.conf")
	if err := os.WriteFile(cfgPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	var out io.Writer = io.Discard
	if opts.logs != nil {
		out = opts.logs
	}
	d, err := NewDaemon(slog.New(slog.NewTextHandler(out, nil)), cfg)
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// fastInventory shortens the daemon's schedules so a test observes several
// cycles per second: no config poll jitter, first claim at once, then a claim
// every 20-50 ms.
func fastInventory(d *Daemon, fake *gateHost) {
	d.configPollJitter = 0
	d.invTiming = inventoryTiming{first: func(string) time.Duration { return 0 }, min: 20 * time.Millisecond, max: 50 * time.Millisecond}
	d.inventoryCollector = &vulnerability.Collector{Host: fake}
}

// runSwitch runs the real config poll loop and inventory supervisor until the
// returned stop function is called; stop fails the test if either leaks.
func runSwitch(t *testing.T, d *Daemon) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); d.configPollLoop(ctx) }()
	go func() { defer wg.Done(); d.inventorySupervisor(ctx) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		finished := make(chan struct{})
		go func() { wg.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatal("config poll loop or inventory supervisor did not exit")
		}
		if _, running := d.inventoryState(); running {
			t.Fatal("inventory loop still marked running after shutdown")
		}
	}
	t.Cleanup(stop)
	return stop
}

func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var hostStates = []struct {
	name   string
	stanza string
	local  config.InventoryLocalSetting
}{
	{"local-absent", "", config.InventoryLocalAbsent},
	{"local-false", "inventory:\n  enabled: false", config.InventoryLocalOff},
	{"local-true", "inventory:\n  enabled: true", config.InventoryLocalOn},
}

// expectedInventory is the contract table, written independently of
// effectiveInventory.
func expectedInventory(local config.InventoryLocalSetting, remote string) (bool, string) {
	switch local {
	case config.InventoryLocalOff:
		return false, "local-off"
	case config.InventoryLocalOn:
		return true, "local-on"
	}
	if remote == "true" {
		return true, "remote-on"
	}
	return false, "remote-off"
}

// TestInventoryRequiresHostOptInAndBackendEnrollment is the full matrix: three
// local states x three remote switch states x eight backend states.
// Collection and upload happen only where the host gate is open (local true,
// or local absent with remote true) AND the backend assigned this agent;
// without an open host gate no inventory route is contacted at all.
func TestInventoryRequiresHostOptInAndBackendEnrollment(t *testing.T) {
	for _, host := range hostStates {
		for _, remote := range remoteStates {
			for _, state := range backendStates {
				host, remote, state := host, remote, state
				t.Run(host.name+"/remote-"+remote+"/"+state.name, func(t *testing.T) {
					t.Parallel()
					backend := newGateBackend(t, state.status, state.body)
					backend.setRemote(remote)
					d := newGateDaemon(t, backend, host.stanza)
					fake := &gateHost{}
					wantOn, wantStatus := expectedInventory(host.local, remote)

					if got := d.cfg.InventoryLocal(); got != host.local {
						t.Fatalf("InventoryLocal = %v, want %v", got, host.local)
					}
					// Before any live poll the remote switch is unknown.
					if got := d.currentInventoryDecision(); got.On != (host.local == config.InventoryLocalOn) {
						t.Fatalf("before poll: %+v", got)
					}
					// Fetch remote config through the real client and manager.
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					rc, err := config.NewRemoteConfigManager(d.api, d.store).PollOnce(ctx, gateServerID)
					if err != nil {
						t.Fatalf("remote config poll: %v", err)
					}
					if (rc.Inventory != nil) != (remote != "absent") {
						t.Fatalf("remote inventory decoded as %+v for %s", rc.Inventory, remote)
					}
					d.setRemoteConfig(rc)

					if got := inventoryOptedIn(d.cfg, rc.Inventory); got != wantOn {
						t.Fatalf("inventoryOptedIn = %v, want %v", got, wantOn)
					}
					if got := d.currentInventoryDecision(); got.On != wantOn || got.Status != wantStatus {
						t.Fatalf("decision %+v, want on=%v status=%s", got, wantOn, wantStatus)
					}
					if got := statusInventory(ctx, d.cfg, d.store); got != wantStatus {
						t.Fatalf("status inventory = %q, want %q", got, wantStatus)
					}
					poller := d.newInventoryPoller(&vulnerability.Collector{Host: fake})
					if !wantOn {
						if poller != nil {
							t.Fatal("inventory poller created with the host gate closed")
						}
						// The daemon's own supervisor must not start a loop either.
						fastInventory(d, fake)
						sctx, scancel := context.WithCancel(context.Background())
						finished := make(chan struct{})
						go func() { defer close(finished); d.inventorySupervisor(sctx) }()
						d.wakeInventory()
						time.Sleep(200 * time.Millisecond)
						if status, running := d.inventoryState(); running || status != wantStatus {
							t.Fatalf("supervisor state %q running=%v with the host gate closed", status, running)
						}
						scancel()
						<-finished
						if n := backend.total(); n != 0 || fake.calls.Load() != 0 {
							t.Fatalf("with the host gate closed: %d inventory requests, %d host observations", n, fake.calls.Load())
						}
						return
					}
					if poller == nil {
						t.Fatal("no inventory poller despite an open host gate")
					}

					_, runErr := poller.RunOnce(ctx)

					claims, pages, completes := backend.count("monitor-agent-inventory-claim"), backend.count("monitor-agent-inventory-page"), backend.count("monitor-agent-inventory-complete")
					if claims != 1 {
						t.Fatalf("claims = %d, want 1", claims)
					}
					// The claim only advertises capabilities; it carries no host data.
					want, _ := json.Marshal(vulnerability.ClaimCapabilities())
					if string(backend.claims[0]) != string(want) {
						t.Fatalf("claim body %s, want %s", backend.claims[0], want)
					}
					if state.name == "enabled-enrolled-assigned" {
						if runErr != nil {
							t.Fatalf("positive control failed: %v", runErr)
						}
						if fake.calls.Load() == 0 || pages < 1 || completes != 1 {
							t.Fatalf("positive control: host observations %d, pages %d, completions %d", fake.calls.Load(), pages, completes)
						}
						return
					}
					if fake.calls.Load() != 0 || pages != 0 || completes != 0 {
						t.Fatalf("backend gate closed (%s) but host observations %d, pages %d, completions %d", state.name, fake.calls.Load(), pages, completes)
					}
				})
			}
		}
	}
}

// TestInventoryRemoteOnRefusedOrDenied runs the real config poll loop and
// supervisor against a backend whose remote switch says ON and whose claim
// would assign this agent. The host gate must stay closed in every case: a
// local hard deny, or a composition unsafe for remote ON. A refusal is logged
// once with its reason and without secrets.
func TestInventoryRemoteOnRefusedOrDenied(t *testing.T) {
	assigned := backendStates[len(backendStates)-1]
	cases := []struct {
		name   string
		useTLS bool
		opts   gateDaemonOptions
		status string
		reason string
	}{
		{"local-false-hard-deny", true, gateDaemonOptions{stanza: "inventory:\n  enabled: false"}, "local-off", ""},
		{"tls-skip-verify", true, gateDaemonOptions{skipVerify: true}, "remote-refused:tls_skip_verify", config.InventoryRefusedTLSSkipVerify},
		{"gateway-stanza", true, gateDaemonOptions{extra: "gateway:\n  listen_addr: \":8443\""}, "remote-refused:gateway_configured", config.InventoryRefusedGateway},
		{"plain-http-api-url", false, gateDaemonOptions{}, "remote-refused:api_url_not_fixed_https", config.InventoryRefusedAPIURL},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			backend := newGateBackendTLS(t, assigned.status, assigned.body, tc.useTLS)
			backend.setRemote("true")
			logs := &syncBuffer{}
			tc.opts.logs = logs
			d := newGateDaemonWith(t, backend, tc.opts)
			fake := &gateHost{}
			fastInventory(d, fake)
			stop := runSwitch(t, d)

			// At least three polls, each saying ON.
			waitFor(t, 10*time.Second, "three config polls", func() bool { return backend.configCount() >= 3 })
			waitFor(t, 2*time.Second, "refused state", func() bool { s, _ := d.inventoryState(); return s == tc.status })
			time.Sleep(100 * time.Millisecond)
			stop()

			if status, running := d.inventoryState(); running || status != tc.status {
				t.Fatalf("state %q running=%v, want %q stopped", status, running, tc.status)
			}
			if n := backend.total(); n != 0 || fake.calls.Load() != 0 {
				t.Fatalf("%d inventory requests and %d host observations despite %s", n, fake.calls.Load(), tc.status)
			}
			if got := statusInventory(context.Background(), d.cfg, d.store); got != tc.status {
				t.Fatalf("status inventory = %q, want %q", got, tc.status)
			}
			out := logs.String()
			refusals := regexp.MustCompile(`passive inventory remote enable refused[^\n]*`).FindAllString(out, -1)
			if tc.reason == "" {
				if len(refusals) != 0 {
					t.Fatalf("hard deny logged a refusal: %v", refusals)
				}
			} else if len(refusals) != 1 || !strings.Contains(refusals[0], "reason="+tc.reason) {
				t.Fatalf("refusal logged %d times (%v), want once with reason %s", len(refusals), refusals, tc.reason)
			}
			if strings.Contains(out, "synthetic-agent-token") || strings.Contains(out, "passive inventory started") {
				t.Fatalf("unexpected log content:\n%s", out)
			}
		})
	}
}

// TestInventoryRemoteSwitchTogglesWithinOnePoll drives the real config poll
// loop and supervisor while the backend flips its remote switch. OFF->ON must
// start claiming within one config poll; ON->OFF must cancel the loop within
// one poll, after which no claim, page or completion is sent; re-enabling
// starts a fresh loop.
func TestInventoryRemoteSwitchTogglesWithinOnePoll(t *testing.T) {
	assigned := backendStates[len(backendStates)-1]
	backend := newGateBackend(t, assigned.status, assigned.body)
	backend.setRemote("false")
	logs := &syncBuffer{}
	d := newGateDaemonWith(t, backend, gateDaemonOptions{logs: logs})
	fake := &gateHost{}
	fastInventory(d, fake)
	poll := d.cfg.ConfigPollInterval()
	onePoll := poll + 500*time.Millisecond // one poll interval plus scheduling slack
	stop := runSwitch(t, d)

	waitFor(t, 5*time.Second, "first config poll", func() bool { return backend.configCount() >= 1 })
	waitFor(t, time.Second, "remote-off state", func() bool { s, _ := d.inventoryState(); return s == "remote-off" })
	time.Sleep(300 * time.Millisecond)
	if n := backend.total(); n != 0 {
		t.Fatalf("remote OFF: %d inventory requests", n)
	}

	claims := func() int { return backend.count("monitor-agent-inventory-claim") }
	for round := 1; round <= 2; round++ {
		// OFF -> ON.
		backend.setRemote("true")
		waitFor(t, onePoll, fmt.Sprintf("round %d: first claim after remote ON", round), func() bool { return backend.total() > 0 && claims() >= 1 })
		if s, running := d.inventoryState(); s != "remote-on" || !running {
			t.Fatalf("round %d: state %q running=%v after remote ON", round, s, running)
		}
		base := claims()
		waitFor(t, 5*time.Second, "repeated cycles", func() bool { return claims() >= base+3 && backend.count("monitor-agent-inventory-complete") >= 1 })

		// ON -> OFF.
		backend.setRemote("false")
		waitFor(t, onePoll, fmt.Sprintf("round %d: loop stopped after remote OFF", round), func() bool { _, running := d.inventoryState(); return !running })
		if s, _ := d.inventoryState(); s != "remote-off" {
			t.Fatalf("round %d: state %q after remote OFF", round, s)
		}
		// Let a request that was already on the wire land, then prove silence
		// for many loop periods (the loop would otherwise claim every <=50 ms).
		time.Sleep(200 * time.Millisecond)
		frozen := backend.total()
		time.Sleep(10 * 50 * time.Millisecond)
		if after := backend.total(); after != frozen {
			t.Fatalf("round %d: %d inventory requests after remote OFF stopped the loop", round, after-frozen)
		}
		// Reset counters for the next round.
		backend.mu.Lock()
		backend.hits = map[string]int{}
		backend.claims = nil
		backend.mu.Unlock()
	}
	stop()
	out := logs.String()
	if n := strings.Count(out, "passive inventory started"); n != 2 {
		t.Fatalf("started logged %d times, want 2", n)
	}
	if n := strings.Count(out, "passive inventory stopped"); n != 2 {
		t.Fatalf("stopped logged %d times, want 2", n)
	}
	if strings.Contains(out, "synthetic-agent-token") {
		t.Fatal("log contains the agent token")
	}
}

// A local true is not stopped by the remote switch being OFF or absent.
func TestInventoryLocalTrueIgnoresRemoteOff(t *testing.T) {
	waiting := backendStates[3]
	backend := newGateBackend(t, waiting.status, waiting.body)
	backend.setRemote("false")
	d := newGateDaemon(t, backend, "inventory:\n  enabled: true")
	fake := &gateHost{}
	fastInventory(d, fake)
	runSwitch(t, d)
	waitFor(t, 5*time.Second, "claims with local opt-in", func() bool { return backend.count("monitor-agent-inventory-claim") >= 2 && backend.configCount() >= 2 })
	if s, running := d.inventoryState(); s != "local-on" || !running {
		t.Fatalf("state %q running=%v", s, running)
	}
}

// A remote ON cached on disk by an earlier process is not honoured until a live
// poll confirms it, so a restart after the backend turned the switch OFF
// cannot claim on stale state.
func TestInventoryCachedRemoteSwitchNeedsLivePoll(t *testing.T) {
	assigned := backendStates[len(backendStates)-1]
	backend := newGateBackend(t, assigned.status, assigned.body)
	backend.setRemote("true")
	first := newGateDaemon(t, backend, "")
	if _, err := config.NewRemoteConfigManager(first.api, first.store).PollOnce(context.Background(), gateServerID); err != nil {
		t.Fatal(err)
	}
	// Same data dir, new process.
	cfg := first.cfg
	_ = first.Close()
	d, err := NewDaemon(slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if d.remoteConf.Inventory == nil || !d.remoteConf.Inventory.Enabled {
		t.Fatal("cached remote config lost its inventory switch")
	}
	if got := d.currentInventoryDecision(); got.On || got.Status != "remote-off" {
		t.Fatalf("cached remote switch honoured before a live poll: %+v", got)
	}
	if d.newInventoryPoller(nil) != nil {
		t.Fatal("poller issued on cached remote switch")
	}
	// `askio-monitor status` reports the cached switch.
	if got := statusInventory(context.Background(), d.cfg, d.store); got != "remote-on" {
		t.Fatalf("status inventory = %q", got)
	}
	backend.setRemote("false")
	fake := &gateHost{}
	fastInventory(d, fake)
	runSwitch(t, d)
	waitFor(t, 5*time.Second, "live poll", func() bool { return backend.configCount() >= 2 })
	time.Sleep(200 * time.Millisecond)
	if n := backend.total(); n != 0 {
		t.Fatalf("%d inventory requests on a stale cached switch", n)
	}
}

func TestEffectiveInventoryTable(t *testing.T) {
	on, off := &model.RemoteInventory{Enabled: true}, &model.RemoteInventory{Enabled: false}
	safe := config.Config{Mode: "host", APIURL: "https://api.example.invalid/functions/v1"}
	withLocal := func(c config.Config, v *bool) config.Config {
		if v != nil {
			c.Inventory = &config.InventoryConfig{Enabled: v}
		}
		return c
	}
	tr, fa := true, false
	unsafe := safe
	unsafe.TLSSkipVerify = true
	cases := []struct {
		cfg    config.Config
		remote *model.RemoteInventory
		want   string
	}{
		{withLocal(safe, nil), nil, "remote-off"},
		{withLocal(safe, nil), off, "remote-off"},
		{withLocal(safe, nil), on, "remote-on"},
		{withLocal(safe, &fa), nil, "local-off"},
		{withLocal(safe, &fa), off, "local-off"},
		{withLocal(safe, &fa), on, "local-off"},
		{withLocal(safe, &tr), nil, "local-on"},
		{withLocal(safe, &tr), off, "local-on"},
		{withLocal(safe, &tr), on, "local-on"},
		{withLocal(unsafe, nil), on, "remote-refused:tls_skip_verify"},
		{withLocal(unsafe, nil), off, "remote-off"},
		{withLocal(unsafe, &fa), on, "local-off"},
		{config.Config{Mode: "gateway", APIURL: safe.APIURL}, on, "remote-refused:not_host_mode"},
		{config.Config{Mode: "host", APIURL: "https://u:p@api.example.invalid"}, on, "remote-refused:api_url_not_fixed_https"},
		{config.Config{Mode: "host", APIURL: safe.APIURL, Gateway: &config.GatewayConfig{}}, on, "remote-refused:gateway_configured"},
	}
	for i, tc := range cases {
		got := effectiveInventory(tc.cfg, tc.remote)
		if got.Status != tc.want || got.On != (tc.want == "local-on" || tc.want == "remote-on") {
			t.Fatalf("case %d: %+v, want %s", i, got, tc.want)
		}
	}
	// An `inventory: {}` stanza (key absent) follows the remote switch.
	empty := safe
	empty.Inventory = &config.InventoryConfig{}
	if got := effectiveInventory(empty, on); got.Status != "remote-on" {
		t.Fatalf("empty stanza: %+v", got)
	}
}

// TestInventoryOptInIsNotSetByInstallerDefaults checks the config the
// installer and `config.Save` produce: an unset Inventory never serializes an
// opt-in or an opt-out, and a config round-trip leaves the key absent, so the
// host follows the backend's remote switch and is off without it.
func TestInventoryOptInIsNotSetByInstallerDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitor.conf")
	cfg := config.Config{APIURL: "https://api.example.invalid/functions/v1", ServerID: gateServerID, AgentToken: "synthetic", PrivilegeMode: config.PrivilegeModeSudo}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "inventory") {
		t.Fatalf("saved default config mentions inventory:\n%s", raw)
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.InventoryLocal() != config.InventoryLocalAbsent {
		t.Fatal("default config set a local inventory value")
	}
	if inventoryOptedIn(loaded, nil) {
		t.Fatal("default config opted in to inventory without a remote switch")
	}
}
