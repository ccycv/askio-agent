package agent

// Enrollment qualification for passive inventory.
//
// Collection and upload must never happen unless BOTH gates are open:
//   1. host opt-in: the operator-managed local config says inventory.enabled: true;
//   2. backend: VULNERABILITY_INVENTORY_ENABLED is on AND this agent is enrolled,
//      which the agent observes only as an "assigned" claim bound to it.
//
// These tests drive the real daemon construction (NewDaemon from a YAML config
// loaded with config.Load), the real HTTPS API client and the real poller
// against an emulated backend that answers the way Askio's
// monitor-agent-inventory routes do. The host collector is a counting fake,
// so "collection ran" is observable without reading this machine's packages.

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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
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

// gateBackend emulates Askio's inventory routes for one backend state.
type gateBackend struct {
	server *httptest.Server
	mu     sync.Mutex
	hits   map[string]int
	claims [][]byte
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

func newGateBackend(t *testing.T, status int, body func() any) *gateBackend {
	t.Helper()
	b := &gateBackend{hits: map[string]int{}}
	b.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := strings.TrimPrefix(r.URL.Path, "/functions/v1/")
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
	}))
	t.Cleanup(b.server.Close)
	return b
}

// newGateDaemon writes an operator config file with the given inventory
// stanza, loads it the way `askio-monitor start` does and builds the daemon.
func newGateDaemon(t *testing.T, backend *gateBackend, inventoryStanza string) *Daemon {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "backend-ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.server.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := strings.Join([]string{
		"api_url: " + backend.server.URL + "/functions/v1",
		"server_id: " + gateServerID,
		"agent_id: " + gateAgentID,
		"agent_token: synthetic-agent-token",
		"ca_cert_path: " + caPath,
		"privilege_mode: sudo",
		"data_dir: " + filepath.Join(dir, "data"),
		inventoryStanza,
	}, "\n") + "\n"
	cfgPath := filepath.Join(dir, "monitor.conf")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	d, err := NewDaemon(slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	if err != nil {
		t.Fatalf("new daemon: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

var hostStates = []struct {
	name    string
	stanza  string
	optedIn bool
}{
	{"opt-in-absent", "", false},
	{"opt-in-false", "inventory:\n  enabled: false", false},
	{"opt-in-true", "inventory:\n  enabled: true", true},
}

// TestInventoryRequiresHostOptInAndBackendEnrollment is the full matrix: three
// host states x eight backend states. Collection and upload happen in exactly
// one cell; without the host opt-in no inventory route is contacted at all.
func TestInventoryRequiresHostOptInAndBackendEnrollment(t *testing.T) {
	for _, host := range hostStates {
		for _, state := range backendStates {
			t.Run(host.name+"/"+state.name, func(t *testing.T) {
				backend := newGateBackend(t, state.status, state.body)
				d := newGateDaemon(t, backend, host.stanza)
				fake := &gateHost{}

				if got := inventoryOptedIn(d.cfg); got != host.optedIn {
					t.Fatalf("inventoryOptedIn = %v, want %v", got, host.optedIn)
				}
				poller := d.newInventoryPoller(&vulnerability.Collector{Host: fake})
				if !host.optedIn {
					if poller != nil {
						t.Fatal("inventory poller created without host opt-in")
					}
					// The daemon's own loop must also return without doing anything.
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					started := time.Now()
					d.inventoryLoop(ctx)
					if time.Since(started) > time.Second {
						t.Fatal("inventory loop ran without host opt-in")
					}
					if n := backend.total(); n != 0 || fake.calls.Load() != 0 {
						t.Fatalf("without host opt-in: %d inventory requests, %d host observations", n, fake.calls.Load())
					}
					return
				}
				if poller == nil {
					t.Fatal("no inventory poller despite host opt-in")
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
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

// TestInventoryOptInIsNotSetByInstallerDefaults checks the config the
// installer and `config.Save` produce: an unset Inventory never serializes an
// opt-in, and a config round-trip keeps it off.
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
	if inventoryOptedIn(loaded) {
		t.Fatal("default config opted in to inventory")
	}
}
