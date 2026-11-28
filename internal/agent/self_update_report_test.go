package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/selfupdate"
)

// The heartbeat carries the agent's own self-update path, so Askio knows
// before queuing an update whether this host needs someone on the console.
func TestHeartbeatReportsSelfUpdatePath(t *testing.T) {
	var (
		mu      sync.Mutex
		payload map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/monitor-agent-heartbeat" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			_ = json.Unmarshal(body, &payload)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	d, err := NewDaemon(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{
		Mode:          "host",
		APIURL:        srv.URL,
		ServerID:      "srv-1",
		AgentToken:    "tok",
		DataDir:       filepath.Join(root, "data"),
		PrivilegeMode: config.PrivilegeModeSudo,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.store.Close() })

	status := filepath.Join(root, "status")
	if err := os.WriteFile(status, []byte("NoNewPrivs:\t1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.selfUpdateProbe = &selfupdate.Probe{
		EUID:             func() int { return 1000 },
		ProcStatus:       status,
		UpdaterUnit:      filepath.Join(root, "askio-monitor-updater.path"),
		UpdaterDir:       filepath.Join(root, "update"),
		HelperPath:       filepath.Join(root, "askio-ops"),
		AllowGenericSudo: true,
		Run:              func(context.Context, string, ...string) error { return nil },
	}

	// Before the first check nothing is reported rather than a guess.
	if err := d.postHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if _, ok := payload["self_update"]; ok {
		t.Fatalf("self_update sent before it was checked: %v", payload["self_update"])
	}
	mu.Unlock()

	d.refreshSelfUpdate(context.Background())
	if err := d.postHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	report, ok := payload["self_update"].(map[string]any)
	if !ok {
		t.Fatalf("heartbeat has no self_update: %v", payload)
	}
	if report["path"] != "none" || report["available"] != false || report["reason_code"] != "no_new_privs" || report["no_new_privs"] != true {
		t.Fatalf("unexpected report: %v", report)
	}
}
