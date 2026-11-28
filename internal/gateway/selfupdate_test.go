package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

const testTargetVersion = "0.4.99-test"

type selfUpdateHarness struct {
	t        *testing.T
	server   *Server
	updater  *selfUpdater
	cloud    *httptest.Server
	mu       sync.Mutex
	results  []model.CommandResult
	command  map[string]any
	binary   []byte
	fetches  int
	commands [][]string
}

func newSelfUpdateHarness(t *testing.T) *selfUpdateHarness {
	t.Helper()
	h := &selfUpdateHarness{t: t}
	h.binary = []byte("#!/bin/sh\necho \"askio-monitor version " + testTargetVersion + " (commit test)\"\nexit 0\n" + strings.Repeat("#", 1_100_000) + "\n")
	sum := sha256.Sum256(h.binary)

	h.cloud = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/monitor-agent-config":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"fetched_at":      time.Now().UTC().Format(time.RFC3339),
				"monitors":        []any{},
				"pending_command": h.command,
			})
		case "/askio-monitor-test.bin":
			h.mu.Lock()
			h.fetches++
			h.mu.Unlock()
			_, _ = w.Write(h.binary)
		case "/monitor-agent-command-result":
			if r.Header.Get("Authorization") != "Bearer cloudtok" {
				t.Errorf("result posted without the gateway cloud token")
			}
			var result model.CommandResult
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &result); err != nil {
				t.Errorf("decode result: %v", err)
			}
			h.mu.Lock()
			h.results = append(h.results, result)
			h.mu.Unlock()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(h.cloud.Close)

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	installDir := filepath.Join(root, "bin")
	for _, dir := range []string{dataDir, installDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	helper := filepath.Join(root, "askio-ops")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	procStatus := filepath.Join(root, "status")
	if err := os.WriteFile(procStatus, []byte("Name:\taskio-monitor\nNoNewPrivs:\t0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h.updater = &selfUpdater{
		dataDir:          dataDir,
		installPath:      filepath.Join(installDir, "askio-monitor"),
		helperPath:       helper,
		updaterDir:       filepath.Join(dataDir, "update"),
		updaterUnit:      filepath.Join(root, "askio-monitor-updater.path"),
		procStatus:       procStatus,
		httpClient:       &http.Client{Timeout: 10 * time.Second},
		allowInsecureURL: true,
		euid:             func() int { return 1000 },
	}
	h.updater.run = func(ctx context.Context, name string, args ...string) (string, error) {
		switch filepath.Base(name) {
		case "sudo", "install", "systemctl", "systemd-run":
			h.mu.Lock()
			h.commands = append(h.commands, append([]string{name}, args...))
			h.mu.Unlock()
			return "", nil
		}
		return runCommand(ctx, name, args...)
	}

	u, _ := url.Parse(h.cloud.URL)
	h.server = &Server{
		cloudBase:       u,
		cloudToken:      "cloudtok",
		key:             []byte("secret"),
		gatewayServerID: "gateway-server",
		httpClient:      &http.Client{Timeout: 10 * time.Second},
		updater:         h.updater,
	}
	h.command = map[string]any{
		"type":            "update_agent",
		"command_id":      "cmd-update-1",
		"binary_url":      h.cloud.URL + "/askio-monitor-test.bin",
		"binary_sha256":   hex.EncodeToString(sum[:]),
		"target_version":  testTargetVersion,
		"timeout_seconds": 60,
		"execution_mode":  "live",
	}
	return h
}

func (h *selfUpdateHarness) poll() {
	h.t.Helper()
	if err := h.server.pollOnce(context.Background()); err != nil {
		h.t.Fatalf("pollOnce: %v", err)
	}
}

func (h *selfUpdateHarness) setNoNewPrivs() {
	h.t.Helper()
	if err := os.WriteFile(h.updater.procStatus, []byte("NoNewPrivs:\t1\n"), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *selfUpdateHarness) lastResult() model.CommandResult {
	h.t.Helper()
	if len(h.results) == 0 {
		h.t.Fatal("no command result posted")
	}
	return h.results[len(h.results)-1]
}

func (h *selfUpdateHarness) stagedLeftovers() []string {
	matches, _ := filepath.Glob(filepath.Join(h.updater.dataDir, "askio-monitor-new.*"))
	return matches
}

func TestSelfUpdate_VerifiesAndInstallsThroughHelper(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.poll()

	if h.server.lastCommandID != "cmd-update-1" {
		t.Fatalf("command not marked handled: %q", h.server.lastCommandID)
	}
	result := h.lastResult()
	if result.Status != "success" || result.CommandType != "update_agent" || result.CommandID != "cmd-update-1" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(h.commands) != 1 || h.commands[0][0] != "sudo" || h.commands[0][2] != h.updater.helperPath || h.commands[0][3] != "self-update" {
		t.Fatalf("expected one sudo askio-ops self-update call, got %v", h.commands)
	}
	staged := h.commands[0][4]
	if filepath.Dir(staged) != h.updater.dataDir || !strings.HasPrefix(filepath.Base(staged), "askio-monitor-new.") {
		t.Fatalf("binary must be staged in the data dir, got %s", staged)
	}
	got, err := os.ReadFile(staged)
	if err != nil || string(got) != string(h.binary) {
		t.Fatalf("staged binary differs from the download: %v", err)
	}

	// A repeated delivery of the same command is not run again.
	h.poll()
	if h.fetches != 1 || len(h.commands) != 1 {
		t.Fatalf("duplicate delivery re-ran the update: fetches=%d commands=%v", h.fetches, h.commands)
	}
}

func TestSelfUpdate_RejectsChecksumMismatch(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.command["binary_sha256"] = strings.Repeat("0", 64)
	h.poll()

	result := h.lastResult()
	if result.Status != "failed" || !strings.Contains(result.Error, "checksum verification failed") {
		t.Fatalf("expected checksum failure, got %+v", result)
	}
	if len(h.commands) != 0 {
		t.Fatalf("nothing may be installed after a checksum failure: %v", h.commands)
	}
	if leftovers := h.stagedLeftovers(); len(leftovers) != 0 {
		t.Fatalf("staged download not removed: %v", leftovers)
	}
}

func TestSelfUpdate_RejectsVersionMismatch(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.command["target_version"] = "0.4.98"
	h.poll()

	if result := h.lastResult(); result.Status != "failed" || !strings.Contains(result.Error, "version mismatch") {
		t.Fatalf("expected version mismatch, got %+v", result)
	}
	if len(h.commands) != 0 || len(h.stagedLeftovers()) != 0 {
		t.Fatalf("version mismatch must not install or leave files: %v", h.commands)
	}
}

func TestSelfUpdate_RequiresHTTPS(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.updater.allowInsecureURL = false
	h.poll()

	if result := h.lastResult(); result.Status != "failed" || !strings.Contains(result.Error, "https") {
		t.Fatalf("expected https requirement, got %+v", result)
	}
	if h.fetches != 0 {
		t.Fatal("binary must not be fetched over plain http")
	}
}

func TestSelfUpdate_NoNewPrivsWithoutUpdaterFailsClearly(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.setNoNewPrivs()
	h.poll()

	result := h.lastResult()
	if result.Status != "failed" || !strings.Contains(result.Error, "no_new_privs") || !strings.Contains(result.Error, "Reinstall") {
		t.Fatalf("expected a no_new_privs reinstall error, got %+v", result)
	}
	if h.fetches != 0 || len(h.commands) != 0 {
		t.Fatalf("must fail before downloading: fetches=%d commands=%v", h.fetches, h.commands)
	}
}

func TestSelfUpdate_UsesRootOwnedUpdaterUnderNoNewPrivs(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.setNoNewPrivs()
	if err := os.MkdirAll(h.updater.updaterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.updater.updaterUnit, []byte("[Path]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.poll()

	if result := h.lastResult(); result.Status != "success" {
		t.Fatalf("expected success, got %+v", result)
	}
	for _, command := range h.commands {
		// Only the read-only "systemctl is-active" check may run.
		if command[0] != "systemctl" || command[1] != "is-active" {
			t.Fatalf("the updater path needs no sudo or install: %v", h.commands)
		}
	}
	staged, err := os.ReadFile(filepath.Join(h.updater.updaterDir, "askio-monitor.new"))
	if err != nil || string(staged) != string(h.binary) {
		t.Fatalf("binary not staged for the updater: %v", err)
	}
	request, err := os.ReadFile(filepath.Join(h.updater.updaterDir, "request"))
	if err != nil || strings.TrimSpace(string(request)) != "cmd-update-1" {
		t.Fatalf("updater request not written: %q %v", request, err)
	}
}

func TestSelfUpdate_HelperMissingFailsClearly(t *testing.T) {
	h := newSelfUpdateHarness(t)
	if err := os.Remove(h.updater.helperPath); err != nil {
		t.Fatal(err)
	}
	h.poll()

	if result := h.lastResult(); result.Status != "failed" || !strings.Contains(result.Error, "is missing") {
		t.Fatalf("expected missing-helper error, got %+v", result)
	}
}

func TestSelfUpdate_RootInstallsAndRestartsWithoutBlocking(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.updater.euid = func() int { return 0 }
	h.poll()

	if result := h.lastResult(); result.Status != "success" {
		t.Fatalf("expected success, got %+v", result)
	}
	if len(h.commands) != 3 {
		t.Fatalf("expected install, daemon-reload and restart, got %v", h.commands)
	}
	install := strings.Join(h.commands[0], " ")
	if !strings.HasPrefix(install, "/usr/bin/install -o root -g root -m 0755 ") || !strings.HasSuffix(install, " "+h.updater.installPath) {
		t.Fatalf("unexpected install call: %s", install)
	}
	if got := strings.Join(h.commands[2], " "); got != "systemctl restart --no-block askio-monitor" {
		t.Fatalf("unexpected restart call: %s", got)
	}
}

func TestSelfUpdate_IgnoresOtherCommandTypes(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.command = map[string]any{"type": "exec_script", "command_id": "cmd-script", "script_b64": "ZWNobyBoaQ=="}
	h.poll()

	if len(h.results) != 0 || len(h.commands) != 0 || h.fetches != 0 {
		t.Fatalf("gateway must not run scripts: results=%v commands=%v", h.results, h.commands)
	}
	if h.server.lastCommandID != "cmd-script" {
		t.Fatalf("ignored command not marked: %q", h.server.lastCommandID)
	}
}

func TestParseReportedVersion(t *testing.T) {
	cases := []struct {
		output string
		want   string
		ok     bool
	}{
		{"askio-monitor version 0.4.42 (commit abc, go1.22.12, linux/amd64)\n", "0.4.42", true},
		{"askio-monitor version 0.4.39\n", "0.4.39", true},
		{"askio-monitor version 0.4.42-rc1 (commit abc)", "0.4.42-rc1", true},
		{"0.4.42", "", false},
		{"something else askio-monitor version 0.4.42", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := parseReportedVersion(tc.output)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parseReportedVersion(%q) = %q, %v; want %q, %v", tc.output, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSelfUpdate_RejectsVersionThatOnlyContainsTheTarget(t *testing.T) {
	for _, tc := range []struct{ name, target string }{
		// The test binary reports 0.4.99-test.
		{"prefix of the reported version", "0.4.9"},
		{"stable release of a prerelease binary", "0.4.99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSelfUpdateHarness(t)
			h.command["target_version"] = tc.target
			h.poll()
			if result := h.lastResult(); result.Status != "failed" || !strings.Contains(result.Error, "version mismatch") {
				t.Fatalf("target %s must not accept a binary reporting %s: %+v", tc.target, testTargetVersion, result)
			}
			if len(h.commands) != 0 || len(h.stagedLeftovers()) != 0 {
				t.Fatalf("mismatch must not install or leave files: %v", h.commands)
			}
		})
	}
}

type exitStatus int

func (e exitStatus) Error() string { return "exit status" }
func (e exitStatus) ExitCode() int { return int(e) }

// An updater whose path unit is not active would take the request and never
// apply it, so the gateway must not hand it the binary.
func TestSelfUpdate_InactiveUpdaterIsNotUsed(t *testing.T) {
	h := newSelfUpdateHarness(t)
	h.setNoNewPrivs()
	if err := os.MkdirAll(h.updater.updaterDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.updater.updaterUnit, []byte("[Path]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := h.updater.run
	h.updater.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if filepath.Base(name) == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", exitStatus(3)
		}
		return base(ctx, name, args...)
	}
	h.poll()

	result := h.lastResult()
	if result.Status != "failed" || !strings.Contains(result.Error, "installed but not active") {
		t.Fatalf("expected an inactive-updater error, got %+v", result)
	}
	if h.fetches != 0 {
		t.Fatal("must fail before downloading")
	}
	if _, err := os.Stat(filepath.Join(h.updater.updaterDir, "request")); !os.IsNotExist(err) {
		t.Fatalf("no request may be written for an inactive updater: %v", err)
	}
}

// The gateway heartbeat reports the same path the update command would use.
func TestGatewayHeartbeatReportsSelfUpdatePath(t *testing.T) {
	h := newSelfUpdateHarness(t)
	var (
		mu   sync.Mutex
		sent []map[string]any
	)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/monitor-agent-heartbeat" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			sent = append(sent, body)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(cloud.Close)
	u, _ := url.Parse(cloud.URL)
	h.server.cloudBase = u

	if err := h.server.postGatewayHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A later change on the host shows up after the refresh interval, not on every heartbeat.
	h.setNoNewPrivs()
	if err := h.server.postGatewayHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.server.selfUpdateChecked = time.Now().Add(-selfUpdateRefresh)
	if err := h.server.postGatewayHeartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 3 {
		t.Fatalf("expected 3 heartbeats, got %d", len(sent))
	}
	paths := []string{}
	for _, body := range sent {
		report, ok := body["self_update"].(map[string]any)
		if !ok {
			t.Fatalf("heartbeat without self_update: %v", body)
		}
		paths = append(paths, report["path"].(string))
	}
	if strings.Join(paths, ",") != "helper,helper,none" {
		t.Fatalf("unexpected paths: %v", paths)
	}
	if last := sent[2]["self_update"].(map[string]any); last["reason_code"] != "no_new_privs" || last["available"] != false {
		t.Fatalf("unexpected last report: %v", last)
	}
}
