package selfupdate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type exitErr int

func (e exitErr) Error() string { return "exit status" }
func (e exitErr) ExitCode() int { return int(e) }

type fixture struct {
	probe Probe
	calls []string
	// isActive is the exit status of `systemctl is-active` (0 active, 3 inactive, -1 cannot run).
	isActive int
	// sudoList is whether `sudo -n -l install|systemctl` succeeds.
	sudoList bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{}
	f.probe = Probe{
		EUID:             func() int { return 1000 },
		ProcStatus:       filepath.Join(root, "status"),
		UpdaterUnit:      filepath.Join(root, "askio-monitor-updater.path"),
		UpdaterDir:       filepath.Join(root, "update"),
		HelperPath:       filepath.Join(root, "askio-ops"),
		AllowGenericSudo: true,
		Run: func(_ context.Context, name string, args ...string) error {
			f.calls = append(f.calls, strings.Join(append([]string{name}, args...), " "))
			switch name {
			case "systemctl":
				switch f.isActive {
				case 0:
					return nil
				case -1:
					return errors.New("exec: systemctl: not found")
				default:
					return exitErr(f.isActive)
				}
			case "sudo":
				if f.sudoList {
					return nil
				}
				return exitErr(1)
			}
			return nil
		},
	}
	f.noNewPrivs(t, false)
	return f
}

func (f *fixture) noNewPrivs(t *testing.T, on bool) {
	t.Helper()
	value := "0"
	if on {
		value = "1"
	}
	if err := os.WriteFile(f.probe.ProcStatus, []byte("Name:\taskio-monitor\nNoNewPrivs:\t"+value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) installUpdater(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.probe.UpdaterUnit, []byte("[Path]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.probe.UpdaterDir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) installHelper(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(f.probe.HelperPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestRootNeedsNothingElse(t *testing.T) {
	f := newFixture(t)
	f.probe.EUID = func() int { return 0 }
	f.noNewPrivs(t, true)
	report := Detect(context.Background(), f.probe)
	if report.Path != PathRoot || !report.Available || !report.NoNewPrivs {
		t.Fatalf("got %+v", report)
	}
}

// The gateway sites in production: no_new_privs, no updater. Nothing remote works.
func TestNoNewPrivsWithoutUpdaterNeedsTheConsole(t *testing.T) {
	f := newFixture(t)
	f.noNewPrivs(t, true)
	f.installHelper(t)
	f.sudoList = true
	report := Detect(context.Background(), f.probe)
	if report.Path != PathNone || report.Available || report.ReasonCode != ReasonNoNewPrivs {
		t.Fatalf("got %+v", report)
	}
	if !strings.Contains(report.Reason, "askio-monitor-updater is not installed") || !strings.Contains(report.Reason, "agent-install.sh | sudo bash -s -- upgrade") {
		t.Fatalf("reason does not say what to run: %q", report.Reason)
	}
	if !report.HelperInstalled || report.UpdaterInstalled {
		t.Fatalf("flags wrong: %+v", report)
	}
	for _, call := range f.calls {
		if strings.HasPrefix(call, "sudo") {
			t.Fatalf("sudo must not be tried under no_new_privs: %v", f.calls)
		}
	}
}

// After `agent-install.sh upgrade`: the updater works even under no_new_privs.
func TestActiveUpdaterWorksUnderNoNewPrivs(t *testing.T) {
	f := newFixture(t)
	f.noNewPrivs(t, true)
	f.installUpdater(t)
	report := Detect(context.Background(), f.probe)
	if report.Path != PathUpdater || !report.Available || !report.UpdaterActive {
		t.Fatalf("got %+v", report)
	}
}

func TestInactiveUpdaterIsNotUsed(t *testing.T) {
	f := newFixture(t)
	f.noNewPrivs(t, true)
	f.installUpdater(t)
	f.isActive = 3
	report := Detect(context.Background(), f.probe)
	if report.Path != PathNone || report.ReasonCode != ReasonUpdaterInactive || report.UpdaterActive || !report.UpdaterInstalled {
		t.Fatalf("got %+v", report)
	}
	if !strings.Contains(report.Reason, "systemctl enable --now askio-monitor-updater.path") {
		t.Fatalf("reason: %q", report.Reason)
	}

	// Without no_new_privs the helper still works.
	f.noNewPrivs(t, false)
	f.installHelper(t)
	if report := Detect(context.Background(), f.probe); report.Path != PathHelper {
		t.Fatalf("got %+v", report)
	}
}

func TestUnknownUpdaterStateStillUsesTheUpdater(t *testing.T) {
	f := newFixture(t)
	f.noNewPrivs(t, true)
	f.installUpdater(t)
	for _, status := range []int{-1, 1, 4} {
		f.isActive = status
		if report := Detect(context.Background(), f.probe); report.Path != PathUpdater {
			t.Fatalf("is-active status %d: got %+v", status, report)
		}
	}
}

func TestUpdaterWithoutWritableStagingDirectory(t *testing.T) {
	f := newFixture(t)
	f.noNewPrivs(t, true)
	if err := os.WriteFile(f.probe.UpdaterUnit, []byte("[Path]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := Detect(context.Background(), f.probe)
	if report.Path != PathNone || report.ReasonCode != ReasonNoNewPrivs || !strings.Contains(report.Reason, "staging directory") {
		t.Fatalf("got %+v", report)
	}
}

func TestHelperThenSudoThenNothing(t *testing.T) {
	f := newFixture(t)
	f.installHelper(t)
	if report := Detect(context.Background(), f.probe); report.Path != PathHelper || !report.Available {
		t.Fatalf("got %+v", report)
	}

	f = newFixture(t)
	f.sudoList = true
	if report := Detect(context.Background(), f.probe); report.Path != PathSudo || !report.Available {
		t.Fatalf("got %+v", report)
	}

	// The Devclash hosts: no helper, sudo asks for a password.
	f = newFixture(t)
	report := Detect(context.Background(), f.probe)
	if report.Path != PathNone || report.ReasonCode != ReasonNoPrivilege || !strings.Contains(report.Reason, "no passwordless sudo") {
		t.Fatalf("got %+v", report)
	}

	// Gateways never use plain sudo.
	f = newFixture(t)
	f.sudoList = true
	f.probe.AllowGenericSudo = false
	report = Detect(context.Background(), f.probe)
	if report.Path != PathNone || strings.Contains(report.Reason, "sudo for install") {
		t.Fatalf("got %+v", report)
	}
}

func TestReportWireShape(t *testing.T) {
	raw, err := json.Marshal(Report{Path: PathNone, ReasonCode: ReasonNoNewPrivs, Reason: "x", NoNewPrivs: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"path", "available", "reason_code", "reason", "no_new_privs", "updater_installed", "updater_active", "helper_installed"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing %s in %s", key, raw)
		}
	}
	if decoded["available"] != false || decoded["path"] != "none" {
		t.Fatalf("got %s", raw)
	}
}

func TestDefaultProbePaths(t *testing.T) {
	probe := DefaultProbe("", true)
	if probe.UpdaterDir != "/var/lib/askio-monitor/update" || probe.HelperPath != "/usr/local/bin/askio-ops" ||
		probe.UpdaterUnit != "/etc/systemd/system/askio-monitor-updater.path" || probe.ProcStatus != "/proc/self/status" {
		t.Fatalf("got %+v", probe)
	}
}
