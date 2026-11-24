package agent

import (
	"strings"
	"testing"

	"github.com/askio-cloud/askio-monitor/internal/config"
)

// systemd sets no_new_privs for a non-root User= when any of these options is
// present, even with NoNewPrivileges=false, which silently disables sudo.
var impliesNoNewPrivs = []string{"PrivateDevices=", "RestrictSUIDSGID=", "LockPersonality="}

func TestSystemdUnitTemplate_SudoModeDoesNotImplyNoNewPrivs(t *testing.T) {
	unit := systemdUnitTemplate("askio-agent", "/etc/askio/monitor.conf", nil)
	if !strings.Contains(unit, "NoNewPrivileges=false\n") {
		t.Fatalf("sudo-mode unit must keep NoNewPrivileges=false:\n%s", unit)
	}
	for _, option := range impliesNoNewPrivs {
		if strings.Contains(unit, option) {
			t.Fatalf("sudo-mode unit must not contain %s, which implies no_new_privs:\n%s", option, unit)
		}
	}
	for _, option := range []string{"ProtectSystem=strict\n", "ProtectHome=true\n", "PrivateTmp=true\n", "ReadWritePaths=/var/lib/askio-monitor\n"} {
		if !strings.Contains(unit, option) {
			t.Fatalf("sudo-mode unit lost %q:\n%s", option, unit)
		}
	}
}

func TestSystemdUnitTemplate_MigrationProfileKeepsFullHardening(t *testing.T) {
	unit := systemdUnitTemplate("askio-agent", "/etc/askio/monitor.conf", &config.MigrationConfig{
		Enabled:  true,
		StateDir: "/var/lib/askio-migrations",
		RootHandles: map[string]string{
			"workspace": "/srv/askio-migrations",
		},
	})
	if !strings.Contains(unit, "NoNewPrivileges=true\n") {
		t.Fatalf("migration unit must set NoNewPrivileges=true:\n%s", unit)
	}
	for _, option := range impliesNoNewPrivs {
		if !strings.Contains(unit, option+"true\n") {
			t.Fatalf("migration unit lost %s:\n%s", option, unit)
		}
	}
}
