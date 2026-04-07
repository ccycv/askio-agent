package remediation

import (
	"testing"

	"github.com/askio-cloud/askio-monitor/internal/config"
)

func TestNewExecutor_PrefersSystemdRunWhenAvailable(t *testing.T) {
	if !HasCommand("systemd-run") {
		t.Skip("systemd-run not available in test environment")
	}
	ex, err := NewExecutor(config.PrivilegeModeSudo)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ex.(SystemdRunExecutor); !ok {
		t.Fatalf("expected SystemdRunExecutor, got %T", ex)
	}
}

