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

func TestIsSystemdRunTransientFailure(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "rocky connection reset",
			output: "Failed to start transient service unit: Connection reset by peer\n",
			want:   true,
		},
		{
			name:   "transport disconnected",
			output: "Failed to start transient service unit: Transport endpoint is not connected",
			want:   true,
		},
		{
			name:   "ordinary command failure",
			output: "cat: /missing: No such file or directory",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSystemdRunTransientFailure(tc.output); got != tc.want {
				t.Fatalf("isSystemdRunTransientFailure() = %v, want %v", got, tc.want)
			}
		})
	}
}
