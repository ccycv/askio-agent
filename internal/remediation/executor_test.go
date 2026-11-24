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

func TestIsSudoRefusal(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"restricted sudoers", "sudo: a password is required\n", true},
		{"no_new_privs", "sudo: The \"no new privileges\" flag is set, which prevents sudo from running as root.\nsudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.\n", true},
		{"nosuid", "sudo: effective uid is not 0, is /usr/bin/sudo on a file system with the 'nosuid' option set or an NFS file system without root privileges?", true},
		{"not allowed", "Sorry, user askio-agent is not allowed to execute '/usr/bin/systemd-run --wait /bin/bash x' as root on host.", true},
		{"command ran and its own sudo failed", "starting update\nsudo: a password is required\n", false},
		{"ordinary failure", "cat: /missing: No such file or directory", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSudoRefusal(tc.output); got != tc.want {
				t.Fatalf("isSudoRefusal(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}
}
