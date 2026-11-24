package remediation

import (
	"context"
	"errors"
	"strings"
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

type execCall struct {
	command string
	args    []string
}

// fakeExec replaces execSimple. The first call is the sudo systemd-run
// wrapper; respond decides what it printed and whether it failed.
func fakeExec(t *testing.T, respond func(marker string) (string, error)) *[]execCall {
	t.Helper()
	calls := &[]execCall{}
	saved := execSimple
	t.Cleanup(func() { execSimple = saved })
	execSimple = func(_ context.Context, command string, args []string, _ int) (ExecResult, error) {
		*calls = append(*calls, execCall{command, append([]string{}, args...)})
		if len(*calls) > 1 {
			return ExecResult{Output: "direct", ExitCode: 0}, nil
		}
		marker := ""
		for _, arg := range args {
			if strings.HasPrefix(arg, "askio-exec-started:") {
				marker = arg
			}
		}
		if marker == "" {
			t.Fatalf("wrapper did not pass a start marker: %v", args)
		}
		out, err := respond(marker)
		code := 0
		if err != nil {
			code = 1
		}
		return ExecResult{Output: out, ExitCode: code}, err
	}
	return calls
}

func TestSystemdRun_NeverReplaysAStartedScriptWhoseInnerSudoFailed(t *testing.T) {
	calls := fakeExec(t, func(marker string) (string, error) {
		// The script started (marker), did its work, then its own sudo failed.
		return marker + "\nsudo: a password is required\n", errors.New("exit status 1")
	})
	res, err := SystemdRunExecutor{}.Run(context.Background(), "/bin/bash", []string{"/var/lib/askio-monitor/askio-cmd-1.sh"}, 30)
	if err == nil {
		t.Fatal("the script's failure must be returned")
	}
	if len(*calls) != 1 {
		t.Fatalf("a started script must never be run again, got calls %v", *calls)
	}
	if strings.Contains(res.Output, "askio-exec-started:") || res.Output != "sudo: a password is required\n" {
		t.Fatalf("marker must be stripped from the output, got %q", res.Output)
	}
}

func TestSystemdRun_FallsBackWhenSudoRefusedBeforeStart(t *testing.T) {
	calls := fakeExec(t, func(string) (string, error) {
		return "sudo: a password is required\n", errors.New("exit status 1")
	})
	res, err := SystemdRunExecutor{}.Run(context.Background(), "/bin/bash", []string{"script.sh"}, 30)
	if err != nil || res.Output != "direct" {
		t.Fatalf("expected the direct fallback, got %q %v", res.Output, err)
	}
	if len(*calls) != 2 || (*calls)[1].command != "/bin/bash" {
		t.Fatalf("expected one direct retry, got %v", *calls)
	}
}

func TestSystemdRun_FallsBackOnTransientFailureBeforeStart(t *testing.T) {
	calls := fakeExec(t, func(string) (string, error) {
		return "Failed to start transient service unit: Connection reset by peer\n", errors.New("exit status 1")
	})
	if _, err := (SystemdRunExecutor{}).Run(context.Background(), "/bin/true", nil, 30); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 {
		t.Fatalf("expected a fallback, got %v", *calls)
	}
}

func TestSystemdRun_NoFallbackAfterStartEvenOnTransientText(t *testing.T) {
	calls := fakeExec(t, func(marker string) (string, error) {
		return marker + "\nconnection reset by peer\n", errors.New("exit status 1")
	})
	_, _ = SystemdRunExecutor{}.Run(context.Background(), "/bin/bash", []string{"script.sh"}, 30)
	if len(*calls) != 1 {
		t.Fatalf("a started command must never be run again, got %v", *calls)
	}
}

func TestSystemdRun_SuccessStripsMarker(t *testing.T) {
	calls := fakeExec(t, func(marker string) (string, error) {
		return marker + "\nhello\n", nil
	})
	res, err := SystemdRunExecutor{}.Run(context.Background(), "/bin/echo", []string{"hello"}, 30)
	if err != nil || res.Output != "hello\n" {
		t.Fatalf("got %q %v", res.Output, err)
	}
	args := (*calls)[0].args
	wantPrefix := []string{"-n", "systemd-run", "--wait", "--collect", "--pipe", "--quiet", "--unit"}
	for i, want := range wantPrefix {
		if args[i] != want {
			t.Fatalf("unexpected wrapper args %v", args)
		}
	}
	if tail := strings.Join(args[len(args)-2:], " "); tail != "/bin/echo hello" {
		t.Fatalf("command must run last and unchanged, got %v", args)
	}
}
