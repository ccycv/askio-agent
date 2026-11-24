package remediation

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
)

func HasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

type Executor interface {
	Run(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error)
	Format(command string, args []string) string
}

// SystemdRunExecutor runs commands via systemd-run (transient units).
// This is used to escape systemd sandboxing of the main askio-monitor service
// (e.g. ProtectSystem=strict / PrivateTmp=true).
//
// It still relies on sudo allowlisting if the agent runs unprivileged.
type SystemdRunExecutor struct{}

type RootExecutor struct{}

type SudoExecutor struct{}

func NewExecutor(mode config.PrivilegeMode) (Executor, error) {
	switch mode {
	case config.PrivilegeModeRoot:
		return RootExecutor{}, nil
	case config.PrivilegeModeSudo:
		// Prefer systemd-run if available; fall back to direct sudo exec.
		if HasCommand("systemd-run") {
			return SystemdRunExecutor{}, nil
		}
		return SudoExecutor{}, nil
	default:
		return nil, fmt.Errorf("unknown privilege mode: %s", mode)
	}
}

// execSimple is ExecSimple; tests replace it to observe what would run.
var execSimple = ExecSimple

// startMarkerScript prints its first argument, then becomes the real command.
// Seeing the marker in the output proves the command started, so it is never
// run a second time.
const startMarkerScript = `printf '%s\n' "$1"; shift; exec "$@"`

func (SystemdRunExecutor) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error) {
	// We run `systemd-run` itself via sudo -n, so it can create the transient unit.
	// `--wait` blocks until the command completes.
	// `--collect` ensures unit is garbage-collected.
	// `--pipe` streams stdout/stderr to caller.
	// `--quiet` reduces noise.
	unit := fmt.Sprintf("askio-cmd-%d", time.Now().UnixNano())
	marker := "askio-exec-started:" + unit
	all := []string{"-n", "systemd-run", "--wait", "--collect", "--pipe", "--quiet", "--unit", unit,
		"/bin/sh", "-c", startMarkerScript, "askio-exec", marker, command}
	all = append(all, args...)
	result, err := execSimple(ctx, "sudo", all, timeoutSeconds)
	started := strings.Contains(result.Output, marker)
	result.Output = stripStartMarker(result.Output, marker)
	if err == nil || started || !(isSystemdRunTransientFailure(result.Output) || isSudoRefusal(result.Output)) {
		return result, err
	}

	// The command never started: systemd-run could not create the transient
	// unit from the agent service context, or sudo refused to run systemd-run
	// at all (a restricted sudoers policy, or no_new_privs on the service).
	// Only then is it safe to try another way. Keep read-only checks useful by
	// falling back to direct unprivileged execution first; many audit checks
	// only need world-readable config or socket state. If that fails, try the
	// direct non-interactive sudo path used when systemd-run is unavailable.
	directResult, directErr := RootExecutor{}.Run(ctx, command, args, timeoutSeconds)
	if directErr == nil {
		return directResult, nil
	}
	sudoResult, sudoErr := SudoExecutor{}.Run(ctx, command, args, timeoutSeconds)
	if sudoErr == nil {
		return sudoResult, nil
	}
	if directResult.Output != "" {
		return directResult, directErr
	}
	return sudoResult, sudoErr
}

func stripStartMarker(output, marker string) string {
	if i := strings.Index(output, marker+"\n"); i >= 0 {
		return output[:i] + output[i+len(marker)+1:]
	}
	return strings.Replace(output, marker, "", 1)
}

func (SystemdRunExecutor) Format(command string, args []string) string {
	return "sudo -n systemd-run --wait --collect --pipe --quiet --unit askio-cmd-<ts> " + command + " " + strings.Join(args, " ")
}

// isSudoRefusal reports whether the output starts with sudo refusing to run.
// It is only consulted when the start marker is absent, i.e. the command
// provably never started.
func isSudoRefusal(output string) bool {
	first := strings.TrimSpace(output)
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = strings.TrimSpace(first[:i])
	}
	lower := strings.ToLower(first)
	if strings.HasPrefix(lower, "sorry, user ") && strings.Contains(lower, "is not allowed to execute") {
		return true
	}
	if !strings.HasPrefix(lower, "sudo: ") {
		return false
	}
	return strings.Contains(lower, "a password is required") ||
		strings.Contains(lower, "no new privileges") ||
		strings.Contains(lower, "effective uid is not 0")
}

func isSystemdRunTransientFailure(output string) bool {
	normalized := strings.ToLower(output)
	return strings.Contains(normalized, "failed to start transient service unit") ||
		strings.Contains(normalized, "connection reset by peer") ||
		strings.Contains(normalized, "transport endpoint is not connected")
}

func (RootExecutor) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error) {
	return execSimple(ctx, command, args, timeoutSeconds)
}

func (RootExecutor) Format(command string, args []string) string {
	return command + " " + strings.Join(args, " ")
}

func (SudoExecutor) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error) {
	// -n: non-interactive (never prompt)
	all := append([]string{"-n", command}, args...)
	return execSimple(ctx, "sudo", all, timeoutSeconds)
}

func (SudoExecutor) Format(command string, args []string) string {
	return "sudo -n " + command + " " + strings.Join(args, " ")
}
