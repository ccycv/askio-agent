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

func (SystemdRunExecutor) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error) {
	// We run `systemd-run` itself via sudo -n, so it can create the transient unit.
	// `--wait` blocks until the command completes.
	// `--collect` ensures unit is garbage-collected.
	// `--pipe` streams stdout/stderr to caller.
	// `--quiet` reduces noise.
	unit := fmt.Sprintf("askio-cmd-%d", time.Now().UnixNano())
	all := []string{"-n", "systemd-run", "--wait", "--collect", "--pipe", "--quiet", "--unit", unit, command}
	all = append(all, args...)
	result, err := ExecSimple(ctx, "sudo", all, timeoutSeconds)
	if err == nil || !(isSystemdRunTransientFailure(result.Output) || isSudoRefusal(result.Output)) {
		return result, err
	}

	// Some distros can have systemd-run installed but unable to create transient
	// units from the agent service context, and some installs do not let the
	// agent run systemd-run through sudo at all (a restricted sudoers policy, or
	// no_new_privs on the service). In both cases the command never started. Keep read-only checks useful by
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

func (SystemdRunExecutor) Format(command string, args []string) string {
	return "sudo -n systemd-run --wait --collect --pipe --quiet --unit askio-cmd-<ts> " + command + " " + strings.Join(args, " ")
}

// isSudoRefusal reports whether sudo itself refused to start the command, so
// it never ran and running it another way cannot repeat its side effects.
// Only sudo's own first line counts: output from a command that did run (for
// example a script that calls sudo internally) does not.
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
	return ExecSimple(ctx, command, args, timeoutSeconds)
}

func (RootExecutor) Format(command string, args []string) string {
	return command + " " + strings.Join(args, " ")
}

func (SudoExecutor) Run(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error) {
	// -n: non-interactive (never prompt)
	all := append([]string{"-n", command}, args...)
	return ExecSimple(ctx, "sudo", all, timeoutSeconds)
}

func (SudoExecutor) Format(command string, args []string) string {
	return "sudo -n " + command + " " + strings.Join(args, " ")
}
