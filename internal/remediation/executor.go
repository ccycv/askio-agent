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
	return ExecSimple(ctx, "sudo", all, timeoutSeconds)
}

func (SystemdRunExecutor) Format(command string, args []string) string {
	return "sudo -n systemd-run --wait --collect --pipe --quiet --unit askio-cmd-<ts> " + command + " " + strings.Join(args, " ")
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
