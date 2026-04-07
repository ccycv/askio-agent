package remediation

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type ExecResult struct {
	ExitCode int
	Output   string
	Duration time.Duration
}

// ExecSimple runs a command with args, with timeoutSeconds. It captures combined output.
// No shell is used.
func ExecSimple(ctx context.Context, command string, args []string, timeoutSeconds int) (ExecResult, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	start := time.Now()
	err := cmd.Run()
	dur := time.Since(start)

	res := ExecResult{Output: out.String(), Duration: dur, ExitCode: 0}
	if ctx.Err() == context.DeadlineExceeded {
		res.ExitCode = 124
		return res, fmt.Errorf("command timeout: %s %s", command, strings.Join(args, " "))
	}
	if err != nil {
		if ee := (&exec.ExitError{}); err != nil && strings.Contains(err.Error(), "exit status") {
			// best-effort; ExitError is platform dependent
			_ = ee
		}
		if cmd.ProcessState != nil {
			res.ExitCode = cmd.ProcessState.ExitCode()
		} else {
			res.ExitCode = 1
		}
		return res, err
	}
	return res, nil
}
