package operations

import (
	"context"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type StepExec struct {
	Exec remediation.Executor
}

func (s StepExec) Run(ctx context.Context, cmd string, args []string, timeout time.Duration) (remediation.ExecResult, error) {
	sec := int(timeout.Seconds())
	if sec <= 0 {
		sec = 30
	}
	return s.Exec.Run(ctx, cmd, args, sec)
}
