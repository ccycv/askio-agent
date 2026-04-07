package operations

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type serviceHandler struct {
	exec StepExec
	op   string // start|stop|restart|reload|enable|disable|status
}

func (h serviceHandler) ID() string { return "service." + h.op }

func (h serviceHandler) Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult {
	name := fmt.Sprint(params["name"])
	name = strings.TrimSpace(name)
	if name == "" {
		return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: name")}
	}
	unit := name
	if !strings.HasSuffix(unit, ".service") {
		unit = unit + ".service"
	}

	cmd := "systemctl"
	args := []string{h.op, unit, "--no-pager"}
	if h.op == "status" {
		args = []string{"status", unit, "--no-pager"}
	}

	pretty := h.exec.Exec.Format(cmd, args)
	if mode.IsDryRun() {
		return HandlerResult{Status: "success", Output: "[DRY RUN] " + pretty, Changed: false}
	}

	exRes, err := h.exec.Run(ctx, cmd, args, 30*time.Second)
	out := remediation.Redact(exRes.Output)
	if err != nil {
		return HandlerResult{Status: "failed", Output: out, Error: err, Changed: false}
	}
	changed := h.op != "status"
	return HandlerResult{Status: "success", Output: out, Changed: changed}
}

func ServiceHandlers(exec StepExec) []Handler {
	ops := []string{"start", "stop", "restart", "reload", "enable", "disable", "status"}
	out := make([]Handler, 0, len(ops))
	for _, op := range ops {
		out = append(out, serviceHandler{exec: exec, op: op})
	}
	return out
}
