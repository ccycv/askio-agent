package operations

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type pkgHandler struct {
	exec StepExec
	op   string // install|remove|upgrade
}

func (h pkgHandler) ID() string { return "package." + h.op }

func (h pkgHandler) Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult {
	name := strings.TrimSpace(fmt.Sprint(params["name"]))

	// Minimal v1: apt-get only (Ubuntu/Debian). You can extend with yum/dnf detection later.
	var cmd string
	var args []string
	changed := true

	switch h.op {
	case "install":
		if name == "" {
			return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: name")}
		}
		cmd = "apt-get"
		args = []string{"install", "-y", name}
	case "remove":
		if name == "" {
			return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: name")}
		}
		cmd = "apt-get"
		args = []string{"remove", "-y", name}
	case "upgrade":
		cmd = "apt-get"
		if name == "" {
			args = []string{"upgrade", "-y"}
		} else {
			args = []string{"install", "-y", "--only-upgrade", name}
		}
	default:
		return HandlerResult{Status: "failed", Error: fmt.Errorf("unknown package op: %s", h.op)}
	}

	pretty := h.exec.Exec.Format(cmd, args)
	if mode.IsDryRun() {
		return HandlerResult{Status: "success", Output: "[DRY RUN] " + pretty, Changed: false}
	}

	exRes, err := h.exec.Run(ctx, cmd, args, 10*time.Minute)
	out := remediation.Redact(exRes.Output)
	if err != nil {
		return HandlerResult{Status: "failed", Output: out, Error: err, Changed: false}
	}
	return HandlerResult{Status: "success", Output: out, Changed: changed}
}

func PackageHandlers(exec StepExec) []Handler {
	ops := []string{"install", "remove", "upgrade"}
	out := make([]Handler, 0, len(ops))
	for _, op := range ops {
		out = append(out, pkgHandler{exec: exec, op: op})
	}
	return out
}
