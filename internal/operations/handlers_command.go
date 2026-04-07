package operations

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

type commandRunHandler struct {
	exec StepExec
	cfg  *config.OperationsConfig
}

func (h commandRunHandler) ID() string { return "command.run" }

func (h commandRunHandler) Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult {
	// Mode 1 (preferred): exe + args
	exe := strings.TrimSpace(fmt.Sprint(params["exe"]))
	argsAny, _ := params["args"].([]any)

	// Mode 2 (gated): cmd + shell:true
	cmd := strings.TrimSpace(fmt.Sprint(params["cmd"]))
	shell := strings.ToLower(strings.TrimSpace(fmt.Sprint(params["shell"])))
	isShell := shell == "true" || shell == "1" || shell == "yes"

	// timeout (seconds)
	to := 30 * time.Second
	if v, ok := params["timeout_seconds"]; ok {
		if n, err := parseInt(fmt.Sprint(v)); err == nil && n > 0 {
			to = time.Duration(n) * time.Second
		}
	}

	if isShell {
		// shell path is gated by config
		allow := h.cfg != nil && h.cfg.AllowShell
		if !allow {
			return HandlerResult{Status: "failed", Error: fmt.Errorf("shell mode disabled (operations.allow_shell=false)")}
		}
		if cmd == "" {
			return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: cmd")}
		}
		if mode.IsDryRun() {
			return HandlerResult{Status: "success", Output: "[DRY RUN] /bin/bash -lc " + cmd, Changed: false}
		}
		ctx2, cancel := context.WithTimeout(ctx, to)
		defer cancel()
		exRes, err := h.exec.Run(ctx2, "/bin/bash", []string{"-lc", cmd}, to)
		out := remediation.Redact(exRes.Output)
		if err != nil {
			return HandlerResult{Status: "failed", Output: out, Error: err, Changed: false}
		}
		return HandlerResult{Status: "success", Output: out, Changed: true}
	}

	if exe == "" {
		return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: exe")}
	}
	exe = resolveExe(exe)
	if !isAllowedExe(h.cfg, exe) {
		return HandlerResult{Status: "failed", Error: fmt.Errorf("exe not allowed: %s", exe)}
	}

	args := make([]string, 0, len(argsAny))
	for _, a := range argsAny {
		args = append(args, fmt.Sprint(a))
	}

	if mode.IsDryRun() {
		return HandlerResult{Status: "success", Output: "[DRY RUN] " + exe + " " + strings.Join(args, " "), Changed: false}
	}

	ctx2, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	// note: no shell used here
	exRes, err := h.exec.Run(ctx2, exe, args, to)
	out := remediation.Redact(exRes.Output)
	if err != nil {
		return HandlerResult{Status: "failed", Output: out, Error: err, Changed: true}
	}
	return HandlerResult{Status: "success", Output: out, Changed: true}
}

func CommandHandlers(exec StepExec, cfg *config.OperationsConfig) []Handler {
	return []Handler{commandRunHandler{exec: exec, cfg: cfg}}
}

func resolveExe(exe string) string {
	// If given a bare name, keep it as-is; if a path, clean it.
	if strings.Contains(exe, "/") {
		return filepath.Clean(exe)
	}
	return exe
}

func isAllowedExe(cfg *config.OperationsConfig, exe string) bool {
	if cfg == nil || len(cfg.Allowlist) == 0 {
		return true
	}
	for _, allowed := range cfg.Allowlist {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		if exe == allowed {
			return true
		}
		// If allowlist contains a bare name, allow matching that too.
		if !strings.Contains(allowed, "/") && exe == allowed {
			return true
		}
		if !strings.Contains(allowed, "/") && filepath.Base(exe) == allowed {
			return true
		}
	}
	return false
}

func parseInt(s string) (int, error) {
	// small, dependency-free
	var n int
	neg := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

