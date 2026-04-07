package operations

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/checks"
)

type httpCheckHandler struct{}

type portCheckHandler struct{}

func (h httpCheckHandler) ID() string { return "http.check" }
func (h portCheckHandler) ID() string { return "port.check" }

func (h httpCheckHandler) Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult {
	url := strings.TrimSpace(fmt.Sprint(params["url"]))
	if url == "" {
		return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: url")}
	}
	expect := 200
	if v, ok := params["expect_status"]; ok {
		if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
			expect = n
		}
	}
	to := 10 * time.Second
	if v, ok := params["timeout"]; ok {
		if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
			to = time.Duration(n) * time.Second
		}
	}

	if mode.IsDryRun() {
		return HandlerResult{Status: "success", Output: fmt.Sprintf("[DRY RUN] http.check %s expect=%d", url, expect), Changed: false}
	}

	ctx2, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	r, err := checks.HTTPGet(ctx2, url, to)
	if err != nil {
		return HandlerResult{Status: "failed", Output: err.Error(), Error: err, Changed: false}
	}
	if r.StatusCode != expect {
		err := fmt.Errorf("unexpected status: got=%d want=%d", r.StatusCode, expect)
		return HandlerResult{Status: "failed", Output: err.Error(), Error: err, Changed: false}
	}
	return HandlerResult{Status: "success", Output: fmt.Sprintf("ok status=%d latency_ms=%d", r.StatusCode, r.LatencyMS), Changed: false}
}

func (h portCheckHandler) Execute(ctx context.Context, params map[string]any, mode ExecutionMode) HandlerResult {
	host := strings.TrimSpace(fmt.Sprint(params["host"]))
	if host == "" {
		host = "localhost"
	}
	portStr := strings.TrimSpace(fmt.Sprint(params["port"]))
	if portStr == "" {
		return HandlerResult{Status: "failed", Error: fmt.Errorf("missing param: port")}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return HandlerResult{Status: "failed", Error: fmt.Errorf("invalid port")}
	}
	to := 5 * time.Second
	if v, ok := params["timeout"]; ok {
		if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
			to = time.Duration(n) * time.Second
		}
	}

	if mode.IsDryRun() {
		return HandlerResult{Status: "success", Output: fmt.Sprintf("[DRY RUN] port.check %s:%d", host, port), Changed: false}
	}

	ctx2, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	open, lat, err := checks.PortOpen(ctx2, host, port, to)
	if err != nil {
		return HandlerResult{Status: "failed", Output: err.Error(), Error: err, Changed: false}
	}
	if !open {
		err := fmt.Errorf("port closed")
		return HandlerResult{Status: "failed", Output: err.Error(), Error: err, Changed: false}
	}
	return HandlerResult{Status: "success", Output: fmt.Sprintf("open latency_ms=%d", lat), Changed: false}
}

func CheckHandlers() []Handler {
	return []Handler{httpCheckHandler{}, portCheckHandler{}}
}
