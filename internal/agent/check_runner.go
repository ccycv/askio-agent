package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/checks"
	"github.com/askio-cloud/askio-monitor/internal/model"
)

func RunSingleCheck(ctx context.Context, logger *slog.Logger, m model.MonitorConfig) (model.CheckResult, error) {
	start := time.Now()
	res := model.CheckResult{
		MonitorID:   m.ID,
		CheckedAt:   time.Now().UTC(),
		Status:      model.StatusOK,
		Details:     map[string]any{},
		ServiceName: m.ServiceName,
		ServiceType: m.ServiceType,
	}

	var worst model.CheckStatus = model.StatusOK
	var activeState string

	for _, ct := range m.CheckTypes {
		switch ct {
		case model.CheckTypeActiveState:
			state, ok, det, err := checks.ActiveState(ctx, m)
			if err != nil {
				logger.Warn("active_state check error", "monitor", m.ID, "err", err)
				res.Details["active_state_error"] = err.Error()
				worst = maxStatus(worst, model.StatusWarning)
				continue
			}
			activeState = state
			res.ActiveState = state
			res.Details["active_state"] = det
			if !ok {
				worst = maxStatus(worst, model.StatusCritical)
			}
		case model.CheckTypePort:
			if m.Port <= 0 {
				worst = maxStatus(worst, model.StatusWarning)
				res.Details["port"] = map[string]any{"error": "port not configured"}
				continue
			}
			open, lat, err := checks.PortOpen(ctx, "127.0.0.1", m.Port, 2*time.Second)
			if err != nil {
				worst = maxStatus(worst, model.StatusWarning)
				res.Details["port"] = map[string]any{"port": m.Port, "error": err.Error()}
				continue
			}
			res.Details["port"] = map[string]any{"port": m.Port, "open": open, "latency_ms": lat}
			if !open {
				worst = maxStatus(worst, model.StatusCritical)
			}
		case model.CheckTypeHTTP:
			if m.HTTPEndpoint == "" {
				worst = maxStatus(worst, model.StatusWarning)
				res.Details["http"] = map[string]any{"error": "http_endpoint not configured"}
				continue
			}
			h, err := checks.HTTPGet(ctx, m.HTTPEndpoint, 4*time.Second)
			if err != nil {
				worst = maxStatus(worst, model.StatusWarning)
				res.Details["http"] = map[string]any{"url": m.HTTPEndpoint, "error": err.Error()}
				continue
			}
			res.Details["http"] = map[string]any{"url": m.HTTPEndpoint, "status_code": h.StatusCode, "latency_ms": h.LatencyMS, "body_prefix": h.BodyPrefix}
			if h.StatusCode < 200 || h.StatusCode >= 300 {
				worst = maxStatus(worst, model.StatusCritical)
			}
		default:
			logger.Warn("unknown check type", "check_type", ct, "monitor", m.ID)
			worst = maxStatus(worst, model.StatusWarning)
		}
	}

	res.Status = worst
	res.LatencyMS = time.Since(start).Milliseconds()
	if activeState != "" {
		res.ActiveState = activeState
	}
	return res, nil
}

func maxStatus(a, b model.CheckStatus) model.CheckStatus {
	order := map[model.CheckStatus]int{model.StatusOK: 0, model.StatusWarning: 1, model.StatusCritical: 2}
	if order[b] > order[a] {
		return b
	}
	return a
}
