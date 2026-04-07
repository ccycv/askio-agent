package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

func ActiveState(ctx context.Context, m model.MonitorConfig) (state string, ok bool, details map[string]any, err error) {
	details = map[string]any{}
	switch m.ServiceType {
	case model.ServiceTypeSystemd:
		unit := m.SystemdUnit
		if unit == "" {
			unit = m.ServiceName + ".service"
		}
		res, err := remediation.ExecSimple(ctx, "systemctl", []string{"is-active", unit, "--no-pager"}, 10)
		state = strings.TrimSpace(res.Output)
		details["unit"] = unit
		details["raw"] = strings.TrimSpace(res.Output)
		if err != nil {
			// systemctl prints state even for non-active.
			if state == "" {
				state = "unknown"
			}
			return state, false, details, nil
		}
		return state, state == "active", details, nil
	case model.ServiceTypeDocker:
		id := m.DockerContainerID
		if id == "" {
			id = m.ServiceName
		}
		res, err := remediation.ExecSimple(ctx, "docker", []string{"inspect", "--format", "{{.State.Running}}", id}, 10)
		state = strings.TrimSpace(res.Output)
		details["container_id"] = id
		if err != nil {
			if state == "" {
				state = "unknown"
			}
			return state, false, details, nil
		}
		return state, state == "true", details, nil
	case model.ServiceTypeProcess:
		// process fallback: check pid exists, otherwise attempt match via pgrep -f.
		if m.ProcessMatch != "" {
			res, err := remediation.ExecSimple(ctx, "pgrep", []string{"-f", m.ProcessMatch}, 5)
			state = "running"
			details["process_match"] = m.ProcessMatch
			if err != nil || strings.TrimSpace(res.Output) == "" {
				state = "not_running"
				return state, false, details, nil
			}
			return state, true, details, nil
		}
		return "unknown", false, details, fmt.Errorf("process monitor missing process_match")
	default:
		return "unknown", false, details, fmt.Errorf("unsupported service type: %s", m.ServiceType)
	}
}
