package agent

import (
	"fmt"
	"strings"
)

type Command struct {
	Kind       string
	PlaybookID string
	IncidentID string
	MonitorID  string
	Raw        string
}

func ParsePendingCommand(s string) (Command, bool, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Command{}, false, nil
	}
	c := Command{Raw: s}

	if s == "discover_services" {
		c.Kind = "discover_services"
		return c, true, nil
	}

	if strings.HasPrefix(s, "run_playbook:") {
		// expected: run_playbook:<playbook_id>:<incident_id>:<monitor_id>
		parts := strings.Split(s, ":")
		if len(parts) < 4 {
			return Command{}, true, fmt.Errorf("invalid run_playbook command format")
		}
		c.Kind = "run_playbook"
		c.PlaybookID = normalizePlaybookID(parts[1])
		c.IncidentID = parts[2]
		c.MonitorID = parts[3]
		return c, true, nil
	}

	return Command{}, true, fmt.Errorf("unknown pending_command: %q", s)
}

func normalizePlaybookID(id string) string {
	id = strings.TrimSpace(id)
	// UI/backends sometimes use friendlier names; map to built-in IDs.
	aliases := map[string]string{
		"restart_nginx": "systemd_restart",
		"restart":       "systemd_restart",
		"reload_nginx":  "nginx_test_reload",
	}
	if v, ok := aliases[id]; ok {
		return v
	}
	return id
}
