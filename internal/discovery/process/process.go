package process

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

var wellKnown = map[string][]string{
	"nginx":      {"nginx"},
	"postgres":   {"postgres", "postgresql"},
	"mysql":      {"mysqld"},
	"redis":      {"redis-server"},
	"docker":     {"dockerd"},
	"sshd":       {"sshd"},
	"fail2ban":   {"fail2ban-server"},
	"caddy":      {"caddy"},
	"apache":     {"apache2", "httpd"},
	"traefik":    {"traefik"},
}

func Detect(ctx context.Context) ([]model.DiscoveredService, error) {
	// ps output: pid comm args
	res, err := remediation.ExecSimple(ctx, "ps", []string{"-eo", "pid,comm,args"}, 10)
	if err != nil {
		return nil, fmt.Errorf("ps failed: %w", err)
	}

	seen := map[string]model.DiscoveredService{}
	scanner := bufio.NewScanner(strings.NewReader(res.Output))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			if strings.Contains(strings.ToLower(line), "pid") {
				continue
			}
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		comm := fields[1]
		args := ""
		if len(fields) > 2 {
			args = strings.Join(fields[2:], " ")
		}

		for name, matches := range wellKnown {
			for _, m := range matches {
				if comm == m || strings.Contains(args, m) {
					if _, ok := seen[name]; !ok {
						seen[name] = model.DiscoveredService{
							Name: name,
							Type: model.ServiceTypeProcess,
							PID:  pid,
							State: "running",
							Meta: map[string]any{"comm": comm, "args": args},
						}
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	out := make([]model.DiscoveredService, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	return out, nil
}
