package systemd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

func Detect(ctx context.Context) ([]model.DiscoveredService, error) {
	// Fast check: systemctl exists and responds.
	_, err := remediation.ExecSimple(ctx, "systemctl", []string{"--no-pager", "--version"}, 5)
	if err != nil {
		return nil, fmt.Errorf("systemctl not available: %w", err)
	}

	res, err := remediation.ExecSimple(ctx, "systemctl", []string{"list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"}, 10)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(res.Output))
	var out []model.DiscoveredService
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Example:
		// nginx.service loaded active running A high performance web server and a reverse proxy server
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		unit := fields[0]
		active := fields[2]
		sub := fields[3]
		name := strings.TrimSuffix(unit, ".service")

		pid, _ := mainPID(ctx, unit)
		out = append(out, model.DiscoveredService{
			Name:  name,
			Type:  model.ServiceTypeSystemd,
			Unit:  unit,
			PID:   pid,
			State: active + "/" + sub,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func mainPID(ctx context.Context, unit string) (int, error) {
	res, err := remediation.ExecSimple(ctx, "systemctl", []string{"show", unit, "--property=MainPID", "--value", "--no-pager"}, 5)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(res.Output)
	if s == "" {
		return 0, nil
	}
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, nil
	}
	if pid < 0 {
		return 0, errors.New("invalid pid")
	}
	return pid, nil
}
