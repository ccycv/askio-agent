package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

// We use the docker CLI to keep dependency footprint small.

type dockerPSRow struct {
	ID      string `json:"ID"`
	Image   string `json:"Image"`
	Names   string `json:"Names"`
	Status  string `json:"Status"`
	Ports   string `json:"Ports"`
}

func Detect(ctx context.Context) ([]model.DiscoveredService, error) {
	_, err := remediation.ExecSimple(ctx, "docker", []string{"version"}, 5)
	if err != nil {
		return nil, fmt.Errorf("docker not available: %w", err)
	}

	res, err := remediation.ExecSimple(ctx, "docker", []string{"ps", "--format", "{{json .}}"}, 10)
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
		var row dockerPSRow
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		name := row.Names
		if name == "" {
			name = row.ID
		}
		out = append(out, model.DiscoveredService{
			Name:  name,
			Type:  model.ServiceTypeDocker,
			State: row.Status,
			Meta: map[string]any{
				"container_id": row.ID,
				"image":        row.Image,
				"ports":        row.Ports,
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
