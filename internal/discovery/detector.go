package discovery

import (
	"context"
	"log/slog"
	"sort"

	"github.com/askio-cloud/askio-monitor/internal/model"
	dockerd "github.com/askio-cloud/askio-monitor/internal/discovery/docker"
	processd "github.com/askio-cloud/askio-monitor/internal/discovery/process"
	systemdd "github.com/askio-cloud/askio-monitor/internal/discovery/systemd"
)

type Detector struct {
	logger *slog.Logger
}

func NewDetector(logger *slog.Logger) *Detector {
	return &Detector{logger: logger}
}

func (d *Detector) Detect(ctx context.Context) ([]model.DiscoveredService, error) {
	var out []model.DiscoveredService

	systemd, err := systemdd.Detect(ctx)
	if err != nil {
		d.logger.Warn("systemd discovery failed", "err", err)
	} else {
		out = append(out, systemd...)
	}

	docker, err := dockerd.Detect(ctx)
	if err != nil {
		d.logger.Warn("docker discovery failed", "err", err)
	} else {
		out = append(out, docker...)
	}

	process, err := processd.Detect(ctx)
	if err != nil {
		d.logger.Warn("process discovery failed", "err", err)
	} else {
		out = append(out, process...)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
