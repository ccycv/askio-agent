package remediation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

var ErrPlaybookNotAllowed = errors.New("playbook not allowed")

type Engine struct {
	logger *slog.Logger
	exec   Executor
	books  map[string]Playbook
}

func (e *Engine) IDs() []string {
	ids := make([]string, 0, len(e.books))
	for id := range e.books {
		ids = append(ids, id)
	}
	return ids
}

func NewEngine(logger *slog.Logger, exec Executor) *Engine {
	m := map[string]Playbook{}
	for _, pb := range BuiltInPlaybooks() {
		m[pb.ID] = pb
	}
	return &Engine{logger: logger, exec: exec, books: m}
}

func (e *Engine) Get(id string) (Playbook, bool) {
	pb, ok := e.books[id]
	return pb, ok
}

func (e *Engine) Run(ctx context.Context, m model.MonitorConfig, playbookID string, trigger string) (model.RemediationRunLog, error) {
	pb, ok := e.books[playbookID]
	if !ok {
		return model.RemediationRunLog{}, fmt.Errorf("unknown playbook: %s", playbookID)
	}
	if !allowedForMonitor(m, pb, trigger) {
		return model.RemediationRunLog{}, ErrPlaybookNotAllowed
	}

	started := time.Now().UTC()
	run := model.RemediationRunLog{
		ServerID:   "", // filled by daemon when posting
		MonitorID:  m.ID,
		PlaybookID: pb.ID,
		Trigger:    trigger,
		StartedAt:  started,
		Steps:      []model.RemediationStepResult{},
	}

	vars := map[string]string{
		"unit":      unitFor(m),
		"container": containerFor(m),
	}

	success := true
	for _, step := range pb.Steps {
		cmd, args := render(step.Command, step.Args, vars)
		pretty := e.exec.Format(cmd, args)
		e.logger.Info("remediation step", "monitor", m.ID, "playbook", pb.ID, "cmd", pretty)

		exRes, err := e.exec.Run(ctx, cmd, args, step.TimeoutSeconds)
		out := Redact(exRes.Output)
		stepRes := model.RemediationStepResult{
			Order:      step.Order,
			Command:    pretty,
			ExitCode:   exRes.ExitCode,
			Output:     out,
			DurationMS: exRes.Duration.Milliseconds(),
		}
		run.Steps = append(run.Steps, stepRes)

		if err != nil {
			success = false
			e.logger.Warn("remediation step failed", "monitor", m.ID, "playbook", pb.ID, "cmd", pretty, "err", err)
			if strings.ToLower(step.FailAction) != "continue" {
				break
			}
		}
	}

	// Verification
	if pb.Verify != nil {
		cmd, args := render(pb.Verify.Command, pb.Verify.Args, vars)
		exRes, err := e.exec.Run(ctx, cmd, args, pb.Verify.TimeoutSeconds)
		out := strings.TrimSpace(Redact(exRes.Output))
		verOK := err == nil
		if pb.Verify.ExpectedOutput != "" {
			verOK = verOK && strings.Contains(out, pb.Verify.ExpectedOutput)
		}
		run.Verification = map[string]any{"command": e.exec.Format(cmd, args), "output": out, "success": verOK}
		if !verOK {
			success = false
		}
	}

	run.Success = success
	run.FinishedAt = time.Now().UTC()
	return run, nil
}

func allowedForMonitor(m model.MonitorConfig, pb Playbook, trigger string) bool {
	// For auto-remediation, require it to be enabled on the monitor.
	// For manual/UI-triggered runs, we allow execution even if auto-remediation is disabled,
	// but still enforce allowlists and service type matching.
	if trigger == "auto" && !m.RemediationEnabled {
		return false
	}
	if len(m.AllowedPlaybookIDs) > 0 {
		allowed := false
		for _, id := range m.AllowedPlaybookIDs {
			if id == pb.ID {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	okType := false
	for _, t := range pb.ServiceTypes {
		if t == m.ServiceType {
			okType = true
			break
		}
	}
	if !okType {
		return false
	}
	if len(pb.ApplicableServices) > 0 {
		for _, s := range pb.ApplicableServices {
			if strings.EqualFold(s, m.ServiceName) {
				return true
			}
		}
		return false
	}
	return true
}

func render(cmd string, args []string, vars map[string]string) (string, []string) {
	r := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, "{"+k+"}", v)
		}
		return s
	}

	outArgs := make([]string, 0, len(args))
	for _, a := range args {
		outArgs = append(outArgs, r(a))
	}
	return r(cmd), outArgs
}

func unitFor(m model.MonitorConfig) string {
	if m.SystemdUnit != "" {
		return m.SystemdUnit
	}
	if m.ServiceName != "" {
		return m.ServiceName + ".service"
	}
	return ""
}

func containerFor(m model.MonitorConfig) string {
	if m.DockerContainerID != "" {
		return m.DockerContainerID
	}
	return m.ServiceName
}
