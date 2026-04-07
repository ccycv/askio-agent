package agent

import (
	"context"
	"encoding/base64"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

func (d *Daemon) handlePendingCommandV2(ctx context.Context, cmd *model.PendingCommand) {
	if cmd == nil {
		return
	}
	started := time.Now().UTC()
	result := model.CommandResult{
		ServerID:    d.cfg.ServerID,
		CommandID:   cmd.CommandID,
		CommandType: cmd.Type,
		Status:      "failed",
		StartedAt:   started,
	}

	timeout := time.Duration(cmd.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 300 * time.Second
	}

	mode := strings.ToLower(strings.TrimSpace(cmd.ExecutionMode))
	if mode == "" {
		mode = "live"
	}

	if cmd.CommandID == "" || cmd.Type == "" {
		result.Error = "missing command_id or type"
		d.finishAndPostCommandResult(ctx, result)
		return
	}

	if d.logger != nil {
		d.logger.Info("pending_command_v2 handling started",
			"type", cmd.Type,
			"command_id", cmd.CommandID,
			"timeout_seconds", cmd.TimeoutSeconds,
			"execution_mode", cmd.ExecutionMode,
			"capability", cmd.Capability,
			"server_id", cmd.ServerID,
		)
	}

	// Dry run: do not execute, just report planned action.
	if mode == "dry_run" {
		result.Status = "success"
		summary := fmt.Sprintf("[DRY RUN] would execute %s", cmd.Type)
		if cmd.Capability != "" {
			summary += " capability=" + cmd.Capability
		}
		result.Output = summary
		result.ExitCode = 0
		d.finishAndPostCommandResult(ctx, result)
		return
	}

	if cmd.Type == "generate_host_token" {
		d.handleGenerateHostToken(ctx, cmd, &result)
		return
	}

	script, err := decodeScriptB64(cmd.ScriptB64)
	if err != nil {
		result.Error = err.Error()
		d.finishAndPostCommandResult(ctx, result)
		return
	}

	// IMPORTANT:
	// If the agent runs under systemd with PrivateTmp=true, /tmp is namespaced.
	// Using DataDir ensures we can access the script file consistently, and it can
	// also be referenced by systemd-run units.
	scriptDir := d.cfg.DataDir
	if strings.TrimSpace(scriptDir) == "" {
		scriptDir = os.TempDir()
	}
	file := filepath.Join(scriptDir, fmt.Sprintf("askio-cmd-%s.sh", cmd.CommandID))
	_ = os.WriteFile(file, []byte(script), 0o700)
	if d.logger != nil {
		d.logger.Info("pending_command_v2 script written", "command_id", cmd.CommandID, "path", file, "bytes", len(script))
	}

	exec := d.remEngExec()
	exRes, execErr := exec.Run(ctx, "/bin/bash", []string{file}, int(timeout.Seconds()))
	if d.logger != nil {
		d.logger.Info("pending_command_v2 execution finished", "command_id", cmd.CommandID, "exit_code", exRes.ExitCode, "err", execErr)
	}
	result.Output = remediation.Redact(exRes.Output)
	result.ExitCode = exRes.ExitCode
	if execErr != nil {
		result.Status = "failed"
		result.Error = execErr.Error()
	} else {
		result.Status = "success"
	}
	result.FinishedAt = time.Now().UTC()
	result.DurationMS = result.FinishedAt.Sub(result.StartedAt).Milliseconds()

	if result.Status == "success" && cmd.Type == "install_capability" {
		// Refresh detected capabilities so the next heartbeat reflects the change quickly.
		d.refreshDetectedCapabilities()
	}
	if err := d.api.PostCommandResult(ctx, result); err != nil {
		if d.logger != nil {
			d.logger.Warn("post command_result failed", "command_id", cmd.CommandID, "err", err)
		}
	} else {
		if d.logger != nil {
			d.logger.Info("post command_result ok", "command_id", cmd.CommandID, "status", result.Status)
		}
	}
}

func (d *Daemon) handleGenerateHostToken(ctx context.Context, cmd *model.PendingCommand, result *model.CommandResult) {
	if d.cfg.Mode != "gateway" {
		result.Error = "generate_host_token only supported in gateway mode"
		d.finishAndPostCommandResult(ctx, *result)
		return
	}
	if d.cfg.Gateway == nil || strings.TrimSpace(d.cfg.Gateway.TokenHMACKey) == "" {
		result.Error = "gateway.token_hmac_key is required"
		d.finishAndPostCommandResult(ctx, *result)
		return
	}
	serverID := strings.TrimSpace(cmd.ServerID)
	if serverID == "" {
		result.Error = "server_id is required"
		d.finishAndPostCommandResult(ctx, *result)
		return
	}
	exp := time.Now().UTC().Add(24 * time.Hour)
	if cmd.ExpiresInSeconds > 0 {
		exp = time.Now().UTC().Add(time.Duration(cmd.ExpiresInSeconds) * time.Second)
	}
	expUnix := exp.Unix()
	msg := fmt.Sprintf("%s.%d", serverID, expUnix)
	mac := hmac.New(sha256.New, []byte(d.cfg.Gateway.TokenHMACKey))
	_, _ = mac.Write([]byte(msg))
	sig := fmt.Sprintf("%x", mac.Sum(nil))
	plain := fmt.Sprintf("%s.%d.%s", serverID, expUnix, sig)
	tok := base64.RawURLEncoding.EncodeToString([]byte(plain))

	// Post token to backend.
	tr := model.GatewayHostTokenResult{CommandID: cmd.CommandID, ServerID: serverID, Token: tok, ExpiresAt: exp}
	if err := d.api.PostGatewayHostTokenResult(ctx, tr); err != nil {
		result.Error = err.Error()
		d.finishAndPostCommandResult(ctx, *result)
		return
	}

	result.Status = "success"
	result.Output = "generated host token"
	result.ExitCode = 0
	d.finishAndPostCommandResult(ctx, *result)
}

func (d *Daemon) finishAndPostCommandResult(ctx context.Context, r model.CommandResult) {
	r.FinishedAt = time.Now().UTC()
	r.DurationMS = r.FinishedAt.Sub(r.StartedAt).Milliseconds()
	if err := d.api.PostCommandResult(ctx, r); err != nil {
		if d.logger != nil {
			d.logger.Warn("post command_result failed", "command_id", r.CommandID, "err", err)
		}
	}
}

func decodeScriptB64(b64 string) (string, error) {
	b64 = strings.TrimSpace(b64)
	if b64 == "" {
		return "", errors.New("script_b64 is required")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// try URL encoding
		b, err2 := base64.RawURLEncoding.DecodeString(b64)
		if err2 != nil {
			return "", fmt.Errorf("decode script_b64: %w", err)
		}
		return string(b), nil
	}
	return string(b), nil
}
