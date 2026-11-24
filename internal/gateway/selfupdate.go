package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/version"
)

// Gateway self-update.
//
// A gateway holds the HMAC key that signs every host token behind it, so it
// never runs a backend-supplied script. It accepts exactly one typed command,
// update_agent, which names a binary URL, its SHA-256 and the release version.
// The gateway downloads the binary, refuses it unless both match, and hands it
// to the same privileged paths a host update uses: direct install when the
// gateway runs as root, the root-owned askio-monitor-updater path unit when it
// is installed, or the restricted askio-ops helper through sudo.

const (
	updateCommandType = "update_agent"
	minBinaryBytes    = 1_000_000
	maxBinaryBytes    = 512 << 20
	reinstallHint     = "Reinstall the gateway with the current Askio installer to restore remote updates."
)

var (
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)
)

type installMode string

const (
	installRoot    installMode = "root"
	installUpdater installMode = "updater"
	installHelper  installMode = "helper"
)

type selfUpdater struct {
	dataDir     string
	installPath string
	helperPath  string
	updaterDir  string
	updaterUnit string
	procStatus  string
	httpClient  *http.Client
	// allowInsecureURL permits http:// binary URLs (tests only).
	allowInsecureURL bool
	euid             func() int
	run              func(ctx context.Context, name string, args ...string) (string, error)
}

func newSelfUpdater(dataDir string) *selfUpdater {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "/var/lib/askio-monitor"
	}
	return &selfUpdater{
		dataDir:     dataDir,
		installPath: "/usr/local/bin/askio-monitor",
		helperPath:  "/usr/local/bin/askio-ops",
		updaterDir:  filepath.Join(dataDir, "update"),
		updaterUnit: "/etc/systemd/system/askio-monitor-updater.path",
		procStatus:  "/proc/self/status",
		httpClient:  &http.Client{Timeout: 4 * time.Minute},
		euid:        os.Geteuid,
		run:         runCommand,
	}
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// validate rejects anything but a well-formed typed update command.
func (u *selfUpdater) validate(cmd *model.PendingCommand) error {
	parsed, err := url.Parse(strings.TrimSpace(cmd.BinaryURL))
	if err != nil || parsed.Host == "" {
		return errors.New("update_agent requires a valid binary_url")
	}
	if parsed.Scheme != "https" && !(u.allowInsecureURL && parsed.Scheme == "http") {
		return errors.New("update_agent binary_url must use https")
	}
	if !sha256Pattern.MatchString(normalizeSHA256(cmd.BinarySHA256)) {
		return errors.New("update_agent requires a 64-character hex binary_sha256")
	}
	if !versionPattern.MatchString(strings.TrimSpace(cmd.TargetVersion)) {
		return errors.New("update_agent requires a target_version")
	}
	return nil
}

// reportedVersionPattern matches the first line of `askio-monitor --version`,
// whose compatibility contract is "askio-monitor version <Version>" followed
// by nothing or by " (build details)".
var reportedVersionPattern = regexp.MustCompile(`^askio-monitor version (\S+)(?: \(.*\))?$`)

// parseReportedVersion extracts <Version> so it can be compared exactly: a
// substring match would accept 0.4.41 for 0.4.4, or a prerelease for a
// stable release.
func parseReportedVersion(output string) (string, bool) {
	line := strings.TrimSpace(output)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	match := reportedVersionPattern.FindStringSubmatch(line)
	if match == nil {
		return "", false
	}
	return match[1], true
}

func normalizeSHA256(value string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", ":", "").Replace(strings.TrimSpace(value)))
}

// resolveMode picks how the binary will be installed before anything is downloaded.
func (u *selfUpdater) resolveMode() (installMode, error) {
	if u.euid() == 0 {
		return installRoot, nil
	}
	if fileExists(u.updaterUnit) && dirWritable(u.updaterDir) {
		return installUpdater, nil
	}
	if u.noNewPrivs() {
		return "", fmt.Errorf("the gateway process has the Linux no_new_privs flag set (systemd NoNewPrivileges=true, or a unit hardening option that implies it), so sudo cannot replace the binary, and the root-owned askio-monitor-updater is not installed. %s", reinstallHint)
	}
	if info, err := os.Stat(u.helperPath); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
		return installHelper, nil
	}
	return "", fmt.Errorf("the restricted helper %s is missing, so the gateway cannot replace its binary. %s", u.helperPath, reinstallHint)
}

func (u *selfUpdater) noNewPrivs() bool {
	data, err := os.ReadFile(u.procStatus)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:")) == "1"
		}
	}
	return false
}

// stageDir returns the first writable directory that allows execution. /tmp
// is never used: it is often mounted noexec and is private to the service.
func (u *selfUpdater) stageDir(ctx context.Context, mode installMode) (string, error) {
	candidates := []string{u.dataDir, filepath.Dir(u.installPath)}
	if mode == installUpdater {
		candidates = []string{u.updaterDir}
	}
	for _, dir := range candidates {
		if u.canExecIn(ctx, dir) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no writable directory that allows executing the downloaded binary was found (checked: %s). %s", strings.Join(candidates, ", "), reinstallHint)
}

func (u *selfUpdater) canExecIn(ctx context.Context, dir string) bool {
	if !dirWritable(dir) {
		return false
	}
	probe, err := os.CreateTemp(dir, ".askio-exec-probe.*")
	if err != nil {
		return false
	}
	name := probe.Name()
	defer os.Remove(name)
	_, writeErr := probe.WriteString("#!/bin/sh\nexit 0\n")
	closeErr := probe.Close()
	if writeErr != nil || closeErr != nil || os.Chmod(name, 0o700) != nil {
		return false
	}
	_, err = u.run(ctx, name)
	return err == nil
}

// prepare downloads and verifies the binary. On success the caller owns the
// staged file; on failure nothing is left behind.
func (u *selfUpdater) prepare(ctx context.Context, cmd *model.PendingCommand) (staged string, mode installMode, reported string, err error) {
	if err := u.validate(cmd); err != nil {
		return "", "", "", err
	}
	mode, err = u.resolveMode()
	if err != nil {
		return "", "", "", err
	}
	dir, err := u.stageDir(ctx, mode)
	if err != nil {
		return "", "", "", err
	}

	var file *os.File
	if mode == installUpdater {
		staged = filepath.Join(u.updaterDir, "askio-monitor.new")
		_ = os.Remove(staged)
		file, err = os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	} else {
		file, err = os.CreateTemp(dir, "askio-monitor-new.*")
	}
	if err != nil {
		return "", "", "", fmt.Errorf("stage download in %s: %w", dir, err)
	}
	staged = file.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(staged)
			staged = ""
		}
	}()

	sum, size, err := u.download(ctx, cmd.BinaryURL, file)
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return staged, "", "", err
	}
	if size < minBinaryBytes {
		return staged, "", "", fmt.Errorf("downloaded file too small (%d bytes) - not a valid binary", size)
	}
	if sum != normalizeSHA256(cmd.BinarySHA256) {
		return staged, "", "", errors.New("checksum verification failed for downloaded binary")
	}
	if err = os.Chmod(staged, 0o700); err != nil {
		return staged, "", "", err
	}
	versionOut, runErr := u.run(ctx, staged, "--version")
	if runErr != nil {
		err = fmt.Errorf("the downloaded binary could not be executed from %s for its version check: %v %s", dir, runErr, strings.TrimSpace(versionOut))
		return staged, "", "", err
	}
	reportedVersion, ok := parseReportedVersion(versionOut)
	if !ok || reportedVersion != strings.TrimSpace(cmd.TargetVersion) {
		err = fmt.Errorf("new binary verification failed - version mismatch (want %s, binary reports %q)", strings.TrimSpace(cmd.TargetVersion), strings.TrimSpace(versionOut))
		return staged, "", "", err
	}
	return staged, mode, strings.TrimSpace(versionOut), nil
}

func (u *selfUpdater) download(ctx context.Context, binaryURL string, dst io.Writer) (string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "askio-monitor-gateway/"+version.Version)
	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("download of the agent binary failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("download of the agent binary failed: status=%d", resp.StatusCode)
	}
	hasher := sha256.New()
	size, err := io.Copy(io.MultiWriter(dst, hasher), io.LimitReader(resp.Body, maxBinaryBytes+1))
	if err != nil {
		return "", size, fmt.Errorf("download of the agent binary failed: %w", err)
	}
	if size > maxBinaryBytes {
		return "", size, errors.New("downloaded file exceeds the maximum agent binary size")
	}
	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// apply installs the staged binary and restarts the service. A successful
// restart stops this process, so callers report the result beforehand.
func (u *selfUpdater) apply(ctx context.Context, staged string, mode installMode, commandID string) error {
	switch mode {
	case installUpdater:
		return os.WriteFile(filepath.Join(u.updaterDir, "request"), []byte(commandID+"\n"), 0o600)
	case installHelper:
		if out, err := u.run(ctx, "sudo", "-n", u.helperPath, "self-update", staged); err != nil {
			return fmt.Errorf("askio-ops self-update failed: %v %s", err, strings.TrimSpace(out))
		}
		return nil
	case installRoot:
		install := []string{"/usr/bin/install", "-o", "root", "-g", "root", "-m", "0755", staged, u.installPath}
		if !dirWritable(filepath.Dir(u.installPath)) {
			// Inside the service's ProtectSystem sandbox: install from a transient unit.
			install = append([]string{"systemd-run", "--wait", "--collect", "--quiet"}, install...)
		}
		if out, err := u.run(ctx, install[0], install[1:]...); err != nil {
			return fmt.Errorf("install of the new binary failed: %v %s", err, strings.TrimSpace(out))
		}
		_ = os.Remove(staged)
		if out, err := u.run(ctx, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("systemctl daemon-reload failed: %v %s", err, strings.TrimSpace(out))
		}
		if out, err := u.run(ctx, "systemctl", "restart", "--no-block", "askio-monitor"); err != nil {
			return fmt.Errorf("systemctl restart failed: %v %s", err, strings.TrimSpace(out))
		}
		return nil
	default:
		return fmt.Errorf("unknown install mode %q", mode)
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirWritable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	probe, err := os.CreateTemp(dir, ".askio-write-probe.*")
	if err != nil {
		return false
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return true
}

// handleSelfUpdate runs a typed update_agent command and reports its result.
func (s *Server) handleSelfUpdate(ctx context.Context, cmd *model.PendingCommand) {
	started := time.Now().UTC()
	result := model.CommandResult{
		ServerID:    s.gatewayServerID,
		CommandID:   cmd.CommandID,
		CommandType: updateCommandType,
		Status:      "failed",
		ExitCode:    1,
		StartedAt:   started,
	}
	post := func() {
		result.FinishedAt = time.Now().UTC()
		result.DurationMS = result.FinishedAt.Sub(result.StartedAt).Milliseconds()
		_ = s.postCommandResult(ctx, result)
	}
	fail := func(err error) {
		result.Status = "failed"
		result.ExitCode = 1
		result.Error = err.Error()
		result.Output = err.Error()
		post()
	}

	if strings.EqualFold(strings.TrimSpace(cmd.ExecutionMode), "dry_run") {
		result.Status, result.ExitCode = "success", 0
		result.Output = "[DRY RUN] would update the gateway to " + cmd.TargetVersion
		post()
		return
	}
	if strings.TrimSpace(cmd.TargetVersion) == version.Version {
		result.Status, result.ExitCode = "success", 0
		result.Output = "Gateway already runs " + version.Version
		post()
		return
	}

	timeout := time.Duration(cmd.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	staged, mode, newVersion, err := s.updater.prepare(runCtx, cmd)
	if err != nil {
		fail(err)
		return
	}
	result.Status, result.ExitCode = "success", 0
	result.Output = fmt.Sprintf("Binary verified (%s -> %s). Installing through %s and restarting...", version.Version, newVersion, mode)
	post()
	if err := s.updater.apply(runCtx, staged, mode, cmd.CommandID); err != nil {
		if mode != installUpdater {
			_ = os.Remove(staged)
		}
		fail(err)
	}
}

func (s *Server) postCommandResult(ctx context.Context, result model.CommandResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	ep := *s.cloudBase
	ep.Path = strings.TrimRight(ep.Path, "/") + "/monitor-agent-command-result"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cloudToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "askio-monitor-gateway/"+version.Version)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("post command result failed: status=%d", resp.StatusCode)
	}
	return nil
}
