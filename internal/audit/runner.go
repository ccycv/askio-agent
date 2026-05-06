package audit

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
)

const maxRawOutputBytes = 200_000

type commandRunner interface {
	Run(ctx context.Context, command string, args []string, timeoutSeconds int) (remediation.ExecResult, error)
	Format(command string, args []string) string
}

type Runner struct {
	exec commandRunner
}

type commandSpec struct {
	Name            string
	Command         string
	Args            []string
	TimeoutSeconds  int
	AcceptExitCodes []int
	Optional        bool
}

type commandOutput struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

func (s commandSpec) acceptsExitCode(code int) bool {
	if len(s.AcceptExitCodes) == 0 {
		return code == 0
	}
	for _, accepted := range s.AcceptExitCodes {
		if code == accepted {
			return true
		}
	}
	return false
}

func NewRunner(exec commandRunner) *Runner {
	return &Runner{exec: exec}
}

func (r *Runner) Execute(ctx context.Context, job model.PendingAuditJob, serverID string) model.AuditAgentResult {
	started := time.Now().UTC()
	result := model.AuditAgentResult{
		RunID:     job.RunID,
		ServerID:  firstNonEmpty(serverID, job.Target.ServerID),
		AgentID:   job.Target.AgentID,
		StartedAt: started,
	}

	timeout := job.TimeoutSeconds
	if timeout <= 0 {
		timeout = 900
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	for _, check := range job.Checks {
		result.Results = append(result.Results, r.executeCheck(ctx, check, job.RedactionRules))
	}
	result.FinishedAt = time.Now().UTC()
	return result
}

func (r *Runner) executeCheck(ctx context.Context, check model.AuditCheckDefinition, rules model.AuditRedactionRules) model.AuditCheckResult {
	started := time.Now().UTC()
	res := model.AuditCheckResult{
		CheckKey:          check.CheckKey,
		CheckDefinitionID: check.ID,
		Status:            "unknown",
		Severity:          normalizeSeverity(check.Severity),
		Confidence:        0.5,
		StartedAt:         started,
	}

	if !check.ReadOnly {
		res.Errors = []string{"check definition is not read-only"}
		res.FinishedAt = time.Now().UTC()
		res.Normalized = map[string]any{"summary": "Audit check was rejected because it is not read-only."}
		return res
	}

	specs, ok := commandRegistry()[check.CheckKey]
	if !ok {
		res.Status = "not_applicable"
		res.Confidence = 1
		res.Normalized = map[string]any{"summary": "No local Linux executor is available for this audit check yet."}
		res.FinishedAt = time.Now().UTC()
		res.EvidenceItems = evidenceFor(check, res.RawResultJSON, res.Normalized)
		return res
	}

	outputs := make([]commandOutput, 0, len(specs))
	for _, spec := range specs {
		out := r.runCommand(ctx, spec, rules)
		outputs = append(outputs, out)
		if out.Error != "" {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %s", spec.Name, out.Error))
		}
	}

	raw := map[string]any{"commands": outputs}
	status, confidence, normalized := normalizeCheck(check.CheckKey, outputs)
	res.Status = status
	res.Confidence = confidence
	res.RawResultJSON = raw
	res.RawOutput = raw
	res.Normalized = normalized
	res.FinishedAt = time.Now().UTC()
	res.EvidenceItems = evidenceFor(check, raw, normalized)
	return res
}

func (r *Runner) runCommand(ctx context.Context, spec commandSpec, rules model.AuditRedactionRules) commandOutput {
	started := time.Now()
	output := commandOutput{
		Name:    spec.Name,
		Command: r.exec.Format(spec.Command, spec.Args),
	}
	execRes, err := r.exec.Run(ctx, spec.Command, spec.Args, spec.TimeoutSeconds)
	output.ExitCode = execRes.ExitCode
	output.Output = redactAndTruncate(execRes.Output, rules)
	output.DurationMS = execRes.Duration.Milliseconds()
	if output.DurationMS == 0 {
		output.DurationMS = time.Since(started).Milliseconds()
	}
	if err != nil && !spec.acceptsExitCode(output.ExitCode) && !(spec.Optional && output.ExitCode == 1) {
		output.Error = err.Error()
	}
	return output
}

func commandRegistry() map[string][]commandSpec {
	return map[string][]commandSpec{
		"ssh_root_login":               {{Name: "sshd_effective_config", Command: "sshd", Args: []string{"-T"}, TimeoutSeconds: 10}, {Name: "sshd_config", Command: "cat", Args: []string{"/etc/ssh/sshd_config"}, TimeoutSeconds: 10}},
		"ssh_password_auth":            {{Name: "sshd_effective_config", Command: "sshd", Args: []string{"-T"}, TimeoutSeconds: 10}, {Name: "sshd_config", Command: "cat", Args: []string{"/etc/ssh/sshd_config"}, TimeoutSeconds: 10}},
		"ssh_weak_ciphers_manual":      {{Name: "sshd_config", Command: "cat", Args: []string{"/etc/ssh/sshd_config"}, TimeoutSeconds: 10}},
		"sudo_users":                   {{Name: "sudo_group", Command: "getent", Args: []string{"group", "sudo"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 2}, Optional: true}, {Name: "admin_group", Command: "getent", Args: []string{"group", "admin"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 2}, Optional: true}, {Name: "wheel_group", Command: "getent", Args: []string{"group", "wheel"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 2}, Optional: true}},
		"inactive_users_manual":        {{Name: "passwd", Command: "getent", Args: []string{"passwd"}, TimeoutSeconds: 10}},
		"missing_mfa_manual":           []commandSpec{},
		"public_ssh":                   {{Name: "listening_sockets", Command: "ss", Args: []string{"-tulpn"}, TimeoutSeconds: 15}},
		"public_postgresql":            {{Name: "listening_sockets", Command: "ss", Args: []string{"-tulpn"}, TimeoutSeconds: 15}},
		"public_mysql":                 {{Name: "listening_sockets", Command: "ss", Args: []string{"-tulpn"}, TimeoutSeconds: 15}},
		"public_redis":                 {{Name: "listening_sockets", Command: "ss", Args: []string{"-tulpn"}, TimeoutSeconds: 15}},
		"public_docker_socket":         {{Name: "docker_socket", Command: "ls", Args: []string{"-l", "/var/run/docker.sock"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 2}, Optional: true}, {Name: "listening_sockets", Command: "ss", Args: []string{"-tulpn"}, TimeoutSeconds: 15}},
		"unexpected_listening_ports":   {{Name: "listening_sockets", Command: "ss", Args: []string{"-tulpn"}, TimeoutSeconds: 15}},
		"pending_security_updates":     {{Name: "apt_upgradable", Command: "apt", Args: []string{"list", "--upgradable"}, TimeoutSeconds: 60}, {Name: "dnf_updates", Command: "dnf", Args: []string{"check-update", "--security"}, TimeoutSeconds: 60, AcceptExitCodes: []int{0, 1, 100}, Optional: true}},
		"reboot_required":              {{Name: "reboot_required", Command: "test", Args: []string{"-f", "/var/run/reboot-required"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 1}}},
		"unsupported_os_version":       {{Name: "os_release", Command: "cat", Args: []string{"/etc/os-release"}, TimeoutSeconds: 10}, {Name: "hostnamectl", Command: "hostnamectl", Args: []string{}, TimeoutSeconds: 10}},
		"unattended_upgrades_disabled": {{Name: "unattended_upgrades", Command: "systemctl", Args: []string{"is-enabled", "unattended-upgrades"}, TimeoutSeconds: 10}},
		"time_sync_disabled":           {{Name: "timedatectl", Command: "timedatectl", Args: []string{}, TimeoutSeconds: 10}},
		"askio_agent_offline":          {{Name: "askio_monitor_status", Command: "systemctl", Args: []string{"is-active", "askio-monitor"}, TimeoutSeconds: 10}},
		"failed_systemd_services":      {{Name: "failed_systemd", Command: "systemctl", Args: []string{"--failed", "--no-pager", "--plain"}, TimeoutSeconds: 20}},
		"auth_log_missing":             {{Name: "auth_log", Command: "test", Args: []string{"-r", "/var/log/auth.log"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 1}, Optional: true}, {Name: "secure_log", Command: "test", Args: []string{"-r", "/var/log/secure"}, TimeoutSeconds: 10, AcceptExitCodes: []int{0, 1}, Optional: true}, {Name: "sshd_journal", Command: "journalctl", Args: []string{"-u", "sshd", "-n", "50", "--no-pager"}, TimeoutSeconds: 20, AcceptExitCodes: []int{0, 1}, Optional: true}},
		"failed_login_spike":           {{Name: "auth_log_tail", Command: "tail", Args: []string{"-n", "500", "/var/log/auth.log"}, TimeoutSeconds: 20, AcceptExitCodes: []int{0, 1}, Optional: true}, {Name: "secure_log_tail", Command: "tail", Args: []string{"-n", "500", "/var/log/secure"}, TimeoutSeconds: 20, AcceptExitCodes: []int{0, 1}, Optional: true}, {Name: "sshd_journal_tail", Command: "journalctl", Args: []string{"-u", "sshd", "-n", "500", "--no-pager"}, TimeoutSeconds: 30, AcceptExitCodes: []int{0, 1}, Optional: true}},
		"disk_usage_critical":          {{Name: "disk_usage", Command: "df", Args: []string{"-P"}, TimeoutSeconds: 15}},
		"backup_not_detected":          {{Name: "cron_daily", Command: "ls", Args: []string{"-la", "/etc/cron.daily"}, TimeoutSeconds: 10}, {Name: "timers", Command: "systemctl", Args: []string{"list-timers", "--all", "--no-pager"}, TimeoutSeconds: 20}},
		"backup_older_than_threshold":  {{Name: "backup_dirs", Command: "find", Args: []string{"/var/backups", "-maxdepth", "2", "-type", "f", "-printf", "%TY-%Tm-%Td %TH:%TM %p\n"}, TimeoutSeconds: 30}},
		"restore_test_missing_manual":  []commandSpec{},
		"tls_certificate_expiring":     {{Name: "certbot_certificates", Command: "certbot", Args: []string{"certificates"}, TimeoutSeconds: 30, Optional: true}},
		"weak_tls_manual":              {{Name: "nginx_config_test", Command: "nginx", Args: []string{"-T"}, TimeoutSeconds: 30}},
		"dns_points_unknown_ip":        []commandSpec{},
		"cloudflare_proxy_disabled":    []commandSpec{},
		"origin_exposed_manual":        []commandSpec{},
	}
}

func normalizeCheck(checkKey string, outputs []commandOutput) (string, float64, map[string]any) {
	combined := strings.ToLower(joinOutputs(outputs))
	commandOK := anyExitCode(outputs, 0)
	switch checkKey {
	case "ssh_root_login":
		value, found := sshdValue(combined, "permitrootlogin")
		if !found {
			return "unknown", 0.5, summary("PermitRootLogin was not found in sshd_config.")
		}
		if value == "yes" || value == "forced-commands-only" {
			return "fail", 0.95, summary("SSH permits direct root login.")
		}
		return "pass", 0.9, summary("SSH root login is disabled or restricted.")
	case "ssh_password_auth":
		value, found := sshdValue(combined, "passwordauthentication")
		if !found {
			return "unknown", 0.5, summary("PasswordAuthentication was not found in sshd_config.")
		}
		if value == "yes" {
			return "fail", 0.95, summary("SSH password authentication is enabled.")
		}
		return "pass", 0.9, summary("SSH password authentication is disabled.")
	case "public_ssh":
		return portStatus(combined, []string{":22 "}, "SSH appears to be listening on a public interface.", "No public SSH listener was detected.")
	case "public_postgresql":
		return portStatus(combined, []string{":5432 "}, "PostgreSQL appears to be listening on a public interface.", "No public PostgreSQL listener was detected.")
	case "public_mysql":
		return portStatus(combined, []string{":3306 "}, "MySQL/MariaDB appears to be listening on a public interface.", "No public MySQL listener was detected.")
	case "public_redis":
		return portStatus(combined, []string{":6379 ", ":6380 "}, "Redis appears to be listening on a public interface.", "No public Redis listener was detected.")
	case "public_docker_socket":
		if strings.Contains(combined, "2375") || strings.Contains(combined, "2376") || strings.Contains(combined, "srw") && strings.Contains(combined, "docker.sock") {
			return "fail", 0.85, summary("Docker socket exposure or permissive socket access was detected.")
		}
		return "pass", 0.75, summary("No obvious Docker socket exposure was detected.")
	case "pending_security_updates":
		if strings.Contains(combined, "security") || strings.Contains(combined, "upgradable") && !strings.Contains(combined, "listing...") {
			return "warning", 0.8, summary("Pending package updates were detected.")
		}
		if !commandOK {
			return "unknown", 0.4, summary("Package update check could not be completed on this host.")
		}
		return "pass", 0.75, summary("No pending security updates were detected.")
	case "reboot_required":
		if anyExitCode(outputs, 0) {
			return "warning", 0.95, summary("A system reboot is required.")
		}
		return "pass", 0.9, summary("No reboot-required marker was detected.")
	case "unattended_upgrades_disabled", "time_sync_disabled":
		if strings.Contains(combined, "disabled") || strings.Contains(combined, "ntp service: inactive") || strings.Contains(combined, "system clock synchronized: no") {
			return "fail", 0.85, summary("The expected security hygiene service appears disabled.")
		}
		if commandOK {
			return "pass", 0.8, summary("The expected security hygiene service appears enabled.")
		}
		return "unknown", 0.4, summary("The security hygiene check could not be completed.")
	case "askio_agent_offline":
		if firstOutputLineEquals(outputs, "active") {
			return "pass", 0.95, summary("Askio monitor service is active.")
		}
		return "fail", 0.8, summary("Askio monitor service is not active.")
	case "failed_systemd_services":
		if strings.Contains(combined, "0 loaded units listed") || strings.Contains(combined, "no failed units") {
			return "pass", 0.9, summary("No failed systemd services were detected.")
		}
		if strings.Contains(combined, "loaded units listed") || strings.Contains(combined, ".service") {
			return "warning", 0.8, summary("Failed systemd services were detected.")
		}
		return "unknown", 0.4, summary("Failed service status could not be determined.")
	case "auth_log_missing":
		if authEvidenceSourceReadable(outputs) {
			return "pass", 0.9, summary("Auth log is present and readable.")
		}
		return "warning", 0.8, summary("Auth log is missing or unreadable.")
	case "failed_login_spike":
		count := strings.Count(combined, "failed password") + strings.Count(combined, "authentication failure")
		if count >= 20 {
			return "fail", 0.85, map[string]any{"summary": "High failed-login volume detected.", "failed_login_count": count}
		}
		if !commandOK {
			return "unknown", 0.4, map[string]any{"summary": "Failed-login evidence could not be collected from auth logs or sshd journal.", "failed_login_count": count}
		}
		return "pass", 0.7, map[string]any{"summary": "No high failed-login spike was detected in the sampled auth log.", "failed_login_count": count}
	case "disk_usage_critical":
		critical := maxDiskPercent(combined)
		if critical >= 90 {
			return "fail", 0.9, map[string]any{"summary": "A filesystem is critically full.", "max_used_percent": critical}
		}
		return "pass", 0.8, map[string]any{"summary": "No critically full filesystem was detected.", "max_used_percent": critical}
	case "backup_not_detected", "backup_older_than_threshold", "tls_certificate_expiring", "weak_tls_manual", "ssh_weak_ciphers_manual", "sudo_users", "inactive_users_manual", "unsupported_os_version", "unexpected_listening_ports":
		if commandOK {
			return "warning", 0.7, summary("Evidence was collected for operator review.")
		}
		return "unknown", 0.4, summary("Evidence collection was incomplete and needs review.")
	default:
		if len(outputs) == 0 {
			return "not_applicable", 1, summary("This check requires manual or external evidence.")
		}
		if commandOK {
			return "warning", 0.6, summary("Evidence was collected for review.")
		}
		return "unknown", 0.4, summary("The check could not be completed.")
	}
}

func evidenceFor(check model.AuditCheckDefinition, raw any, normalized map[string]any) []model.AuditEvidenceItem {
	return []model.AuditEvidenceItem{{
		Title:             check.Name,
		EvidenceType:      "command_output",
		RawOutput:         raw,
		NormalizedSummary: normalized,
		RedactionStatus:   "redacted",
		MetadataJSON: map[string]any{
			"check_key": check.CheckKey,
			"read_only": true,
		},
	}}
}

func redactAndTruncate(output string, rules model.AuditRedactionRules) string {
	for _, pattern := range rules.RedactPatterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		re := regexp.MustCompile(`(?i)(\b` + regexp.QuoteMeta(pattern) + `\w*\b\s*[:=]\s*)\S+`)
		output = re.ReplaceAllString(output, "${1}[REDACTED]")
	}
	if len(output) > maxRawOutputBytes {
		return output[:maxRawOutputBytes] + "\n[TRUNCATED]"
	}
	return output
}

func normalizeSeverity(value string) string {
	switch value {
	case "low", "medium", "high", "critical":
		return value
	default:
		return "medium"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func joinOutputs(outputs []commandOutput) string {
	var b strings.Builder
	for _, output := range outputs {
		b.WriteString(output.Output)
		b.WriteByte('\n')
	}
	return b.String()
}

func anyExitCode(outputs []commandOutput, code int) bool {
	for _, output := range outputs {
		if output.ExitCode == code {
			return true
		}
	}
	return false
}

func firstOutputLineEquals(outputs []commandOutput, expected string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	for _, output := range outputs {
		for _, line := range strings.Split(output.Output, "\n") {
			if strings.ToLower(strings.TrimSpace(line)) == expected {
				return true
			}
		}
	}
	return false
}

func authEvidenceSourceReadable(outputs []commandOutput) bool {
	for _, output := range outputs {
		if output.ExitCode != 0 {
			continue
		}
		switch output.Name {
		case "auth_log", "secure_log":
			return true
		case "sshd_journal":
			normalized := strings.ToLower(strings.TrimSpace(output.Output))
			if normalized != "" &&
				!strings.Contains(normalized, "no entries") &&
				!strings.Contains(normalized, "no journal files") &&
				!strings.Contains(normalized, "failed to") {
				return true
			}
		}
	}
	return false
}

func summary(text string) map[string]any {
	return map[string]any{"summary": text}
}

func sshdValue(output string, key string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.EqualFold(parts[0], key) {
			return strings.ToLower(parts[1]), true
		}
	}
	return "", false
}

func portStatus(output string, ports []string, failSummary string, passSummary string) (string, float64, map[string]any) {
	public := false
	for _, line := range strings.Split(output, "\n") {
		lower := strings.ToLower(line)
		if !(strings.Contains(lower, "listen") || strings.Contains(lower, "udp")) {
			continue
		}
		for _, field := range strings.Fields(lower) {
			for _, port := range ports {
				if strings.Contains(field, strings.TrimSpace(port)) && isPublicListenAddress(field) {
					public = true
				}
			}
		}
	}
	if public {
		return "fail", 0.9, summary(failSummary)
	}
	return "pass", 0.75, summary(passSummary)
}

func isPublicListenAddress(address string) bool {
	address = strings.TrimSpace(strings.ToLower(address))
	return strings.HasPrefix(address, "0.0.0.0:") ||
		strings.HasPrefix(address, "[::]:") ||
		strings.HasPrefix(address, ":::") ||
		strings.HasPrefix(address, "*:")
}

func maxDiskPercent(output string) int {
	maxPct := 0
	for _, field := range strings.Fields(output) {
		if !strings.HasSuffix(field, "%") {
			continue
		}
		pct, err := strconv.Atoi(strings.TrimSuffix(field, "%"))
		if err == nil && pct > maxPct {
			maxPct = pct
		}
	}
	return maxPct
}
