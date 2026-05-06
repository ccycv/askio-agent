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

var auditNow = time.Now

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
	case "unsupported_os_version":
		return unsupportedOSStatus(outputs)
	case "backup_not_detected", "backup_older_than_threshold", "tls_certificate_expiring", "weak_tls_manual", "ssh_weak_ciphers_manual", "sudo_users", "inactive_users_manual", "unexpected_listening_ports":
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

type osReleaseInfo struct {
	ID         string
	Name       string
	PrettyName string
	VersionID  string
	Major      int
	Minor      int
	Stream     bool
}

func unsupportedOSStatus(outputs []commandOutput) (string, float64, map[string]any) {
	output := outputByName(outputs, "os_release")
	if strings.TrimSpace(output) == "" {
		return "unknown", 0.4, summary("OS release metadata could not be collected.")
	}
	info, err := parseOSRelease(output)
	if err != nil {
		return "unknown", 0.4, summary("OS release metadata could not be parsed for lifecycle evaluation.")
	}
	return evaluateOSSupport(info, auditNow().UTC())
}

func outputByName(outputs []commandOutput, name string) string {
	for _, output := range outputs {
		if output.Name == name {
			return output.Output
		}
	}
	return ""
}

func parseOSRelease(output string) (osReleaseInfo, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	id := strings.ToLower(strings.TrimSpace(fields["ID"]))
	versionID := strings.TrimSpace(fields["VERSION_ID"])
	major, minor, err := parseMajorMinor(versionID)
	if id == "" || versionID == "" || err != nil {
		return osReleaseInfo{}, fmt.Errorf("invalid os-release fields")
	}
	name := strings.TrimSpace(fields["NAME"])
	prettyName := strings.TrimSpace(fields["PRETTY_NAME"])
	streamText := strings.ToLower(name + " " + prettyName + " " + fields["VERSION"])
	return osReleaseInfo{
		ID:         id,
		Name:       firstNonEmpty(name, id),
		PrettyName: prettyName,
		VersionID:  versionID,
		Major:      major,
		Minor:      minor,
		Stream:     strings.Contains(streamText, "stream"),
	}, nil
}

func parseMajorMinor(version string) (int, int, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return 0, 0, fmt.Errorf("empty version")
	}
	parts := strings.SplitN(version, ".", 3)
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	minor := 0
	if len(parts) > 1 {
		if parsedMinor, parseErr := strconv.Atoi(parts[1]); parseErr == nil {
			minor = parsedMinor
		}
	}
	return major, minor, nil
}

func evaluateOSSupport(info osReleaseInfo, now time.Time) (string, float64, map[string]any) {
	family := info.ID
	if info.ID == "centos" && info.Stream {
		family = "centos_stream"
	}

	type lifecycle struct {
		Phase       string
		StandardEnd string
		ExtendedEnd string
	}

	policy := map[string]map[int]lifecycle{
		"ubuntu": {
			24: {Phase: "standard_support", StandardEnd: "2029-06-30"},
			22: {Phase: "standard_support", StandardEnd: "2027-06-30"},
			20: {Phase: "extended_support", StandardEnd: "2025-05-31", ExtendedEnd: "2030-05-31"},
			18: {Phase: "extended_support", StandardEnd: "2023-05-31", ExtendedEnd: "2028-05-31"},
		},
		"debian": {
			13: {Phase: "standard_support", StandardEnd: "2028-08-09", ExtendedEnd: "2030-06-30"},
			12: {Phase: "standard_support", StandardEnd: "2026-06-10", ExtendedEnd: "2028-06-30"},
			11: {Phase: "lts_support", StandardEnd: "2024-08-14", ExtendedEnd: "2026-08-31"},
		},
		"almalinux": {
			10: {Phase: "maintenance_support", ExtendedEnd: "2035-05-31"},
			9:  {Phase: "maintenance_support", ExtendedEnd: "2032-05-31"},
			8:  {Phase: "maintenance_support", ExtendedEnd: "2029-05-31"},
		},
		"rocky": {
			10: {Phase: "maintenance_support", ExtendedEnd: "2035-05-31"},
			9:  {Phase: "maintenance_support", ExtendedEnd: "2032-05-31"},
			8:  {Phase: "maintenance_support", ExtendedEnd: "2029-05-31"},
		},
		"rhel": {
			10: {Phase: "maintenance_support", ExtendedEnd: "2035-05-31"},
			9:  {Phase: "maintenance_support", ExtendedEnd: "2032-05-31"},
			8:  {Phase: "maintenance_support", ExtendedEnd: "2029-05-31"},
			7:  {Phase: "extended_support", StandardEnd: "2024-06-30", ExtendedEnd: "2029-05-31"},
		},
		"centos": {
			8: {Phase: "eol", ExtendedEnd: "2021-12-31"},
			7: {Phase: "eol", ExtendedEnd: "2024-06-30"},
		},
		"centos_stream": {
			10: {Phase: "maintenance_support", ExtendedEnd: "2030-05-31"},
			9:  {Phase: "maintenance_support", ExtendedEnd: "2027-05-31"},
		},
		"fedora": {
			43: {Phase: "standard_support", StandardEnd: "2026-11-30"},
			42: {Phase: "standard_support", StandardEnd: "2026-05-31"},
			41: {Phase: "standard_support", StandardEnd: "2025-12-01"},
			40: {Phase: "eol", StandardEnd: "2025-05-13"},
		},
	}

	displayName := firstNonEmpty(info.PrettyName, info.Name, info.ID+" "+info.VersionID)
	normalized := map[string]any{
		"os_id":      info.ID,
		"os_version": info.VersionID,
		"os_name":    displayName,
	}
	if info.Stream {
		normalized["os_stream"] = true
	}

	item, ok := policy[family][info.Major]
	if !ok {
		normalized["support_phase"] = "unmodeled"
		normalized["summary"] = fmt.Sprintf("%s is not in the current lifecycle matrix; review support status manually.", displayName)
		return "warning", 0.5, normalized
	}

	standardEnd := parseLifecycleDate(item.StandardEnd)
	extendedEnd := parseLifecycleDate(item.ExtendedEnd)
	normalized["support_phase"] = item.Phase
	if !standardEnd.IsZero() {
		normalized["standard_support_ends_on"] = standardEnd.Format("2006-01-02")
	}
	if !extendedEnd.IsZero() {
		normalized["support_ends_on"] = extendedEnd.Format("2006-01-02")
	}

	switch item.Phase {
	case "standard_support":
		if !standardEnd.IsZero() && now.After(standardEnd) {
			if !extendedEnd.IsZero() && !now.After(extendedEnd) {
				normalized["support_phase"] = "extended_support"
				normalized["summary"] = fmt.Sprintf("%s is out of standard support and should be upgraded or covered by extended vendor support.", displayName)
				return "warning", 0.85, normalized
			}
			normalized["support_phase"] = "eol"
			normalized["summary"] = fmt.Sprintf("%s is end-of-life and should be upgraded.", displayName)
			return "fail", 0.95, normalized
		}
		normalized["summary"] = fmt.Sprintf("%s is within vendor-supported lifecycle.", displayName)
		return "pass", 0.95, normalized
	case "lts_support":
		if !extendedEnd.IsZero() && now.After(extendedEnd) {
			normalized["support_phase"] = "eol"
			normalized["summary"] = fmt.Sprintf("%s is end-of-life and should be upgraded.", displayName)
			return "fail", 0.95, normalized
		}
		normalized["summary"] = fmt.Sprintf("%s is within Debian LTS support.", displayName)
		return "pass", 0.9, normalized
	case "maintenance_support":
		if !extendedEnd.IsZero() && now.After(extendedEnd) {
			normalized["support_phase"] = "eol"
			normalized["summary"] = fmt.Sprintf("%s is end-of-life and should be upgraded.", displayName)
			return "fail", 0.95, normalized
		}
		normalized["summary"] = fmt.Sprintf("%s is within vendor-supported maintenance lifecycle.", displayName)
		return "pass", 0.9, normalized
	case "extended_support":
		if !extendedEnd.IsZero() && now.After(extendedEnd) {
			normalized["support_phase"] = "eol"
			normalized["summary"] = fmt.Sprintf("%s is end-of-life and should be upgraded.", displayName)
			return "fail", 0.95, normalized
		}
		normalized["summary"] = fmt.Sprintf("%s is outside standard support and should be upgraded or covered by extended vendor support.", displayName)
		return "warning", 0.85, normalized
	case "eol":
		normalized["support_phase"] = "eol"
		normalized["summary"] = fmt.Sprintf("%s is end-of-life and should be upgraded.", displayName)
		return "fail", 0.95, normalized
	default:
		normalized["support_phase"] = "unmodeled"
		normalized["summary"] = fmt.Sprintf("%s lifecycle status could not be classified automatically.", displayName)
		return "warning", 0.5, normalized
	}
}

func parseLifecycleDate(value string) time.Time {
	if strings.TrimSpace(value) == "" {
		return time.Time{}
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
