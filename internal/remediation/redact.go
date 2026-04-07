package remediation

import (
	"regexp"
	"strings"
)

var (
	// Basic heuristics. This is intentionally conservative for v1.
	reEnvSecret = regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*[^\s]+`)
	reSSHKey    = regexp.MustCompile(`(?s)-----BEGIN (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----.*?-----END (OPENSSH|RSA|EC|DSA) PRIVATE KEY-----`)
)

func Redact(s string) string {
	if s == "" {
		return s
	}
	s = reSSHKey.ReplaceAllString(s, "[REDACTED_SSH_KEY]")
	s = reEnvSecret.ReplaceAllStringFunc(s, func(m string) string {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=[REDACTED]"
		}
		parts = strings.SplitN(m, ":", 2)
		if len(parts) == 2 {
			return parts[0] + ":[REDACTED]"
		}
		return "[REDACTED]"
	})
	return s
}
