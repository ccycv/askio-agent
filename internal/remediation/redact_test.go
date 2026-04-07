package remediation

import "testing"

func TestRedact(t *testing.T) {
	in := "PASSWORD=supersecret\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
	out := Redact(in)
	if out == in {
		t.Fatalf("expected redaction")
	}
	if contains(out, "supersecret") {
		t.Fatalf("secret not redacted")
	}
	if !contains(out, "[REDACTED_SSH_KEY]") {
		t.Fatalf("ssh key not redacted")
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (stringIndex(s, sub) >= 0))
}

func stringIndex(s, sub string) int {
	// minimal dependency-free index
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
