package version

import (
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultVersionMatchesVERSIONFile(t *testing.T) {
	raw, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\n$`).Match(raw) {
		t.Fatalf("VERSION must be one MAJOR.MINOR.PATCH line, got %q", raw)
	}
	if want := strings.TrimSuffix(string(raw), "\n"); Version != want {
		t.Fatalf("version.Version default %q differs from VERSION %q", Version, want)
	}
}

// Askio's installers and agent-update script match "askio-monitor version X"
// as a substring and interpolate the whole output into a hand-built JSON
// string, so the line must keep that prefix and stay JSON-string safe.
func TestLineKeepsParsedPrefixAndIsOneSafeLine(t *testing.T) {
	saved := [3]string{Version, Commit, GoVersion}
	t.Cleanup(func() { Version, Commit, GoVersion = saved[0], saved[1], saved[2] })

	Version, Commit, GoVersion = "1.2.3", strings.Repeat("a", 40), "go1.22.12"
	want := "askio-monitor version 1.2.3 (commit " + strings.Repeat("a", 40) + ", go1.22.12, " + runtime.GOOS + "/" + runtime.GOARCH + ")"
	if got := Line(); got != want {
		t.Fatalf("Line() = %q, want %q", got, want)
	}

	Commit, GoVersion = "", ""
	line := Line()
	if !strings.HasPrefix(line, "askio-monitor version 1.2.3 (commit ") {
		t.Fatalf("unexpected prefix: %q", line)
	}
	if !strings.Contains(line, ", "+runtime.Version()+", ") {
		t.Fatalf("missing runtime Go version fallback: %q", line)
	}
	if strings.ContainsAny(line, "\"\\\n\r\t") {
		t.Fatalf("version line is not a single JSON-safe line: %q", line)
	}
}

func TestResolvedFallbacks(t *testing.T) {
	saved := [2]string{Commit, GoVersion}
	t.Cleanup(func() { Commit, GoVersion = saved[0], saved[1] })
	Commit, GoVersion = "", ""
	if got := ResolvedGoVersion(); got != runtime.Version() {
		t.Fatalf("ResolvedGoVersion() = %q", got)
	}
	if got := ResolvedCommit(); got == "" {
		t.Fatal("ResolvedCommit() is empty")
	}
	Commit = "0123456789abcdef0123456789abcdef01234567"
	if got := ResolvedCommit(); got != Commit {
		t.Fatalf("ResolvedCommit() = %q", got)
	}
}
