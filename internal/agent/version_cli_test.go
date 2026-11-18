package agent

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/askio-cloud/askio-monitor/internal/version"
)

func TestVersionFlagPrintsOneCompatibleLine(t *testing.T) {
	saved := [2]string{version.Commit, version.GoVersion}
	t.Cleanup(func() { version.Commit, version.GoVersion = saved[0], saved[1] })
	// Template metacharacters in a build value must be printed, not executed.
	version.Commit, version.GoVersion = "{{.Name}}", "go1.22.12"

	cmd := NewCLI(CLIOptions{Logger: slog.Default()})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if got != version.Line()+"\n" {
		t.Fatalf("--version printed %q, want %q", got, version.Line()+"\n")
	}
	if strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "askio-monitor version "+version.Version+" (") {
		t.Fatalf("--version is not one line with the parsed prefix: %q", got)
	}
}
