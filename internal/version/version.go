package version

import (
	"runtime"
	"runtime/debug"
)

// Version is the agent release version. It is the plain version string used
// in the heartbeat (`agent_version`), the HTTP User-Agent and the first words
// of `askio-monitor --version`; the backend compares it verbatim.
//
// The default must equal the repository's VERSION file (enforced by
// TestDefaultVersionMatchesVERSIONFile). Release builds set it explicitly with
// `-ldflags "-X github.com/askio-cloud/askio-monitor/internal/version.Version=<VERSION>"`
// (see Makefile and scripts/release-build.sh). It is a var only so the linker
// can set it; nothing assigns it at run time.
var Version = "0.4.47"

// Commit is the full source revision the binary was built from. Release
// builds set it with -ldflags -X. Builds without it fall back to the VCS
// revision Go embeds (if any), and otherwise report "unknown".
var Commit = ""

// GoVersion is the toolchain version recorded by the release build with
// -ldflags -X. Builds without it report runtime.Version().
var GoVersion = ""

// ResolvedCommit returns the embedded source revision, or "unknown".
func ResolvedCommit() string {
	if Commit != "" {
		return Commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		revision, modified := "", false
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				revision = setting.Value
			case "vcs.modified":
				modified = setting.Value == "true"
			}
		}
		if revision != "" {
			if modified {
				return revision + "-dirty"
			}
			return revision
		}
	}
	return "unknown"
}

// ResolvedGoVersion returns the embedded toolchain version, or the runtime's.
func ResolvedGoVersion() string {
	if GoVersion != "" {
		return GoVersion
	}
	return runtime.Version()
}

// Line is the single line printed by `askio-monitor --version`.
//
// Compatibility contract: it starts with "askio-monitor version <Version>"
// exactly as earlier releases printed it, because Askio's installers, the
// agent-update script and the public artifact smoke check match that text as a
// substring. Build details follow in parentheses on the same line. The line
// never contains a newline, quote or backslash, because the agent-update
// script interpolates this output into a hand-built JSON string.
func Line() string {
	return "askio-monitor version " + Version + " (commit " + ResolvedCommit() + ", " + ResolvedGoVersion() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
