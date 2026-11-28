// Package selfupdate decides how this agent can replace its own binary, and
// reports it to Askio.
//
// The backend's update script (hosts) and the gateway's typed update_agent
// handler pick an install path in the same order: run as root, hand the
// binary to the root-owned askio-monitor-updater path unit, use the
// restricted askio-ops helper through sudo, or (hosts only) plain
// passwordless sudo. When none works the update fails on the host, and until
// now Askio learnt that only from the failed command.
//
// In production (2026-11-24 to 27) the 8 gateways and the 8 hosts behind
// them ran under systemd units that implied no_new_privs and had no
// askio-monitor-updater, so every remote update failed and someone had to
// run the installer's `upgrade` on the console; hosts without the helper and
// without passwordless sudo needed SSH. Reporting the path in every
// heartbeat lets Askio show which agents need a person before an update is
// queued, refuse a command that cannot work, and see when a hand upgrade
// restored the remote path.
package selfupdate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Path is the install path an update would use.
type Path string

const (
	PathRoot    Path = "root"
	PathUpdater Path = "updater"
	PathHelper  Path = "helper"
	PathSudo    Path = "sudo"
	PathNone    Path = "none"
)

// Reason codes for PathNone (and for an updater that is installed but not used).
const (
	ReasonNoNewPrivs      = "no_new_privs"
	ReasonNoPrivilege     = "no_privilege"
	ReasonUpdaterInactive = "updater_inactive"
)

const UpgradeHint = "Run the current Askio installer's upgrade command on the host once (curl -sSL https://api.askio.cloud/agent-install.sh | sudo bash -s -- upgrade)."

// Report is the heartbeat `self_update` object. The backend stores only these
// fields, bounded, and trusts the report only while the agent still runs the
// version that sent it.
type Report struct {
	Path             Path   `json:"path"`
	Available        bool   `json:"available"`
	ReasonCode       string `json:"reason_code,omitempty"`
	Reason           string `json:"reason,omitempty"`
	NoNewPrivs       bool   `json:"no_new_privs"`
	UpdaterInstalled bool   `json:"updater_installed"`
	UpdaterActive    bool   `json:"updater_active"`
	HelperInstalled  bool   `json:"helper_installed"`
}

// Probe holds everything Detect looks at, so tests can point it at a scratch
// directory and stub the commands.
type Probe struct {
	EUID        func() int
	ProcStatus  string
	UpdaterUnit string
	UpdaterDir  string
	HelperPath  string
	// AllowGenericSudo enables the hosts' last path: passwordless sudo for
	// install and systemctl. Gateways never use it.
	AllowGenericSudo bool
	// Run runs a command; only its exit status matters. A nil error is exit 0.
	Run func(ctx context.Context, name string, args ...string) error
	// Output runs a command and returns its standard output (hosts only:
	// `sudo -n -l`, to read which commands need no password).
	Output func(ctx context.Context, name string, args ...string) (string, error)
}

// DefaultProbe is the probe for the installed agent.
func DefaultProbe(dataDir string, allowGenericSudo bool) Probe {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "/var/lib/askio-monitor"
	}
	return Probe{
		EUID:             os.Geteuid,
		ProcStatus:       "/proc/self/status",
		UpdaterUnit:      "/etc/systemd/system/askio-monitor-updater.path",
		UpdaterDir:       filepath.Join(dataDir, "update"),
		HelperPath:       "/usr/local/bin/askio-ops",
		AllowGenericSudo: allowGenericSudo,
		Run:              runQuiet,
		Output:           outputQuiet,
	}
}

// outputQuiet returns at most 64 KiB of a command's standard output.
func outputQuiet(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var out limitedBuffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

type limitedBuffer struct{ data []byte }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := 64<<10 - len(b.data); room > 0 {
		if len(p) > room {
			b.data = append(b.data, p[:room]...)
		} else {
			b.data = append(b.data, p...)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string { return string(b.data) }

// sudoTag matches a leading sudoers tag such as "NOPASSWD:" or "SETENV:".
var sudoTag = regexp.MustCompile(`^([A-Z_]+):\s*`)

// NoPasswordCommands reads `sudo -n -l` output and reports, for each name in
// want (a command basename), whether a NOPASSWD entry allows it. An exit
// status of 0 from `sudo -n -l <command>` proves only that the command is
// permitted, not that it runs without a password: with a mixed sudoers
// (one NOPASSWD rule, install and systemctl behind a password) both checks
// succeed and every update then fails with "a password is required".
// Tags carry over within one entry ("(root) NOPASSWD: /a, PASSWD: /b"),
// "ALL" covers every command and negated commands ("!/b") are ignored.
func NoPasswordCommands(listing string, want ...string) map[string]bool {
	allowed := make(map[string]bool, len(want))
	inCommands := false
	for _, raw := range strings.Split(listing, "\n") {
		line := strings.TrimSpace(raw)
		if strings.Contains(line, "may run the following commands") {
			inCommands = true
			continue
		}
		if !inCommands || !strings.HasPrefix(line, "(") {
			continue
		}
		end := strings.Index(line, ")")
		if end < 0 {
			continue
		}
		noPassword := false
		for _, item := range strings.Split(line[end+1:], ",") {
			item = strings.TrimSpace(item)
			for {
				match := sudoTag.FindStringSubmatch(item)
				if match == nil {
					break
				}
				switch match[1] {
				case "NOPASSWD":
					noPassword = true
				case "PASSWD":
					noPassword = false
				}
				item = strings.TrimSpace(item[len(match[0]):])
			}
			if !noPassword || item == "" || strings.HasPrefix(item, "!") {
				continue
			}
			command := strings.Fields(item)[0]
			for _, name := range want {
				if command == "ALL" || filepath.Base(command) == name {
					allowed[name] = true
				}
			}
		}
	}
	return allowed
}

// passwordlessSudo reports whether sudo runs install and systemctl without
// a password, from the NOPASSWD entries `sudo -n -l` lists.
func (p Probe) passwordlessSudo(ctx context.Context) bool {
	if p.Output == nil {
		return false
	}
	listing, err := p.Output(ctx, "sudo", "-n", "-l")
	if err != nil {
		return false
	}
	allowed := NoPasswordCommands(listing, "install", "systemctl")
	return allowed["install"] && allowed["systemctl"]
}

func runQuiet(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

// exitCode returns the exit status of err, or -1 when the command did not run.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	var coded interface{ ExitCode() int }
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return -1
}

// UpdaterInactive reports whether systemd says the updater's path unit is not
// active. `systemctl is-active` exits 3 for an inactive or failed unit; any
// other failure (no systemctl, no D-Bus access from the sandbox) is not proof
// that the updater would be ignored, so it counts as active.
func (p Probe) UpdaterInactive(ctx context.Context) bool {
	if p.Run == nil {
		return false
	}
	return exitCode(p.Run(ctx, "systemctl", "is-active", "--quiet", filepath.Base(p.UpdaterUnit))) == 3
}

// NoNewPrivs reports the Linux no_new_privs flag of this process.
func (p Probe) NoNewPrivs() bool {
	data, err := os.ReadFile(p.ProcStatus)
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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
}

// DirWritable reports whether a file can be created in dir.
func DirWritable(dir string) bool {
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

// Detect decides the install path in the order the update script and the
// gateway handler use. It never changes anything on the host.
func Detect(ctx context.Context, p Probe) Report {
	report := Report{
		NoNewPrivs:       p.NoNewPrivs(),
		UpdaterInstalled: fileExists(p.UpdaterUnit),
		HelperInstalled:  executable(p.HelperPath),
	}
	inactive := report.UpdaterInstalled && p.UpdaterInactive(ctx)
	report.UpdaterActive = report.UpdaterInstalled && !inactive

	switch {
	case p.EUID != nil && p.EUID() == 0:
		report.Path, report.Available = PathRoot, true
	case report.UpdaterActive && DirWritable(p.UpdaterDir):
		report.Path, report.Available = PathUpdater, true
	case report.NoNewPrivs && inactive:
		report.Path, report.ReasonCode = PathNone, ReasonUpdaterInactive
		report.Reason = "askio-monitor-updater.path is installed but not active, and the agent runs with no_new_privs, so sudo cannot replace the binary. Run 'systemctl enable --now askio-monitor-updater.path' as root."
	case report.NoNewPrivs && report.UpdaterInstalled:
		report.Path, report.ReasonCode = PathNone, ReasonNoNewPrivs
		report.Reason = "the agent runs with no_new_privs and askio-monitor-updater is installed, but the agent cannot write its staging directory " + p.UpdaterDir + ". " + UpgradeHint
	case report.NoNewPrivs:
		report.Path, report.ReasonCode = PathNone, ReasonNoNewPrivs
		report.Reason = "the agent runs with the Linux no_new_privs flag (systemd NoNewPrivileges=true, or PrivateDevices, RestrictSUIDSGID or LockPersonality for a non-root user), so sudo cannot replace the binary, and the root-owned askio-monitor-updater is not installed. " + UpgradeHint
	case report.HelperInstalled:
		report.Path, report.Available = PathHelper, true
	case p.AllowGenericSudo && p.passwordlessSudo(ctx):
		report.Path, report.Available = PathSudo, true
	default:
		report.Path, report.ReasonCode = PathNone, ReasonNoPrivilege
		if p.AllowGenericSudo {
			report.Reason = "the restricted helper " + p.HelperPath + " is missing and the agent has no passwordless sudo for install and systemctl. " + UpgradeHint
		} else {
			report.Reason = "the restricted helper " + p.HelperPath + " is missing. " + UpgradeHint
		}
	}
	return report
}
