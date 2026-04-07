package remediation

import "github.com/askio-cloud/askio-monitor/internal/model"

type Step struct {
	Order          int
	Command        string
	Args           []string
	Description    string
	TimeoutSeconds int
	FailAction     string // abort|continue
}

type Verification struct {
	Command        string
	Args           []string
	ExpectedOutput string
	TimeoutSeconds int
}

type Playbook struct {
	ID          string
	Name        string
	Description string
	ServiceTypes []model.ServiceType
	ApplicableServices []string
	Steps       []Step
	Verify      *Verification
}

func BuiltInPlaybooks() []Playbook {
	return []Playbook{
		{
			ID:          "systemd_restart",
			Name:        "Restart Service",
			Description: "Restart a systemd service",
			ServiceTypes: []model.ServiceType{model.ServiceTypeSystemd},
			Steps: []Step{{Order: 1, Command: "systemctl", Args: []string{"restart", "{unit}", "--no-pager"}, TimeoutSeconds: 30, FailAction: "abort"}},
			Verify: &Verification{Command: "systemctl", Args: []string{"is-active", "{unit}", "--no-pager"}, ExpectedOutput: "active", TimeoutSeconds: 10},
		},
		{
			ID:          "systemd_reload",
			Name:        "Reload Service",
			Description: "Reload a systemd service",
			ServiceTypes: []model.ServiceType{model.ServiceTypeSystemd},
			Steps: []Step{{Order: 1, Command: "systemctl", Args: []string{"reload", "{unit}", "--no-pager"}, TimeoutSeconds: 30, FailAction: "abort"}},
			Verify: &Verification{Command: "systemctl", Args: []string{"is-active", "{unit}", "--no-pager"}, ExpectedOutput: "active", TimeoutSeconds: 10},
		},
		{
			ID:          "systemd_reset_failed",
			Name:        "Clear Failed State",
			Description: "Reset failed state and start the unit",
			ServiceTypes: []model.ServiceType{model.ServiceTypeSystemd},
			Steps: []Step{
				{Order: 1, Command: "systemctl", Args: []string{"reset-failed", "{unit}", "--no-pager"}, TimeoutSeconds: 30, FailAction: "continue"},
				{Order: 2, Command: "systemctl", Args: []string{"start", "{unit}", "--no-pager"}, TimeoutSeconds: 30, FailAction: "abort"},
			},
			Verify: &Verification{Command: "systemctl", Args: []string{"is-active", "{unit}", "--no-pager"}, ExpectedOutput: "active", TimeoutSeconds: 10},
		},
		{
			ID:          "nginx_test_reload",
			Name:        "Nginx Config Test + Reload",
			Description: "Test nginx configuration then reload",
			ServiceTypes: []model.ServiceType{model.ServiceTypeSystemd},
			ApplicableServices: []string{"nginx"},
			Steps: []Step{
				{Order: 1, Command: "nginx", Args: []string{"-t"}, TimeoutSeconds: 30, FailAction: "abort"},
				{Order: 2, Command: "systemctl", Args: []string{"reload", "nginx", "--no-pager"}, TimeoutSeconds: 30, FailAction: "abort"},
			},
			Verify: &Verification{Command: "systemctl", Args: []string{"is-active", "nginx", "--no-pager"}, ExpectedOutput: "active", TimeoutSeconds: 10},
		},
		{
			ID:          "postgres_restart_verify",
			Name:        "PostgreSQL Restart + Verify",
			Description: "Restart postgresql and verify readiness",
			ServiceTypes: []model.ServiceType{model.ServiceTypeSystemd},
			ApplicableServices: []string{"postgresql", "postgres"},
			Steps: []Step{
				{Order: 1, Command: "systemctl", Args: []string{"restart", "{unit}", "--no-pager"}, TimeoutSeconds: 60, FailAction: "abort"},
				{Order: 2, Command: "pg_isready", Args: []string{}, TimeoutSeconds: 10, FailAction: "abort"},
			},
			Verify: &Verification{Command: "pg_isready", Args: []string{}, ExpectedOutput: "accepting connections", TimeoutSeconds: 10},
		},
		{
			ID:          "docker_restart",
			Name:        "Docker Container Restart",
			Description: "Restart a docker container",
			ServiceTypes: []model.ServiceType{model.ServiceTypeDocker},
			Steps: []Step{{Order: 1, Command: "docker", Args: []string{"restart", "{container}"}, TimeoutSeconds: 60, FailAction: "abort"}},
			Verify: &Verification{Command: "docker", Args: []string{"inspect", "--format", "{{.State.Running}}", "{container}"}, ExpectedOutput: "true", TimeoutSeconds: 10},
		},
	}
}

// SudoersTemplate returns an example sudoers file to allow needed commands.
func SudoersTemplate() string {
	return `# /etc/sudoers.d/askio-monitor
# Allow the askio-agent user to run safe, allowlisted commands without password.
# Review carefully before applying.

askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl restart *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reload *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl start *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl stop *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl enable *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl disable *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl status *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl is-active *
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reset-failed *

# Package management (capability installs / operations)
askio-agent ALL=(root) NOPASSWD: /usr/bin/apt-get update
askio-agent ALL=(root) NOPASSWD: /usr/bin/apt-get install *
askio-agent ALL=(root) NOPASSWD: /usr/bin/apt-get remove *
askio-agent ALL=(root) NOPASSWD: /usr/bin/apt-get upgrade *
askio-agent ALL=(root) NOPASSWD: /usr/bin/dnf install *
askio-agent ALL=(root) NOPASSWD: /usr/bin/yum install *

# systemd-run (used to run scripts outside the askio-monitor service sandbox)
askio-agent ALL=(root) NOPASSWD: /usr/bin/systemd-run *

# Remediation helpers
askio-agent ALL=(root) NOPASSWD: /usr/sbin/nginx -t
askio-agent ALL=(root) NOPASSWD: /usr/bin/pg_isready *
askio-agent ALL=(root) NOPASSWD: /usr/bin/docker restart *
askio-agent ALL=(root) NOPASSWD: /usr/bin/docker inspect *

# Ansible (for pending_action.action_type=ansible)
askio-agent ALL=(root) NOPASSWD: /usr/bin/ansible-playbook *
`
}
