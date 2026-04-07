package model

import (
	"encoding/json"
	"time"
)

type ServiceType string

const (
	ServiceTypeSystemd ServiceType = "systemd"
	ServiceTypeDocker  ServiceType = "docker"
	ServiceTypeProcess ServiceType = "process"
)

type CheckType string

const (
	CheckTypeActiveState CheckType = "active_state"
	CheckTypePort        CheckType = "port"
	CheckTypeHTTP        CheckType = "http"
)

type RemediationPolicy string

const (
	RemediationPolicyRestartOnly RemediationPolicy = "restart_only"
	RemediationPolicyReloadFirst RemediationPolicy = "reload_first"
	RemediationPolicyFull        RemediationPolicy = "full"
)

type MonitorConfig struct {
	ID                   string            `json:"id"`
	ServiceName           string            `json:"service_name"`
	ServiceType           ServiceType       `json:"service_type"`
	SystemdUnit           string            `json:"systemd_unit,omitempty"`
	DockerContainerID     string            `json:"docker_container_id,omitempty"`
	ProcessMatch          string            `json:"process_match,omitempty"`
	CheckTypes            []CheckType        `json:"check_types"`
	CheckIntervalSeconds  int               `json:"check_interval_seconds"`
	Port                 int               `json:"port,omitempty"`
	HTTPEndpoint         string            `json:"http_endpoint,omitempty"`
	Enabled              bool              `json:"enabled"`
	RemediationEnabled   bool              `json:"remediation_enabled"`
	RemediationPolicy    RemediationPolicy `json:"remediation_policy"`
	AllowedPlaybookIDs   []string          `json:"allowed_playbook_ids,omitempty"`
	AdditionalProperties map[string]any    `json:"additional_properties,omitempty"`
}

func (m MonitorConfig) Interval() time.Duration {
	if m.CheckIntervalSeconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(m.CheckIntervalSeconds) * time.Second
}

type RemoteConfig struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Monitors  []MonitorConfig `json:"monitors"`

	// PendingCommandRaw supports both legacy string and the new JSON-object format.
	//
	// - legacy: pending_command: "discover_services" or "run_playbook:..."
	// - new:    pending_command: {"type":"exec_script",...}
	PendingCommand PendingCommandOrString `json:"pending_command,omitempty"`
	// Backward compat for legacy systems that send a separate command id.
	CommandID string `json:"command_id,omitempty"`

	// Operations Platform
	PendingAction *PendingAction `json:"pending_action,omitempty"`
	Capabilities  map[string]any `json:"capabilities,omitempty"`
}

type DiscoveredService struct {
	Name  string      `json:"name"`
	Type  ServiceType `json:"type"`
	Unit  string      `json:"unit,omitempty"`
	PID   int         `json:"pid,omitempty"`
	State string      `json:"state,omitempty"`
	Ports []int       `json:"ports,omitempty"`
	Meta  any         `json:"meta,omitempty"`
}

type CheckStatus string

const (
	StatusOK       CheckStatus = "ok"
	StatusWarning  CheckStatus = "warning"
	StatusCritical CheckStatus = "critical"
)

type CheckResult struct {
	MonitorID   string         `json:"monitor_id"`
	CheckedAt   time.Time      `json:"checked_at"`
	Status      CheckStatus    `json:"status"`
	LatencyMS   int64          `json:"latency_ms"`
	Details     map[string]any `json:"details"`
	ActiveState string         `json:"active_state,omitempty"`
	ServiceName string         `json:"service_name,omitempty"`
	ServiceType ServiceType    `json:"service_type,omitempty"`
}

type RemediationStepResult struct {
	Order      int    `json:"order"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	DurationMS int64  `json:"duration_ms"`
}

type RemediationRunLog struct {
	ServerID      string                  `json:"server_id"`
	MonitorID     string                  `json:"monitor_id"`
	IncidentID    string                  `json:"incident_id,omitempty"`
	PlaybookID    string                  `json:"playbook_id"`
	Trigger       string                  `json:"trigger"`
	Success       bool                    `json:"success"`
	Steps         []RemediationStepResult `json:"steps"`
	Verification  map[string]any          `json:"verification,omitempty"`
	StartedAt     time.Time               `json:"started_at"`
	FinishedAt    time.Time               `json:"finished_at"`
}

// ---- Operations Platform (v1) ----

type PendingAction struct {
	RunID          string                 `json:"run_id"`
	ActionID       string                 `json:"action_id"`
	ActionName     string                 `json:"action_name"`
	ActionType     string                 `json:"action_type"`     // script|plan|playbook|ansible
	TimeoutSeconds int                    `json:"timeout_seconds"` // default 300
	ExecutionMode  string                 `json:"execution_mode"`  // live|dry_run
	Parameters     map[string]any         `json:"parameters,omitempty"`
	EnableRollback bool                   `json:"enable_rollback"`
	ScriptContent  string                 `json:"script_content,omitempty"`
	RollbackScript string                 `json:"rollback_script,omitempty"`
	ActionPlan     *ActionPlan            `json:"action_plan,omitempty"`
	Playbook       *OperationsPlaybook    `json:"playbook,omitempty"`
	AnsiblePlaybook *AnsiblePlaybook      `json:"ansible_playbook,omitempty"`
}

// AnsiblePlaybook is a simple locally executed playbook payload.
// The agent writes Content to a temp .yml and runs ansible-playbook with -i localhost, -c local.
type AnsiblePlaybook struct {
	Content   string         `json:"content"`
	Inventory string         `json:"inventory,omitempty"`
	ExtraVars map[string]any `json:"extra_vars,omitempty"`
}

type ActionPlan struct {
	Version  string     `json:"version"`
	Steps    []PlanStep `json:"steps"`
	Rollback []PlanStep `json:"rollback,omitempty"`
}

type PlanStep struct {
	ID        string         `json:"id"`
	Action    string         `json:"action"`
	Params    map[string]any `json:"params"`
	OnFailure string         `json:"on_failure"` // abort|continue|warn
}

type OperationsPlaybookStep struct {
	ID            string `json:"id,omitempty"`
	Command       string `json:"command"`
	Description   string `json:"description,omitempty"`
	TimeoutSeconds int   `json:"timeout_seconds,omitempty"`
	FailAction    string `json:"fail_action,omitempty"` // abort|continue
}

type OperationsPlaybook struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	Steps              []OperationsPlaybookStep `json:"steps"`
	VerificationCommand string                `json:"verification_command,omitempty"`
	RollbackSteps      []OperationsPlaybookStep `json:"rollback_steps,omitempty"`
}

type OperationsAgentResult struct {
	RunID       string                 `json:"run_id"`
	ServerID    string                 `json:"server_id"`
	Status      string                 `json:"status"` // success|failed|partial
	StepResults []OperationsStepResult `json:"step_results,omitempty"`
	Output      string                 `json:"output,omitempty"`
	Error       string                 `json:"error,omitempty"`
	StartedAt   time.Time              `json:"started_at"`
	FinishedAt  time.Time              `json:"finished_at"`
}

type OperationsStepResult struct {
	StepID     string    `json:"step_id"`
	Action     string    `json:"action"`
	Status     string    `json:"status"` // success|failed|skipped
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Changed    bool      `json:"changed"`
}

// ---- Command execution (install_capability / exec_script) ----

type PendingCommand struct {
	Type           string `json:"type"` // exec_script|install_capability
	CommandID      string `json:"command_id"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	ExecutionMode  string `json:"execution_mode,omitempty"` // live|dry_run

	// generate_host_token
	ServerID          string `json:"server_id,omitempty"`
	ExpiresInSeconds  int    `json:"expires_in_seconds,omitempty"`

	// install_capability
	Capability string `json:"capability,omitempty"`

	// script payload
	ScriptB64 string `json:"script_b64,omitempty"`
}

type PendingCommandOrString struct {
	Legacy string
	V2     *PendingCommand
}

func (p *PendingCommandOrString) UnmarshalJSON(b []byte) error {
	// Accept both string and object.
	if len(b) == 0 || string(b) == "null" {
		p.Legacy = ""
		p.V2 = nil
		return nil
	}
	// JSON string
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		p.Legacy = s
		p.V2 = nil
		return nil
	}
	// JSON object
	var cmd PendingCommand
	if err := json.Unmarshal(b, &cmd); err != nil {
		return err
	}
	p.Legacy = ""
	p.V2 = &cmd
	return nil
}

type CommandResult struct {
	ServerID    string    `json:"server_id"`
	CommandID   string    `json:"command_id"`
	CommandType string    `json:"command_type"`
	Status      string    `json:"status"` // success|failed
	Output      string    `json:"output,omitempty"`
	Error       string    `json:"error,omitempty"`
	ExitCode    int       `json:"exit_code"`
	StartedAt   time.Time `json:"started_at"`
	FinishedAt  time.Time `json:"finished_at"`
	DurationMS  int64     `json:"duration_ms"`
}

type GatewayHostTokenResult struct {
	CommandID  string    `json:"command_id"`
	ServerID   string    `json:"server_id"`
	Token      string    `json:"token"`
	ExpiresAt  time.Time `json:"expires_at"`
}
