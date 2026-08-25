package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var ErrConfigNotFound = errors.New("askio-monitor config not found")

type PrivilegeMode string

const (
	PrivilegeModeRoot                      PrivilegeMode = "root"
	PrivilegeModeSudo                      PrivilegeMode = "sudo"
	DefaultMigrationDataPlaneListenAddress               = "0.0.0.0:9443"
)

var migrationServicePattern = regexp.MustCompile(`^[A-Za-z0-9@_.-]+\.service$`)

func CanonicalMigrationRootHandles() map[string]string {
	return map[string]string{
		"workspace":        "/srv/askio-migrations",
		"state":            "/var/lib/askio-migrations",
		"source-workspace": "/srv/askio-migrations/source-workspace",
		"source-data":      "/srv/askio-migrations/source-data",
		"source-staging":   "/var/lib/askio-migrations/source-staging",
		"target-workspace": "/srv/askio-migrations/target-workspace",
		"target-data":      "/srv/askio-migrations/target-data",
		"target-staging":   "/var/lib/askio-migrations/target-staging",
	}
}

func CanonicalMigrationAllowedRoots() []string {
	handles := CanonicalMigrationRootHandles()
	roots := make([]string, 0, len(handles))
	for _, root := range handles {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	return roots
}

func NormalizeMigrationAllowedServices(services []string) ([]string, error) {
	if len(services) > 32 {
		return nil, fmt.Errorf("migration allows at most 32 systemd services")
	}
	normalized := append([]string{}, services...)
	sort.Strings(normalized)
	for index, service := range normalized {
		if !migrationServicePattern.MatchString(service) {
			return nil, fmt.Errorf("invalid migration allowed service %q", service)
		}
		if index > 0 && normalized[index-1] == service {
			return nil, fmt.Errorf("duplicate migration allowed service %q", service)
		}
	}
	return normalized, nil
}

func migrationRootHandlesAreCanonical(handles map[string]string) bool {
	expected := CanonicalMigrationRootHandles()
	if len(handles) != len(expected) {
		return false
	}
	for handle, root := range expected {
		if handles[handle] != root {
			return false
		}
	}
	return true
}

func migrationAllowedRootsAreCanonical(roots []string) bool {
	expected := CanonicalMigrationAllowedRoots()
	if len(roots) != len(expected) {
		return false
	}
	actual := append([]string{}, roots...)
	sort.Strings(actual)
	for index := range expected {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

type Config struct {
	Mode                         string        `yaml:"mode"`
	APIURL                       string        `yaml:"api_url"`
	ServerID                     string        `yaml:"server_id"`
	AgentID                      string        `yaml:"agent_id,omitempty"`
	AgentToken                   string        `yaml:"agent_token"`
	TLSSkipVerify                bool          `yaml:"tls_skip_verify"`
	CACertPath                   string        `yaml:"ca_cert_path"`
	PrivilegeMode                PrivilegeMode `yaml:"privilege_mode"`
	HeartbeatIntervalSeconds     int           `yaml:"heartbeat_interval_seconds"`
	ConfigPollIntervalSeconds    int           `yaml:"config_poll_interval_seconds"`
	DiscoveryPollIntervalSeconds int           `yaml:"discovery_poll_interval_seconds"`
	LogLevel                     string        `yaml:"log_level"`

	// Local state/cache
	DataDir string `yaml:"data_dir"`

	Operations *OperationsConfig `yaml:"operations,omitempty"`

	Migration *MigrationConfig `yaml:"migration,omitempty"`

	Gateway *GatewayConfig `yaml:"gateway,omitempty"`
}

// MigrationConfig extends the existing host agent with the migration task
// protocol. It does not create a second agent identity or control plane.
type MigrationConfig struct {
	Enabled                              bool              `yaml:"enabled"`
	KeyDir                               string            `yaml:"key_dir"`
	StateDir                             string            `yaml:"state_dir"`
	BrokerSocket                         string            `yaml:"broker_socket"`
	DataPlaneListenAddress               string            `yaml:"data_plane_listen_address,omitempty"`
	AllowedRoots                         []string          `yaml:"allowed_roots"`
	RootHandles                          map[string]string `yaml:"root_handles"`
	AllowedServices                      []string          `yaml:"allowed_services"`
	BackendTaskSigningKeyID              string            `yaml:"backend_task_signing_key_id"`
	BackendTaskSigningPublicKeyPEMBase64 string            `yaml:"backend_task_signing_public_key_pem_base64"`
	PollIntervalSeconds                  int               `yaml:"poll_interval_seconds"`
	GenericHelperEnabled                 bool              `yaml:"generic_helper_enabled"`
}

type OperationsConfig struct {
	// AllowShell enables executing shell commands through operations handler command.run
	// when params include {cmd:"...", shell:true}.
	//
	// Default: false.
	AllowShell bool `yaml:"allow_shell"`
	// Allowlist is an optional list of allowed executables for {exe,args} mode.
	// If empty, exe is not restricted by the agent.
	Allowlist []string `yaml:"allowlist,omitempty"`
}

type GatewayConfig struct {
	ListenAddr      string `yaml:"listen_addr"`
	TLSCertPath     string `yaml:"tls_cert_path"`
	TLSKeyPath      string `yaml:"tls_key_path"`
	TokenHMACKey    string `yaml:"token_hmac_key"`
	CloudAPIURL     string `yaml:"cloud_api_url"`
	CloudAgentToken string `yaml:"cloud_agent_token"`
	GatewayServerID string `yaml:"gateway_server_id"`
}

func DefaultConfigPath() string {
	return "/etc/askio/monitor.conf"
}

func DefaultDataDir() string {
	// Prefer system path when running as root, fallback to user cache.
	if os.Geteuid() == 0 {
		return "/var/lib/askio-monitor"
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "askio-monitor")
	}
	return "./.askio-monitor"
}

func (c Config) HeartbeatInterval() time.Duration {
	if c.HeartbeatIntervalSeconds <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.HeartbeatIntervalSeconds) * time.Second
}

func (c Config) ConfigPollInterval() time.Duration {
	if c.ConfigPollIntervalSeconds <= 0 {
		return 60 * time.Second
	}
	return time.Duration(c.ConfigPollIntervalSeconds) * time.Second
}

func (c Config) DiscoveryPollInterval() time.Duration {
	// default: every 6 hours
	if c.DiscoveryPollIntervalSeconds <= 0 {
		return 6 * time.Hour
	}
	return time.Duration(c.DiscoveryPollIntervalSeconds) * time.Second
}

func (c Config) MigrationPollInterval() time.Duration {
	if c.Migration == nil || c.Migration.PollIntervalSeconds <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.Migration.PollIntervalSeconds) * time.Second
}

func (c Config) Normalized() (Config, error) {
	out := c
	if out.Mode == "" {
		out.Mode = "host"
	}
	if out.Mode != "host" && out.Mode != "gateway" {
		return Config{}, fmt.Errorf("invalid mode: %q", out.Mode)
	}

	if out.Mode == "gateway" {
		if out.Gateway == nil {
			return Config{}, fmt.Errorf("gateway config is required when mode=gateway")
		}
		if out.Gateway.ListenAddr == "" {
			out.Gateway.ListenAddr = ":8443"
		}
		if out.Gateway.TLSCertPath == "" || out.Gateway.TLSKeyPath == "" {
			return Config{}, fmt.Errorf("gateway.tls_cert_path and gateway.tls_key_path are required")
		}
		if out.Gateway.TokenHMACKey == "" {
			return Config{}, fmt.Errorf("gateway.token_hmac_key is required")
		}
		if out.Gateway.CloudAPIURL == "" {
			return Config{}, fmt.Errorf("gateway.cloud_api_url is required")
		}
		if out.Gateway.CloudAgentToken == "" {
			return Config{}, fmt.Errorf("gateway.cloud_agent_token is required")
		}
		if out.Gateway.GatewayServerID == "" {
			// Optional, but recommended for heartbeats to be attributable.
			out.Gateway.GatewayServerID = out.ServerID
		}
		if out.DataDir == "" {
			out.DataDir = DefaultDataDir()
		}
		return out, nil
	}
	if out.PrivilegeMode == "" {
		out.PrivilegeMode = PrivilegeModeSudo
	}
	if out.DataDir == "" {
		out.DataDir = DefaultDataDir()
	}
	if out.APIURL == "" {
		return Config{}, fmt.Errorf("api_url is required")
	}
	if out.ServerID == "" {
		return Config{}, fmt.Errorf("server_id is required")
	}
	if out.AgentToken == "" {
		return Config{}, fmt.Errorf("agent_token is required")
	}
	switch out.PrivilegeMode {
	case PrivilegeModeRoot, PrivilegeModeSudo:
	default:
		return Config{}, fmt.Errorf("invalid privilege_mode: %q", out.PrivilegeMode)
	}
	if out.Migration != nil && out.Migration.Enabled {
		if out.Mode != "host" {
			return Config{}, fmt.Errorf("migration requires direct host mode")
		}
		if out.AgentID == "" {
			return Config{}, fmt.Errorf("agent_id is required when migration is enabled")
		}
		if out.PrivilegeMode == PrivilegeModeRoot {
			return Config{}, fmt.Errorf("migration requires an unprivileged main agent")
		}
		if out.Migration.GenericHelperEnabled {
			return Config{}, fmt.Errorf("migration security profile forbids the generic privilege helper")
		}
		if out.Operations != nil && (out.Operations.AllowShell || len(out.Operations.Allowlist) > 0) {
			return Config{}, fmt.Errorf("migration security profile forbids shell mode and executable allowlists")
		}
		if out.Migration.KeyDir == "" {
			out.Migration.KeyDir = "/var/lib/askio-monitor/migration/keys"
		}
		if out.Migration.StateDir == "" {
			out.Migration.StateDir = "/var/lib/askio-monitor/migration/state"
		}
		if out.Migration.BrokerSocket == "" {
			out.Migration.BrokerSocket = "/run/askio-migration-broker/broker.sock"
		}
		if out.Migration.DataPlaneListenAddress == "" {
			out.Migration.DataPlaneListenAddress = DefaultMigrationDataPlaneListenAddress
		}
		if out.Migration.DataPlaneListenAddress != DefaultMigrationDataPlaneListenAddress {
			return Config{}, fmt.Errorf("migration data_plane_listen_address must use the canonical V1 listener")
		}
		if out.Migration.DataPlaneListenAddress != "" {
			host, port, err := net.SplitHostPort(out.Migration.DataPlaneListenAddress)
			if err != nil || strings.ContainsAny(host, "\x00\r\n\t") {
				return Config{}, fmt.Errorf("migration data_plane_listen_address is invalid")
			}
			portNumber, err := strconv.Atoi(port)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				return Config{}, fmt.Errorf("migration data_plane_listen_address requires a fixed port")
			}
		}
		if len(out.Migration.RootHandles) == 0 {
			out.Migration.RootHandles = CanonicalMigrationRootHandles()
		}
		if !migrationRootHandlesAreCanonical(out.Migration.RootHandles) {
			return Config{}, fmt.Errorf("migration root handles must match the canonical V1 profile")
		}
		if len(out.Migration.AllowedRoots) == 0 {
			out.Migration.AllowedRoots = CanonicalMigrationAllowedRoots()
		}
		if !migrationAllowedRootsAreCanonical(out.Migration.AllowedRoots) {
			return Config{}, fmt.Errorf("migration allowed roots must match the canonical V1 profile")
		}
		for _, root := range out.Migration.AllowedRoots {
			if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
				return Config{}, fmt.Errorf("migration allowed root must be an absolute clean non-root path: %q", root)
			}
		}
		for handle, root := range out.Migration.RootHandles {
			if len(handle) < 2 || len(handle) > 64 || strings.ContainsAny(handle, "/\\ \t\n") {
				return Config{}, fmt.Errorf("invalid migration root handle: %q", handle)
			}
			if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
				return Config{}, fmt.Errorf("migration root handle %q has an unsafe path", handle)
			}
		}
		normalizedServices, err := NormalizeMigrationAllowedServices(out.Migration.AllowedServices)
		if err != nil {
			return Config{}, err
		}
		out.Migration.AllowedServices = normalizedServices
		if out.Migration.BackendTaskSigningKeyID == "" || out.Migration.BackendTaskSigningPublicKeyPEMBase64 == "" {
			return Config{}, fmt.Errorf("backend migration task-signing key is required")
		}
	}
	return out, nil
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, ErrConfigNotFound
		}
		return Config{}, err
	}

	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, err
	}
	return c.Normalized()
}

func Save(path string, c Config) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
