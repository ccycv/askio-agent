package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

var ErrConfigNotFound = errors.New("askio-monitor config not found")

type PrivilegeMode string

const (
	PrivilegeModeRoot PrivilegeMode = "root"
	PrivilegeModeSudo PrivilegeMode = "sudo"
)

type Config struct {
	Mode                     string        `yaml:"mode"`
	APIURL                    string        `yaml:"api_url"`
	ServerID                  string        `yaml:"server_id"`
	AgentToken                string        `yaml:"agent_token"`
	TLSSkipVerify             bool          `yaml:"tls_skip_verify"`
	CACertPath                string        `yaml:"ca_cert_path"`
	PrivilegeMode             PrivilegeMode `yaml:"privilege_mode"`
	HeartbeatIntervalSeconds  int           `yaml:"heartbeat_interval_seconds"`
	ConfigPollIntervalSeconds int           `yaml:"config_poll_interval_seconds"`
	DiscoveryPollIntervalSeconds int        `yaml:"discovery_poll_interval_seconds"`
	LogLevel                  string        `yaml:"log_level"`

	// Local state/cache
	DataDir string `yaml:"data_dir"`

	Operations *OperationsConfig `yaml:"operations,omitempty"`

	Gateway *GatewayConfig `yaml:"gateway,omitempty"`
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
	ListenAddr     string `yaml:"listen_addr"`
	TLSCertPath    string `yaml:"tls_cert_path"`
	TLSKeyPath     string `yaml:"tls_key_path"`
	TokenHMACKey   string `yaml:"token_hmac_key"`
	CloudAPIURL    string `yaml:"cloud_api_url"`
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
