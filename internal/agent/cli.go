package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/discovery"
	"github.com/askio-cloud/askio-monitor/internal/gateway"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
	"github.com/askio-cloud/askio-monitor/internal/store"
	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/version"
	"github.com/spf13/cobra"
)

type CLIOptions struct {
	Logger *slog.Logger
}

func NewCLI(opts CLIOptions) *cobra.Command {
	var cfgPath string

	root := &cobra.Command{
		Use:     "askio-monitor",
		Short:   "Askio service monitor agent",
		Version: version.Version,
	}

	root.PersistentFlags().StringVar(&cfgPath, "config", config.DefaultConfigPath(), "Path to agent YAML config")

	root.AddCommand(newStartCmd(opts.Logger, &cfgPath))
	root.AddCommand(newDiscoverCmd(opts.Logger, &cfgPath))
	root.AddCommand(newCheckCmd(opts.Logger, &cfgPath))
	root.AddCommand(newRemediateCmd(opts.Logger, &cfgPath))
	root.AddCommand(newStatusCmd(opts.Logger, &cfgPath))
	root.AddCommand(newInstallCmd(opts.Logger, &cfgPath))

	return root
}

func loadConfigOrDie(path string) (config.Config, error) {
	return config.Load(path)
}

func newStartCmd(logger *slog.Logger, cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Run the monitoring daemon in foreground (systemd should run this)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDie(*cfgPath)
			if err != nil {
				return err
			}
			if cfg.Mode == "gateway" {
				gw := cfg.Gateway
				if gw == nil {
					return fmt.Errorf("gateway config missing")
				}
				srv, err := gateway.NewServer(gateway.Config{
					ListenAddr:      gw.ListenAddr,
					TLSCertPath:     gw.TLSCertPath,
					TLSKeyPath:      gw.TLSKeyPath,
					TokenHMACKey:    []byte(gw.TokenHMACKey),
					CloudAPIURL:     gw.CloudAPIURL,
					CloudAgentToken: gw.CloudAgentToken,
					GatewayServerID: gw.GatewayServerID,
				})
				if err != nil {
					return err
				}
				logger.Info("starting gateway server", "listen", gw.ListenAddr, "cloud_api_url", gw.CloudAPIURL)
				return srv.Start(cmd.Context())
			}

			a, err := NewDaemon(logger, cfg)
			if err != nil {
				return err
			}
			return a.Run(cmd.Context())
		},
	}
	return cmd
}

func newDiscoverCmd(logger *slog.Logger, cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover services (systemd + docker + process)",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := loadConfigOrDie(*cfgPath)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			d := discovery.NewDetector(logger)
			svcs, err := d.Detect(ctx)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"discovered_at": time.Now().UTC(), "services": svcs})
		},
	}
	return cmd
}

func newCheckCmd(logger *slog.Logger, cfgPath *string) *cobra.Command {
	var monitorJSON string
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run a single monitor check from JSON config (for debugging)",
		Example: `askio-monitor check --monitor '{"id":"x","service_name":"nginx","service_type":"systemd","systemd_unit":"nginx.service","check_types":["active_state"],"check_interval_seconds":60,"enabled":true}'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := loadConfigOrDie(*cfgPath)
			if err != nil {
				return err
			}
			var m model.MonitorConfig
			if err := json.Unmarshal([]byte(monitorJSON), &m); err != nil {
				return fmt.Errorf("parse --monitor JSON: %w", err)
			}
			res, err := RunSingleCheck(cmd.Context(), logger, m)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		},
	}
	cmd.Flags().StringVar(&monitorJSON, "monitor", "", "Monitor JSON")
	_ = cmd.MarkFlagRequired("monitor")
	return cmd
}

func newRemediateCmd(logger *slog.Logger, cfgPath *string) *cobra.Command {
	var playbookID string
	var monitorJSON string

	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Run a playbook for a monitor (manual remediation)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDie(*cfgPath)
			if err != nil {
				return err
			}

			var m model.MonitorConfig
			if err := json.Unmarshal([]byte(monitorJSON), &m); err != nil {
				return fmt.Errorf("parse --monitor JSON: %w", err)
			}

			exec, err := remediation.NewExecutor(cfg.PrivilegeMode)
			if err != nil {
				return err
			}
			eng := remediation.NewEngine(logger, exec)
			run, err := eng.Run(cmd.Context(), m, playbookID, "manual")
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(run)
		},
	}
	cmd.Flags().StringVar(&playbookID, "playbook", "", "Playbook ID to run")
	cmd.Flags().StringVar(&monitorJSON, "monitor", "", "Monitor JSON")
	_ = cmd.MarkFlagRequired("playbook")
	_ = cmd.MarkFlagRequired("monitor")
	return cmd
}

func newStatusCmd(logger *slog.Logger, cfgPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print agent status (local config + last cached remote config)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDie(*cfgPath)
			if err != nil {
				return err
			}
			st, err := store.OpenFileStore(cfg.DataDir)
			if err != nil {
				return err
			}
			defer st.Close()

			out := map[string]any{"config_path": *cfgPath, "api_url": cfg.APIURL, "server_id": cfg.ServerID, "privilege_mode": cfg.PrivilegeMode, "data_dir": cfg.DataDir}

			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	return cmd
}

func newInstallCmd(logger *slog.Logger, cfgPath *string) *cobra.Command {
	var apiURL, serverID, token string
	var agentMode string
	var privilegeMode string
	var legacyMode string
	var installPrefix string
	var unitUser string

	// Gateway-only
	var gwListenAddr, gwTLSCert, gwTLSKey, gwTokenHMACKey, gwCloudAPIURL, gwCloudToken string

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install binary + systemd unit + config (requires root for system paths)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return fmt.Errorf("install must be run as root")
			}
			// Backward compatibility:
			// - historically `--mode` meant privilege mode (sudo|root)
			// - some scripts use `--privilege-mode`
			pm := privilegeMode
			if pm == "" {
				pm = legacyMode
			}
			priv := config.PrivilegeMode(pm)

			if agentMode == "" {
				agentMode = "host"
			}
			cfg := config.Config{
				Mode:                      agentMode,
				APIURL:                     apiURL,
				ServerID:                   serverID,
				AgentToken:                 token,
				PrivilegeMode:              priv,
				HeartbeatIntervalSeconds:   30,
				ConfigPollIntervalSeconds:  60,
				LogLevel:                   "info",
				DataDir:                    config.DefaultDataDir(),
			}
			if agentMode == "gateway" {
				cfg.Gateway = &config.GatewayConfig{
					ListenAddr:      gwListenAddr,
					TLSCertPath:     gwTLSCert,
					TLSKeyPath:      gwTLSKey,
					TokenHMACKey:    gwTokenHMACKey,
					CloudAPIURL:     gwCloudAPIURL,
					CloudAgentToken: gwCloudToken,
					GatewayServerID: serverID,
				}
				// In gateway mode, top-level fields are not used at runtime.
				// Keep them if provided so the config remains attributable.
				if cfg.APIURL == "" {
					cfg.APIURL = "http://unused"
				}
				if cfg.ServerID == "" {
					cfg.ServerID = serverID
				}
				if cfg.AgentToken == "" {
					cfg.AgentToken = "gateway"
				}
			}
			n, err := cfg.Normalized()
			if err != nil {
				return err
			}
			if err := config.Save(*cfgPath, n); err != nil {
				return err
			}

			// Copy current executable into /usr/local/bin (or custom prefix).
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			targetBin := filepath.Join(installPrefix, "bin", "askio-monitor")
			if err := os.MkdirAll(filepath.Dir(targetBin), 0o755); err != nil {
				return err
			}
			if err := copyFile(exe, targetBin, 0o755); err != nil {
				return err
			}

			if priv == config.PrivilegeModeSudo {
				// Provide the sudoers file template.
				sudoersPath := "/etc/sudoers.d/askio-monitor"
				if err := os.WriteFile(sudoersPath, []byte(remediation.SudoersTemplate()), 0o440); err != nil {
					return err
				}
			}

			unitPath := "/etc/systemd/system/askio-monitor.service"
			if err := os.WriteFile(unitPath, []byte(systemdUnitTemplate(unitUser, *cfgPath)), 0o644); err != nil {
				return err
			}

			// Enable/start.
			_, _ = remediation.ExecSimple(cmd.Context(), "systemctl", []string{"daemon-reload"}, 30)
			_, _ = remediation.ExecSimple(cmd.Context(), "systemctl", []string{"enable", "--now", "askio-monitor"}, 30)

			fmt.Printf("Installed. Config: %s\nSystemd unit: %s\nBinary: %s\n", *cfgPath, unitPath, targetBin)
			return nil
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Backend base URL (host mode)")
	cmd.Flags().StringVar(&serverID, "server-id", "", "Server ID (host mode; also used as gateway_server_id in gateway mode)")
	cmd.Flags().StringVar(&token, "token", "", "Agent token (host mode)")
	cmd.Flags().StringVar(&agentMode, "agent-mode", "host", "Agent mode: host|gateway")
	cmd.Flags().StringVar(&privilegeMode, "privilege-mode", string(config.PrivilegeModeSudo), "Privilege mode: sudo|root")
	cmd.Flags().StringVar(&legacyMode, "mode", "", "(deprecated) Privilege mode: sudo|root")

	cmd.Flags().StringVar(&gwListenAddr, "gateway-listen-addr", ":8443", "Gateway listen address")
	cmd.Flags().StringVar(&gwTLSCert, "gateway-tls-cert", "", "Gateway TLS cert path")
	cmd.Flags().StringVar(&gwTLSKey, "gateway-tls-key", "", "Gateway TLS key path")
	cmd.Flags().StringVar(&gwTokenHMACKey, "gateway-token-hmac-key", "", "Gateway token HMAC key")
	cmd.Flags().StringVar(&gwCloudAPIURL, "gateway-cloud-api-url", "", "Cloud API URL to forward to")
	cmd.Flags().StringVar(&gwCloudToken, "gateway-cloud-token", "", "Cloud agent token for gateway")

	cmd.Flags().StringVar(&installPrefix, "prefix", "/usr/local", "Install prefix")
	cmd.Flags().StringVar(&unitUser, "unit-user", "askio-agent", "systemd unit User= (ignored if running as root)")
	// Host mode requires these.
	// (gateway mode validates its own required flags in Config.Normalized)
	// We can't conditionally require flags in cobra without custom validation.
	return cmd
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, b, mode); err != nil {
		return err
	}
	return nil
}

func systemdUnitTemplate(user, cfgPath string) string {
	// If you run in root mode, set User=root (or remove User=) when installing.
	if user == "" {
		user = "askio-agent"
	}
	return fmt.Sprintf(`[Unit]
Description=Askio Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
ExecStart=/usr/local/bin/askio-monitor start --config %s
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
`, user, cfgPath)
}
