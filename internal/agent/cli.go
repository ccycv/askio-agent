package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/discovery"
	"github.com/askio-cloud/askio-monitor/internal/gateway"
	"github.com/askio-cloud/askio-monitor/internal/migration"
	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/remediation"
	"github.com/askio-cloud/askio-monitor/internal/store"
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
	root.AddCommand(newMigrationEnrollmentChallengeCmd())
	root.AddCommand(newMigrationEnrollmentCmd())
	root.AddCommand(newMigrationBrokerCmd(&cfgPath))

	return root
}

func newMigrationEnrollmentChallengeCmd() *cobra.Command {
	var keyDir string
	cmd := &cobra.Command{
		Use:    "migration-enrollment-challenge",
		Short:  "Prepare the host-bound migration enrollment challenge",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			identity, err := migration.LoadOrCreateIdentity(keyDir)
			if err != nil {
				return err
			}
			digest, err := migration.EnrollmentChallengeDigest(identity)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(os.Stdout, digest)
			return err
		},
	}
	cmd.Flags().StringVar(&keyDir, "key-dir", "/var/lib/askio-monitor/migration/keys", "Root for agent-owned migration keys")
	return cmd
}

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func migrationCapabilities() []string {
	return []string{
		"migration.security_profile.v1", "migration.discovery.v1", "migration.task_envelope.v1",
		"migration.preflight.v1", "migration.files_manifest.v1", "migration.compose_inspect.v1",
		"migration.checkpoint_resume.v1", "migration.validation.v1", "migration.evidence.v1",
		"migration.cleanup.v1", "migration.maintenance.v1",
		"migration.files_sync.v1", "migration.direct_mtls_chunks.v1",
		"migration.postgres_offline.v1", "migration.compose_isolation.v1", "migration.quiescence.v1",
	}
}

func newMigrationEnrollmentCmd() *cobra.Command {
	var registrationToken, keyDir, daemonUser, unitDigest, brokerDigest, packageVersion string
	var dataPlaneListenAddress string
	var allowedRoots []string
	var rootHandleBindings []string
	var allowedServices []string
	cmd := &cobra.Command{
		Use:    "migration-enrollment",
		Short:  "Generate migration keys and a registration proof",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if registrationToken == "" || !digestPattern.MatchString(unitDigest) || !digestPattern.MatchString(brokerDigest) {
				return fmt.Errorf("registration token and SHA-256 unit/broker digests are required")
			}
			if daemonUser == "" || daemonUser == "root" || packageVersion == "" {
				return fmt.Errorf("a non-root daemon user and package version are required")
			}
			rootHandles := config.CanonicalMigrationRootHandles()
			if len(rootHandleBindings) > 0 {
				rootHandles = map[string]string{}
				for _, binding := range rootHandleBindings {
					handle, root, found := strings.Cut(binding, "=")
					if !found || handle == "" || root == "" {
						return fmt.Errorf("migration root handles use handle=/absolute/path")
					}
					if _, exists := rootHandles[handle]; exists {
						return fmt.Errorf("duplicate migration root handle %q", handle)
					}
					rootHandles[handle] = root
				}
			}
			if len(allowedRoots) == 0 {
				allowedRoots = config.CanonicalMigrationAllowedRoots()
			}
			profileConfig, err := (config.Config{
				Mode: "host", APIURL: "https://enrollment.invalid", ServerID: "enrollment", AgentID: "enrollment",
				AgentToken: "enrollment", PrivilegeMode: config.PrivilegeModeSudo,
				Migration: &config.MigrationConfig{
					Enabled: true, RootHandles: rootHandles, AllowedRoots: allowedRoots,
					AllowedServices: allowedServices, DataPlaneListenAddress: dataPlaneListenAddress,
					BackendTaskSigningKeyID: "enrollment", BackendTaskSigningPublicKeyPEMBase64: "enrollment",
				},
			}).Normalized()
			if err != nil {
				return err
			}
			identity, err := migration.LoadOrCreateIdentity(keyDir)
			if err != nil {
				return err
			}
			profile := migration.SecurityProfile{
				DaemonIsRoot: false, DaemonUser: daemonUser, ShellMode: false, TypedBroker: true,
				ProtectSystem: "strict", ProtectHome: true, GenericHelperEnabled: false,
				PackageVersion: packageVersion, UnitDigest: unitDigest, BrokerDigest: brokerDigest,
				AllowedRoots:           profileConfig.Migration.AllowedRoots,
				RootHandles:            profileConfig.Migration.RootHandles,
				AllowedServices:        profileConfig.Migration.AllowedServices,
				DataPlaneListenAddress: profileConfig.Migration.DataPlaneListenAddress,
			}
			enrollment, err := migration.BuildEnrollment(identity, registrationToken, profile, migrationCapabilities())
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(os.Stdout)
			encoder.SetEscapeHTML(false)
			return encoder.Encode(enrollment)
		},
	}
	cmd.Flags().StringVar(&registrationToken, "registration-token", "", "One-time registration token")
	cmd.Flags().StringVar(&keyDir, "key-dir", "/var/lib/askio-monitor/migration/keys", "Root for agent-owned migration keys")
	cmd.Flags().StringVar(&daemonUser, "daemon-user", "askio-agent", "Unprivileged daemon account")
	cmd.Flags().StringVar(&unitDigest, "unit-digest", "", "Canonical systemd unit SHA-256 digest")
	cmd.Flags().StringVar(&brokerDigest, "broker-digest", "", "Typed broker binary SHA-256 digest")
	cmd.Flags().StringVar(&packageVersion, "package-version", version.Version, "Agent package version")
	cmd.Flags().StringSliceVar(&allowedRoots, "allowed-root", nil, "Fixed migration root (repeatable)")
	cmd.Flags().StringSliceVar(&rootHandleBindings, "root-handle", nil, "Fixed typed root handle as handle=/absolute/path")
	cmd.Flags().StringSliceVar(&allowedServices, "allowed-service", nil, "Preconfigured systemd service handle")
	cmd.Flags().StringVar(&dataPlaneListenAddress, "data-plane-listen", config.DefaultMigrationDataPlaneListenAddress, "Fixed direct-transfer listener")
	return cmd
}

func newMigrationBrokerCmd(cfgPath *string) *cobra.Command {
	return &cobra.Command{
		Use:    "migration-broker",
		Short:  "Run the root-owned typed migration privilege broker",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfigOrDie(*cfgPath)
			if err != nil {
				return err
			}
			if cfg.Migration == nil || !cfg.Migration.Enabled {
				return fmt.Errorf("migration broker is not enabled")
			}
			broker, err := migration.NewBroker(migration.BrokerConfig{
				SocketPath: cfg.Migration.BrokerSocket, StatePath: migration.DefaultBrokerStatePath,
				AgentUser: "askio-agent", AgentID: cfg.AgentID,
				BackendKeyID: cfg.Migration.BackendTaskSigningKeyID, BackendPublicKeyBase64: cfg.Migration.BackendTaskSigningPublicKeyPEMBase64,
				RootHandles: cfg.Migration.RootHandles, AllowedServices: cfg.Migration.AllowedServices,
			})
			if err != nil {
				return err
			}
			return broker.Serve(cmd.Context())
		},
	}
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
		Use:     "check",
		Short:   "Run a single monitor check from JSON config (for debugging)",
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
	var apiURL, serverID, agentID, token string
	var agentMode string
	var privilegeMode string
	var legacyMode string
	var installPrefix string
	var unitUser string
	var migrationEnabled bool
	var migrationKeyDir, migrationStateDir, migrationBrokerSocket, migrationDataPlaneListen string
	var backendSigningKeyID, backendSigningPublicKeyBase64 string
	var migrationRootHandles []string
	var migrationAllowedServices []string

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
			if migrationEnabled && (agentMode != "host" || priv == config.PrivilegeModeRoot || unitUser == "root") {
				return fmt.Errorf("migration requires host mode, sudo privilege mode, and a non-root service user")
			}
			cfg := config.Config{
				Mode:                      agentMode,
				APIURL:                    apiURL,
				ServerID:                  serverID,
				AgentID:                   agentID,
				AgentToken:                token,
				PrivilegeMode:             priv,
				HeartbeatIntervalSeconds:  30,
				ConfigPollIntervalSeconds: 60,
				LogLevel:                  "info",
				DataDir:                   config.DefaultDataDir(),
			}
			if migrationEnabled {
				rootHandles := config.CanonicalMigrationRootHandles()
				if len(migrationRootHandles) > 0 {
					rootHandles = map[string]string{}
					for _, binding := range migrationRootHandles {
						handle, root, found := strings.Cut(binding, "=")
						if !found || handle == "" || root == "" {
							return fmt.Errorf("migration root handles use handle=/absolute/path")
						}
						rootHandles[handle] = root
					}
				}
				cfg.Migration = &config.MigrationConfig{
					Enabled: true, KeyDir: migrationKeyDir, StateDir: migrationStateDir,
					BrokerSocket: migrationBrokerSocket, DataPlaneListenAddress: migrationDataPlaneListen, RootHandles: rootHandles,
					AllowedServices:                      append([]string{}, migrationAllowedServices...),
					BackendTaskSigningKeyID:              backendSigningKeyID,
					BackendTaskSigningPublicKeyPEMBase64: backendSigningPublicKeyBase64,
					PollIntervalSeconds:                  5, GenericHelperEnabled: false,
				}
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

			if priv == config.PrivilegeModeSudo && !migrationEnabled {
				// Provide the sudoers file template.
				sudoersPath := "/etc/sudoers.d/askio-monitor"
				if err := os.WriteFile(sudoersPath, []byte(remediation.SudoersTemplate()), 0o440); err != nil {
					return err
				}
			}
			if migrationEnabled {
				_ = os.Remove("/etc/sudoers.d/askio-monitor")
				_ = os.Remove(filepath.Join(installPrefix, "bin", "askio-ops"))
				account, err := user.Lookup(unitUser)
				if err != nil {
					return fmt.Errorf("resolve migration service user: %w", err)
				}
				uid, uidErr := strconv.Atoi(account.Uid)
				gid, gidErr := strconv.Atoi(account.Gid)
				if uidErr != nil || gidErr != nil || uid == 0 {
					return fmt.Errorf("migration service user has an invalid identity")
				}
				if err := os.Chown(*cfgPath, 0, gid); err != nil {
					return err
				}
				if err := os.Chmod(*cfgPath, 0o640); err != nil {
					return err
				}
				for _, root := range n.Migration.RootHandles {
					info, statErr := os.Lstat(root)
					if os.IsNotExist(statErr) {
						if err := os.MkdirAll(root, 0o770); err != nil {
							return err
						}
						info, statErr = os.Lstat(root)
					}
					if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
						return fmt.Errorf("migration root %q must be an existing non-symlink directory", root)
					}
					if err := os.Chown(root, 0, gid); err != nil {
						return err
					}
					if err := os.Chmod(root, 0o770); err != nil {
						return err
					}
				}
				for _, directory := range []string{n.Migration.KeyDir, n.Migration.StateDir} {
					if err := os.MkdirAll(directory, 0o700); err != nil {
						return err
					}
					if err := os.Chown(directory, uid, gid); err != nil {
						return err
					}
				}
				if err := os.MkdirAll(filepath.Dir(n.Migration.BrokerSocket), 0o750); err != nil {
					return err
				}
				if err := os.Chown(filepath.Dir(n.Migration.BrokerSocket), 0, gid); err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(migration.DefaultBrokerStatePath), 0o700); err != nil {
					return err
				}
				if err := os.Chown(filepath.Dir(migration.DefaultBrokerStatePath), 0, 0); err != nil {
					return err
				}
			}

			unitPath := "/etc/systemd/system/askio-monitor.service"
			if err := os.WriteFile(unitPath, []byte(systemdUnitTemplate(unitUser, *cfgPath, n.Migration)), 0o644); err != nil {
				return err
			}
			if migrationEnabled {
				brokerUnitPath := "/etc/systemd/system/askio-migration-broker.service"
				if err := os.WriteFile(brokerUnitPath, []byte(migrationBrokerUnitTemplate(*cfgPath, n.Migration)), 0o644); err != nil {
					return err
				}
			}

			// Enable/start.
			_, _ = remediation.ExecSimple(cmd.Context(), "systemctl", []string{"daemon-reload"}, 30)
			if migrationEnabled {
				_, _ = remediation.ExecSimple(cmd.Context(), "systemctl", []string{"enable", "--now", "askio-migration-broker"}, 30)
			}
			_, _ = remediation.ExecSimple(cmd.Context(), "systemctl", []string{"enable", "--now", "askio-monitor"}, 30)

			fmt.Printf("Installed. Config: %s\nSystemd unit: %s\nBinary: %s\n", *cfgPath, unitPath, targetBin)
			return nil
		},
	}
	cmd.Flags().StringVar(&apiURL, "api-url", "", "Backend base URL (host mode)")
	cmd.Flags().StringVar(&serverID, "server-id", "", "Server ID (host mode; also used as gateway_server_id in gateway mode)")
	cmd.Flags().StringVar(&agentID, "agent-id", "", "Agent identity returned during registration")
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
	cmd.Flags().BoolVar(&migrationEnabled, "migration-enabled", false, "Enable the signed migration task protocol")
	cmd.Flags().StringVar(&migrationKeyDir, "migration-key-dir", "/var/lib/askio-monitor/migration/keys", "Agent-owned migration key directory")
	cmd.Flags().StringVar(&migrationStateDir, "migration-state-dir", "/var/lib/askio-monitor/migration/state", "Agent-owned durable migration state")
	cmd.Flags().StringVar(&migrationBrokerSocket, "migration-broker-socket", "/run/askio-migration-broker/broker.sock", "Typed broker Unix socket")
	cmd.Flags().StringVar(&migrationDataPlaneListen, "migration-data-plane-listen", config.DefaultMigrationDataPlaneListenAddress, "Fixed TCP listen address for direct mTLS migration data transfer")
	cmd.Flags().StringVar(&backendSigningKeyID, "migration-backend-key-id", "", "Pinned backend task-signing key ID")
	cmd.Flags().StringVar(&backendSigningPublicKeyBase64, "migration-backend-public-key-base64", "", "Pinned backend task-signing public PEM, base64 encoded")
	cmd.Flags().StringSliceVar(&migrationRootHandles, "migration-root-handle", nil, "Fixed typed root handle as handle=/absolute/path")
	cmd.Flags().StringSliceVar(&migrationAllowedServices, "migration-allowed-service", nil, "Preconfigured systemd service handle")
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

func systemdUnitTemplate(user, cfgPath string, migrationConfig *config.MigrationConfig) string {
	// If you run in root mode, set User=root (or remove User=) when installing.
	if user == "" {
		user = "askio-agent"
	}
	readWritePaths := "/var/lib/askio-monitor"
	brokerDependency := ""
	noNewPrivileges := "false"
	if migrationConfig != nil && migrationConfig.Enabled {
		noNewPrivileges = "true"
		paths := []string{"/var/lib/askio-monitor", "/run/askio-monitor", migrationConfig.StateDir}
		for _, root := range migrationConfig.RootHandles {
			paths = append(paths, root)
		}
		sort.Strings(paths)
		readWritePaths = strings.Join(paths, " ")
		brokerDependency = "Requires=askio-migration-broker.service\nAfter=askio-migration-broker.service\n"
	}
	return fmt.Sprintf(`[Unit]
Description=Askio Monitor Agent
After=network-online.target
Wants=network-online.target
%s

[Service]
Type=simple
User=%s
ExecStart=/usr/local/bin/askio-monitor start --config %s
Restart=always
RestartSec=3
NoNewPrivileges=%s
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
RuntimeDirectory=askio-monitor
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, brokerDependency, user, cfgPath, noNewPrivileges, readWritePaths)
}

func migrationBrokerUnitTemplate(cfgPath string, migrationConfig *config.MigrationConfig) string {
	paths := []string{filepath.Dir(migration.DefaultBrokerStatePath), filepath.Dir(migrationConfig.BrokerSocket), "-/run/askio-monitor"}
	for _, root := range migrationConfig.RootHandles {
		paths = append(paths, root)
	}
	sort.Strings(paths)
	return fmt.Sprintf(`[Unit]
Description=Askio Typed Migration Privilege Broker
After=local-fs.target
Before=askio-monitor.service

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/local/bin/askio-monitor migration-broker --config %s
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, cfgPath, strings.Join(paths, " "))
}
