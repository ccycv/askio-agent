package config

import "testing"

func baseMigrationConfig() Config {
	return Config{
		Mode: "host", APIURL: "https://api.example/functions/v1", ServerID: "server", AgentID: "agent",
		AgentToken: "token", PrivilegeMode: PrivilegeModeSudo,
		Migration: &MigrationConfig{Enabled: true, BackendTaskSigningKeyID: "backend-key", BackendTaskSigningPublicKeyPEMBase64: "cGVt"},
	}
}

func TestMigrationConfigRejectsRootAndGenericShell(t *testing.T) {
	root := baseMigrationConfig()
	root.PrivilegeMode = PrivilegeModeRoot
	if _, err := root.Normalized(); err == nil {
		t.Fatal("root migration daemon was accepted")
	}
	shell := baseMigrationConfig()
	shell.Operations = &OperationsConfig{AllowShell: true}
	if _, err := shell.Normalized(); err == nil {
		t.Fatal("shell-enabled migration daemon was accepted")
	}
}

func TestMigrationConfigDefaultsToFixedHandles(t *testing.T) {
	config, err := baseMigrationConfig().Normalized()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Migration.RootHandles) != 8 ||
		config.Migration.RootHandles["source-data"] != "/srv/askio-migrations/source-data" ||
		config.Migration.RootHandles["target-staging"] != "/var/lib/askio-migrations/target-staging" ||
		config.Migration.DataPlaneListenAddress != DefaultMigrationDataPlaneListenAddress ||
		config.Migration.BrokerSocket == "" {
		t.Fatalf("migration defaults missing: %#v", config.Migration)
	}
}

func TestMigrationConfigRejectsProfileDrift(t *testing.T) {
	driftedRoot := baseMigrationConfig()
	driftedRoot.Migration.RootHandles = CanonicalMigrationRootHandles()
	driftedRoot.Migration.RootHandles["source-data"] = "/tmp/source-data"
	if _, err := driftedRoot.Normalized(); err == nil {
		t.Fatal("drifted migration root profile was accepted")
	}

	driftedListener := baseMigrationConfig()
	driftedListener.Migration.DataPlaneListenAddress = "127.0.0.1:9443"
	if _, err := driftedListener.Normalized(); err == nil {
		t.Fatal("drifted migration data-plane listener was accepted")
	}

	invalidService := baseMigrationConfig()
	invalidService.Migration.AllowedServices = []string{"fixture;shutdown.service"}
	if _, err := invalidService.Normalized(); err == nil {
		t.Fatal("invalid migration service handle was accepted")
	}
}
