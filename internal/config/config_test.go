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
	if config.Migration.RootHandles["workspace"] != "/srv/askio-migrations" || config.Migration.BrokerSocket == "" {
		t.Fatalf("migration defaults missing: %#v", config.Migration)
	}
}
