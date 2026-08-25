package migration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func validComposeYAML() string {
	return `services:
  web:
    image: registry.example.test/fixture/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    user: "10001:10001"
    read_only: true
    init: true
    restart: "no"
    environment:
      APP_MODE: isolated
    volumes:
      - ./data:/srv/data:rw
    networks:
      isolated:
        ipv4_address: 172.29.250.2
    tmpfs:
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - "no-new-privileges:true"
    cpus: "0.50"
    mem_limit: 256M
    pids_limit: 128
    stop_grace_period: 30s
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
networks:
  isolated:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.29.250.0/24
          gateway: 172.29.250.1
`
}

func validComposeWithSecretYAML() string {
	return strings.Replace(validComposeYAML(), "    environment:\n      APP_MODE: isolated", `    environment:
      APP_MODE: isolated
      DATABASE_PASSWORD_FILE: /run/secrets/database_password
    secrets:
      - database_password`, 1) + `secrets:
  database_password:
    file: /run/askio-monitor/migration-secrets/askio_mig_fixture/database_password
`
}

func TestComposePolicyAcceptsOnlyIsolatedBoundedDocument(t *testing.T) {
	result, err := parseComposePolicy([]byte(validComposeYAML()))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Document.Services) != 1 || result.Digest == "" || len(result.PublishedPorts) != 0 {
		t.Fatalf("unexpected policy result: %+v", result)
	}
	if len(result.BindMountRoots) != 1 || result.BindMountRoots[0] != "data" {
		t.Fatalf("unexpected bind roots: %v", result.BindMountRoots)
	}
}

func TestComposePolicyRejectsEscapeFieldsAndUnpinnedImages(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
	}{
		{name: "privileged", from: "    user: \"10001:10001\"", to: "    privileged: true\n    user: \"10001:10001\""},
		{name: "host namespace", from: "    user: \"10001:10001\"", to: "    network_mode: host\n    user: \"10001:10001\""},
		{name: "command", from: "    user: \"10001:10001\"", to: "    command: [sh, -c, id]\n    user: \"10001:10001\""},
		{name: "absolute mount", from: "./data:/srv/data:rw", to: "/etc:/srv/data:ro"},
		{name: "unpinned image", from: "registry.example.test/fixture/web@sha256:" + strings.Repeat("a", 64), to: "registry.example.test/fixture/web:latest"},
		{name: "public network", from: "    internal: true", to: "    internal: false"},
		{name: "dynamic service address", from: "        ipv4_address: 172.29.250.2", to: "        ipv4_address: \"\""},
		{name: "public service address", from: "        ipv4_address: 172.29.250.2", to: "        ipv4_address: 203.0.113.2"},
		{name: "noncanonical subnet", from: "        - subnet: 172.29.250.0/24", to: "        - subnet: 172.29.250.0/16"},
		{name: "ignored loopback publish", from: "    networks:\n", to: "    ports:\n      - \"127.0.0.1:18080:8080\"\n    networks:\n"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			data := strings.Replace(validComposeYAML(), testCase.from, testCase.to, 1)
			if _, err := parseComposePolicy([]byte(data)); err == nil {
				t.Fatal("expected unsafe Compose document to be rejected")
			}
		})
	}
}

func TestComposePolicyRejectsAliasesAndInterpolation(t *testing.T) {
	if _, err := parseComposePolicy([]byte(strings.Replace(validComposeYAML(), "environment:\n      APP_MODE: isolated", "environment: &shared\n      APP_MODE: isolated", 1))); err == nil {
		t.Fatal("expected YAML anchor to be rejected")
	}
	if _, err := parseComposePolicy([]byte(strings.Replace(validComposeYAML(), "APP_MODE: isolated", "APP_MODE: ${APP_MODE}", 1))); err == nil {
		t.Fatal("expected interpolation to be rejected")
	}
}

func TestComposePolicyAcceptsOnlyDeclaredRuntimeSecretFiles(t *testing.T) {
	result, err := parseComposePolicy([]byte(validComposeWithSecretYAML()))
	if err != nil {
		t.Fatal(err)
	}
	if result.SecretFiles["database_password"] != "/run/askio-monitor/migration-secrets/askio_mig_fixture/database_password" {
		t.Fatalf("unexpected secret files: %v", result.SecretFiles)
	}
	unsafe := strings.Replace(validComposeWithSecretYAML(), "/run/askio-monitor/migration-secrets/askio_mig_fixture/database_password", "/tmp/database_password", 1)
	if _, err := parseComposePolicy([]byte(unsafe)); err == nil {
		t.Fatal("expected out-of-root Compose secret file to be rejected")
	}
}

func TestComposeRenderCreatesNewCanonicalFileOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	executor, err := NewNativeExecutor(map[string]string{"target": root}, filepath.Join(t.TempDir(), "broker.sock"), state)
	if err != nil {
		t.Fatal(err)
	}
	var rendered map[string]any
	if err := yaml.Unmarshal([]byte(validComposeYAML()), &rendered); err != nil {
		t.Fatal(err)
	}
	outputs, err := executor.composeRender(map[string]any{"root_handle": "target", "compose_file": "migration.yaml", "rendered_compose": rendered})
	if err != nil {
		t.Fatal(err)
	}
	if outputs["compose_digest"] == "" {
		t.Fatal("compose digest was not emitted")
	}
	if _, err := executor.composeRender(map[string]any{"root_handle": "target", "compose_file": "migration.yaml", "rendered_compose": rendered}); err == nil {
		t.Fatal("expected Compose file collision to be rejected")
	}
}

func TestComposeRuntimeSecretBindingRequiresCanonicalNamedValues(t *testing.T) {
	binding, err := parseComposeRuntimeSecretsBinding([]byte(`{"schema_version":"operations.migration.compose-runtime-secrets.v1","secrets":{"database_password":"fixture-secret"}}`))
	if err != nil || binding.Secrets["database_password"] != "fixture-secret" {
		t.Fatalf("unexpected runtime binding: %+v %v", binding, err)
	}
	if _, err := parseComposeRuntimeSecretsBinding([]byte(`{"schema_version":"operations.migration.compose-runtime-secrets.v1","secrets":{"../escape":"fixture-secret"}}`)); err == nil {
		t.Fatal("expected unsafe runtime secret name to be rejected")
	}
}

func TestComposeRuntimeSecretCleanupWipesReadOnlyLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime_credential")
	if err := os.WriteFile(path, []byte("synthetic-runtime-value"), 0o444); err != nil {
		t.Fatal(err)
	}
	if err := wipeAndRemoveComposeSecret(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("runtime secret leaf still exists after cleanup: %v", err)
	}
}
