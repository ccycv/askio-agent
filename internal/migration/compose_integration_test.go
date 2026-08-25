package migration

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestComposeRuntimeSecretLifecycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_COMPOSE_INTEGRATION") != "disposable-dind" {
		t.Skip("set ASKIO_MIGRATION_COMPOSE_INTEGRATION=disposable-dind inside the privileged disposable fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the disposable Docker-in-Docker fixture must run as root")
	}
	image := os.Getenv("ASKIO_MIGRATION_COMPOSE_IMAGE")
	if !composeImagePattern.MatchString(image) {
		t.Fatal("the fixture image must be pinned to its pulled repository digest")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	executor, err := NewNativeExecutor(map[string]string{"target": workspace}, filepath.Join(t.TempDir(), "unused.sock"), state)
	if err != nil {
		t.Fatal(err)
	}
	const (
		project   = "askio_mig_secret_semantics"
		bindingID = "11111111-1111-4111-8111-111111111111"
		secret    = "fixture-runtime-credential"
	)
	rendered := composeIntegrationDocument(image, project)
	renderOutputs, err := executor.composeRender(map[string]any{
		"root_handle": "target", "compose_file": "migration.yaml", "rendered_compose": rendered,
	})
	if err != nil {
		t.Fatal(err)
	}
	composeDigest, ok := renderOutputs["compose_digest"].(string)
	if !ok || composeDigest == "" {
		t.Fatal("Compose render did not return its policy digest")
	}
	binding, _ := json.Marshal(composeRuntimeSecretsBinding{
		SchemaVersion: composeRuntimeSecretsBindingSchema,
		Secrets:       map[string]string{"runtime_credential": secret},
	})
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, requested string) ([]byte, error) {
		if requested != bindingID {
			return nil, os.ErrNotExist
		}
		return append([]byte(nil), binding...), nil
	})
	inputs := map[string]any{
		"root_handle": "target", "compose_file": "migration.yaml", "project_name": project,
		"compose_digest": composeDigest, "runtime_secret_binding_id": bindingID,
	}
	task := TaskEnvelope{MigrationID: "22222222-2222-4222-8222-222222222222", AttemptID: "33333333-3333-4333-8333-333333333333", Inputs: inputs}
	cleanup, err := executor.stageComposeRuntimeSecrets(ctx, task, inputs)
	if err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(composeRuntimeSecretsRoot, project, "runtime_credential")
	secretInfo, err := os.Lstat(secretPath)
	if err != nil || secretInfo.Mode().Perm() != 0o444 {
		_ = cleanup()
		t.Fatalf("runtime secret leaf does not have the required read-only mode: %v", err)
	}

	broker := &Broker{resolver: executor.resolver}
	request := BrokerRequest{Task: task}
	started := false
	defer func() {
		if !started {
			_ = cleanup()
		}
	}()
	outputs, err := broker.composeStart(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	started = true
	if outputs["started"] != true || outputs["isolated"] != true {
		t.Fatalf("Compose start did not return bounded success outputs: %#v", outputs)
	}
	docker, err := fixedExecutable("/usr/bin/docker", "/usr/local/bin/docker")
	if err != nil {
		t.Fatal(err)
	}
	containers, exitCode, err := runFixedCapture(ctx, docker, "ps", "-q", "--filter", "label=com.docker.compose.project="+project)
	containerID := strings.TrimSpace(containers)
	if err != nil || exitCode != 0 || containerID == "" || strings.Contains(containerID, "\n") {
		t.Fatal("the isolated Compose project did not produce exactly one running container")
	}
	inside, exitCode, err := runFixedCapture(ctx, docker, "exec", containerID, "cat", "/run/secrets/runtime_credential")
	if err != nil || exitCode != 0 || inside != secret {
		t.Fatal("the declared non-root container could not read its file-backed runtime secret")
	}
	if data, err := os.ReadFile(secretPath); err != nil || string(data) != secret {
		t.Fatal("the memory-backed runtime secret did not remain available while the target was running")
	}

	stopTask := task
	stopTask.Inputs = map[string]any{
		"root_handle": "target", "compose_file": "migration.yaml", "project_name": project,
		"compose_digest": composeDigest, "remove_volumes": true,
	}
	stopOutputs, err := broker.composeStop(ctx, BrokerRequest{Task: stopTask})
	if err != nil {
		t.Fatal(err)
	}
	if stopOutputs["stopped"] != true || stopOutputs["volumes_preserved"] != false {
		t.Fatalf("Compose stop did not return bounded cleanup outputs: %#v", stopOutputs)
	}
	started = false
	if _, err := os.Lstat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("runtime secret leaf remains after typed stop: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(composeRuntimeSecretsRoot, project)); !os.IsNotExist(err) {
		t.Fatalf("runtime secret project directory remains after typed stop: %v", err)
	}
	containers, exitCode, err = runFixedCapture(ctx, docker, "ps", "-aq", "--filter", "label=com.docker.compose.project="+project)
	if err != nil || exitCode != 0 || strings.TrimSpace(containers) != "" {
		t.Fatal("typed stop left residual Compose containers")
	}
}

func composeIntegrationDocument(image, project string) map[string]any {
	data := `services:
  cache:
    image: IMAGE
    user: "999:999"
    read_only: true
    init: true
    restart: "no"
    environment:
      REDIS_PASSWORD_FILE: /run/secrets/runtime_credential
    volumes:
      - ./data:/fixture-data:rw
    networks:
      isolated:
        ipv4_address: 172.29.253.2
    secrets:
      - runtime_credential
    tmpfs:
      - /data
      - /tmp
    cap_drop:
      - ALL
    security_opt:
      - "no-new-privileges:true"
    cpus: "0.25"
    mem_limit: 128M
    pids_limit: 64
    stop_grace_period: 10s
    logging:
      driver: json-file
      options:
        max-size: 1m
        max-file: "2"
networks:
  isolated:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.29.253.0/24
          gateway: 172.29.253.1
secrets:
  runtime_credential:
    file: /run/askio-monitor/migration-secrets/PROJECT/runtime_credential
`
	data = strings.ReplaceAll(data, "IMAGE", image)
	data = strings.ReplaceAll(data, "PROJECT", project)
	var document map[string]any
	if err := yaml.Unmarshal([]byte(data), &document); err != nil {
		panic(err)
	}
	return document
}
