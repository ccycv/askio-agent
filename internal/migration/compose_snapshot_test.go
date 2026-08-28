package migration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImmutableComposeSnapshotDoesNotExecuteMutableAgentPaths(t *testing.T) {
	root := t.TempDir()
	project := "askio_mig_snapshot_race"
	mutableSecretDirectory := filepath.Join(root, "mutable-secrets", project)
	if err := os.MkdirAll(mutableSecretDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	mutableSecret := filepath.Join(mutableSecretDirectory, "database_password")
	if err := os.WriteFile(mutableSecret, []byte("approved-secret"), 0o444); err != nil {
		t.Fatal(err)
	}
	policy, err := parseComposePolicy([]byte(strings.ReplaceAll(validComposeWithSecretYAML(), "askio_mig_fixture", project)))
	if err != nil {
		t.Fatal(err)
	}
	policy.SecretFiles["database_password"] = mutableSecret
	policy.Document.Secrets["database_password"] = composeSecret{File: mutableSecret}
	broker := &Broker{config: BrokerConfig{ComposeSnapshotRoot: filepath.Join(root, "broker-snapshots")}}

	snapshot, err := broker.createImmutableComposeSnapshot(root, project, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.removeImmutableComposeSnapshot(snapshot)

	// The broker consumes only its root-owned copy and never mutates an
	// agent-owned path. The unprivileged agent performs its own descriptor-bound
	// wipe as soon as the broker call returns.
	if _, err := os.Lstat(mutableSecret); err != nil {
		t.Fatalf("broker unexpectedly changed the mutable source secret: %v", err)
	}
	if err := wipeAndRemoveComposeSecret(mutableSecret); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(mutableSecretDirectory); err != nil {
		t.Fatal(err)
	}
	mutableCompose := filepath.Join(root, "agent-compose.yaml")
	if err := os.WriteFile(mutableCompose, []byte("services:\n  escape:\n    privileged: true\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, err := broker.loadImmutableComposeSnapshot(project, policy.Digest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(loaded.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "privileged") || digestBytes(data) != loaded.Metadata.SnapshotDigest {
		t.Fatal("root-owned Compose snapshot changed with the mutable agent path")
	}
	for _, path := range []string{loaded.Directory, loaded.FilePath, filepath.Join(loaded.Directory, "secret-database_password")} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o022 != 0 {
			t.Fatalf("snapshot path is writable by the agent group or others: %s", path)
		}
	}
}

func TestRootBrokerRejectsComposeBindMounts(t *testing.T) {
	policy, err := parseComposePolicy([]byte(validComposeYAML()))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateComposeSecretScope("askio_mig_fixture", policy, false); err == nil {
		t.Fatal("root broker accepted an agent-mutable bind mount")
	}
}

func TestComposePolicyContinuousPathSwapNeverChangesApprovedBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	approved := []byte(validComposeYAML())
	hostile := []byte(strings.Replace(validComposeYAML(), strings.Repeat("a", 64), strings.Repeat("b", 64), 1))
	approvedPolicy, err := parseComposePolicy(approved)
	if err != nil {
		t.Fatal(err)
	}
	composePath := filepath.Join(root, "migration.yaml")
	if err := os.WriteFile(composePath, approved, 0o640); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewScopeResolver(map[string]string{"target": root})
	if err != nil {
		t.Fatal(err)
	}
	broker := &Broker{resolver: resolver}
	request := BrokerRequest{Task: TaskEnvelope{Inputs: map[string]any{
		"root_handle": "target", "compose_file": "migration.yaml",
		"project_name": "askio_mig_snapshot_race", "compose_digest": approvedPolicy.Digest,
	}}}

	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		iteration := 0
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			data := approved
			if iteration%2 == 1 {
				data = hostile
			}
			temporary := filepath.Join(root, ".compose-swap")
			if err := os.WriteFile(temporary, data, 0o640); err != nil {
				done <- err
				return
			}
			if err := os.Rename(temporary, composePath); err != nil {
				done <- err
				return
			}
			iteration++
		}
	}()

	for iteration := 0; iteration < 500; iteration++ {
		_, _, _, policy, readErr := broker.readComposePolicy(request, false)
		if readErr == nil && (policy.Digest != approvedPolicy.Digest || !bytesEqual(policy.CanonicalYAML, approvedPolicy.CanonicalYAML)) {
			close(stop)
			<-done
			t.Fatal("path swap changed the approved Compose policy")
		}
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func bytesEqual(left, right []byte) bool {
	return string(left) == string(right)
}
