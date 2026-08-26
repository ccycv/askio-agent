package migration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalJSONSortsAndDoesNotHTMLEscape(t *testing.T) {
	encoded, err := CanonicalJSON(map[string]any{"z": "<safe>", "a": map[string]any{"y": 2, "x": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"a":{"x":1,"y":2},"z":"<safe>"}`; got != want {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func signedTaskFixture(t *testing.T, private ed25519.PrivateKey) TaskEnvelope {
	t.Helper()
	now := time.Now().UTC()
	inputs := map[string]any{"inputs": map[string]any{"root_handle": "workspace"}}
	subjectDigest, err := Digest(inputs)
	if err != nil {
		t.Fatal(err)
	}
	task := TaskEnvelope{
		SchemaVersion: "operations.migration.task.v1", KeyID: "backend-key-test", Algorithm: "ed25519-v1", Audience: "askio-monitor",
		AgentID: "agent-test", EndpointID: "endpoint-test", MigrationID: "migration-test", AttemptID: "attempt-test",
		AttemptToken: strings.Repeat("t", 32), FencingToken: 42, SubjectDigest: subjectDigest,
		Primitive: PrimitiveRef{ID: "migration.not-implemented.v1", Version: "1.0.0"}, ResourceScope: map[string]any{}, Inputs: inputs,
		IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano), Nonce: "signed-task-nonce-test",
	}
	runID := "run-test"
	runStepID := "run-step-test"
	task.RunID = &runID
	task.RunStepID = &runStepID
	canonical, err := CanonicalJSON(envelopeUnsigned(task))
	if err != nil {
		t.Fatal(err)
	}
	task.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, canonical))
	return task
}

func TestBrokerRequiresBackendSignedEnvelopeAndRejectsReplay(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	task := signedTaskFixture(t, private)
	broker := &Broker{
		config:        BrokerConfig{AgentID: task.AgentID, BackendKeyID: task.KeyID, StatePath: filepath.Join(t.TempDir(), "broker-state.json")},
		backendPublic: public,
		state:         brokerPersistentState{SchemaVersion: "operations.migration.broker-state.v1", Fences: map[string]int64{}, SeenNonces: []string{}, SeenNonceExpiries: map[string]string{}},
	}
	tampered := task
	tampered.Inputs = map[string]any{"inputs": map[string]any{"root_handle": "other"}}
	denied := broker.execute(context.Background(), BrokerRequest{SchemaVersion: brokerSchemaVersion, RequestID: tampered.Nonce, Task: tampered})
	if denied.Error == nil || denied.Error.Code != "MIGRATION_BROKER_TASK_UNAUTHORIZED" {
		t.Fatalf("tampered task was not denied: %#v", denied)
	}
	first := broker.execute(context.Background(), BrokerRequest{SchemaVersion: brokerSchemaVersion, RequestID: task.Nonce, Task: task})
	if first.Error == nil || first.Error.Code != "MIGRATION_BROKER_OPERATION_REJECTED" {
		t.Fatalf("signed unsupported task did not reach typed dispatch: %#v", first)
	}
	second := broker.execute(context.Background(), BrokerRequest{SchemaVersion: brokerSchemaVersion, RequestID: task.Nonce, Task: task})
	if second.Error == nil || second.Error.Code != "MIGRATION_BROKER_FENCED" {
		t.Fatalf("replayed signed task was not fenced: %#v", second)
	}
}

func TestBrokerDoesNotEvictAStillValidReplayNonce(t *testing.T) {
	now := time.Now().UTC()
	expiresAt := now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	state := brokerPersistentState{
		SchemaVersion: "operations.migration.broker-state.v1",
		Fences:        map[string]int64{}, WriterFences: map[string]writerFenceState{},
		SeenNonceExpiries: map[string]string{"replayed-live-nonce": expiresAt},
	}
	for index := 0; index < 600; index++ {
		state.SeenNonceExpiries[fmt.Sprintf("live-nonce-%03d", index)] = expiresAt
	}
	runID := "run-test"
	runStepID := "run-step-test"
	task := TaskEnvelope{
		MigrationID: "migration-test", RunID: &runID, RunStepID: &runStepID,
		FencingToken: 700, Primitive: PrimitiveRef{ID: "migration.cleanup.staging.v1", Version: "1.0.0"},
		Nonce: "replayed-live-nonce", ExpiresAt: expiresAt,
	}
	broker := &Broker{config: BrokerConfig{StatePath: filepath.Join(t.TempDir(), "broker-state.json")}, state: state}
	if err := broker.acceptFence(BrokerRequest{Task: task}); err == nil {
		t.Fatal("still-valid nonce was evicted from broker replay protection")
	}
}

func TestRunnerDoesNotEvictAStillValidReplayNonce(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	task := signedTaskFixture(t, private)
	state := persistentState{
		SchemaVersion:     "operations.migration.agent-state.v1",
		SeenNonceExpiries: map[string]string{task.Nonce: task.ExpiresAt},
	}
	for index := 0; index < 600; index++ {
		state.SeenNonceExpiries[fmt.Sprintf("runner-live-nonce-%03d", index)] = task.ExpiresAt
	}
	runner := &Runner{
		agentID: task.AgentID, backendKeyID: task.KeyID, backendPublic: public,
		executor: inertExecutor{}, state: state,
	}
	if _, err := runner.verifyEnvelope(task); err == nil {
		t.Fatal("still-valid nonce was evicted from runner replay protection")
	}
}

func TestIdentityEnrollmentPersistsPrivateKeysAndVerifiesProof(t *testing.T) {
	directory := t.TempDir()
	identity, err := LoadOrCreateIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	challengeDigest, err := EnrollmentChallengeDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(challengeDigest, "sha256:") {
		t.Fatalf("enrollment challenge digest is invalid: %s", challengeDigest)
	}
	profile := SecurityProfile{
		DaemonUser: "askio-agent", TypedBroker: true, ProtectSystem: "strict", ProtectHome: true,
		PackageVersion: "test", UnitDigest: "sha256:" + strings.Repeat("a", 64),
		BrokerDigest: "sha256:" + strings.Repeat("b", 64), AllowedRoots: []string{"/srv/askio-migrations"},
		RootHandles:     map[string]string{"workspace": "/srv/askio-migrations"},
		AllowedServices: []string{"fixture.service"}, DataPlaneListenAddress: "0.0.0.0:9443",
	}
	capabilities := []string{"migration.discovery.v1", "migration.security_profile.v1", "migration.task_envelope.v1"}
	enrollment, err := BuildEnrollment(identity, "registration-token", profile, capabilities)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enrollment.HostIdentityDigest, "machine") || !strings.HasPrefix(enrollment.HostIdentityDigest, "sha256:") {
		t.Fatalf("host identity was not privacy-safe: %s", enrollment.HostIdentityDigest)
	}
	attestation := map[string]any{
		"schema_version":            enrollment.SchemaVersion,
		"signing_key_id":            enrollment.SigningKeyID,
		"signing_public_key_pem":    enrollment.SigningPublicKeyPEM,
		"encryption_key_id":         enrollment.EncryptionKeyID,
		"encryption_public_key_pem": enrollment.EncryptionPublicKeyPEM,
		"host_identity_digest":      enrollment.HostIdentityDigest,
		"security_profile":          enrollment.SecurityProfile,
		"capabilities":              enrollment.Capabilities,
	}
	proof := map[string]any{}
	for key, value := range attestation {
		proof[key] = value
	}
	proof["attestation_digest"] = enrollment.AttestationDigest
	proof["nonce"] = enrollment.Nonce
	proof["registration_token_digest"] = "d5379496cc5edfa03edcf22a87e1f61f35977b186ceae1f05f763abcab271c13"
	canonical, err := CanonicalJSON(proof)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(enrollment.ProofSignature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(identity.SigningPrivateKey.Public().(ed25519.PublicKey), canonical, signature) {
		t.Fatal("enrollment proof did not verify")
	}
	reloaded, err := LoadOrCreateIdentity(directory)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.SigningKeyID != identity.SigningKeyID || reloaded.EncryptionKeyID != identity.EncryptionKeyID {
		t.Fatal("identity changed across reload")
	}
	for _, name := range []string{signingPrivateFile, encryptionPrivateFile, hostIdentityKeyFile} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode is %o", name, info.Mode().Perm())
		}
	}
}

func TestEnrollmentChallengeDigestMatchesBackendVector(t *testing.T) {
	identity := &Identity{
		SigningKeyID:           "signing-key-vector",
		SigningPublicKeyPEM:    "-----BEGIN PUBLIC KEY-----\nSIGNING-VECTOR\n-----END PUBLIC KEY-----\n",
		EncryptionKeyID:        "encryption-key-vector",
		EncryptionPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nENCRYPTION-VECTOR\n-----END PUBLIC KEY-----\n",
		HostIdentityDigest:     "sha256:" + strings.Repeat("c", 64),
	}
	digest, err := EnrollmentChallengeDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:285a94d57329f0d1acbc86d11823e3bb809f47eb8178e57528451a4e313c5644"
	if digest != expected {
		t.Fatalf("challenge vector mismatch: got %s want %s", digest, expected)
	}
}
