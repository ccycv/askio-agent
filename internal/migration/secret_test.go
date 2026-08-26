package migration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/api"
)

type inertExecutor struct{}

func (inertExecutor) Supports(PrimitiveRef) bool { return true }
func (inertExecutor) Execute(context.Context, TaskEnvelope, func(string, int64, *int64) error) PrimitiveResult {
	return PrimitiveResult{State: "succeeded", Outputs: map[string]any{}, EvidenceDigests: []string{}}
}

func testBackendKey(t *testing.T) (string, string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return "backend-test", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func sealForTest(t *testing.T, identity *Identity, task TaskEnvelope, bindingID, deliveryNonce string, plaintext []byte) sealedSecretResponse {
	t.Helper()
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ephemeral.ECDH(identity.EncryptionPrivateKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(shared)
	key := hkdfSHA256SingleBlock(shared, []byte(task.AttemptID), []byte("askio-migration-secret-v1"))
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(ephemeral.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	envelope := sealedSecretEnvelope{
		SchemaVersion: "operations.migration.sealed-secret.v1", BindingID: bindingID,
		Purpose: "postgres.source", AttemptID: task.AttemptID, AgentID: task.AgentID,
		AgentKeyID: identity.EncryptionKeyID, DeliveryNonce: deliveryNonce,
		ExpiresAt:          time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
		Algorithm:          "x25519-hkdf-sha256-aes-256-gcm-v1",
		EphemeralPublicPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
		Nonce:              base64.RawURLEncoding.EncodeToString(nonce),
	}
	aad, err := CanonicalJSON(sealedSecretAAD(envelope))
	if err != nil {
		t.Fatal(err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	tagOffset := len(sealed) - gcm.Overhead()
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(sealed[:tagOffset])
	envelope.AuthTag = base64.RawURLEncoding.EncodeToString(sealed[tagOffset:])
	digest, err := Digest(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return sealedSecretResponse{SealedSecret: envelope, Digest: digest}
}

func TestRunnerResolvesAttemptScopedSealedBinding(t *testing.T) {
	keyDir := filepath.Join(t.TempDir(), "keys")
	identity, err := LoadOrCreateIdentity(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	bindingID := "22222222-2222-4222-8222-222222222222"
	task := TaskEnvelope{AgentID: "agent-test", AttemptID: "11111111-1111-4111-8111-111111111111", AttemptToken: "attempt-token-with-at-least-thirty-two-bytes", FencingToken: 7, Primitive: PrimitiveRef{ID: "migration.postgres.inspect.v1", Version: "1.0.0"}, Inputs: map[string]any{"endpoint_role": "source", "inputs": map[string]any{"database_binding_id": bindingID}}}
	want := []byte(`{"schema_version":"operations.migration.postgres-binding.v1","database":"fixture"}`)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		deliveryNonce, _ := body["delivery_nonce"].(string)
		response := sealForTest(t, identity, task, bindingID, deliveryNonce, want)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	client, err := api.New(api.Options{BaseURL: server.URL, Token: "test", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	backendKeyID, backendPublic := testBackendKey(t)
	runner, err := NewRunner(client, task.AgentID, identity, backendKeyID, backendPublic, filepath.Join(t.TempDir(), "state"), inertExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := runner.resolveBinding(context.Background(), task, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(got)
	if string(got) != string(want) {
		t.Fatalf("resolved binding mismatch: got %q", got)
	}
}

func TestRunnerRejectsSealedBindingDigestMismatch(t *testing.T) {
	identity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	bindingID := "22222222-2222-4222-8222-222222222222"
	task := TaskEnvelope{AgentID: "agent-test", AttemptID: "11111111-1111-4111-8111-111111111111", AttemptToken: "attempt-token-with-at-least-thirty-two-bytes", FencingToken: 7, Primitive: PrimitiveRef{ID: "migration.postgres.inspect.v1", Version: "1.0.0"}, Inputs: map[string]any{"endpoint_role": "source", "inputs": map[string]any{"database_binding_id": bindingID}}}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		response := sealForTest(t, identity, task, bindingID, body["delivery_nonce"].(string), []byte("secret"))
		response.Digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		_ = json.NewEncoder(writer).Encode(response)
	}))
	defer server.Close()
	client, _ := api.New(api.Options{BaseURL: server.URL, Token: "test"})
	backendKeyID, backendPublic := testBackendKey(t)
	runner, err := NewRunner(client, task.AgentID, identity, backendKeyID, backendPublic, filepath.Join(t.TempDir(), "state"), inertExecutor{})
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, err := runner.resolveBinding(context.Background(), task, bindingID); err == nil {
		zeroBytes(plaintext)
		t.Fatal("expected sealed binding digest mismatch")
	}
}

func TestComposeRuntimeBindingPurposeIsLimitedToTargetStart(t *testing.T) {
	bindingID := "44444444-4444-4444-8444-444444444444"
	task := TaskEnvelope{
		Primitive: PrimitiveRef{ID: "migration.compose.start-isolated.v1", Version: "1.0.0"},
		Inputs:    map[string]any{"endpoint_role": "target", "inputs": map[string]any{"runtime_secret_binding_id": bindingID}},
	}
	if purpose := expectedBindingPurpose(task, bindingID); purpose != "compose.runtime-secrets" {
		t.Fatalf("unexpected Compose binding purpose %q", purpose)
	}
	task.Primitive.ID = "migration.compose.stop.v1"
	if purpose := expectedBindingPurpose(task, bindingID); purpose != "" {
		t.Fatalf("Compose stop unexpectedly received runtime secret purpose %q", purpose)
	}
}

func TestDatabaseBindingPurposesFollowTypedEngineAndEndpoint(t *testing.T) {
	bindingID := "55555555-5555-4555-8555-555555555555"
	for _, test := range []struct {
		primitive string
		engine    string
		role      string
		want      string
	}{
		{"migration.mysql.dump.v1", "", "source", "mysql.source"},
		{"migration.mysql.restore.v1", "", "target", "mysql.target"},
		{"migration.mongodb.inspect.v1", "", "source", "mongodb.source"},
		{"migration.mongodb.verify.v1", "", "target", "mongodb.target"},
		{"migration.source.estimate.v1", "mariadb", "source", "mysql.source"},
		{"migration.source.verify-quiescence.v1", "mongodb", "source", "mongodb.source"},
	} {
		inputs := map[string]any{"database_binding_id": bindingID}
		if test.engine != "" {
			inputs["database_engine"] = test.engine
		}
		task := TaskEnvelope{
			Primitive: PrimitiveRef{ID: test.primitive, Version: "1.0.0"},
			Inputs:    map[string]any{"endpoint_role": test.role, "inputs": inputs},
		}
		if got := expectedBindingPurpose(task, bindingID); got != test.want {
			t.Fatalf("%s %s purpose = %q, want %q", test.primitive, test.role, got, test.want)
		}
	}
}
