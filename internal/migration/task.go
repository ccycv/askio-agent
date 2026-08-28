package migration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/api"
)

const (
	RouteTaskClaim        = "monitor-agent-migration-task-claim"
	RouteTaskProgress     = "monitor-agent-migration-task-progress"
	RouteTaskResult       = "monitor-agent-migration-task-result"
	RouteTaskCancelStatus = "monitor-agent-migration-task-cancel-status"
	RouteSecretUnwrap     = "monitor-agent-migration-secret-unwrap"
	RouteDataPlaneTicket  = "monitor-agent-migration-data-plane-ticket"
)

type PrimitiveRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type TaskEnvelope struct {
	SchemaVersion string         `json:"schema_version"`
	KeyID         string         `json:"key_id"`
	Algorithm     string         `json:"algorithm"`
	Audience      string         `json:"audience"`
	AgentID       string         `json:"agent_id"`
	EndpointID    string         `json:"endpoint_id"`
	MigrationID   string         `json:"migration_id"`
	RunID         *string        `json:"run_id"`
	RunStepID     *string        `json:"run_step_id"`
	AttemptID     string         `json:"attempt_id"`
	AttemptToken  string         `json:"attempt_token"`
	FencingToken  int64          `json:"fencing_token"`
	PlanDigest    *string        `json:"plan_digest"`
	SubjectDigest string         `json:"subject_digest"`
	Primitive     PrimitiveRef   `json:"primitive"`
	ResourceScope map[string]any `json:"resource_scope"`
	Inputs        map[string]any `json:"inputs"`
	IssuedAt      string         `json:"issued_at"`
	ExpiresAt     string         `json:"expires_at"`
	Nonce         string         `json:"nonce"`
	Signature     string         `json:"signature"`
}

type ClaimResponse struct {
	Task *TaskEnvelope `json:"task"`
}

type PrimitiveResult struct {
	State           string         `json:"state"`
	Outputs         map[string]any `json:"outputs"`
	EvidenceDigests []string       `json:"evidence_digests"`
	Checkpoint      map[string]any `json:"checkpoint,omitempty"`
	Error           *SafeError     `json:"error,omitempty"`
}

type SafeError struct {
	Code        string `json:"code"`
	SafeMessage string `json:"safe_message"`
	Retryable   bool   `json:"retryable"`
}

type Executor interface {
	Supports(PrimitiveRef) bool
	Execute(context.Context, TaskEnvelope, func(phase string, completed int64, total *int64) error) PrimitiveResult
}

// BindingResolver returns one attempt-scoped plaintext binding. Implementations
// must not persist, log, or place the returned bytes in task results, and the
// caller must zero the slice as soon as the primitive has parsed it.
type BindingResolver func(context.Context, TaskEnvelope, string) ([]byte, error)

// TicketResolver refreshes only the short-lived authorization for an existing
// immutable file-transfer task. It cannot change the signed task scope.
type TicketResolver func(context.Context, TaskEnvelope) (DataPlaneTicket, error)

type bindingAwareExecutor interface {
	SetBindingResolver(BindingResolver)
}

type ticketAwareExecutor interface {
	SetTicketResolver(TicketResolver)
}

type sealedSecretEnvelope struct {
	SchemaVersion      string `json:"schema_version"`
	BindingID          string `json:"binding_id"`
	Purpose            string `json:"purpose"`
	AttemptID          string `json:"attempt_id"`
	AgentID            string `json:"agent_id"`
	AgentKeyID         string `json:"agent_key_id"`
	DeliveryNonce      string `json:"delivery_nonce"`
	ExpiresAt          string `json:"expires_at"`
	Algorithm          string `json:"algorithm"`
	EphemeralPublicPEM string `json:"ephemeral_public_key_pem"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
	AuthTag            string `json:"auth_tag"`
}

type sealedSecretResponse struct {
	SealedSecret sealedSecretEnvelope `json:"sealedSecret"`
	Digest       string               `json:"digest"`
}

type persistentState struct {
	SchemaVersion     string            `json:"schema_version"`
	AcceptedDigest    string            `json:"accepted_envelope_digest,omitempty"`
	ActiveAttemptID   string            `json:"active_attempt_id,omitempty"`
	ActivePrimitive   string            `json:"active_primitive,omitempty"`
	CurrentPhase      string            `json:"current_phase,omitempty"`
	ProgressSequence  int64             `json:"progress_sequence,omitempty"`
	PendingRoute      string            `json:"pending_route,omitempty"`
	PendingResultBody map[string]any    `json:"pending_result_body,omitempty"`
	SeenNonces        []string          `json:"seen_nonces,omitempty"`
	SeenNonceExpiries map[string]string `json:"seen_nonce_expiries,omitempty"`
}

type Runner struct {
	client        *api.Client
	agentID       string
	identity      *Identity
	backendKeyID  string
	backendPublic ed25519.PublicKey
	statePath     string
	executor      Executor
	activityHook  func(bool)
	mu            sync.Mutex
	state         persistentState
}

var errTaskPauseRequested = errors.New("migration task pause requested")
var errTaskCancelRequested = errors.New("migration task safe cancellation requested")

func (r *Runner) SetActivityHook(hook func(bool)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activityHook = hook
}

func parseBackendSigningKey(encoded string) (ed25519.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode backend signing key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("backend signing key PEM is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("backend signing key is not Ed25519")
	}
	return key, nil
}

func NewRunner(client *api.Client, agentID string, identity *Identity, backendKeyID, backendPublicKeyBase64, stateDir string, executor Executor) (*Runner, error) {
	if client == nil || identity == nil || executor == nil {
		return nil, errors.New("migration runner dependencies are required")
	}
	backendPublic, err := parseBackendSigningKey(backendPublicKeyBase64)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("migration state directory must be absolute")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	runner := &Runner{
		client: client, agentID: agentID, identity: identity, backendKeyID: backendKeyID,
		backendPublic: backendPublic, statePath: filepath.Join(stateDir, "task-state.json"), executor: executor,
		state: persistentState{
			SchemaVersion: "operations.migration.agent-state.v1",
			SeenNonces:    []string{}, SeenNonceExpiries: map[string]string{},
		},
	}
	if aware, ok := executor.(bindingAwareExecutor); ok {
		aware.SetBindingResolver(runner.resolveBinding)
	}
	if aware, ok := executor.(ticketAwareExecutor); ok {
		aware.SetTicketResolver(runner.resolveDataPlaneTicket)
	}
	if err := runner.loadState(); err != nil {
		return nil, err
	}
	return runner, nil
}

func (r *Runner) resolveDataPlaneTicket(ctx context.Context, task TaskEnvelope) (DataPlaneTicket, error) {
	if task.Primitive.ID != "migration.files.sync.v1" || task.RunID == nil || task.RunStepID == nil {
		return DataPlaneTicket{}, errors.New("direct-transfer ticket refresh is outside the task scope")
	}
	response := struct {
		Ticket DataPlaneTicket `json:"ticket"`
	}{}
	_, err := r.postSigned(ctx, RouteDataPlaneTicket, map[string]any{
		"attempt_id": task.AttemptID, "attempt_token": task.AttemptToken,
		"fencing_token": task.FencingToken,
	}, &response)
	if err != nil {
		return DataPlaneTicket{}, errors.New("direct-transfer ticket refresh failed")
	}
	return response.Ticket, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// hkdfSHA256SingleBlock implements the RFC 5869 extract-and-expand operation
// for the only output size used by the sealed-secret contract (32 bytes).
// Keeping it local avoids introducing a second crypto dependency into the
// agent package while matching Node's hkdfSync("sha256", ...).
func hkdfSHA256SingleBlock(secret, salt, info []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	defer zeroBytes(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func parseX25519PublicKey(pemText string) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("sealed secret ephemeral key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("sealed secret ephemeral key is invalid")
	}
	publicKey, ok := parsed.(*ecdh.PublicKey)
	if !ok || publicKey.Curve() != ecdh.X25519() {
		return nil, errors.New("sealed secret ephemeral key is not X25519")
	}
	return publicKey, nil
}

func sealedSecretAAD(envelope sealedSecretEnvelope) map[string]any {
	return map[string]any{
		"schema_version": envelope.SchemaVersion,
		"binding_id":     envelope.BindingID,
		"purpose":        envelope.Purpose,
		"attempt_id":     envelope.AttemptID,
		"agent_id":       envelope.AgentID,
		"agent_key_id":   envelope.AgentKeyID,
		"delivery_nonce": envelope.DeliveryNonce,
		"expires_at":     envelope.ExpiresAt,
	}
}

func expectedBindingPurpose(task TaskEnvelope, bindingID string) string {
	inputs := taskInputs(task)
	endpointRole, _ := task.Inputs["endpoint_role"].(string)
	if value, _ := inputs["transfer_binding_id"].(string); value == bindingID && task.Primitive.ID == "migration.files.sync.v1" && endpointRole == "target" {
		return "transfer.source-address"
	}
	if value, _ := inputs["runtime_secret_binding_id"].(string); value == bindingID && task.Primitive.ID == "migration.compose.start-isolated.v1" && endpointRole == "target" {
		return "compose.runtime-secrets"
	}
	if value, _ := inputs["logical_source_binding_id"].(string); value == bindingID && endpointRole == "target" &&
		strings.HasPrefix(task.Primitive.ID, "migration.postgres.logical-") {
		return "postgres.logical-source"
	}
	if value, _ := inputs["database_binding_id"].(string); value != bindingID {
		return ""
	}
	family := ""
	switch {
	case strings.HasPrefix(task.Primitive.ID, "migration.postgres."):
		family = "postgres"
	case strings.HasPrefix(task.Primitive.ID, "migration.mysql."):
		family = "mysql"
	case strings.HasPrefix(task.Primitive.ID, "migration.mongodb."):
		family = "mongodb"
	case strings.HasPrefix(task.Primitive.ID, "migration.redis."):
		family = "redis"
	case task.Primitive.ID == "migration.source.estimate.v1" || task.Primitive.ID == "migration.source.verify-quiescence.v1":
		engine, _ := inputs["database_engine"].(string)
		switch engine {
		case "postgresql":
			family = "postgres"
		case "mysql", "mariadb":
			family = "mysql"
		case "mongodb":
			family = "mongodb"
		case "redis", "valkey":
			family = "redis"
		}
	}
	if family == "" {
		return ""
	}
	sourcePrimitive := strings.HasSuffix(task.Primitive.ID, ".inspect.v1") || strings.HasSuffix(task.Primitive.ID, ".dump.v1") ||
		task.Primitive.ID == "migration.source.estimate.v1" || task.Primitive.ID == "migration.source.verify-quiescence.v1" ||
		task.Primitive.ID == "migration.postgres.logical-preflight.v1" || task.Primitive.ID == "migration.postgres.logical-schema-dump.v1" ||
		task.Primitive.ID == "migration.postgres.logical-prepare-source.v1" || task.Primitive.ID == "migration.postgres.logical-finalize-source.v1" ||
		task.Primitive.ID == "migration.postgres.logical-cleanup-source.v1"
	targetPrimitive := strings.HasSuffix(task.Primitive.ID, ".inspect.v1") || strings.HasSuffix(task.Primitive.ID, ".reset-empty-target.v1") ||
		strings.HasSuffix(task.Primitive.ID, ".restore.v1") || strings.HasSuffix(task.Primitive.ID, ".verify.v1") ||
		task.Primitive.ID == "migration.postgres.logical-preflight.v1" || task.Primitive.ID == "migration.postgres.logical-restore-schema.v1" ||
		task.Primitive.ID == "migration.postgres.logical-start-subscription.v1" || task.Primitive.ID == "migration.postgres.logical-finalize-target.v1" ||
		task.Primitive.ID == "migration.postgres.logical-cleanup-target.v1"
	if endpointRole == "source" && sourcePrimitive {
		return family + ".source"
	}
	if endpointRole == "target" && targetPrimitive {
		return family + ".target"
	}
	return ""
}

func (r *Runner) resolveBinding(ctx context.Context, task TaskEnvelope, bindingID string) ([]byte, error) {
	if bindingID == "" || r.identity.EncryptionPrivateKey == nil {
		return nil, errors.New("attempt-scoped binding is unavailable")
	}
	deliveryNonce, err := randomNonce()
	if err != nil {
		return nil, errors.New("attempt-scoped binding nonce failed")
	}
	var response sealedSecretResponse
	_, err = r.postSigned(ctx, RouteSecretUnwrap, map[string]any{
		"attempt_id": task.AttemptID, "attempt_token": task.AttemptToken,
		"fencing_token": task.FencingToken, "binding_id": bindingID,
		"delivery_nonce": deliveryNonce,
	}, &response)
	if err != nil {
		return nil, errors.New("attempt-scoped binding delivery failed")
	}
	envelope := response.SealedSecret
	if response.Digest == "" {
		return nil, errors.New("attempt-scoped binding digest is missing")
	}
	digest, err := Digest(envelope)
	if err != nil || digest != response.Digest {
		return nil, errors.New("attempt-scoped binding digest mismatch")
	}
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if expiryErr != nil || time.Now().UTC().After(expiresAt) || expiresAt.After(time.Now().UTC().Add(2*time.Minute)) {
		return nil, errors.New("attempt-scoped binding is expired")
	}
	expectedPurpose := expectedBindingPurpose(task, bindingID)
	if expectedPurpose == "" || envelope.SchemaVersion != "operations.migration.sealed-secret.v1" ||
		envelope.Algorithm != "x25519-hkdf-sha256-aes-256-gcm-v1" ||
		envelope.Purpose != expectedPurpose ||
		envelope.BindingID != bindingID || envelope.AttemptID != task.AttemptID ||
		envelope.AgentID != r.agentID || envelope.AgentKeyID != r.identity.EncryptionKeyID ||
		envelope.DeliveryNonce != deliveryNonce {
		return nil, errors.New("attempt-scoped binding audience mismatch")
	}
	ephemeralPublic, err := parseX25519PublicKey(envelope.EphemeralPublicPEM)
	if err != nil {
		return nil, err
	}
	shared, err := r.identity.EncryptionPrivateKey.ECDH(ephemeralPublic)
	if err != nil {
		return nil, errors.New("attempt-scoped binding key agreement failed")
	}
	defer zeroBytes(shared)
	key := hkdfSHA256SingleBlock(shared, []byte(task.AttemptID), []byte("askio-migration-secret-v1"))
	defer zeroBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("attempt-scoped binding cipher setup failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("attempt-scoped binding cipher setup failed")
	}
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	ciphertext, ciphertextErr := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	tag, tagErr := base64.RawURLEncoding.DecodeString(envelope.AuthTag)
	if nonceErr != nil || ciphertextErr != nil || tagErr != nil || len(nonce) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
		zeroBytes(ciphertext)
		zeroBytes(tag)
		return nil, errors.New("attempt-scoped binding ciphertext is invalid")
	}
	defer zeroBytes(ciphertext)
	defer zeroBytes(tag)
	aad, err := CanonicalJSON(sealedSecretAAD(envelope))
	if err != nil {
		return nil, errors.New("attempt-scoped binding metadata is invalid")
	}
	sealed := append(ciphertext, tag...)
	plaintext, err := gcm.Open(nil, nonce, sealed, aad)
	zeroBytes(sealed)
	if err != nil {
		return nil, errors.New("attempt-scoped binding authentication failed")
	}
	if len(plaintext) == 0 || len(plaintext) > 65_536 {
		zeroBytes(plaintext)
		return nil, errors.New("attempt-scoped binding plaintext is invalid")
	}
	return plaintext, nil
}

func (r *Runner) loadState() error {
	data, err := os.ReadFile(r.statePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&r.state); err != nil {
		return fmt.Errorf("decode migration task state: %w", err)
	}
	if r.state.SchemaVersion != "operations.migration.agent-state.v1" {
		return errors.New("unsupported migration task state schema")
	}
	if r.state.SeenNonceExpiries == nil {
		r.state.SeenNonceExpiries = map[string]string{}
	}
	return nil
}

func (r *Runner) saveState() error {
	data, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(r.statePath), ".task-state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, r.statePath)
}

func randomNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (r *Runner) signedBody(route string, fields map[string]any) (map[string]any, error) {
	body := map[string]any{}
	for key, value := range fields {
		body[key] = value
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	body["key_id"] = r.identity.SigningKeyID
	body["request_timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	body["request_nonce"] = nonce
	material := map[string]any{"route": route, "agent_id": r.agentID, "body": body}
	canonical, err := CanonicalJSON(material)
	if err != nil {
		return nil, err
	}
	body["request_signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(r.identity.SigningPrivateKey, canonical))
	return body, nil
}

func envelopeUnsigned(task TaskEnvelope) map[string]any {
	return map[string]any{
		"schema_version": task.SchemaVersion, "key_id": task.KeyID, "algorithm": task.Algorithm,
		"audience": task.Audience, "agent_id": task.AgentID, "endpoint_id": task.EndpointID,
		"migration_id": task.MigrationID, "run_id": task.RunID, "run_step_id": task.RunStepID,
		"attempt_id": task.AttemptID, "attempt_token": task.AttemptToken, "fencing_token": task.FencingToken,
		"plan_digest": task.PlanDigest, "subject_digest": task.SubjectDigest, "primitive": task.Primitive,
		"resource_scope": task.ResourceScope, "inputs": task.Inputs,
		"issued_at": task.IssuedAt, "expires_at": task.ExpiresAt,
		"nonce": task.Nonce,
	}
}

func verifySignedTaskEnvelope(task TaskEnvelope, backendKeyID, agentID string, backendPublic ed25519.PublicKey) (string, error) {
	if task.SchemaVersion != "operations.migration.task.v1" || task.Algorithm != "ed25519-v1" || task.Audience != "askio-monitor" {
		return "", errors.New("unsupported task envelope contract")
	}
	if task.KeyID != backendKeyID || task.AgentID != agentID {
		return "", errors.New("task envelope audience or signing key mismatch")
	}
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, task.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, task.ExpiresAt)
	now := time.Now().UTC()
	if issuedErr != nil || expiresErr != nil || expiresAt.Before(now) || issuedAt.After(now.Add(30*time.Second)) || expiresAt.Sub(issuedAt) > 10*time.Minute {
		return "", errors.New("task envelope is expired or has an invalid validity window")
	}
	if task.EndpointID == "" || task.MigrationID == "" || task.Primitive.ID == "" || task.Primitive.Version == "" ||
		task.FencingToken < 1 || task.AttemptID == "" || len(task.AttemptToken) < 32 || task.Nonce == "" {
		return "", errors.New("task envelope attempt fields are invalid")
	}
	inputDigest, err := Digest(task.Inputs)
	if err != nil || inputDigest != task.SubjectDigest {
		return "", errors.New("task subject digest mismatch")
	}
	canonical, err := CanonicalJSON(envelopeUnsigned(task))
	if err != nil {
		return "", err
	}
	signature, err := base64.RawURLEncoding.DecodeString(task.Signature)
	if err != nil || !ed25519.Verify(backendPublic, canonical, signature) {
		return "", errors.New("task envelope signature is invalid")
	}
	digest, err := Digest(map[string]any{"envelope": envelopeUnsigned(task), "signature": task.Signature})
	if err != nil {
		return "", err
	}
	return digest, nil
}

func (r *Runner) verifyEnvelope(task TaskEnvelope) (string, error) {
	digest, err := verifySignedTaskEnvelope(task, r.backendKeyID, r.agentID, r.backendPublic)
	if err != nil {
		return "", err
	}
	if !r.executor.Supports(task.Primitive) {
		return "", fmt.Errorf("unsupported primitive %s@%s", task.Primitive.ID, task.Primitive.Version)
	}
	for _, seen := range r.state.SeenNonces {
		if seen == task.Nonce {
			return "", errors.New("task envelope nonce was already accepted")
		}
	}
	now := time.Now().UTC()
	for nonce, expiry := range r.state.SeenNonceExpiries {
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, expiry)
		if parseErr == nil && expiresAt.Before(now) {
			delete(r.state.SeenNonceExpiries, nonce)
		}
	}
	if _, seen := r.state.SeenNonceExpiries[task.Nonce]; seen {
		return "", errors.New("task envelope nonce was already accepted")
	}
	return digest, nil
}

func (r *Runner) postSigned(ctx context.Context, route string, fields map[string]any, out any) (int, error) {
	body, err := r.signedBody(route, fields)
	if err != nil {
		return 0, err
	}
	return r.client.PostMigration(ctx, route, body, out)
}

func (r *Runner) flushPending(ctx context.Context) (bool, error) {
	if r.state.PendingRoute == "" || r.state.PendingResultBody == nil {
		return false, nil
	}
	_, err := r.postSigned(ctx, r.state.PendingRoute, r.state.PendingResultBody, nil)
	if err != nil {
		var statusError *api.StatusError
		if errors.As(err, &statusError) && statusError.StatusCode == 409 && strings.Contains(statusError.Body, "MIGRATION_ATTEMPT_FENCED") {
			r.state.PendingRoute = ""
			r.state.PendingResultBody = nil
			r.state.ActiveAttemptID = ""
			r.state.ActivePrimitive = ""
			r.state.CurrentPhase = "fenced"
			return true, r.saveState()
		}
		return true, err
	}
	r.state.PendingRoute = ""
	r.state.PendingResultBody = nil
	r.state.ActiveAttemptID = ""
	r.state.ActivePrimitive = ""
	r.state.CurrentPhase = "idle"
	r.state.ProgressSequence = 0
	return true, r.saveState()
}

func (r *Runner) progressCallback(ctx context.Context, task TaskEnvelope, phase string, completed int64, total *int64) error {
	r.state.ProgressSequence++
	r.state.CurrentPhase = phase
	if err := r.saveState(); err != nil {
		return err
	}
	units := map[string]any{"completed": completed, "total": total, "name": "items"}
	response := struct {
		CancelRequested bool   `json:"cancelRequested"`
		Control         string `json:"control"`
	}{}
	_, err := r.postSigned(ctx, RouteTaskProgress, map[string]any{
		"attempt_id": task.AttemptID, "attempt_token": task.AttemptToken, "fencing_token": task.FencingToken,
		"sequence": r.state.ProgressSequence, "phase": phase, "units": units,
		"rate_per_second": nil, "estimated_seconds_remaining": nil,
	}, &response)
	if err != nil {
		return err
	}
	switch response.Control {
	case "pause":
		return errTaskPauseRequested
	case "cancel_safe":
		return errTaskCancelRequested
	case "":
		if response.CancelRequested {
			// A pre-control-contract backend only exposed the boolean. Preserve
			// the safest compatible behavior: checkpoint and wait for an operator.
			return errTaskPauseRequested
		}
	default:
		return errors.New("migration task control response is invalid")
	}
	return nil
}

func controlledResult(control error, phase, envelopeDigest string) PrimitiveResult {
	checkpoint := map[string]any{"phase": phase, "envelope_digest": envelopeDigest}
	if errors.Is(control, errTaskCancelRequested) {
		return PrimitiveResult{State: "cancelled", Outputs: map[string]any{}, EvidenceDigests: []string{}, Checkpoint: checkpoint}
	}
	return PrimitiveResult{State: "paused_at_checkpoint", Outputs: map[string]any{}, EvidenceDigests: []string{}, Checkpoint: checkpoint}
}

func normalizeResult(result PrimitiveResult) PrimitiveResult {
	if result.Outputs == nil {
		result.Outputs = map[string]any{}
	}
	if result.EvidenceDigests == nil {
		result.EvidenceDigests = []string{}
	}
	if result.State == "" {
		result.State = "failed"
		result.Error = &SafeError{Code: "MIGRATION_PRIMITIVE_EMPTY_RESULT", SafeMessage: "The primitive returned no terminal state.", Retryable: false}
	}
	return result
}

func (r *Runner) RunOnce(ctx context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if handled, err := r.flushPending(ctx); handled || err != nil {
		return handled, err
	}
	claim := ClaimResponse{}
	status, err := r.postSigned(ctx, RouteTaskClaim, map[string]any{}, &claim)
	if err != nil {
		return false, err
	}
	if status == 204 || claim.Task == nil {
		return false, nil
	}
	task := *claim.Task
	envelopeDigest, err := r.verifyEnvelope(task)
	if err != nil {
		return true, err
	}
	r.state.AcceptedDigest = envelopeDigest
	r.state.ActiveAttemptID = task.AttemptID
	r.state.ActivePrimitive = task.Primitive.ID
	r.state.CurrentPhase = "accepted"
	r.state.ProgressSequence = 0
	if r.state.SeenNonceExpiries == nil {
		r.state.SeenNonceExpiries = map[string]string{}
	}
	r.state.SeenNonceExpiries[task.Nonce] = task.ExpiresAt
	if err := r.saveState(); err != nil {
		return true, err
	}
	if r.activityHook != nil {
		r.activityHook(true)
		defer r.activityHook(false)
	}
	if err := r.progressCallback(ctx, task, "starting", 0, nil); err != nil {
		if errors.Is(err, errTaskPauseRequested) || errors.Is(err, errTaskCancelRequested) {
			return true, r.persistAndPostResult(ctx, task, controlledResult(err, "starting", envelopeDigest))
		}
		return true, err
	}
	result := normalizeResult(r.executor.Execute(ctx, task, func(phase string, completed int64, total *int64) error {
		return r.progressCallback(ctx, task, phase, completed, total)
	}))
	completed := int64(1)
	controlErr := r.progressCallback(ctx, task, "finalizing_result", completed, &completed)
	if errors.Is(controlErr, errTaskPauseRequested) || errors.Is(controlErr, errTaskCancelRequested) {
		result = controlledResult(controlErr, "finalizing_result", envelopeDigest)
	}
	return true, r.persistAndPostResult(ctx, task, result)
}

func (r *Runner) persistAndPostResult(ctx context.Context, task TaskEnvelope, result PrimitiveResult) error {
	var checkpoint any
	if result.Checkpoint != nil {
		checkpoint = result.Checkpoint
	}
	var safeError any
	if result.Error != nil {
		safeError = result.Error
	}
	material := map[string]any{
		"attempt_id": task.AttemptID, "fencing_token": task.FencingToken, "state": result.State,
		"outputs": result.Outputs, "evidence_digests": result.EvidenceDigests,
		"checkpoint": checkpoint, "error": safeError,
	}
	resultDigest, err := Digest(material)
	if err != nil {
		return err
	}
	body := map[string]any{}
	for key, value := range material {
		body[key] = value
	}
	body["attempt_token"] = task.AttemptToken
	body["result_digest"] = resultDigest
	r.state.PendingRoute = RouteTaskResult
	r.state.PendingResultBody = body
	r.state.CurrentPhase = "result_pending"
	if err := r.saveState(); err != nil {
		return err
	}
	_, err = r.postSigned(ctx, RouteTaskResult, body, nil)
	if err != nil {
		return err
	}
	r.state.PendingRoute = ""
	r.state.PendingResultBody = nil
	r.state.ActiveAttemptID = ""
	r.state.ActivePrimitive = ""
	r.state.CurrentPhase = "idle"
	r.state.ProgressSequence = 0
	return r.saveState()
}
