package migration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func dataPlaneBackendIdentity(t *testing.T) (string, string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return "backend-data-plane-test", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), privateKey, publicKey
}

func signedDataPlaneTicket(t *testing.T, keyID string, privateKey ed25519.PrivateKey, source, target *Identity, sourceAgent, targetAgent, manifestDigest string, totalBytes int64) DataPlaneTicket {
	t.Helper()
	ticket := DataPlaneTicket{
		SchemaVersion: dataPlaneTicketSchema, KeyID: keyID, Algorithm: "ed25519-v1", Audience: dataPlaneAudience,
		MigrationID: "11111111-1111-4111-8111-111111111111", RunID: "22222222-2222-4222-8222-222222222222",
		AttemptID: "33333333-3333-4333-8333-333333333333", FencingToken: 11,
		BindingID: "44444444-4444-4444-8444-444444444444", SourceAgentID: sourceAgent, TargetAgentID: targetAgent,
		SourceSigningKeyID: source.SigningKeyID, SourceSigningPublicPEM: source.SigningPublicKeyPEM,
		TargetSigningKeyID: target.SigningKeyID, TargetSigningPublicPEM: target.SigningPublicKeyPEM,
		SourceRootHandle: "source", SourceRelativeHandle: "payload", ManifestDigest: manifestDigest,
		ChunkSizeBytes: transferChunkSize, MaximumBytes: totalBytes,
		IssuedAt: time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano),
		Nonce: base64.RawURLEncoding.EncodeToString([]byte("012345678901234567890123")),
	}
	canonical, err := CanonicalJSON(dataPlaneTicketUnsigned(ticket))
	if err != nil {
		t.Fatal(err)
	}
	ticket.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	return ticket
}

func ticketAsMap(t *testing.T, ticket DataPlaneTicket) map[string]any {
	t.Helper()
	data, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func startDataPlaneFixture(t *testing.T) (*DataPlaneServer, context.CancelFunc, <-chan error, *Identity, *Identity, string, ed25519.PrivateKey, ed25519.PublicKey, string, FileManifestSummary) {
	t.Helper()
	sourceIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "source-keys"))
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "target-keys"))
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := t.TempDir()
	payloadRoot := filepath.Join(sourceRoot, "payload")
	if err := os.MkdirAll(filepath.Join(payloadRoot, "nested"), 0o750); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, transferChunkSize+128*1024)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloadRoot, "nested", "large.bin"), large, 0o640); err != nil {
		t.Fatal(err)
	}
	zeroBytes(large)
	if err := os.WriteFile(filepath.Join(payloadRoot, "small.txt"), []byte("askio-direct-transfer-fixture\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	summary, err := buildFileManifest(context.Background(), payloadRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, publicBase64, privateKey, publicKey := dataPlaneBackendIdentity(t)
	server, err := NewDataPlaneServer("127.0.0.1:0", "source-agent", keyID, publicBase64, sourceIdentity, map[string]string{"source": sourceRoot})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	return server, cancel, done, sourceIdentity, targetIdentity, keyID, privateKey, publicKey, publicBase64, summary
}

func TestDirectDataPlaneTransfersManifestAndChunksOverPinnedMutualTLS(t *testing.T) {
	server, cancel, done, source, target, keyID, privateKey, publicKey, _, summary := startDataPlaneFixture(t)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ticket := signedDataPlaneTicket(t, keyID, privateKey, source, target, "source-agent", "target-agent", summary.Digest, summary.TotalBytes)
	if err := validateDataPlaneTicket(ticket, keyID, publicKey); err != nil {
		t.Fatal(err)
	}
	client, err := newDataPlaneClient(server.Address(), target, ticket)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := client.manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	entry, found := findManifestEntry(manifest.Entries, "nested/large.bin")
	if !found {
		t.Fatal("large fixture file missing from direct manifest")
	}
	first, _, err := client.chunk(context.Background(), entry.Relative, 0, entry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(first)) != transferChunkSize {
		t.Fatalf("unexpected first chunk length %d", len(first))
	}
	zeroBytes(first)
	second, _, err := client.chunk(context.Background(), entry.Relative, 1, entry.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 128*1024 {
		t.Fatalf("unexpected second chunk length %d", len(second))
	}
	zeroBytes(second)
}

func TestFileSyncCapacityPolicyPreservesReserve(t *testing.T) {
	const gib = int64(1024 * 1024 * 1024)
	if !hasFileSystemCapacity(40*gib, 100*gib, 25*gib) {
		t.Fatal("capacity policy rejected a request that leaves the 15 percent reserve")
	}
	if hasFileSystemCapacity(39*gib, 100*gib, 25*gib) {
		t.Fatal("capacity policy accepted a request that breaches the 15 percent reserve")
	}
	if hasFileSystemCapacity(15*1024*1024, 32*1024*1024, 0) {
		t.Fatal("capacity policy did not retain the fixed minimum reserve on a small filesystem")
	}
}

func TestFileSyncDiskExhaustionStopsBeforeTransferOrTargetMutation(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_CAPACITY_INTEGRATION") != "disposable-tmpfs" {
		t.Skip("set ASKIO_MIGRATION_CAPACITY_INTEGRATION=disposable-tmpfs inside the disposable tmpfs fixture")
	}
	capacityRoot := os.Getenv("ASKIO_MIGRATION_CAPACITY_ROOT")
	if capacityRoot != "/capacity" {
		t.Fatal("the disk-capacity fixture must use the dedicated /capacity tmpfs")
	}
	workspace, err := os.MkdirTemp(capacityRoot, "askio-file-capacity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspace) })
	targetRoot := filepath.Join(workspace, "target")
	stateRoot := filepath.Join(workspace, "state")
	if err := os.Mkdir(targetRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	sourceIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "source-keys"))
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "target-keys"))
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := t.TempDir()
	payloadRoot := filepath.Join(sourceRoot, "payload")
	if err := os.Mkdir(payloadRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	large := make([]byte, 12*1024*1024)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payloadRoot, "capacity.bin"), large, 0o600); err != nil {
		t.Fatal(err)
	}
	zeroBytes(large)
	summary, err := buildFileManifest(context.Background(), payloadRoot, nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, publicBase64, privateKey, _ := dataPlaneBackendIdentity(t)
	server, err := NewDataPlaneServer("127.0.0.1:0", "source-agent", keyID, publicBase64, sourceIdentity, map[string]string{"source": sourceRoot})
	if err != nil {
		t.Fatal(err)
	}
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverContext) }()
	t.Cleanup(func() {
		cancelServer()
		if err := <-serverDone; err != nil {
			t.Error(err)
		}
	})

	ticket := signedDataPlaneTicket(t, keyID, privateKey, sourceIdentity, targetIdentity, "source-agent", "target-agent", summary.Digest, summary.TotalBytes)
	executor, err := NewNativeExecutor(map[string]string{"target": targetRoot}, filepath.Join(t.TempDir(), "broker.sock"), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := executor.ConfigureDataPlaneIdentity("target-agent", keyID, publicBase64, targetIdentity); err != nil {
		t.Fatal(err)
	}
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		if bindingID != ticket.BindingID {
			return nil, errors.New("unexpected binding")
		}
		return json.Marshal(map[string]any{"schema_version": transferBindingSchema, "source_address": server.Address()})
	})
	runID := ticket.RunID
	task := TaskEnvelope{
		AgentID: "target-agent", MigrationID: ticket.MigrationID, RunID: &runID, AttemptID: ticket.AttemptID,
		FencingToken: ticket.FencingToken, Primitive: PrimitiveRef{ID: "migration.files.sync.v1", Version: "1.0.0"},
		Inputs: map[string]any{
			"transfer_binding_id": ticket.BindingID, "source_root_handle": "source", "source_relative_handle": "payload",
			"target_root_handle": "target", "target_relative_handle": "deployment", "manifest_digest": summary.Digest,
			"transfer_mib_per_second": float64(32), "maximum_bytes": summary.TotalBytes,
			"transfer_ticket": ticketAsMap(t, ticket),
		},
	}
	result := executor.Execute(context.Background(), task, func(string, int64, *int64) error { return nil })
	if result.State != "failed" || result.Error == nil || result.Error.Code != "MIGRATION_DISK_CAPACITY_INSUFFICIENT" {
		t.Fatalf("expected typed capacity safe-stop, got %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(targetRoot, "deployment")); !os.IsNotExist(err) {
		t.Fatalf("capacity rejection mutated the destination: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(executor.transferCachePath(task, summary.Digest), "tree")); !os.IsNotExist(err) {
		t.Fatalf("capacity rejection started the payload transfer: %v", err)
	}
}

func TestFileSyncAppliesVerifiedTreeAndReplaysIdempotently(t *testing.T) {
	server, cancel, done, source, target, keyID, privateKey, _, publicBase64, summary := startDataPlaneFixture(t)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ticket := signedDataPlaneTicket(t, keyID, privateKey, source, target, "source-agent", "target-agent", summary.Digest, summary.TotalBytes)
	targetParent := t.TempDir()
	executor, err := NewNativeExecutor(map[string]string{"target": targetParent}, filepath.Join(t.TempDir(), "broker.sock"), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	// Capacity enforcement has a dedicated real-filesystem fixture. Keep this
	// transport/idempotency test independent from the CI host's current usage.
	executor.capacityCheck = func(string, int64) error { return nil }
	if err := executor.ConfigureDataPlaneIdentity("target-agent", keyID, publicBase64, target); err != nil {
		t.Fatal(err)
	}
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		if bindingID != ticket.BindingID {
			return nil, errors.New("unexpected binding")
		}
		return json.Marshal(map[string]any{"schema_version": transferBindingSchema, "source_address": server.Address()})
	})
	task := TaskEnvelope{
		AgentID: "target-agent", MigrationID: ticket.MigrationID, RunID: &ticket.RunID, AttemptID: ticket.AttemptID,
		FencingToken: ticket.FencingToken, Primitive: PrimitiveRef{ID: "migration.files.sync.v1", Version: "1.0.0"},
	}
	inputs := map[string]any{
		"transfer_binding_id": ticket.BindingID, "source_root_handle": "source", "source_relative_handle": "payload",
		"target_root_handle": "target", "target_relative_handle": "deployment", "manifest_digest": summary.Digest,
		"transfer_mib_per_second": float64(32), "maximum_bytes": summary.TotalBytes,
		"transfer_ticket": ticketAsMap(t, ticket),
	}
	outputs, err := executor.filesSync(context.Background(), task, inputs, func(string, int64, *int64) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if outputs["manifest_digest"] != summary.Digest || outputs["transport"] != "migration.direct.mtls-chunks.v1" {
		t.Fatalf("unexpected file sync outputs: %+v", outputs)
	}
	if _, err := os.Lstat(executor.transferCachePath(task, summary.Digest)); !os.IsNotExist(err) {
		t.Fatalf("completed transfer cache was not removed: %v", err)
	}
	targetSummary, err := buildFileManifest(context.Background(), filepath.Join(targetParent, "deployment"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if targetSummary.Digest != summary.Digest {
		t.Fatalf("target manifest mismatch: %s != %s", targetSummary.Digest, summary.Digest)
	}
	replayed, err := executor.filesSync(context.Background(), task, inputs, func(string, int64, *int64) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if replayed["resumed"] != true {
		t.Fatalf("expected idempotent replay to report resumed, got %+v", replayed)
	}
	if _, err := os.Lstat(executor.transferCachePath(task, summary.Digest)); !os.IsNotExist(err) {
		t.Fatalf("replayed transfer cache was not removed: %v", err)
	}
}

func TestFileSyncResumesAfterInterruptionAndRepairsCorruptCachedChunk(t *testing.T) {
	server, cancel, done, source, target, keyID, privateKey, _, publicBase64, summary := startDataPlaneFixture(t)
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ticket := signedDataPlaneTicket(t, keyID, privateKey, source, target, "source-agent", "target-agent", summary.Digest, summary.TotalBytes)
	targetParent := t.TempDir()
	executor, err := NewNativeExecutor(map[string]string{"target": targetParent}, filepath.Join(t.TempDir(), "broker.sock"), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	executor.capacityCheck = func(string, int64) error { return nil }
	if err := executor.ConfigureDataPlaneIdentity("target-agent", keyID, publicBase64, target); err != nil {
		t.Fatal(err)
	}
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		if bindingID != ticket.BindingID {
			return nil, errors.New("unexpected binding")
		}
		return json.Marshal(map[string]any{"schema_version": transferBindingSchema, "source_address": server.Address()})
	})
	task := TaskEnvelope{
		AgentID: "target-agent", MigrationID: ticket.MigrationID, RunID: &ticket.RunID, AttemptID: ticket.AttemptID,
		FencingToken: ticket.FencingToken, Primitive: PrimitiveRef{ID: "migration.files.sync.v1", Version: "1.0.0"},
	}
	inputs := map[string]any{
		"transfer_binding_id": ticket.BindingID, "source_root_handle": "source", "source_relative_handle": "payload",
		"target_root_handle": "target", "target_relative_handle": "deployment", "manifest_digest": summary.Digest,
		"transfer_mib_per_second": float64(32), "maximum_bytes": summary.TotalBytes,
		"transfer_ticket": ticketAsMap(t, ticket),
	}
	interrupted := false
	_, err = executor.filesSync(context.Background(), task, inputs, func(phase string, _ int64, _ *int64) error {
		if phase == "file_transfer" && !interrupted {
			interrupted = true
			return errors.New("synthetic transfer interruption")
		}
		return nil
	})
	if err == nil || !interrupted {
		t.Fatalf("expected a checkpointed synthetic interruption, got %v", err)
	}
	partialPath := filepath.Join(executor.transferCachePath(task, summary.Digest), "tree", "nested", "large.bin.partial")
	partial, err := os.OpenFile(partialPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partial.WriteAt([]byte{0xff}, 0); err != nil {
		_ = partial.Close()
		t.Fatal(err)
	}
	if err := partial.Close(); err != nil {
		t.Fatal(err)
	}
	outputs, err := executor.filesSync(context.Background(), task, inputs, func(string, int64, *int64) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if outputs["manifest_digest"] != summary.Digest {
		t.Fatalf("resumed transfer did not verify the source manifest: %+v", outputs)
	}
	if _, err := os.Lstat(executor.transferCachePath(task, summary.Digest)); !os.IsNotExist(err) {
		t.Fatalf("resumed transfer cache was not removed: %v", err)
	}
}

func TestDirectDataPlaneRejectsSourceDriftAndWrongClientIdentity(t *testing.T) {
	server, cancel, done, source, target, keyID, privateKey, _, _, summary := startDataPlaneFixture(t)
	defer func() {
		cancel()
		_ = <-done
	}()
	ticket := signedDataPlaneTicket(t, keyID, privateKey, source, target, "source-agent", "target-agent", summary.Digest, summary.TotalBytes)
	wrongIdentity, err := LoadOrCreateIdentity(filepath.Join(t.TempDir(), "wrong-keys"))
	if err != nil {
		t.Fatal(err)
	}
	wrongClient, err := newDataPlaneClient(server.Address(), wrongIdentity, ticket)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongClient.manifest(context.Background()); err == nil {
		t.Fatal("expected mutual TLS client identity mismatch to be rejected")
	}
	// The source root location is opaque to the target. A separately issued
	// ticket is required after any source manifest drift.
	client, err := newDataPlaneClient(server.Address(), target, ticket)
	if err != nil {
		t.Fatal(err)
	}
	entry, found := findManifestEntry(summary.Manifest.Entries, "small.txt")
	if !found {
		t.Fatal("small fixture file missing")
	}
	_ = entry
	// Locate the fixture through the server's configured resolver only inside
	// this package-level test; this path never crosses the protocol.
	sourceBase, err := server.resolver.Resolve("source", "payload", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceBase, "small.txt"), []byte("drifted\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	ctx, cancelRequest := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelRequest()
	if _, err := client.manifest(ctx); err == nil {
		t.Fatal("expected stale manifest ticket to reject source drift")
	}
}

func TestDataPlaneTicketRefreshPreservesImmutableTransferScope(t *testing.T) {
	current := DataPlaneTicket{
		SchemaVersion: dataPlaneTicketSchema, KeyID: "backend", Algorithm: "ed25519-v1", Audience: dataPlaneAudience,
		MigrationID: "migration", RunID: "run", AttemptID: "attempt", FencingToken: 9,
		BindingID: "22222222-2222-4222-8222-222222222222", SourceAgentID: "source", TargetAgentID: "target",
		SourceSigningKeyID: "source-key", SourceSigningPublicPEM: "source-public",
		TargetSigningKeyID: "target-key", TargetSigningPublicPEM: "target-public",
		SourceRootHandle: "source", SourceRelativeHandle: "payload",
		ManifestDigest: "sha256:" + string(make([]byte, 64)), ChunkSizeBytes: transferChunkSize, MaximumBytes: 128,
		IssuedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano),
	}
	client := &dataPlaneClient{ticket: current, refresh: func(_ context.Context, prior DataPlaneTicket) (DataPlaneTicket, error) {
		prior.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
		prior.ExpiresAt = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
		prior.Nonce = "fresh"
		prior.Signature = "fresh"
		return prior, nil
	}}
	if err := client.ensureTicket(context.Background()); err != nil {
		t.Fatal(err)
	}
	client.ticket.ExpiresAt = time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339Nano)
	client.refresh = func(_ context.Context, prior DataPlaneTicket) (DataPlaneTicket, error) {
		prior.ManifestDigest = "sha256:" + string(make([]byte, 63)) + "1"
		prior.ExpiresAt = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339Nano)
		return prior, nil
	}
	if err := client.ensureTicket(context.Background()); err == nil {
		t.Fatal("expected refresh scope drift to be rejected")
	}
}
