package migration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const mongodbDisposableIntegrationGate = "disposable-same-major-cycle"

func TestMongoDBOfflineMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_MONGODB_INTEGRATION") != mongodbDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_MONGODB_INTEGRATION=disposable-same-major-cycle inside the disposable fixture")
	}
	sourcePort, sourceErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MONGODB_SOURCE_PORT"))
	targetPort, targetErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MONGODB_TARGET_PORT"))
	password := os.Getenv("ASKIO_MIGRATION_MONGODB_PASSWORD")
	if sourceErr != nil || targetErr != nil || sourcePort == targetPort || password == "" {
		t.Fatal("the disposable fixture requires distinct source and target ports plus a password")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	workspace := t.TempDir()
	sourceStaging := filepath.Join(workspace, "source-staging")
	targetStaging := filepath.Join(workspace, "target-staging")
	stateDir := filepath.Join(workspace, "state")
	for _, directory := range []string{sourceStaging, targetStaging, stateDir} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executor, err := NewNativeExecutor(
		map[string]string{"source_staging": sourceStaging, "target_staging": targetStaging},
		filepath.Join(workspace, "unused-broker.sock"), stateDir,
	)
	if err != nil {
		t.Fatal(err)
	}
	executor.capacityCheck = func(string, int64) error { return nil }
	const (
		sourceBindingID = "71111111-1111-4111-8111-111111111111"
		targetBindingID = "72222222-2222-4222-8222-222222222222"
		sourceDatabase  = "askio_fixture_source"
		targetDatabase  = "askio_mig_fixture"
	)
	bindingJSON := func(mode string, port int, database string, reset bool) []byte {
		value := map[string]any{
			"schema_version": mongodbBindingSchema, "mode": mode,
			"host": "127.0.0.1", "port": port, "database": database, "auth_database": "admin",
			"username": "root", "password": password, "ssl_mode": "disable",
		}
		if reset {
			value["reset_allowed"] = true
		}
		encoded, encodeErr := json.Marshal(value)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		return encoded
	}
	sourceJSON := bindingJSON("source", sourcePort, sourceDatabase, false)
	targetJSON := bindingJSON("target", targetPort, targetDatabase, true)
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		switch bindingID {
		case sourceBindingID:
			return append([]byte(nil), sourceJSON...), nil
		case targetBindingID:
			return append([]byte(nil), targetJSON...), nil
		default:
			return nil, errors.New("unexpected integration binding")
		}
	})
	source, err := parseMongoDBBinding(sourceJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer source.clear()
	target, err := parseMongoDBBinding(targetJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer target.clear()
	fixtureBody := `
const fixture = askioConnection.getDB("askio_fixture_source");
fixture.dropDatabase();
fixture.widgets.insertMany([
  {_id: 1, name: "alpha", tags: ["one", "two"], nested: {enabled: true}},
  {_id: 2, name: "bravo", tags: [], nested: {enabled: false}},
  {_id: 3, name: "unicode-șț", binary: BinData(0, "AAEC/w==")}
]);
fixture.events.insertMany([{widget_id: 1, event: "created"}, {widget_id: 2, event: "created"}, {widget_id: 3, event: "created"}]);
fixture.widgets.createIndex({name: 1}, {unique: true});
fixture.events.createIndex({widget_id: 1});
print("ASKIO_JSON:" + EJSON.stringify({ok: true}, {relaxed: true}));`
	var fixtureResult struct {
		OK bool `json:"ok"`
	}
	if err := executor.runMongoDBShell(ctx, source, fixtureBody, &fixtureResult); err != nil || !fixtureResult.OK {
		t.Fatalf("source fixture setup failed: %v", err)
	}
	clearTargetBody := "askioConnection.getDB(" + strconv.Quote(targetDatabase) + ").dropDatabase();\n" +
		"print('ASKIO_JSON:' + EJSON.stringify({ok: true}, {relaxed: true}));"
	if err := executor.runMongoDBShell(ctx, target, clearTargetBody, &fixtureResult); err != nil {
		t.Fatalf("target fixture setup failed: %v", err)
	}
	task := TaskEnvelope{MigrationID: "73333333-3333-4333-8333-333333333333", AttemptID: "74444444-4444-4444-8444-444444444444"}
	progress := func(string, int64, *int64) error { return nil }
	sourceOutputs, err := executor.mongodbInspect(ctx, task, map[string]any{"database_binding_id": sourceBindingID})
	if err != nil {
		t.Fatalf("source inspection failed: %v", err)
	}
	targetOutputs, err := executor.mongodbInspect(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "require_empty_target": true,
		"required_source_major":  sourceOutputs["server_major"],
		"required_source_fcv":    sourceOutputs["feature_compatibility_version"],
		"required_tools_version": sourceOutputs["tools_version"],
	})
	if err != nil {
		t.Fatalf("target compatibility inspection failed: %v", err)
	}
	dumpOutputs, err := executor.mongodbDump(ctx, task, map[string]any{
		"database_binding_id": sourceBindingID, "staging_root_handle": "source_staging",
	}, progress)
	if err != nil {
		t.Fatalf("source dump failed: %v", err)
	}
	stagingRelative := mustStringOutput(t, dumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, stagingRelative), filepath.Join(targetStaging, stagingRelative))
	if _, err := executor.mongodbReset(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("target reset failed: %v", err)
	}
	if _, err := executor.mongodbRestore(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "staging_root_handle": "target_staging",
		"dump_staging_relative_handle": stagingRelative,
		"dump_artifact_handle":         mustStringOutput(t, dumpOutputs, "dump_artifact_handle"),
		"dump_artifact_digest":         mustStringOutput(t, dumpOutputs, "dump_artifact_digest"),
		"source_database":              mustStringOutput(t, dumpOutputs, "source_database"),
		"expected_manifest_digest":     mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}, progress); err != nil {
		t.Fatalf("target restore failed: %v", err)
	}
	if _, err := executor.mongodbVerify(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_manifest_digest": mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}); err != nil {
		t.Fatalf("target verification failed: %v", err)
	}
	targetInspection, err := executor.inspectMongoDB(ctx, targetBindingID, target)
	if err != nil {
		t.Fatal(err)
	}
	if targetInspection.TotalDocuments != 6 || len(targetInspection.Manifest.Collections) != 2 {
		t.Fatalf("restored MongoDB fixture diverged: %+v", targetInspection)
	}
}
