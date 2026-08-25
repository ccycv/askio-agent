package migration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const postgresDisposableIntegrationGate = "disposable-postgres-14-to-16"

func TestPostgresOfflineMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_POSTGRES_INTEGRATION") != postgresDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_POSTGRES_INTEGRATION=disposable-postgres-14-to-16 inside the disposable fixture")
	}

	sourceSocket := os.Getenv("ASKIO_MIGRATION_POSTGRES_SOURCE_SOCKET")
	targetSocket := os.Getenv("ASKIO_MIGRATION_POSTGRES_TARGET_SOCKET")
	if !filepath.IsAbs(sourceSocket) || !filepath.IsAbs(targetSocket) || sourceSocket == targetSocket {
		t.Fatal("the disposable fixture requires two distinct absolute PostgreSQL socket directories")
	}
	password := os.Getenv("ASKIO_MIGRATION_POSTGRES_PASSWORD")
	if password == "" {
		t.Fatal("the disposable fixture password is missing")
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
	// The capacity policy has a dedicated constrained-filesystem integration
	// fixture. Keep this database semantic test independent from Docker's
	// current overlay utilization while still exercising the dump call site.
	executor.capacityCheck = func(string, int64) error { return nil }

	const (
		sourceBindingID = "11111111-1111-4111-8111-111111111111"
		targetBindingID = "22222222-2222-4222-8222-222222222222"
		sourceDatabase  = "askio_fixture_source"
		targetDatabase  = "askio_mig_fixture"
		sourceOwner     = "askio_source_owner"
		sourceReader    = "askio_source_reader"
		targetOwner     = "askio_mig_owner"
	)
	// PostgreSQL owns the built-in public schema in the pristine source cluster;
	// keeping that cluster role explicit proves that ownership is normalized
	// instead of silently relying on a same-named role on the destination.
	roleMap := map[string]string{"postgres": targetOwner, sourceOwner: targetOwner, sourceReader: targetOwner}
	sourceBindingJSON := mustPostgresIntegrationBindingJSON(t, map[string]any{
		"schema_version": postgresBindingSchema, "mode": "source", "host": sourceSocket, "port": 5432,
		"database": sourceDatabase, "maintenance_database": "postgres", "username": "postgres",
		"password": password, "ssl_mode": "disable", "role_map": roleMap,
	})
	targetBindingJSON := mustPostgresIntegrationBindingJSON(t, map[string]any{
		"schema_version": postgresBindingSchema, "mode": "target", "host": targetSocket, "port": 5432,
		"database": targetDatabase, "maintenance_database": "postgres", "username": "postgres",
		"password": password, "ssl_mode": "disable", "role_map": roleMap, "target_role": targetOwner,
		"reset_allowed": true,
	})
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		switch bindingID {
		case sourceBindingID:
			return append([]byte(nil), sourceBindingJSON...), nil
		case targetBindingID:
			return append([]byte(nil), targetBindingJSON...), nil
		default:
			return nil, errors.New("unexpected integration binding")
		}
	})

	sourceBinding := mustParsePostgresIntegrationBinding(t, sourceBindingJSON)
	defer sourceBinding.clear()
	targetBinding := mustParsePostgresIntegrationBinding(t, targetBindingJSON)
	defer targetBinding.clear()

	createPostgresIntegrationFixture(t, ctx, executor, sourceBinding, targetBinding)
	task := TaskEnvelope{
		MigrationID: "33333333-3333-4333-8333-333333333333",
		AttemptID:   "44444444-4444-4444-8444-444444444444",
	}
	progress := func(string, int64, *int64) error { return nil }

	sourceOutputs, err := executor.postgresInspect(ctx, task, map[string]any{"database_binding_id": sourceBindingID})
	if err != nil {
		t.Fatalf("source inspection failed: %v; ACL diagnostics: %s", err, postgresIntegrationACLDiagnostics(ctx, executor, sourceBinding))
	}
	requiredExtensions, ok := sourceOutputs["required_extensions"].([]string)
	if !ok || !containsString(requiredExtensions, "pgcrypto@1.3") {
		t.Fatalf("source extension inventory is incomplete: %#v", sourceOutputs["required_extensions"])
	}
	targetOutputs, err := executor.postgresInspect(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "require_empty_target": true,
		"required_source_major": sourceOutputs["server_major"], "required_extensions": requiredExtensions,
	})
	if err != nil {
		t.Fatalf("empty target compatibility inspection failed: %v", err)
	}
	if targetOutputs["empty"] != true {
		t.Fatalf("target is not empty: %#v", targetOutputs)
	}

	dumpOutputs, err := executor.postgresDump(ctx, task, map[string]any{
		"database_binding_id": sourceBindingID, "staging_root_handle": "source_staging",
	}, progress)
	if err != nil {
		t.Fatalf("source dump failed: %v", err)
	}
	stagingRelative := mustStringOutput(t, dumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, stagingRelative), filepath.Join(targetStaging, stagingRelative))

	if _, err := executor.postgresReset(ctx, task, map[string]any{
		"database_binding_id":          targetBindingID,
		"expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("target reset failed: %v", err)
	}
	restoreInputs := map[string]any{
		"database_binding_id": targetBindingID, "staging_root_handle": "target_staging",
		"dump_staging_relative_handle": stagingRelative,
		"dump_artifact_handle":         mustStringOutput(t, dumpOutputs, "dump_artifact_handle"),
		"dump_artifact_digest":         mustStringOutput(t, dumpOutputs, "dump_artifact_digest"),
		"acl_artifact_handle":          mustStringOutput(t, dumpOutputs, "acl_artifact_handle"),
		"acl_artifact_digest":          mustStringOutput(t, dumpOutputs, "acl_artifact_digest"),
		"role_map_digest":              mustStringOutput(t, dumpOutputs, "role_map_digest"),
		"expected_manifest_digest":     mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}
	if _, err := executor.postgresRestore(ctx, task, restoreInputs, progress); err != nil {
		t.Fatalf("target restore failed: %v", err)
	}
	if _, err := executor.postgresVerify(ctx, task, map[string]any{
		"database_binding_id":      targetBindingID,
		"expected_manifest_digest": mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}); err != nil {
		t.Fatalf("target verification failed: %v", err)
	}

	sourceInspection, err := executor.inspectPostgres(ctx, sourceBindingID, sourceBinding)
	if err != nil {
		t.Fatal(err)
	}
	targetInspection, err := executor.inspectPostgres(ctx, targetBindingID, targetBinding)
	if err != nil {
		t.Fatal(err)
	}
	if sourceInspection.ManifestDigest != targetInspection.ManifestDigest || sourceInspection.TotalRows != 6 {
		t.Fatalf("restored database diverged: source=%s target=%s rows=%d", sourceInspection.ManifestDigest, targetInspection.ManifestDigest, sourceInspection.TotalRows)
	}
	assertPostgresIntegrationManifest(t, targetInspection.Manifest, targetOwner)

	if _, err := executor.postgresReset(ctx, task, map[string]any{
		"database_binding_id":          targetBindingID,
		"expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("second owned target reset failed: %v", err)
	}
	corruptHandle := "database.corrupt.dump"
	corruptPath := filepath.Join(targetStaging, stagingRelative, corruptHandle)
	copyPostgresIntegrationFile(t, filepath.Join(targetStaging, stagingRelative, mustStringOutput(t, dumpOutputs, "dump_artifact_handle")), corruptPath)
	info, err := os.Stat(corruptPath)
	if err != nil || info.Size() < 32 {
		t.Fatalf("dump archive is unexpectedly small: %v", err)
	}
	if err := os.Truncate(corruptPath, info.Size()/3); err != nil {
		t.Fatal(err)
	}
	corruptDigest, _, err := fileSHA256(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	corruptInputs := clonePostgresIntegrationInputs(restoreInputs)
	corruptInputs["dump_artifact_handle"] = corruptHandle
	corruptInputs["dump_artifact_digest"] = corruptDigest
	if _, err := executor.postgresRestore(ctx, task, corruptInputs, progress); err == nil || !strings.Contains(err.Error(), "archive validation failed") {
		t.Fatalf("corrupted archive did not fail closed before restore: %v", err)
	}
	afterCorruption, err := executor.inspectPostgres(ctx, targetBindingID, targetBinding)
	if err != nil {
		t.Fatal(err)
	}
	if !afterCorruption.Empty || afterCorruption.TotalRows != 0 {
		t.Fatalf("corrupted archive mutated the empty target: %+v", afterCorruption)
	}
}

func postgresIntegrationACLDiagnostics(ctx context.Context, executor *NativeExecutor, binding postgresBinding) string {
	queries := []string{
		"select distinct case when c.relkind='S' then 'SEQUENCE' else 'TABLE' end,acl.privilege_type from pg_class c join pg_namespace n on n.oid=c.relnamespace cross join lateral aclexplode(coalesce(c.relacl,acldefault(case when c.relkind='S' then 's'::\"char\" else 'r'::\"char\" end,c.relowner))) acl where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and c.relkind in('r','p','v','m','f','S') order by 1,2",
		"select distinct case when acl.grantee=0 then 'PUBLIC' else pg_get_userbyid(acl.grantee) end from pg_class c join pg_namespace n on n.oid=c.relnamespace cross join lateral aclexplode(coalesce(c.relacl,acldefault(case when c.relkind='S' then 's'::\"char\" else 'r'::\"char\" end,c.relowner))) acl where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and c.relkind in('r','p','v','m','f','S') order by 1",
		"select distinct acl.privilege_type from pg_namespace n cross join lateral aclexplode(coalesce(n.nspacl,acldefault('n'::\"char\",n.nspowner))) acl where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' order by 1",
	}
	parts := make([]string, 0, len(queries))
	for _, query := range queries {
		rows, err := executor.queryPostgres(ctx, binding, binding.Database, query)
		if err != nil {
			parts = append(parts, err.Error())
			continue
		}
		encoded, _ := json.Marshal(rows)
		parts = append(parts, string(encoded))
	}
	return strings.Join(parts, "; ")
}

func mustPostgresIntegrationBindingJSON(t *testing.T, value map[string]any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustParsePostgresIntegrationBinding(t *testing.T, raw []byte) postgresBinding {
	t.Helper()
	binding, err := parsePostgresBinding(raw)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func createPostgresIntegrationFixture(t *testing.T, ctx context.Context, executor *NativeExecutor, source, target postgresBinding) {
	t.Helper()
	for _, statement := range []string{
		"create role askio_source_owner",
		"create role askio_source_reader",
		"create database askio_fixture_source with owner askio_source_owner template template0 encoding 'UTF8'",
	} {
		if _, err := executor.queryPostgres(ctx, source, source.MaintenanceDatabase, statement); err != nil {
			t.Fatalf("source fixture setup failed: %v", err)
		}
	}
	sourceSchema := `
set role askio_source_owner;
create extension pgcrypto;
create schema app authorization askio_source_owner;
create table app.widgets (
  id bigserial primary key,
  name text not null check (length(name) > 0),
  token uuid not null default gen_random_uuid(),
  updated_at timestamptz not null default clock_timestamp()
);
create table app.widget_audit (
  id bigserial primary key,
  widget_id bigint not null references app.widgets(id),
  action text not null
);
create function app.audit_widget() returns trigger language plpgsql as $$
begin
  insert into app.widget_audit(widget_id, action) values (new.id, TG_OP);
  return new;
end
$$;
create trigger widgets_audit after insert on app.widgets for each row execute function app.audit_widget();
insert into app.widgets(name) values ('alpha'), ('beta'), ('gamma');
grant usage on schema app to askio_source_reader;
grant select on table app.widgets to askio_source_reader with grant option;
grant usage, select on sequence app.widgets_id_seq to askio_source_reader;
`
	if _, err := executor.queryPostgres(ctx, source, source.Database, sourceSchema); err != nil {
		t.Fatalf("source schema setup failed: %v", err)
	}
	for _, statement := range []string{
		"create role askio_mig_owner",
		"create database askio_mig_fixture with owner askio_mig_owner template template0 encoding 'UTF8'",
	} {
		if _, err := executor.queryPostgres(ctx, target, target.MaintenanceDatabase, statement); err != nil {
			t.Fatalf("target fixture setup failed: %v", err)
		}
	}
}

func copyPostgresIntegrationDirectory(t *testing.T, source, target string) {
	t.Helper()
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatalf("unexpected non-regular dump artifact: %s", entry.Name())
		}
		copyPostgresIntegrationFile(t, filepath.Join(source, entry.Name()), filepath.Join(target, entry.Name()))
	}
}

func copyPostgresIntegrationFile(t *testing.T, source, target string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustStringOutput(t *testing.T, outputs map[string]any, key string) string {
	t.Helper()
	value, ok := outputs[key].(string)
	if !ok || value == "" {
		t.Fatalf("missing string output %s: %#v", key, outputs[key])
	}
	return value
}

func clonePostgresIntegrationInputs(source map[string]any) map[string]any {
	clone := make(map[string]any, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func assertPostgresIntegrationManifest(t *testing.T, manifest postgresManifest, targetOwner string) {
	t.Helper()
	if manifest.ObjectCounts["triggers"] != 1 || manifest.ObjectCounts["constraints"] < 4 || manifest.ObjectCounts["functions"] < 1 {
		t.Fatalf("object inventory is incomplete: %#v", manifest.ObjectCounts)
	}
	foundSequence := false
	for _, sequence := range manifest.Sequences {
		if sequence.Schema == "app" && sequence.Name == "widgets_id_seq" && sequence.Last == "3" && sequence.IsCalled {
			foundSequence = true
		}
	}
	if !foundSequence {
		t.Fatalf("sequence state was not preserved: %#v", manifest.Sequences)
	}
	foundGrant := false
	for _, privilege := range manifest.Privileges {
		if privilege.ObjectType == "TABLE" && privilege.Schema == "app" && privilege.Name == "widgets" &&
			privilege.Grantee == targetOwner && privilege.Privilege == "SELECT" && privilege.Grantable {
			foundGrant = true
		}
	}
	if !foundGrant {
		t.Fatalf("normalized ACL grant option was not preserved: %#v", manifest.Privileges)
	}
}
