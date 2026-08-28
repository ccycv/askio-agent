package migration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const postgresLogicalDisposableIntegrationGate = "disposable-postgres-logical"

func TestPostgresLogicalLowerDowntimeCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_POSTGRES_LOGICAL_INTEGRATION") != postgresLogicalDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_POSTGRES_LOGICAL_INTEGRATION=disposable-postgres-logical inside the disposable fixture")
	}
	sourceHost := os.Getenv("ASKIO_MIGRATION_POSTGRES_LOGICAL_SOURCE_HOST")
	targetHost := os.Getenv("ASKIO_MIGRATION_POSTGRES_LOGICAL_TARGET_HOST")
	password := os.Getenv("ASKIO_MIGRATION_POSTGRES_LOGICAL_PASSWORD")
	rootCertPath := os.Getenv("ASKIO_MIGRATION_POSTGRES_LOGICAL_CA_PATH")
	if sourceHost == "" || targetHost == "" || sourceHost == targetHost || password == "" || !filepath.IsAbs(rootCertPath) {
		t.Fatal("the disposable logical fixture requires distinct hosts, a password, and an absolute CA path")
	}
	rootCert, err := os.ReadFile(rootCertPath)
	if err != nil || !strings.Contains(string(rootCert), "BEGIN CERTIFICATE") {
		t.Fatalf("the disposable logical fixture CA is invalid: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	executor, err := NewNativeExecutor(map[string]string{
		"source_staging": sourceStaging,
		"target_staging": targetStaging,
	}, filepath.Join(workspace, "unused-broker.sock"), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	executor.capacityCheck = func(string, int64) error { return nil }

	const (
		sourceBindingID  = "71111111-1111-4111-8111-111111111111"
		targetBindingID  = "72222222-2222-4222-8222-222222222222"
		logicalBindingID = "73333333-3333-4333-8333-333333333333"
		sourceDatabase   = "askio_logical_source"
		targetDatabase   = "askio_mig_logical"
		targetOwner      = "askio_mig_owner"
		replicationRole  = "askio_replicator"
	)
	roleMap := map[string]string{"postgres": targetOwner, replicationRole: targetOwner}
	sourceJSON := mustPostgresIntegrationBindingJSON(t, map[string]any{
		"schema_version": postgresBindingSchema, "mode": "source", "host": sourceHost, "port": 5432,
		"database": sourceDatabase, "maintenance_database": "postgres", "username": "postgres",
		"password": password, "ssl_mode": "require", "role_map": roleMap,
	})
	targetJSON := mustPostgresIntegrationBindingJSON(t, map[string]any{
		"schema_version": postgresBindingSchema, "mode": "target", "host": targetHost, "port": 5432,
		"database": targetDatabase, "maintenance_database": "postgres", "username": "postgres",
		"password": password, "ssl_mode": "disable", "role_map": roleMap, "target_role": targetOwner,
		"reset_allowed": true,
	})
	logicalJSON, err := json.Marshal(map[string]any{
		"schema_version": postgresLogicalBindingSchema, "host": sourceHost, "port": 5432,
		"database": sourceDatabase, "username": replicationRole, "password": password,
		"ssl_mode": "verify-full", "ssl_root_cert_pem": string(rootCert), "server_ssl_root_cert_path": rootCertPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		switch bindingID {
		case sourceBindingID:
			return append([]byte(nil), sourceJSON...), nil
		case targetBindingID:
			return append([]byte(nil), targetJSON...), nil
		case logicalBindingID:
			return append([]byte(nil), logicalJSON...), nil
		default:
			return nil, errors.New("unexpected PostgreSQL logical integration binding")
		}
	})

	source := mustParsePostgresIntegrationBinding(t, sourceJSON)
	defer source.clear()
	target := mustParsePostgresIntegrationBinding(t, targetJSON)
	defer target.clear()
	for _, statement := range []string{
		"create database " + quotePostgresIdentifier(sourceDatabase) + " with owner postgres template template0 encoding 'UTF8'",
	} {
		if _, err := executor.queryPostgres(ctx, source, source.MaintenanceDatabase, statement); err != nil {
			t.Fatalf("source fixture setup failed: %v", err)
		}
	}
	if _, err := executor.queryPostgres(ctx, target, target.MaintenanceDatabase,
		"create role "+quotePostgresIdentifier(targetOwner)); err != nil {
		t.Fatalf("target owner setup failed: %v", err)
	}
	if _, err := executor.queryPostgres(ctx, target, target.MaintenanceDatabase,
		"create database "+quotePostgresIdentifier(targetDatabase)+" with owner "+quotePostgresIdentifier(targetOwner)+" template template0 encoding 'UTF8'"); err != nil {
		t.Fatalf("target database setup failed: %v", err)
	}
	if _, err := executor.queryPostgres(ctx, source, source.MaintenanceDatabase,
		"create role "+quotePostgresIdentifier(replicationRole)+" login replication bypassrls password "+quotePostgresLiteral(password)); err != nil {
		t.Fatalf("replication role setup failed: %v", err)
	}
	if _, err := executor.queryPostgres(ctx, source, source.Database,
		"create table no_primary_key(payload text); grant connect on database "+quotePostgresIdentifier(sourceDatabase)+" to "+quotePostgresIdentifier(replicationRole)+"; grant usage on schema public to "+quotePostgresIdentifier(replicationRole)+"; grant select on table no_primary_key to "+quotePostgresIdentifier(replicationRole)); err != nil {
		t.Fatalf("unsupported source fixture setup failed: %v", err)
	}

	contract := map[string]any{
		"schema_version": "operations.migration.database-contract.v1", "source_engine": "postgresql", "target_engine": "postgresql",
		"database_mappings": []map[string]string{{"source_database": sourceDatabase, "target_database": targetDatabase}},
		"role_map":          roleMap,
		"logical_replication": map[string]any{
			"mode": "lower-downtime", "replication_role": replicationRole,
			"maximum_catchup_seconds": 120, "maximum_slot_wal_bytes": int64(1024 * 1024 * 1024),
		},
	}
	planDigest := "sha256:" + strings.Repeat("a", 64)
	task := TaskEnvelope{
		MigrationID: "74444444-4444-4444-8444-444444444444",
		AttemptID:   "75555555-5555-4555-8555-555555555555",
		PlanDigest:  &planDigest,
	}
	progress := func(string, int64, *int64) error { return nil }
	sourceInputs := map[string]any{"database_binding_id": sourceBindingID, "database_contract": contract}
	targetInputs := map[string]any{"database_binding_id": targetBindingID, "logical_source_binding_id": logicalBindingID, "database_contract": contract}
	if _, err := executor.postgresLogicalPreflight(ctx, task, sourceInputs); err == nil || !strings.Contains(err.Error(), "primary-keyed") {
		t.Fatalf("a table without a primary key was not rejected: %v", err)
	}
	if _, err := executor.queryPostgres(ctx, source, source.Database, "drop table no_primary_key; create table widgets(id bigserial primary key,payload text not null); insert into widgets(payload) values('alpha'),('beta'); grant select on table widgets to "+quotePostgresIdentifier(replicationRole)); err != nil {
		t.Fatalf("eligible source fixture setup failed: %v", err)
	}
	if _, err := executor.postgresLogicalPreflight(ctx, task, sourceInputs); err != nil {
		t.Fatalf("source logical preflight failed: %v", err)
	}
	if _, err := executor.postgresLogicalPreflight(ctx, task, targetInputs); err != nil {
		t.Fatalf("target logical preflight failed: %v", err)
	}
	targetInspect, err := executor.postgresInspect(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "database_contract": contract, "require_empty_target": true,
	})
	if err != nil || targetInspect["empty"] != true {
		t.Fatalf("target empty inspection failed: %#v %v", targetInspect, err)
	}
	if _, err := executor.postgresReset(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "database_contract": contract,
		"expected_empty_target_digest": mustStringOutput(t, targetInspect, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("target reset failed: %v", err)
	}

	schemaInputs := clonePostgresIntegrationInputs(sourceInputs)
	schemaInputs["staging_root_handle"] = "source_staging"
	schemaOutput, err := executor.postgresLogicalSchemaDump(ctx, task, schemaInputs, progress)
	if err != nil {
		t.Fatalf("logical schema dump failed: %v", err)
	}
	schemaRelative := mustStringOutput(t, schemaOutput, "schema_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, schemaRelative), filepath.Join(targetStaging, schemaRelative))
	restoreInputs := clonePostgresIntegrationInputs(targetInputs)
	restoreInputs["staging_root_handle"] = "target_staging"
	restoreInputs["schema_staging_relative_handle"] = schemaRelative
	restoreInputs["schema_artifact_handle"] = mustStringOutput(t, schemaOutput, "schema_artifact_handle")
	restoreInputs["schema_artifact_digest"] = mustStringOutput(t, schemaOutput, "schema_artifact_digest")
	if _, err := executor.postgresLogicalRestoreSchema(ctx, task, restoreInputs); err != nil {
		t.Fatalf("logical schema restore failed: %v", err)
	}
	prepareInputs := clonePostgresIntegrationInputs(sourceInputs)
	prepareInputs["expected_schema_digest"] = mustStringOutput(t, schemaOutput, "schema_digest")
	if _, err := executor.postgresLogicalPrepareSource(ctx, task, prepareInputs); err != nil {
		t.Fatalf("logical source preparation failed: %v", err)
	}
	startInputs := clonePostgresIntegrationInputs(targetInputs)
	startInputs["expected_schema_digest"] = mustStringOutput(t, schemaOutput, "schema_digest")
	if _, err := executor.postgresLogicalStartSubscription(ctx, task, startInputs, progress); err != nil {
		t.Fatalf("logical initial copy failed: %v", err)
	}

	if _, err := executor.queryPostgres(ctx, source, source.Database,
		"update widgets set payload='alpha-updated' where id=1; delete from widgets where id=2; insert into widgets(payload) values('gamma')"); err != nil {
		t.Fatalf("live source mutation failed: %v", err)
	}
	finalSourceInputs := clonePostgresIntegrationInputs(sourceInputs)
	finalSourceInputs["staging_root_handle"] = "source_staging"
	finalOutput, err := executor.postgresLogicalFinalizeSource(ctx, task, finalSourceInputs, progress)
	if err != nil {
		t.Fatalf("logical final source capture failed: %v", err)
	}
	finalRelative := mustStringOutput(t, finalOutput, "final_state_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, finalRelative), filepath.Join(targetStaging, finalRelative))
	finalTargetInputs := clonePostgresIntegrationInputs(targetInputs)
	finalTargetInputs["staging_root_handle"] = "target_staging"
	finalTargetInputs["final_state_staging_relative_handle"] = finalRelative
	finalTargetInputs["final_state_artifact_handle"] = mustStringOutput(t, finalOutput, "final_state_artifact_handle")
	finalTargetInputs["final_state_artifact_digest"] = mustStringOutput(t, finalOutput, "final_state_artifact_digest")
	finalTarget, err := executor.postgresLogicalFinalizeTarget(ctx, task, finalTargetInputs, progress)
	if err != nil || finalTarget["verified"] != true || finalTarget["subscription_detached"] != true {
		t.Fatalf("logical target finalization failed: %#v %v", finalTarget, err)
	}
	rows, err := executor.queryPostgres(ctx, target, target.Database, "select id::text,payload from widgets order by id")
	if err != nil || len(rows) != 2 || rows[0][0] != "1" || rows[0][1] != "alpha-updated" || rows[1][0] != "3" || rows[1][1] != "gamma" {
		t.Fatalf("logical target content diverged: %#v %v", rows, err)
	}
	sequenceRows, err := executor.queryPostgres(ctx, target, target.Database, "select last_value::text,is_called::text from widgets_id_seq")
	if err != nil || len(sequenceRows) != 1 || len(sequenceRows[0]) != 2 || sequenceRows[0][0] != "3" {
		t.Fatalf("logical target sequence diverged: %#v %v", sequenceRows, err)
	}
	sequenceCalled, sequenceCalledErr := postgresBool([][]string{{sequenceRows[0][1]}})
	if sequenceCalledErr != nil || !sequenceCalled {
		t.Fatalf("logical target sequence call state diverged: %#v %v", sequenceRows, sequenceCalledErr)
	}
	if _, err := executor.postgresLogicalCleanupSource(ctx, task, sourceInputs); err != nil {
		t.Fatalf("logical source cleanup failed: %v", err)
	}
	if _, err := executor.postgresLogicalCleanupTarget(ctx, task, targetInputs); err != nil {
		t.Fatalf("logical target cleanup failed: %v", err)
	}
	names, _ := postgresLogicalObjectNames(task.MigrationID, sourceDatabase)
	sourceInventory, err := executor.queryPostgres(ctx, source, source.Database,
		"select (not exists(select 1 from pg_publication where pubname="+quotePostgresLiteral(names.Publication)+") and not exists(select 1 from pg_replication_slots where slot_name="+quotePostgresLiteral(names.Slot)+"))::text")
	cleanSource, cleanSourceErr := postgresBool(sourceInventory)
	targetInventory, errTarget := executor.queryPostgres(ctx, target, target.Database,
		"select (not exists(select 1 from pg_subscription where subname="+quotePostgresLiteral(names.Subscription)+"))::text")
	cleanTarget, cleanTargetErr := postgresBool(targetInventory)
	if err != nil || cleanSourceErr != nil || !cleanSource || errTarget != nil || cleanTargetErr != nil || !cleanTarget {
		t.Fatalf("logical objects remained after cleanup: source=%#v target=%#v errors=%v/%v/%v/%v", sourceInventory, targetInventory, err, cleanSourceErr, errTarget, cleanTargetErr)
	}
}
