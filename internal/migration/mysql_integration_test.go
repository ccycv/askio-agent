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

const mysqlDisposableIntegrationGate = "disposable-same-engine-cycle"

func TestMySQLOfflineMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_MYSQL_INTEGRATION") != mysqlDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_MYSQL_INTEGRATION=disposable-same-engine-cycle inside the disposable fixture")
	}
	engine := os.Getenv("ASKIO_MIGRATION_MYSQL_ENGINE")
	if engine != "mysql" && engine != "mariadb" {
		t.Fatal("the disposable fixture requires mysql or mariadb")
	}
	sourcePort, sourceErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MYSQL_SOURCE_PORT"))
	targetPort, targetErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MYSQL_TARGET_PORT"))
	password := os.Getenv("ASKIO_MIGRATION_MYSQL_PASSWORD")
	host := os.Getenv("ASKIO_MIGRATION_MYSQL_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	sslMode := os.Getenv("ASKIO_MIGRATION_MYSQL_SSL_MODE")
	if sslMode == "" {
		sslMode = "disable"
	}
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
		sourceBindingID = "61111111-1111-4111-8111-111111111111"
		targetBindingID = "62222222-2222-4222-8222-222222222222"
		sourceDatabase  = "askio_fixture_source"
		targetDatabase  = "askio_mig_fixture"
	)
	bindingJSON := func(mode string, port int, database string, reset bool) []byte {
		value := map[string]any{
			"schema_version": mysqlBindingSchema, "engine": engine, "mode": mode,
			"host": host, "port": port, "database": database,
			"username": "root", "password": password, "ssl_mode": sslMode,
		}
		if reset {
			value["reset_allowed"] = true
			value["target_character_set"] = "utf8mb4"
			value["target_collation"] = "utf8mb4_unicode_ci"
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
	source, err := parseMySQLBinding(sourceJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer source.clear()
	target, err := parseMySQLBinding(targetJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer target.clear()
	for _, fixture := range []struct {
		binding mysqlBinding
		query   string
	}{
		{source, "drop database if exists `askio_fixture_source`"},
		{source, "create database `askio_fixture_source` character set utf8mb4 collate utf8mb4_unicode_ci"},
		{target, "drop database if exists `askio_mig_fixture`"},
		{target, "create database `askio_mig_fixture` character set utf8mb4 collate utf8mb4_unicode_ci"},
	} {
		if _, err := executor.queryMySQL(ctx, fixture.binding, "", fixture.query); err != nil {
			t.Fatalf("fixture database setup failed: %v", err)
		}
	}
	for _, statement := range []string{
		"create table widgets (id bigint unsigned not null auto_increment primary key, name varchar(100) not null, payload blob not null, created_at timestamp(6) not null default current_timestamp(6)) engine=InnoDB",
		"create table widget_events (id bigint unsigned not null auto_increment primary key, widget_id bigint unsigned not null, event_name varchar(64) not null, constraint fk_widget foreign key (widget_id) references widgets(id)) engine=InnoDB",
		"insert into widgets(name,payload) values ('alpha',x'000102'),('bravo',x'fffefd'),('unicode-șț',x'102030')",
		"insert into widget_events(widget_id,event_name) values (1,'created'),(2,'created'),(3,'created')",
	} {
		if _, err := executor.queryMySQL(ctx, source, source.Database, statement); err != nil {
			t.Fatalf("source fixture setup failed: %v", err)
		}
	}
	task := TaskEnvelope{MigrationID: "63333333-3333-4333-8333-333333333333", AttemptID: "64444444-4444-4444-8444-444444444444"}
	progress := func(string, int64, *int64) error { return nil }
	sourceOutputs, err := executor.mysqlInspect(ctx, task, map[string]any{"database_binding_id": sourceBindingID})
	if err != nil {
		t.Fatalf("source inspection failed: %v", err)
	}
	targetOutputs, err := executor.mysqlInspect(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "require_empty_target": true,
		"required_source_engine": sourceOutputs["engine"], "required_source_series": sourceOutputs["server_series"],
		"required_character_set": sourceOutputs["character_set"], "required_collation": sourceOutputs["collation"],
		"required_sql_mode": sourceOutputs["sql_mode"],
	})
	if err != nil {
		t.Fatalf("target compatibility inspection failed: %v", err)
	}
	dumpOutputs, err := executor.mysqlDump(ctx, task, map[string]any{
		"database_binding_id": sourceBindingID, "staging_root_handle": "source_staging",
	}, progress)
	if err != nil {
		t.Fatalf("source dump failed: %v", err)
	}
	stagingRelative := mustStringOutput(t, dumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, stagingRelative), filepath.Join(targetStaging, stagingRelative))
	if _, err := executor.mysqlReset(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("target reset failed: %v", err)
	}
	if _, err := executor.mysqlRestore(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "staging_root_handle": "target_staging",
		"dump_staging_relative_handle": stagingRelative,
		"dump_artifact_handle":         mustStringOutput(t, dumpOutputs, "dump_artifact_handle"),
		"dump_artifact_digest":         mustStringOutput(t, dumpOutputs, "dump_artifact_digest"),
		"expected_manifest_digest":     mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}, progress); err != nil {
		t.Fatalf("target restore failed: %v", err)
	}
	if _, err := executor.mysqlVerify(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_manifest_digest": mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}); err != nil {
		t.Fatalf("target verification failed: %v", err)
	}
	targetInspection, err := executor.inspectMySQL(ctx, targetBindingID, target)
	if err != nil {
		t.Fatal(err)
	}
	if targetInspection.TotalRows != 6 || len(targetInspection.Manifest.Tables) != 2 {
		t.Fatalf("restored MySQL fixture diverged: %+v", targetInspection)
	}
}
