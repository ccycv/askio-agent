package migration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const mysqlDisposableIntegrationGate = "disposable-conversion-cycle"

func TestMySQLOfflineMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_MYSQL_INTEGRATION") != mysqlDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_MYSQL_INTEGRATION=disposable-conversion-cycle inside the disposable fixture")
	}
	sourceEngine := os.Getenv("ASKIO_MIGRATION_MYSQL_SOURCE_ENGINE")
	targetEngine := os.Getenv("ASKIO_MIGRATION_MYSQL_TARGET_ENGINE")
	if (sourceEngine != "mysql" && sourceEngine != "mariadb") || (targetEngine != "mysql" && targetEngine != "mariadb") {
		t.Fatal("the disposable fixture requires mysql or mariadb source and target engines")
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
	accountMap := []map[string]string{{
		"source_user": "fixture_app", "source_host": "%",
		"target_user": "fixture_target", "target_host": "%",
	}}
	bindingJSON := func(mode, engine string, port int, database string, reset bool) []byte {
		value := map[string]any{
			"schema_version": mysqlBindingSchemaV2, "engine": engine, "mode": mode,
			"host": host, "port": port, "database": database,
			"username": "root", "password": password, "ssl_mode": sslMode,
			"account_map": accountMap,
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
	sourceJSON := bindingJSON("source", sourceEngine, sourcePort, sourceDatabase, false)
	targetJSON := bindingJSON("target", targetEngine, targetPort, targetDatabase, true)
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
		{source, "drop user if exists 'fixture_app'@'%'"},
		{source, "create user 'fixture_app'@'%' identified by 'fixture-source-password'"},
		{source, "create database `askio_fixture_source` character set utf8mb4 collate utf8mb4_unicode_ci"},
		{target, "drop database if exists `askio_mig_fixture`"},
		{target, "drop user if exists 'fixture_target'@'%'"},
		{target, "create user 'fixture_target'@'%' identified by 'fixture-target-password'"},
		{target, "create database `askio_mig_fixture` character set utf8mb4 collate utf8mb4_unicode_ci"},
	} {
		if _, err := executor.queryMySQL(ctx, fixture.binding, "", fixture.query); err != nil {
			t.Fatalf("fixture database setup failed: %v", err)
		}
	}
	missingAccountTarget := target
	missingAccountTarget.AccountMap = []mysqlAccountMapping{{
		SourceUser: "fixture_app", SourceHost: "%", TargetUser: "fixture_missing", TargetHost: "%",
	}}
	if _, err := executor.inspectMySQL(ctx, targetBindingID, missingAccountTarget); err == nil {
		t.Fatal("target inspection accepted an account map whose destination account does not exist")
	}
	nonTransactionalEngine := "MyISAM"
	if sourceEngine == "mariadb" {
		nonTransactionalEngine = "Aria"
	}
	statements := []string{
		"create table widgets (id bigint unsigned not null auto_increment primary key, name varchar(100) not null, payload blob not null, created_at timestamp(6) not null default current_timestamp(6)) engine=InnoDB",
		"create table widget_audit (id bigint unsigned not null auto_increment primary key, widget_id bigint unsigned not null, action_name varchar(64) not null) engine=InnoDB",
		"create table legacy_flags (id int not null primary key, flag_name varchar(64) not null) engine=" + nonTransactionalEngine,
		"insert into widgets(name,payload) values ('alpha',x'000102'),('bravo',x'fffefd'),('unicode-șț',x'102030')",
		"insert into legacy_flags(id,flag_name) values (1,'first'),(2,'second')",
		"create definer='fixture_app'@'%' sql security definer view active_widgets as select id,name from widgets where id > 0",
		"create definer='fixture_app'@'%' trigger widgets_audit after insert on widgets for each row insert into widget_audit(widget_id,action_name) values (new.id,'inserted')",
		"create definer='fixture_app'@'%' function fixture_answer() returns int deterministic return 42",
		"create definer='fixture_app'@'%' procedure count_widgets() sql security definer select count(*) as widget_count from widgets",
		"create definer='fixture_app'@'%' event fixture_daily on schedule every 1 day disable do insert into widget_audit(widget_id,action_name) values (0,'event')",
		"grant insert,update,delete,show view,trigger,event on `askio_fixture_source`.* to 'fixture_app'@'%'",
		"grant select on `askio_fixture_source`.`widgets` to 'fixture_app'@'%' with grant option",
		"grant select on `askio_fixture_source`.`legacy_flags` to 'fixture_app'@'%'",
		"grant select (action_name) on `askio_fixture_source`.`widget_audit` to 'fixture_app'@'%'",
		"grant execute on function `askio_fixture_source`.`fixture_answer` to 'fixture_app'@'%'",
		"grant execute on procedure `askio_fixture_source`.`count_widgets` to 'fixture_app'@'%'",
	}
	for _, statement := range statements {
		if _, err := executor.queryMySQL(ctx, source, source.Database, statement); err != nil {
			t.Fatalf("source fixture setup failed for %q: %v", statement, err)
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
	if _, err := executor.queryMySQL(ctx, target, "", "grant select on `askio_mig_fixture`.* to 'fixture_target'@'%'"); err != nil {
		t.Fatalf("could not create the unowned-grant negative fixture: %v", err)
	}
	if _, err := executor.mysqlReset(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err == nil {
		t.Fatal("target reset accepted an unowned database grant")
	}
	if _, err := executor.queryMySQL(ctx, target, "", "revoke select on `askio_mig_fixture`.* from 'fixture_target'@'%'"); err != nil {
		t.Fatalf("could not remove the unowned-grant negative fixture: %v", err)
	}
	dumpOutputs, err := executor.mysqlDump(ctx, task, map[string]any{
		"database_binding_id": sourceBindingID, "staging_root_handle": "source_staging",
		"target_engine": targetOutputs["engine"], "target_character_set": targetOutputs["character_set"],
		"target_collation": targetOutputs["collation"],
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
	restoreInputs := map[string]any{
		"database_binding_id": targetBindingID, "staging_root_handle": "target_staging",
		"dump_staging_relative_handle": stagingRelative,
		"dump_artifact_handle":         mustStringOutput(t, dumpOutputs, "dump_artifact_handle"),
		"dump_artifact_digest":         mustStringOutput(t, dumpOutputs, "dump_artifact_digest"),
		"expected_manifest_digest":     mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
		"migration_metadata_digest":    mustStringOutput(t, dumpOutputs, "migration_metadata_digest"),
	}
	metadataPath := filepath.Join(targetStaging, stagingRelative, "database.metadata.json")
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadataPath, append(append([]byte(nil), metadataBytes...), []byte("\n{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.mysqlRestore(ctx, task, restoreInputs, progress); err == nil {
		t.Fatal("target restore accepted tampered conversion metadata")
	}
	if err := os.WriteFile(metadataPath, metadataBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.mysqlRestore(ctx, task, restoreInputs, progress); err != nil {
		sourceInspection, sourceInspectErr := executor.inspectMySQL(ctx, sourceBindingID, source)
		targetInspection, targetInspectErr := executor.inspectMySQL(ctx, targetBindingID, target)
		t.Fatalf("target restore failed: %v\nsource=%+v (err=%v)\ntarget=%+v (err=%v)", err, sourceInspection.Manifest, sourceInspectErr, targetInspection.Manifest, targetInspectErr)
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
	if targetInspection.TotalRows != 5 || len(targetInspection.Manifest.Tables) != 3 || len(targetInspection.Manifest.Objects) != 5 || len(targetInspection.Manifest.Grants) < 1 {
		t.Fatalf("restored MySQL fixture diverged: %+v", targetInspection)
	}
	verificationRows, err := executor.queryMySQL(ctx, target, target.Database, "select (select count(*) from active_widgets),(select fixture_answer()),(select count(*) from information_schema.events where event_schema="+quoteMySQLLiteral(target.Database)+" and event_name='fixture_daily' and event_definition like '%widget_audit%'),(select count(*) from information_schema.routines where routine_schema="+quoteMySQLLiteral(target.Database)+" and routine_name='count_widgets' and routine_type='PROCEDURE')")
	if err != nil || len(verificationRows) != 1 || strings.Join(verificationRows[0], ",") != "3,42,1,1" {
		t.Fatalf("restored programmable objects failed verification: rows=%v err=%v", verificationRows, err)
	}
	procedureRows, err := executor.queryMySQL(ctx, target, target.Database, "call count_widgets()")
	if err != nil || len(procedureRows) < 1 || len(procedureRows[0]) != 1 || procedureRows[0][0] != "3" {
		t.Fatalf("restored procedure could not execute: rows=%v err=%v", procedureRows, err)
	}
	if _, err := executor.queryMySQL(ctx, target, target.Database, "insert into widgets(name,payload) values ('after-restore',x'0102')"); err != nil {
		t.Fatalf("restored trigger could not execute: %v", err)
	}
	auditRows, err := executor.queryMySQL(ctx, target, target.Database, "select count(*) from widget_audit where action_name='inserted'")
	if err != nil || len(auditRows) != 1 || auditRows[0][0] != "1" {
		t.Fatalf("restored trigger did not write the expected audit row: rows=%v err=%v", auditRows, err)
	}
	grantRows, err := executor.queryMySQL(ctx, target, "", "select (select count(*) from information_schema.schema_privileges where table_schema="+quoteMySQLLiteral(target.Database)+" and grantee=\"'fixture_target'@'%'\"),(select count(*) from information_schema.table_privileges where table_schema="+quoteMySQLLiteral(target.Database)+" and grantee=\"'fixture_target'@'%'\"),(select count(*) from information_schema.column_privileges where table_schema="+quoteMySQLLiteral(target.Database)+" and grantee=\"'fixture_target'@'%'\"),(select count(*) from mysql.procs_priv where Db="+quoteMySQLLiteral(target.Database)+" and User='fixture_target' and Host='%')")
	if err != nil || len(grantRows) != 1 || len(grantRows[0]) != 4 || strings.Join(grantRows[0], ",") != "6,2,1,2" {
		t.Fatalf("mapped destination grants were not restored: rows=%v err=%v", grantRows, err)
	}
	engineRows, err := executor.queryMySQL(ctx, target, "", "select engine from information_schema.tables where table_schema="+quoteMySQLLiteral(target.Database)+" and table_name='legacy_flags'")
	if err != nil || len(engineRows) != 1 {
		t.Fatalf("non-InnoDB target engine could not be inspected: rows=%v err=%v", engineRows, err)
	}
	if sourceEngine == "mariadb" && targetEngine == "mysql" && !strings.EqualFold(engineRows[0][0], "InnoDB") {
		t.Fatalf("MariaDB Aria table was not converted to InnoDB: %v", engineRows)
	}
	if sourceEngine == "mysql" && targetEngine == "mariadb" && !strings.EqualFold(engineRows[0][0], "MyISAM") {
		t.Fatalf("MySQL MyISAM table was not preserved on MariaDB: %v", engineRows)
	}
	if _, err := executor.mysqlReset(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("owned target could not be reset after verification: %v", err)
	}
	cleaned, err := executor.inspectMySQL(ctx, targetBindingID, target)
	if err != nil || !cleaned.Empty || len(cleaned.Manifest.Grants) != 0 || len(cleaned.Manifest.Tables) != 0 || len(cleaned.Manifest.Objects) != 0 {
		t.Fatalf("owned target cleanup did not remove restored state: inspection=%+v err=%v", cleaned, err)
	}
}
