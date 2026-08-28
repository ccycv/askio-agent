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

const redisDisposableIntegrationGate = "disposable-redis-valkey-cycle"

func TestRedisValkeyOfflineMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_REDIS_INTEGRATION") != redisDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_REDIS_INTEGRATION=disposable-redis-valkey-cycle inside the disposable fixture")
	}
	engine := os.Getenv("ASKIO_MIGRATION_REDIS_ENGINE")
	if engine != "redis" && engine != "valkey" {
		t.Fatal("the disposable fixture requires redis or valkey")
	}
	sourcePort, sourceErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_REDIS_SOURCE_PORT"))
	targetPort, targetErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_REDIS_TARGET_PORT"))
	password := os.Getenv("ASKIO_MIGRATION_REDIS_PASSWORD")
	if sourceErr != nil || targetErr != nil || sourcePort == targetPort || password == "" {
		t.Fatal("the disposable fixture requires distinct source and target ports plus a password")
	}
	host := os.Getenv("ASKIO_MIGRATION_REDIS_HOST")
	if host == "" {
		host = "127.0.0.1"
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
		cacheSourceID   = "73333333-3333-4333-8333-333333333333"
		cacheTargetID   = "74444444-4444-4444-8444-444444444444"
	)
	aclMap := []map[string]string{{"source": "default", "target": "default"}, {"source": "sourceapp", "target": "targetapp"}}
	bindingJSON := func(mode, stateMode string, port int, reset bool) []byte {
		value := map[string]any{
			"schema_version": redisBindingSchema, "engine": engine, "mode": mode,
			"host": host, "port": port, "username": "default", "password": password,
			"tls_mode": "disable", "state_mode": stateMode,
			"database_indexes": []int{0, 2}, "acl_map": aclMap,
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
	bindings := map[string][]byte{
		sourceBindingID: bindingJSON("source", "durable", sourcePort, false),
		targetBindingID: bindingJSON("target", "durable", targetPort, true),
		cacheSourceID:   bindingJSON("source", "cache", sourcePort, false),
		cacheTargetID:   bindingJSON("target", "cache", targetPort, true),
	}
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		value, exists := bindings[bindingID]
		if !exists {
			return nil, errors.New("unexpected integration binding")
		}
		return append([]byte(nil), value...), nil
	})

	contract := func(stateMode string) map[string]any {
		return map[string]any{
			"schema_version": redisDatabaseContractSchema,
			"source_engine":  engine, "target_engine": engine, "state_mode": stateMode,
			"database_indexes": []int{0, 2}, "acl_map": aclMap,
		}
	}
	inputs := func(bindingID, stateMode string) map[string]any {
		return map[string]any{"database_binding_id": bindingID, "database_contract": contract(stateMode)}
	}
	parseBinding := func(bindingID string) redisBinding {
		binding, parseErr := parseRedisBinding(bindings[bindingID])
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return binding
	}
	source := parseBinding(sourceBindingID)
	target := parseBinding(targetBindingID)
	defer source.clear()
	defer target.clear()
	sourceAdmin, err := source.client(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceAdmin.Do(ctx, "ACL", "SETUSER", "sourceapp", "reset", "on", ">source-app-secret", "~app:*", "+@read", "+@write").Err(); err != nil {
		t.Fatal(err)
	}
	_ = sourceAdmin.Close()
	targetAdmin, err := target.client(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := targetAdmin.Do(ctx, "ACL", "SETUSER", "targetapp", "reset", "on", ">different-target-secret", "~app:*", "+@read", "+@write").Err(); err != nil {
		t.Fatal(err)
	}
	_ = targetAdmin.Close()
	for _, binding := range []redisBinding{source, target} {
		for _, database := range binding.DatabaseIndexes {
			client, clientErr := binding.client(database)
			if clientErr != nil {
				t.Fatal(clientErr)
			}
			if flushErr := client.FlushDB(ctx).Err(); flushErr != nil {
				_ = client.Close()
				t.Fatal(flushErr)
			}
			_ = client.Close()
		}
	}
	sourceZero, err := source.client(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceZero.Set(ctx, string([]byte{0, 'b', 'i', 'n'}), string([]byte{0, 1, 2, 255}), 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := sourceZero.RPush(ctx, "queue", "alpha", "bravo", "unicode-șț").Err(); err != nil {
		t.Fatal(err)
	}
	if err := sourceZero.Set(ctx, "expiring", "temporary", 90*time.Second).Err(); err != nil {
		t.Fatal(err)
	}
	_ = sourceZero.Close()
	sourceTwo, err := source.client(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceTwo.HSet(ctx, "profile", "name", "Askio", "mode", "durable").Err(); err != nil {
		t.Fatal(err)
	}
	_ = sourceTwo.Close()

	task := TaskEnvelope{MigrationID: "75555555-5555-4555-8555-555555555555", AttemptID: "76666666-6666-4666-8666-666666666666"}
	progress := func(string, int64, *int64) error { return nil }
	if engine == "redis" {
		facts, factsErr := inspectRedisServer(ctx, source)
		if factsErr != nil {
			t.Fatal(factsErr)
		}
		if facts.VersionSeries == "8.2" {
			moduleClient, clientErr := source.client(0)
			if clientErr != nil {
				t.Fatal(clientErr)
			}
			if commandErr := moduleClient.Do(ctx, "VADD", "module-vector", "VALUES", 2, 1, 2, "item").Err(); commandErr != nil {
				_ = moduleClient.Close()
				t.Fatalf("could not seed Redis 8 module-backed fixture: %v", commandErr)
			}
			if _, inspectErr := executor.redisInspect(ctx, task, inputs(sourceBindingID, "durable")); inspectErr == nil {
				_ = moduleClient.Close()
				t.Fatal("durable inspection accepted a Redis 8 module-backed value")
			}
			if deleteErr := moduleClient.Del(ctx, "module-vector").Err(); deleteErr != nil {
				_ = moduleClient.Close()
				t.Fatal(deleteErr)
			}
			_ = moduleClient.Close()
		}
	}
	sourceOutputs, err := executor.redisInspect(ctx, task, inputs(sourceBindingID, "durable"))
	if err != nil {
		t.Fatalf("source inspection failed: %v", err)
	}
	if sourceOutputs["key_count"] != int64(4) {
		t.Fatalf("unexpected source key count: %v", sourceOutputs["key_count"])
	}
	expectedPersistence := "rdb"
	if engine == "valkey" {
		expectedPersistence = "aof"
	}
	if sourceOutputs["persistence_mode"] != expectedPersistence {
		t.Fatalf("unexpected %s persistence mode: %v", engine, sourceOutputs["persistence_mode"])
	}
	targetInputs := inputs(targetBindingID, "durable")
	targetInputs["require_empty_target"] = true
	targetInputs["required_source_engine"] = sourceOutputs["engine"]
	targetInputs["required_source_series"] = sourceOutputs["server_series"]
	targetInputs["required_persistence_mode"] = sourceOutputs["persistence_mode"]
	if _, err := executor.redisInspect(ctx, task, targetInputs); err == nil {
		t.Fatal("target compatibility accepted a mismatched persistence mode")
	}
	targetConfig, err := target.client(0)
	if err != nil {
		t.Fatal(err)
	}
	if expectedPersistence == "rdb" {
		if err := targetConfig.ConfigSet(ctx, "appendonly", "no").Err(); err != nil {
			t.Fatal(err)
		}
		if err := targetConfig.ConfigSet(ctx, "save", "3600 1").Err(); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := targetConfig.ConfigSet(ctx, "save", "").Err(); err != nil {
			t.Fatal(err)
		}
		if err := targetConfig.ConfigSet(ctx, "appendonly", "yes").Err(); err != nil {
			t.Fatal(err)
		}
	}
	_ = targetConfig.Close()
	targetOutputs, err := executor.redisInspect(ctx, task, targetInputs)
	if err != nil {
		t.Fatalf("target compatibility inspection failed: %v", err)
	}
	topologyClient, err := target.client(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := topologyClient.Do(ctx, "REPLICAOF", "127.0.0.1", sourcePort).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.redisInspect(ctx, task, targetInputs); err == nil {
		t.Fatal("target compatibility accepted a replica")
	}
	if err := topologyClient.Do(ctx, "REPLICAOF", "NO", "ONE").Err(); err != nil {
		t.Fatal(err)
	}
	_ = topologyClient.Close()
	if _, err := executor.redisInspect(ctx, task, targetInputs); err != nil {
		t.Fatalf("target did not recover standalone-primary eligibility: %v", err)
	}
	dumpInputs := inputs(sourceBindingID, "durable")
	dumpInputs["staging_root_handle"] = "source_staging"
	dumpOutputs, err := executor.redisDump(ctx, task, dumpInputs, progress)
	if err != nil {
		t.Fatalf("source snapshot failed: %v", err)
	}
	stagingRelative := mustStringOutput(t, dumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, stagingRelative), filepath.Join(targetStaging, stagingRelative))
	resetInputs := inputs(targetBindingID, "durable")
	resetInputs["expected_empty_target_digest"] = mustStringOutput(t, targetOutputs, "empty_target_digest")
	if _, err := executor.redisReset(ctx, task, resetInputs); err != nil {
		t.Fatalf("target reset failed: %v", err)
	}
	restoreInputs := inputs(targetBindingID, "durable")
	restoreInputs["staging_root_handle"] = "target_staging"
	restoreInputs["dump_staging_relative_handle"] = stagingRelative
	restoreInputs["dump_artifact_handle"] = mustStringOutput(t, dumpOutputs, "dump_artifact_handle")
	restoreInputs["dump_artifact_digest"] = mustStringOutput(t, dumpOutputs, "dump_artifact_digest")
	restoreInputs["expected_manifest_digest"] = mustStringOutput(t, dumpOutputs, "database_manifest_digest")
	badRestore := make(map[string]any, len(restoreInputs))
	for key, value := range restoreInputs {
		badRestore[key] = value
	}
	badRestore["dump_artifact_digest"] = "sha256:" + strings.Repeat("0", 64)
	if _, err := executor.redisRestore(ctx, task, badRestore, progress); err == nil {
		t.Fatal("restore accepted an invalid archive digest")
	}
	interrupted := false
	interruptRestore := func(stage string, _ int64, _ *int64) error {
		if stage == "redis_restore" && !interrupted {
			interrupted = true
			return errors.New("injected restore interruption")
		}
		return nil
	}
	if _, err := executor.redisRestore(ctx, task, restoreInputs, interruptRestore); err == nil || !interrupted {
		t.Fatal("restore interruption was not exercised")
	}
	restoreOutputs, err := executor.redisRestore(ctx, task, restoreInputs, progress)
	if err != nil {
		t.Fatalf("target restore failed: %v", err)
	}
	if restoreOutputs["retry_reset_applied"] != true {
		t.Fatalf("retry did not reset the partially restored owned target: %+v", restoreOutputs)
	}
	if _, err := executor.redisVerify(ctx, task, restoreInputs); err != nil {
		t.Fatalf("target verification failed: %v", err)
	}
	targetZero, err := target.client(0)
	if err != nil {
		t.Fatal(err)
	}
	binaryValue, err := targetZero.Get(ctx, string([]byte{0, 'b', 'i', 'n'})).Bytes()
	if err != nil || string(binaryValue) != string([]byte{0, 1, 2, 255}) {
		t.Fatalf("binary key/value did not survive: value=%v err=%v", binaryValue, err)
	}
	if ttl, ttlErr := targetZero.PTTL(ctx, "expiring").Result(); ttlErr != nil || ttl <= 0 || ttl > 90*time.Second {
		t.Fatalf("absolute expiration did not survive: ttl=%v err=%v", ttl, ttlErr)
	}
	_ = targetZero.Close()

	for _, binding := range []redisBinding{source, target} {
		for _, database := range binding.DatabaseIndexes {
			client, clientErr := binding.client(database)
			if clientErr != nil {
				t.Fatal(clientErr)
			}
			if flushErr := client.FlushDB(ctx).Err(); flushErr != nil {
				_ = client.Close()
				t.Fatal(flushErr)
			}
			_ = client.Close()
		}
	}
	cacheSource := parseBinding(cacheSourceID)
	cacheTarget := parseBinding(cacheTargetID)
	defer cacheSource.clear()
	defer cacheTarget.clear()
	cacheZero, _ := cacheSource.client(0)
	if err := cacheZero.Set(ctx, "session:a", "discard-me", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	_ = cacheZero.Close()
	cacheTwo, _ := cacheSource.client(2)
	if err := cacheTwo.Set(ctx, "session:b", "discard-me-too", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	_ = cacheTwo.Close()
	cacheTask := TaskEnvelope{MigrationID: "77777777-7777-4777-8777-777777777777", AttemptID: "78888888-8888-4888-8888-888888888888"}
	cacheTargetInputs := inputs(cacheTargetID, "cache")
	cacheTargetInputs["require_empty_target"] = true
	cacheTargetOutputs, err := executor.redisInspect(ctx, cacheTask, cacheTargetInputs)
	if err != nil {
		t.Fatal(err)
	}
	cacheDumpInputs := inputs(cacheSourceID, "cache")
	cacheDumpInputs["staging_root_handle"] = "source_staging"
	cacheDumpOutputs, err := executor.redisDump(ctx, cacheTask, cacheDumpInputs, progress)
	if err != nil {
		t.Fatalf("cache snapshot failed: %v", err)
	}
	if cacheDumpOutputs["excluded_cache_key_count"] != int64(2) || cacheDumpOutputs["key_count"] != int64(0) {
		t.Fatalf("cache exclusion evidence is wrong: %+v", cacheDumpOutputs)
	}
	cacheRelative := mustStringOutput(t, cacheDumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, cacheRelative), filepath.Join(targetStaging, cacheRelative))
	cacheResetInputs := inputs(cacheTargetID, "cache")
	cacheResetInputs["expected_empty_target_digest"] = mustStringOutput(t, cacheTargetOutputs, "empty_target_digest")
	if _, err := executor.redisReset(ctx, cacheTask, cacheResetInputs); err != nil {
		t.Fatal(err)
	}
	cacheRestoreInputs := inputs(cacheTargetID, "cache")
	cacheRestoreInputs["staging_root_handle"] = "target_staging"
	cacheRestoreInputs["dump_staging_relative_handle"] = cacheRelative
	cacheRestoreInputs["dump_artifact_handle"] = mustStringOutput(t, cacheDumpOutputs, "dump_artifact_handle")
	cacheRestoreInputs["dump_artifact_digest"] = mustStringOutput(t, cacheDumpOutputs, "dump_artifact_digest")
	cacheRestoreInputs["expected_manifest_digest"] = mustStringOutput(t, cacheDumpOutputs, "database_manifest_digest")
	if _, err := executor.redisRestore(ctx, cacheTask, cacheRestoreInputs, progress); err != nil {
		t.Fatalf("cache recreate failed: %v", err)
	}
	if _, err := executor.redisVerify(ctx, cacheTask, cacheRestoreInputs); err != nil {
		t.Fatalf("cache verification failed: %v", err)
	}
	for _, database := range cacheTarget.DatabaseIndexes {
		client, clientErr := cacheTarget.client(database)
		if clientErr != nil {
			t.Fatal(clientErr)
		}
		count, sizeErr := client.DBSize(ctx).Result()
		_ = client.Close()
		if sizeErr != nil || count != 0 {
			t.Fatalf("cache target was not recreated empty: db=%d count=%d err=%v", database, count, sizeErr)
		}
	}
}
