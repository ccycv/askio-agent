package migration

import (
	"encoding/json"
	"testing"
)

func redisBindingJSON(overrides map[string]any) []byte {
	value := map[string]any{
		"schema_version":   redisBindingSchema,
		"engine":           "redis",
		"mode":             "source",
		"host":             "127.0.0.1",
		"port":             6379,
		"username":         "default",
		"password":         "bounded-test-value",
		"tls_mode":         "disable",
		"state_mode":       "durable",
		"database_indexes": []int{0, 2},
		"acl_map":          []map[string]string{{"source": "default", "target": "default"}},
	}
	for key, entry := range overrides {
		value[key] = entry
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func TestRedisBindingAcceptsBoundedRedisAndValkeyContracts(t *testing.T) {
	for _, engine := range []string{"redis", "valkey"} {
		for _, stateMode := range []string{"cache", "durable"} {
			binding, err := parseRedisBinding(redisBindingJSON(map[string]any{"engine": engine, "state_mode": stateMode}))
			if err != nil {
				t.Fatalf("%s %s source binding: %v", engine, stateMode, err)
			}
			binding.clear()
		}
		target, err := parseRedisBinding(redisBindingJSON(map[string]any{"engine": engine, "mode": "target", "reset_allowed": true}))
		if err != nil {
			t.Fatalf("%s target binding: %v", engine, err)
		}
		target.clear()
	}
}

func TestRedisBindingRejectsRemotePlaintextUnknownScopeAndInvalidACL(t *testing.T) {
	tests := map[string]map[string]any{
		"remote plaintext": {"host": "cache.example.test"},
		"unknown field":    {"command": "FLUSHALL"},
		"source reset":     {"reset_allowed": true},
		"duplicate db":     {"database_indexes": []int{0, 0}},
		"too many dbs":     {"database_indexes": []int{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		"duplicate target": {"acl_map": []map[string]string{{"source": "default", "target": "app"}, {"source": "reader", "target": "app"}}},
		"unsorted source":  {"acl_map": []map[string]string{{"source": "reader", "target": "reader"}, {"source": "default", "target": "default"}}},
		"cross engine":     {"engine": "keydb"},
		"tls require":      {"tls_mode": "require"},
	}
	for name, overrides := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseRedisBinding(redisBindingJSON(overrides)); err == nil {
				t.Fatal("expected binding to be rejected")
			}
		})
	}
}

func TestRedisDurableCoreTypesExcludeModuleBackedValues(t *testing.T) {
	for _, valueType := range []string{"string", "list", "set", "zset", "hash", "stream"} {
		if !supportedRedisCoreType(valueType) {
			t.Fatalf("core type %s was rejected", valueType)
		}
	}
	for _, valueType := range []string{"none", "ReJSON-RL", "vectorset", "timeseries", ""} {
		if supportedRedisCoreType(valueType) {
			t.Fatalf("module-backed or unknown type %s was accepted", valueType)
		}
	}
}

func TestCanonicalRedisKeysSortsBinaryTextAndRemovesScanDuplicates(t *testing.T) {
	keys := canonicalRedisKeys([]string{"z", "\x00binary", "a", "z", "a"})
	if len(keys) != 3 || keys[0] != "\x00binary" || keys[1] != "a" || keys[2] != "z" {
		t.Fatalf("unexpected canonical key order: %#v", keys)
	}
}

func TestRedisDatabaseContractRequiresExactEngineStateDatabasesAndACL(t *testing.T) {
	binding, err := parseRedisBinding(redisBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.clear()
	valid := map[string]any{
		"schema_version": redisDatabaseContractSchema,
		"source_engine":  "redis", "target_engine": "redis", "state_mode": "durable",
		"database_indexes": []int{0, 2},
		"acl_map":          []map[string]string{{"source": "default", "target": "default"}},
	}
	if err := validateRedisDatabaseContract(map[string]any{"database_contract": valid}, binding); err != nil {
		t.Fatalf("valid database contract: %v", err)
	}
	for name, value := range map[string]any{
		"cross engine": map[string]any{
			"schema_version": redisDatabaseContractSchema, "source_engine": "redis", "target_engine": "valkey",
			"state_mode": "durable", "database_indexes": []int{0, 2},
			"acl_map": []map[string]string{{"source": "default", "target": "default"}},
		},
		"state drift": map[string]any{
			"schema_version": redisDatabaseContractSchema, "source_engine": "redis", "target_engine": "redis",
			"state_mode": "cache", "database_indexes": []int{0, 2},
			"acl_map": []map[string]string{{"source": "default", "target": "default"}},
		},
		"database drift": map[string]any{
			"schema_version": redisDatabaseContractSchema, "source_engine": "redis", "target_engine": "redis",
			"state_mode": "durable", "database_indexes": []int{0},
			"acl_map": []map[string]string{{"source": "default", "target": "default"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRedisDatabaseContract(map[string]any{"database_contract": value}, binding); err == nil {
				t.Fatal("expected mismatched contract to be rejected")
			}
		})
	}
}

func TestRedisCacheManifestExcludesKeyPayload(t *testing.T) {
	binding, err := parseRedisBinding(redisBindingJSON(map[string]any{"state_mode": "cache"}))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.clear()
	facts := redisServerFacts{Engine: "redis", VersionSeries: "7.4", PersistenceMode: "rdb"}
	first, err := redisManifestDigest(facts, binding, "sha256:acl", redisScanSummary{KeyCount: 2})
	if err != nil {
		t.Fatal(err)
	}
	second, err := redisManifestDigest(facts, binding, "sha256:acl", redisScanSummary{KeyCount: 200, DatabaseBytes: 8_000})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("cache manifest was coupled to intentionally excluded key payload")
	}
}

func TestRedisDurableManifestBindsVolatileKeyPayload(t *testing.T) {
	binding, err := parseRedisBinding(redisBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.clear()
	facts := redisServerFacts{Engine: "redis", VersionSeries: "7.4", PersistenceMode: "rdb"}
	first, err := redisManifestDigest(facts, binding, "sha256:acl", redisScanSummary{KeyCount: 1, VolatileKeyCount: 1, AllRecordDigest: "sha256:first"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := redisManifestDigest(facts, binding, "sha256:acl", redisScanSummary{KeyCount: 1, VolatileKeyCount: 1, AllRecordDigest: "sha256:second"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("durable manifest did not bind the volatile key payload")
	}
}

func TestRedisArchiveCapacityIncludesFramingAndExcludesCachePayload(t *testing.T) {
	durable, err := parseRedisBinding(redisBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer durable.clear()
	required, err := redisArchiveCapacityBytes(durable, redisInspection{KeyCount: 3, DatabaseBytes: 1_024})
	if err != nil {
		t.Fatal(err)
	}
	expected := int64(len(redisArchiveMagic)+5+maximumRedisTrailerBytes) + 1_024 + 3*23
	if required != expected {
		t.Fatalf("archive capacity omitted bounded framing: got %d want %d", required, expected)
	}

	cache, err := parseRedisBinding(redisBindingJSON(map[string]any{"state_mode": "cache"}))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.clear()
	cacheRequired, err := redisArchiveCapacityBytes(cache, redisInspection{KeyCount: maximumRedisKeys, DatabaseBytes: maximumRedisBytes})
	if err != nil {
		t.Fatal(err)
	}
	if cacheRequired != int64(len(redisArchiveMagic)+5+maximumRedisTrailerBytes) {
		t.Fatalf("cache archive reserved excluded payload: %d", cacheRequired)
	}

	if _, err := redisArchiveCapacityBytes(durable, redisInspection{KeyCount: maximumRedisKeys + 1}); err == nil {
		t.Fatal("archive capacity accepted an oversized key count")
	}
}

func TestRedisACLSanitizerRemovesCredentialMaterial(t *testing.T) {
	tokens, err := sanitizeRedisACLRule("user app on #012345 >plaintext ~app:* +@read +@write", "app")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(tokens)
	if string(encoded) != `["on","~app:*","+@read","+@write"]` {
		t.Fatalf("unexpected sanitized ACL policy: %s", encoded)
	}
}
