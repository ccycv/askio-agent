package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func mongodbBindingJSON(overrides map[string]any) []byte {
	value := map[string]any{
		"schema_version": mongodbBindingSchema,
		"mode":           "source",
		"host":           "127.0.0.1",
		"port":           27017,
		"database":       "fixture",
		"auth_database":  "admin",
		"username":       "fixture_user",
		"password":       "bounded-test-value",
		"ssl_mode":       "disable",
	}
	for key, entry := range overrides {
		value[key] = entry
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func TestMongoDBBindingAcceptsConstrainedTarget(t *testing.T) {
	source, err := parseMongoDBBinding(mongodbBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	source.clear()
	target, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"mode": "target", "database": "askio_mig_fixture", "reset_allowed": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	target.clear()
}

func TestMongoDBBindingRejectsSystemDatabaseRemotePlaintextAndUnknownFields(t *testing.T) {
	if _, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{"database": "admin"})); err == nil {
		t.Fatal("expected MongoDB system database to be rejected")
	}
	if _, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{"host": "db.example.test"})); err == nil {
		t.Fatal("expected remote plaintext MongoDB binding to be rejected")
	}
	if _, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{"javascript": "db.dropDatabase()"})); err == nil {
		t.Fatal("expected unknown MongoDB binding field to be rejected")
	}
}

func TestMongoDBAdvancedBindingRequiresMatchingDatabaseContract(t *testing.T) {
	binding, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"schema_version":             mongodbBindingSchemaV2,
		"features":                   map[string]any{"users_and_roles": true, "views_and_system_collections": true},
		"user_map":                   []map[string]string{{"source": "application", "target": "askio_application"}},
		"role_map":                   []map[string]string{{"source": "applicationRole", "target": "askioApplicationRole"}},
		"allowed_system_collections": []string{"system.js"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	contract := map[string]any{
		"schema_version": "operations.migration.database-contract.v1",
		"source_engine":  "mongodb", "target_engine": "mongodb",
		"database_mappings":          []map[string]string{{"source_database": "fixture", "target_database": "askio_mig_fixture"}},
		"features":                   map[string]any{"users_and_roles": true, "views_and_system_collections": true, "oplog_replay": false, "queryable_encryption": false},
		"user_map":                   []map[string]string{{"source": "application", "target": "askio_application"}},
		"role_map":                   []map[string]string{{"source": "applicationRole", "target": "askioApplicationRole"}},
		"allowed_system_collections": []string{"system.js"},
	}
	if err := validateMongoDBDatabaseContract(map[string]any{"database_contract": contract}, binding); err != nil {
		t.Fatal(err)
	}
	if err := validateMongoDBDatabaseContract(map[string]any{}, binding); err == nil {
		t.Fatal("expected a v2 binding without a reviewed contract to be rejected")
	}
	contract["database_mappings"] = []map[string]string{{"source_database": "other", "target_database": "askio_mig_fixture"}}
	if err := validateMongoDBDatabaseContract(map[string]any{"database_contract": contract}, binding); err == nil {
		t.Fatal("expected a source binding/database contract mismatch to be rejected")
	}
}

func TestMongoDBURIEncodesCredentialsAndBindsAuthenticationDatabase(t *testing.T) {
	binding, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"username": "user@example.test", "password": "colon:slash/value?and#fragment",
	}))
	if err != nil {
		t.Fatal(err)
	}
	uri := mongodbURI(binding, "")
	binding.clear()
	if strings.Contains(uri, "colon:slash/value?and#fragment") || !strings.Contains(uri, "authSource=admin") || !strings.Contains(uri, "directConnection=true") {
		t.Fatalf("MongoDB URI did not safely encode and scope the credential: %q", uri)
	}
}

func TestMongoDBAdvancedBindingAcceptsBoundedMappingsAndKeyVault(t *testing.T) {
	binding, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"schema_version": mongodbBindingSchemaV2,
		"features": map[string]any{
			"users_and_roles": true, "views_and_system_collections": true,
			"oplog_replay": true, "queryable_encryption": true,
		},
		"user_map":                   []map[string]string{{"source": "application", "target": "askio_application"}},
		"role_map":                   []map[string]string{{"source": "applicationRole", "target": "askioApplicationRole"}},
		"allowed_system_collections": []string{"system.js"},
		"queryable_encryption_key_vault_collection": "keyVault",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Features.OplogReplay || binding.QueryableEncryptionKeyVaultCollection != "keyVault" {
		t.Fatalf("advanced controls were not retained: %#v", binding)
	}
	binding.clear()
}

func TestMongoDBAdvancedBindingRejectsUnsafeOrAmbiguousControls(t *testing.T) {
	cases := []map[string]any{
		{
			"features": map[string]any{"users_and_roles": true},
			"user_map": []map[string]string{{"source": "application", "target": "askio_application"}},
		},
		{
			"schema_version": mongodbBindingSchemaV2,
			"features":       map[string]any{"users_and_roles": true},
			"user_map":       []map[string]string{{"source": "b", "target": "same"}, {"source": "a", "target": "same"}},
		},
		{
			"schema_version":             mongodbBindingSchemaV2,
			"features":                   map[string]any{"views_and_system_collections": true},
			"allowed_system_collections": []string{"system.profile"},
		},
		{
			"schema_version": mongodbBindingSchemaV2,
			"features":       map[string]any{"queryable_encryption": true},
			"queryable_encryption_key_vault_collection": "system.keys",
		},
	}
	for _, overrides := range cases {
		if _, err := parseMongoDBBinding(mongodbBindingJSON(overrides)); err == nil {
			t.Fatalf("expected unsafe advanced binding to be rejected: %#v", overrides)
		}
	}
}

func TestMongoDBIdentityArtifactIsMappedAndSecretFree(t *testing.T) {
	binding, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"schema_version": mongodbBindingSchemaV2,
		"features":       map[string]any{"users_and_roles": true},
		"user_map":       []map[string]string{{"source": "application", "target": "askio_application"}},
		"role_map":       []map[string]string{{"source": "applicationRole", "target": "askioApplicationRole"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	observed := mongodbShellObservation{
		Users: []mongodbUserObservation{{User: "application", Roles: []mongodbRoleReference{{Role: "readWrite", DB: "fixture"}}}},
		Roles: []mongodbRoleObservation{{
			Role: "applicationRole", Roles: []mongodbRoleReference{{Role: "read", DB: "fixture"}},
			Privileges:                 []mongodbPrivilegeObservation{{Resource: map[string]any{"db": "fixture", "collection": "widgets"}, Actions: []string{"update", "find"}}},
			AuthenticationRestrictions: []any{},
		}},
	}
	manifest, err := normalizeMongoDBIdentities(observed, binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Users) != 1 || len(manifest.Users[0].Roles) != 1 || manifest.Users[0].Roles[0].DB != "application" || manifest.Roles[0].Role != "askioApplicationRole" {
		t.Fatalf("unexpected normalized identity manifest: %#v", manifest)
	}
	encoded, _ := json.Marshal(manifest)
	if strings.Contains(string(encoded), "fixture") {
		t.Fatalf("identity artifact leaked an unrelated role or source namespace: %s", encoded)
	}
	observed.Users[0].Roles = append(observed.Users[0].Roles, mongodbRoleReference{Role: "root", DB: "admin"})
	if _, err := normalizeMongoDBIdentities(observed, binding); err == nil {
		t.Fatal("expected a mapped user with a cross-database role to be rejected")
	}
}

func TestMongoDBOplogDeltaRejectsDuplicatesAndNamespaceEscapes(t *testing.T) {
	binding, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"schema_version": mongodbBindingSchemaV2,
		"features":       map[string]any{"oplog_replay": true},
	}))
	if err != nil {
		t.Fatal(err)
	}
	baseDigest := "sha256:" + strings.Repeat("a", 64)
	base := mongodbOplogDelta{
		SchemaVersion: "operations.migration.mongodb-oplog-delta.v1", Enabled: true,
		BaseArchiveDigest: baseDigest, SourceDatabase: "fixture",
		Mutations: []mongodbOplogMutation{{Collection: "widgets", ID: json.RawMessage(`{"$oid":"64b000000000000000000001"}`), Document: json.RawMessage(`{"_id":{"$oid":"64b000000000000000000001"},"name":"fixture"}`)}},
	}
	if err := validateMongoDBOplogDelta(base, binding, baseDigest, "fixture"); err != nil {
		t.Fatal(err)
	}
	duplicate := base
	duplicate.Mutations = append(append([]mongodbOplogMutation{}, base.Mutations...), base.Mutations[0])
	if err := validateMongoDBOplogDelta(duplicate, binding, baseDigest, "fixture"); err == nil {
		t.Fatal("expected duplicate oplog document identity to be rejected")
	}
	escape := base
	escape.Mutations = []mongodbOplogMutation{{Collection: "$cmd", ID: json.RawMessage(`1`), Document: json.RawMessage(`null`)}}
	if err := validateMongoDBOplogDelta(escape, binding, baseDigest, "fixture"); err == nil {
		t.Fatal("expected command namespace to be rejected")
	}
	mismatched := base
	mismatched.Mutations = []mongodbOplogMutation{{Collection: "widgets", ID: json.RawMessage(`1`), Document: json.RawMessage(`{"_id":2}`)}}
	if err := validateMongoDBOplogDelta(mismatched, binding, baseDigest, "fixture"); err == nil {
		t.Fatal("expected a replay document with a different _id to be rejected")
	}
}

func TestMongoDBOplogTimestampAcceptsStrictExtendedJSON(t *testing.T) {
	var timestamp mongodbOplogTimestamp
	if err := json.Unmarshal([]byte(`{"seconds":{"$numberLong":"1720000000"},"increment":{"$numberInt":"42"}}`), &timestamp); err != nil {
		t.Fatal(err)
	}
	if timestamp.Seconds != 1720000000 || timestamp.Increment != 42 {
		t.Fatalf("unexpected strict Extended JSON timestamp: %+v", timestamp)
	}
	if err := json.Unmarshal([]byte(`{"seconds":{"$numberDecimal":"1"},"increment":2}`), &timestamp); err == nil {
		t.Fatal("expected an unsupported Extended JSON integer to be rejected")
	}
}
