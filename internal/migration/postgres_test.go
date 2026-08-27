package migration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func postgresBindingJSON(overrides map[string]any) []byte {
	value := map[string]any{
		"schema_version":       postgresBindingSchema,
		"mode":                 "source",
		"host":                 "127.0.0.1",
		"port":                 5432,
		"database":             "fixture",
		"maintenance_database": "postgres",
		"username":             "fixture_owner",
		"password":             "bounded-test-value",
		"ssl_mode":             "disable",
		"role_map":             map[string]string{"fixture_owner": "askio_mig_owner"},
	}
	for key, entry := range overrides {
		value[key] = entry
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func TestPostgresBindingAcceptsLoopbackSourceAndConstrainedTarget(t *testing.T) {
	source, err := parsePostgresBinding(postgresBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	source.clear()
	target, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"mode": "target", "database": "askio_mig_fixture", "target_role": "askio_mig_owner", "reset_allowed": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	target.clear()
}

func TestPostgresBindingRejectsUnsafeResetAndUnencryptedRemoteHost(t *testing.T) {
	if _, err := parsePostgresBinding(postgresBindingJSON(map[string]any{"host": "db.example.test"})); err == nil {
		t.Fatal("expected remote ssl_mode=disable binding to be rejected")
	}
	if _, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"mode": "target", "database": "customer_production", "target_role": "missing_from_map", "reset_allowed": true,
	})); err == nil {
		t.Fatal("expected undeclared target role to be rejected")
	}
}

func TestPostgresBindingRejectsUnknownFieldsAndControlCharacters(t *testing.T) {
	if _, err := parsePostgresBinding(postgresBindingJSON(map[string]any{"command": "drop database fixture"})); err == nil {
		t.Fatal("expected unknown command field to be rejected")
	}
	if _, err := parsePostgresBinding(postgresBindingJSON(map[string]any{"password": "bad\nvalue"})); err == nil {
		t.Fatal("expected newline in credential to be rejected")
	}
}

func TestPostgresIdentifiersAreAlwaysQuoted(t *testing.T) {
	quoted := quotePostgresIdentifier(`name"with"quotes`)
	if quoted != `"name""with""quotes"` {
		t.Fatalf("unexpected quoted identifier: %s", quoted)
	}
	literal := quotePostgresLiteral(`value'with'quotes`)
	if literal != `'value''with''quotes'` {
		t.Fatalf("unexpected quoted literal: %s", literal)
	}
	if strings.Contains(quoted, ";") || strings.Contains(literal, ";") {
		t.Fatal("quote helpers unexpectedly emitted a statement separator")
	}
}

func TestPostgresACLArtifactIsDigestBoundAndCanonical(t *testing.T) {
	directory := t.TempDir()
	privilege := postgresPrivilegeManifest{ObjectType: "TABLE", Schema: "public", Name: "widgets", Grantee: "askio_mig_owner", Privilege: "SELECT"}
	inspection := postgresInspection{
		RoleMapDigest: "sha256:" + strings.Repeat("a", 64),
		Manifest:      postgresManifest{Privileges: []postgresPrivilegeManifest{privilege}},
	}
	digest, size, err := writePostgresACLArtifact(directory, inspection)
	if err != nil {
		t.Fatal(err)
	}
	if size < 1 || !fileDigestPattern.MatchString(digest) {
		t.Fatalf("unexpected ACL artifact identity: %s %d", digest, size)
	}
	artifact, err := readPostgresACLArtifact(filepath.Join(directory, postgresACLArtifactHandle), digest, inspection.RoleMapDigest, "askio_mig_owner")
	if err != nil || len(artifact.Privileges) != 1 {
		t.Fatalf("ACL artifact did not round trip: %+v %v", artifact, err)
	}

	duplicate := postgresACLArtifact{SchemaVersion: postgresACLArtifactSchema, RoleMapDigest: inspection.RoleMapDigest, Privileges: []postgresPrivilegeManifest{privilege, privilege}}
	data, _ := json.Marshal(duplicate)
	duplicatePath := filepath.Join(t.TempDir(), postgresACLArtifactHandle)
	if err := os.WriteFile(duplicatePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	duplicateDigest, _, err := fileSHA256(duplicatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readPostgresACLArtifact(duplicatePath, duplicateDigest, inspection.RoleMapDigest, "askio_mig_owner"); err == nil {
		t.Fatal("expected duplicate non-canonical ACL entries to be rejected")
	}
}

func TestPostgresACLNormalizesDatabaseOwnerButRejectsBuiltInGrantRoles(t *testing.T) {
	binding, err := parsePostgresBinding(postgresBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizePostgresACLGrantee("pg_database_owner", binding, "askio_mig_owner")
	if err != nil || normalized != "askio_mig_owner" {
		t.Fatalf("unexpected database owner normalization: %s %v", normalized, err)
	}
	if _, err := normalizePostgresACLGrantee("pg_read_all_data", binding, "askio_mig_owner"); err == nil {
		t.Fatal("expected cluster-wide built-in grant role to be rejected")
	}
}

func TestPostgresPrivilegeAllowlistCoversSupportedServerMajors(t *testing.T) {
	if !validPostgresPrivilege("TABLE", "MAINTAIN") {
		t.Fatal("PostgreSQL 15+ MAINTAIN must survive typed ACL migration")
	}
	if validPostgresPrivilege("TABLE", "CONNECT") || validPostgresPrivilege("DATABASE", "CONNECT") {
		t.Fatal("privileges outside the offline object allowlist must remain rejected")
	}
}

func TestPostgresContentManifestDigestIsPortableAcrossSupportedMajors(t *testing.T) {
	base := postgresManifest{
		SchemaVersion: "operations.migration.postgres-manifest.v1",
		ServerMajor:   14,
		Encoding:      "UTF8",
		Collation:     "C.UTF-8",
		CType:         "C.UTF-8",
		Extensions:    []string{"plpgsql@1.0"},
		Tables: []postgresTableManifest{{
			Schema: "public", Name: "widgets", Kind: "r", RowCount: 3,
			SampleChecksum: strings.Repeat("a", 32),
		}},
		Sequences:          []postgresSequenceManifest{},
		ObjectCounts:       map[string]int64{"constraints": 1, "functions": 0, "indexes": 1, "schemas": 0, "triggers": 0},
		NormalizedOwners:   []string{"askio_mig_owner"},
		NormalizedGrantees: []string{"PUBLIC", "askio_mig_owner"},
		Privileges: []postgresPrivilegeManifest{
			{ObjectType: "SCHEMA", Schema: "public", Grantee: "PUBLIC", Privilege: "USAGE"},
			{ObjectType: "TABLE", Schema: "public", Name: "widgets", Grantee: "askio_mig_owner", Privilege: "SELECT"},
		},
	}
	target := base
	target.ServerMajor = 16
	target.Privileges = append(append([]postgresPrivilegeManifest{}, base.Privileges...),
		postgresPrivilegeManifest{ObjectType: "TABLE", Schema: "public", Name: "widgets", Grantee: "askio_mig_owner", Privilege: "MAINTAIN"})
	sourceDigest, err := postgresContentManifestDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	targetDigest, err := postgresContentManifestDigest(target)
	if err != nil {
		t.Fatal(err)
	}
	if sourceDigest != targetDigest {
		t.Fatalf("portable PostgreSQL content changed across supported majors: source=%s target=%s", sourceDigest, targetDigest)
	}
}

func TestPostgresContentManifestDigestStillBindsDataAndGrantOptions(t *testing.T) {
	base := postgresManifest{
		SchemaVersion:      "operations.migration.postgres-manifest.v1",
		ServerMajor:        14,
		Encoding:           "UTF8",
		Collation:          "C.UTF-8",
		CType:              "C.UTF-8",
		Extensions:         []string{},
		Tables:             []postgresTableManifest{{Schema: "public", Name: "widgets", Kind: "r", RowCount: 1, SampleChecksum: strings.Repeat("a", 32)}},
		Sequences:          []postgresSequenceManifest{},
		ObjectCounts:       map[string]int64{},
		NormalizedOwners:   []string{"askio_mig_owner"},
		NormalizedGrantees: []string{"askio_mig_owner"},
		Privileges:         []postgresPrivilegeManifest{},
	}
	baseDigest, err := postgresContentManifestDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	changedData := base
	changedData.Tables = append([]postgresTableManifest{}, base.Tables...)
	changedData.Tables[0].SampleChecksum = strings.Repeat("b", 32)
	changedDataDigest, err := postgresContentManifestDigest(changedData)
	if err != nil {
		t.Fatal(err)
	}
	if changedDataDigest == baseDigest {
		t.Fatal("portable PostgreSQL content digest did not bind table data")
	}
	changedGrant := base
	changedGrant.Privileges = []postgresPrivilegeManifest{{
		ObjectType: "TABLE", Schema: "public", Name: "widgets", Grantee: "askio_mig_owner", Privilege: "SELECT", Grantable: true,
	}}
	changedGrantDigest, err := postgresContentManifestDigest(changedGrant)
	if err != nil {
		t.Fatal(err)
	}
	if changedGrantDigest == baseDigest {
		t.Fatal("portable PostgreSQL content digest did not bind explicit grant options")
	}
}

func TestRequiredPostgresExtensionsMustBeBoundedCanonicalAndVersioned(t *testing.T) {
	values, err := requiredPostgresExtensionsInput(map[string]any{
		"required_extensions": []any{"pgcrypto@1.3", "plpgsql@1.0"},
	})
	if err != nil || len(values) != 2 {
		t.Fatalf("expected canonical extensions, got %#v: %v", values, err)
	}
	for _, invalid := range []any{
		[]any{},
		[]any{"plpgsql@1.0", "pgcrypto@1.3"},
		[]any{"pgcrypto"},
		[]any{"pgcrypto@1.3", "pgcrypto@1.3"},
	} {
		if _, err := requiredPostgresExtensionsInput(map[string]any{"required_extensions": invalid}); err == nil {
			t.Fatalf("expected invalid extension set to be rejected: %#v", invalid)
		}
	}
}

func TestPostgresDatabaseSetBindingAcceptsOneToEightOrderedMembers(t *testing.T) {
	binding, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"schema_version": postgresBindingSchemaV2,
		"database":       nil,
		"databases":      []string{"accounts", "analytics", "jobs"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(binding.Databases) != 3 || binding.Database != "accounts" || postgresDatabaseScopes(binding)[2].Database != "jobs" {
		t.Fatalf("database-set order was not retained: %#v", binding.Databases)
	}
	binding.clear()

	target, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"schema_version": postgresBindingSchemaV2,
		"database":       nil,
		"databases":      []string{"askio_mig_accounts", "askio_mig_analytics"},
		"mode":           "target", "target_role": "askio_mig_owner", "reset_allowed": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	target.clear()
}

func TestPostgresDatabaseSetBindingRejectsDuplicatesSystemsAndUnsafeTargets(t *testing.T) {
	for _, databases := range [][]string{
		{"accounts", "accounts"},
		{"accounts", "postgres"},
		{"accounts", "template1"},
	} {
		if _, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
			"schema_version": postgresBindingSchemaV2, "database": nil, "databases": databases,
		})); err == nil {
			t.Fatalf("expected invalid source database set to be rejected: %#v", databases)
		}
	}
	if _, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"schema_version": postgresBindingSchemaV2, "database": nil,
		"databases": []string{"customer_production", "askio_mig_analytics"},
		"mode":      "target", "target_role": "askio_mig_owner", "reset_allowed": true,
	})); err == nil {
		t.Fatal("expected every target database to require the migration namespace")
	}
}

func TestPostgresDatabaseSetRequiresMatchingOrderedContract(t *testing.T) {
	binding, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"schema_version": postgresBindingSchemaV2, "database": nil,
		"databases": []string{"accounts", "analytics"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	contract := map[string]any{
		"schema_version": "operations.migration.database-contract.v1",
		"source_engine":  "postgresql", "target_engine": "postgresql",
		"database_mappings": []map[string]string{
			{"source_database": "accounts", "target_database": "askio_mig_accounts"},
			{"source_database": "analytics", "target_database": "askio_mig_analytics"},
		},
		"role_map": map[string]string{"fixture_owner": "askio_mig_owner"},
	}
	if err := validatePostgresDatabaseContract(map[string]any{"database_contract": contract}, binding); err != nil {
		t.Fatal(err)
	}
	if err := validatePostgresDatabaseContract(map[string]any{}, binding); err == nil {
		t.Fatal("expected a database-set binding without a reviewed contract to be rejected")
	}
	contract["database_mappings"] = []map[string]string{
		{"source_database": "analytics", "target_database": "askio_mig_analytics"},
		{"source_database": "accounts", "target_database": "askio_mig_accounts"},
	}
	if err := validatePostgresDatabaseContract(map[string]any{"database_contract": contract}, binding); err == nil {
		t.Fatal("expected reordered database mappings to be rejected")
	}
}

func TestPostgresDatabaseBundleIsDigestBoundAndOrdered(t *testing.T) {
	directory := t.TempDir()
	binding, err := parsePostgresBinding(postgresBindingJSON(map[string]any{
		"schema_version": postgresBindingSchemaV2, "database": nil,
		"databases": []string{"askio_mig_accounts", "askio_mig_jobs"},
		"mode":      "target", "target_role": "askio_mig_owner", "reset_allowed": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	bundle := postgresDatabaseBundle{
		SchemaVersion: "operations.migration.postgres-database-bundle.v1", AggregateManifestDigest: digestA,
		Members: []postgresDatabaseBundleMember{
			{Ordinal: 0, SourceDatabase: "accounts", DumpArtifactHandle: "database-1.dump", DumpArtifactDigest: digestA, DumpSizeBytes: 10, ACLArtifactHandle: "database-1.acl.json", ACLArtifactDigest: digestB, ACLSizeBytes: 5, ManifestDigest: digestA, RoleMapDigest: MustDigest(binding.RoleMap)},
			{Ordinal: 1, SourceDatabase: "jobs", DumpArtifactHandle: "database-2.dump", DumpArtifactDigest: digestB, DumpSizeBytes: 12, ACLArtifactHandle: "database-2.acl.json", ACLArtifactDigest: digestA, ACLSizeBytes: 6, ManifestDigest: digestB, RoleMapDigest: MustDigest(binding.RoleMap)},
		},
	}
	digest, _, err := writePostgresDatabaseBundle(directory, bundle)
	if err != nil {
		t.Fatal(err)
	}
	read, err := readPostgresDatabaseBundle(filepath.Join(directory, postgresDatabaseBundleHandle), digest, binding)
	if err != nil || len(read.Members) != 2 {
		t.Fatalf("database bundle did not round trip: %#v %v", read, err)
	}
	read.Members[1].Ordinal = 0
	data, _ := json.Marshal(read)
	badPath := filepath.Join(t.TempDir(), postgresDatabaseBundleHandle)
	if err := os.WriteFile(badPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	badDigest, _, _ := fileSHA256(badPath)
	if _, err := readPostgresDatabaseBundle(badPath, badDigest, binding); err == nil {
		t.Fatal("expected reordered database bundle to be rejected")
	}
}
