package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func postgresLogicalContractFixture() postgresLogicalContract {
	return postgresLogicalContract{
		Mode: "lower-downtime", ReplicationRole: "askio_replicator",
		MaximumCatchupSeconds: 900, MaximumSlotWALBytes: 4 * 1024 * 1024 * 1024,
	}
}

func postgresLogicalBindingJSON(overrides map[string]any) []byte {
	value := map[string]any{
		"schema_version":            postgresLogicalBindingSchema,
		"host":                      "source.internal.test",
		"port":                      5432,
		"database":                  "fixture",
		"username":                  "askio_replicator",
		"password":                  "secret-for-test",
		"ssl_mode":                  "verify-full",
		"ssl_root_cert_pem":         "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
		"server_ssl_root_cert_path": "/var/lib/askio-migrations/certs/source-ca.crt",
	}
	for key, entry := range overrides {
		value[key] = entry
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func TestPostgresLogicalContractIsSingleDatabaseAndBounded(t *testing.T) {
	contract := postgresLogicalContractFixture()
	binding, err := parsePostgresBinding(postgresBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	mappings := []postgresDatabaseMapping{{SourceDatabase: "fixture", TargetDatabase: "askio_mig_fixture"}}
	if err := validatePostgresLogicalContract(&contract, binding, mappings); err != nil {
		t.Fatal(err)
	}
	contract.MaximumCatchupSeconds = 59
	if err := validatePostgresLogicalContract(&contract, binding, mappings); err == nil {
		t.Fatal("expected short unbounded catch-up window to be rejected")
	}
	contract = postgresLogicalContractFixture()
	binding.Databases = []string{"fixture", "other"}
	if err := validatePostgresLogicalContract(&contract, binding, mappings); err == nil {
		t.Fatal("expected multi-database logical contract to be rejected")
	}
}

func TestPostgresLogicalBooleanCatalogFormsAreAccepted(t *testing.T) {
	for _, fixture := range []struct {
		value string
		want  bool
	}{{"t", true}, {"true", true}, {"f", false}, {"false", false}} {
		got, err := postgresBool([][]string{{fixture.value}})
		if err != nil || got != fixture.want {
			t.Fatalf("postgresBool(%q) = %t, %v", fixture.value, got, err)
		}
	}
	if _, err := postgresBool([][]string{{"1"}}); err == nil {
		t.Fatal("expected a non-boolean catalog value to be rejected")
	}
}

func TestPostgresLogicalSourceBindingRequiresVerifiedTLSAndDedicatedRole(t *testing.T) {
	contract := postgresLogicalContractFixture()
	binding, err := parsePostgresLogicalSourceBinding(postgresLogicalBindingJSON(nil), contract)
	if err != nil {
		t.Fatal(err)
	}
	conninfo := postgresLogicalConninfo(binding)
	if !strings.Contains(conninfo, "sslmode=verify-full") || !strings.Contains(conninfo, "sslrootcert='/var/lib/askio-migrations/") {
		t.Fatalf("logical conninfo lost verified TLS: %s", conninfo)
	}
	binding.clear()
	if _, err := parsePostgresLogicalSourceBinding(postgresLogicalBindingJSON(map[string]any{"ssl_mode": "require"}), contract); err == nil {
		t.Fatal("expected unverified TLS to be rejected")
	}
	if _, err := parsePostgresLogicalSourceBinding(postgresLogicalBindingJSON(map[string]any{"username": "postgres"}), contract); err == nil {
		t.Fatal("expected undeclared replication role to be rejected")
	}
	if _, err := parsePostgresLogicalSourceBinding(postgresLogicalBindingJSON(map[string]any{"server_ssl_root_cert_path": "/tmp/source-ca.crt"}), contract); err == nil {
		t.Fatal("expected target-server CA path outside approved roots to be rejected")
	}
}

func TestPostgresLogicalNamesAreDeterministicAndNamespaced(t *testing.T) {
	namesA, err := postgresLogicalObjectNames("11111111-1111-4111-8111-111111111111", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	namesB, _ := postgresLogicalObjectNames("11111111-1111-4111-8111-111111111111", "fixture")
	if namesA != namesB || !strings.HasPrefix(namesA.Publication, "askio_pub_") ||
		!strings.HasPrefix(namesA.Slot, "askio_slot_") || !strings.HasPrefix(namesA.Subscription, "askio_sub_") {
		t.Fatalf("unexpected logical names: %+v", namesA)
	}
	if len(namesA.Publication) > 63 || len(namesA.Slot) > 63 || len(namesA.Subscription) > 63 {
		t.Fatal("logical object name exceeded PostgreSQL identifier limit")
	}
}

func TestPostgresLogicalSchemaNormalizationRemovesOnlyDynamicGuards(t *testing.T) {
	raw := []byte("-- PostgreSQL database dump\r\n-- Dumped from database version 17.2\r\n-- Dumped by pg_dump version 17.2\r\n\\restrict abc\r\nCREATE TABLE \"public\".\"widgets\" (\r\n  \"id\" bigint NOT NULL   \r\n);\r\n\\unrestrict abc\r\n")
	normalized, err := normalizePostgresLogicalSchema(raw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(normalized)
	if strings.Contains(text, "Dumped from") || strings.Contains(text, `\restrict`) || strings.Contains(text, "\r") {
		t.Fatalf("dynamic schema content survived normalization: %q", text)
	}
	if !strings.Contains(text, `CREATE TABLE "public"."widgets"`) || !strings.HasSuffix(text, "\n") {
		t.Fatalf("schema content was not preserved: %q", text)
	}
}

func TestPostgresLogicalFinalStateRejectsNonCanonicalSequences(t *testing.T) {
	task := TaskEnvelope{MigrationID: "11111111-1111-4111-8111-111111111111"}
	mapping := postgresDatabaseMapping{SourceDatabase: "fixture", TargetDatabase: "askio_mig_fixture"}
	names, _ := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	state := postgresLogicalFinalState{
		SchemaVersion: postgresLogicalFinalStateSchema, MigrationID: task.MigrationID,
		SourceDatabase: mapping.SourceDatabase, TargetDatabase: mapping.TargetDatabase, Names: names,
		SchemaDigest: "sha256:" + strings.Repeat("a", 64), ManifestDigest: "sha256:" + strings.Repeat("b", 64), FinalLSN: "0/16B6C50",
		Sequences: []postgresSequenceManifest{{Schema: "public", Name: "widgets_id_seq", Last: "12", IsCalled: true}},
	}
	if err := validatePostgresLogicalFinalState(state, task, mapping, names); err != nil {
		t.Fatal(err)
	}
	state.Sequences = append(state.Sequences, state.Sequences[0])
	if err := validatePostgresLogicalFinalState(state, task, mapping, names); err == nil {
		t.Fatal("expected duplicate sequence state to be rejected")
	}
}

func TestNativeExecutorSupportsPostgresLogicalPrimitiveSet(t *testing.T) {
	executor := &NativeExecutor{}
	for _, primitive := range []string{
		"migration.postgres.logical-preflight.v1", "migration.postgres.logical-schema-dump.v1",
		"migration.postgres.logical-restore-schema.v1", "migration.postgres.logical-prepare-source.v1",
		"migration.postgres.logical-start-subscription.v1", "migration.postgres.logical-finalize-source.v1",
		"migration.postgres.logical-finalize-target.v1", "migration.postgres.logical-cleanup-target.v1",
		"migration.postgres.logical-cleanup-source.v1",
	} {
		if !executor.Supports(PrimitiveRef{ID: primitive, Version: "1.0.0"}) {
			t.Fatalf("logical primitive is unsupported: %s", primitive)
		}
	}
}
