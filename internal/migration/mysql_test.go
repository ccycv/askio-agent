package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func mysqlBindingJSON(overrides map[string]any) []byte {
	value := map[string]any{
		"schema_version": mysqlBindingSchema,
		"engine":         "mysql",
		"mode":           "source",
		"host":           "127.0.0.1",
		"port":           3306,
		"database":       "fixture",
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

func TestMySQLBindingAcceptsEachEngineAndConstrainedTarget(t *testing.T) {
	for _, engine := range []string{"mysql", "mariadb"} {
		source, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{"engine": engine}))
		if err != nil {
			t.Fatalf("%s source binding: %v", engine, err)
		}
		source.clear()
		target, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{
			"engine": engine, "mode": "target", "database": "askio_mig_fixture", "reset_allowed": true,
			"target_character_set": "utf8mb4", "target_collation": "utf8mb4_unicode_ci",
		}))
		if err != nil {
			t.Fatalf("%s target binding: %v", engine, err)
		}
		target.clear()
	}
}

func TestMySQLBindingRejectsRemotePlaintextUnknownFieldsAndSourceReset(t *testing.T) {
	if _, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{"host": "db.example.test"})); err == nil {
		t.Fatal("expected remote plaintext MySQL binding to be rejected")
	}
	if _, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{"command": "drop database fixture"})); err == nil {
		t.Fatal("expected unknown MySQL binding field to be rejected")
	}
	if _, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{"reset_allowed": true})); err == nil {
		t.Fatal("expected source reset control to be rejected")
	}
}

func TestMySQLOptionFileEscapesCredentialsAndModesAreCanonical(t *testing.T) {
	escaped := mysqlOptionFileValue(`quote" and slash\ value`)
	if !strings.HasPrefix(escaped, `"`) || !strings.HasSuffix(escaped, `"`) || strings.Contains(escaped, ` and slash\ value"`) {
		t.Fatalf("unexpected option-file escaping %q", escaped)
	}
	if got := canonicalMySQLMode("STRICT_TRANS_TABLES, no_engine_substitution"); got != "NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES" {
		t.Fatalf("unexpected canonical sql_mode %q", got)
	}
}

func TestMySQLCreateDDLNormalizationTreatsInheritedCharacterSetAsEquivalent(t *testing.T) {
	source := "`name` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL"
	target := "`name` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL"
	if normalizeMySQLCreateDDL(source, "utf8mb4") != normalizeMySQLCreateDDL(target, "utf8mb4") {
		t.Fatal("equivalent inherited and explicit column character sets did not normalize")
	}
	if normalizeMySQLCreateDDL(target, "latin1") == source {
		t.Fatal("normalization erased a non-default character set")
	}
}
