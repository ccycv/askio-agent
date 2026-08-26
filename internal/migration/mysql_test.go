package migration

import (
	"bytes"
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

func TestTransformMariaDBDumpForMySQL(t *testing.T) {
	binding, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{
		"schema_version": mysqlBindingSchemaV2,
		"engine":         "mariadb",
		"account_map": []map[string]string{{
			"source_user": "fixture_app", "source_host": "%", "target_user": "fixture_target", "target_host": "%",
		}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	input := strings.Join([]string{
		"/*!50003 SET sql_mode = 'STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION' */;",
		"CREATE TABLE `fixture`.`legacy` (`id` int) ENGINE=Aria PAGE_CHECKSUM=1 COLLATE=utf8mb4_unicode_ci;",
		"/*!50017 DEFINER=`fixture_app`@`%`*/ CREATE TRIGGER `fixture`.`audit` AFTER INSERT ON `legacy` FOR EACH ROW SET @value=1;",
		"CREATE DEFINER=`fixture_app`@`%` PROCEDURE `fixture`.`literal_guard`() SELECT 'DEFINER=`fixture_app`@`%`', 'COLLATE=utf8mb4_unicode_ci', '`fixture`.literal';",
		"INSERT INTO `fixture`.`legacy` VALUES (1);",
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := transformMySQLDump(strings.NewReader(input), &output, binding, "mariadb", "mysql", "utf8mb4_0900_ai_ci"); err != nil {
		t.Fatal(err)
	}
	actual := output.String()
	for _, excluded := range []string{"NO_AUTO_CREATE_USER", "ENGINE=Aria", "PAGE_CHECKSUM"} {
		if strings.Contains(actual, excluded) {
			t.Fatalf("transformed dump retained %q:\n%s", excluded, actual)
		}
	}
	for _, required := range []string{
		"STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION",
		"ENGINE=InnoDB",
		"COLLATE utf8mb4_0900_ai_ci",
		"DEFINER=`fixture_target`@`%`",
		"INSERT INTO `legacy` VALUES (1);",
		"SELECT 'DEFINER=`fixture_app`@`%`', 'COLLATE=utf8mb4_unicode_ci', '`fixture`.literal';",
	} {
		if !strings.Contains(actual, required) {
			t.Fatalf("transformed dump omitted %q:\n%s", required, actual)
		}
	}
	if strings.Count(actual, "DEFINER=`fixture_target`@`%`") != 2 {
		t.Fatalf("actual object definers were not mapped exactly twice:\n%s", actual)
	}
}

func TestMySQLBindingAccountMapIsOneToOneAndRejectsSystemTargets(t *testing.T) {
	valid := map[string]any{
		"schema_version": mysqlBindingSchemaV2,
		"account_map": []map[string]string{{
			"source_user": "application", "source_host": "%", "target_user": "application_target", "target_host": "%",
		}},
	}
	if _, err := parseMySQLBinding(mysqlBindingJSON(valid)); err != nil {
		t.Fatalf("valid account map was rejected: %v", err)
	}
	for name, accountMap := range map[string][]map[string]string{
		"duplicate source": {
			{"source_user": "application", "source_host": "%", "target_user": "target_a", "target_host": "%"},
			{"source_user": "application", "source_host": "%", "target_user": "target_b", "target_host": "%"},
		},
		"duplicate target": {
			{"source_user": "source_a", "source_host": "%", "target_user": "application_target", "target_host": "%"},
			{"source_user": "source_b", "source_host": "%", "target_user": "application_target", "target_host": "%"},
		},
		"root target": {
			{"source_user": "application", "source_host": "%", "target_user": "root", "target_host": "%"},
		},
		"system target": {
			{"source_user": "application", "source_host": "%", "target_user": "mysql.session", "target_host": "localhost"},
		},
		"invalid identifier": {
			{"source_user": "application' OR 1=1", "source_host": "%", "target_user": "application_target", "target_host": "%"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{
				"schema_version": mysqlBindingSchemaV2,
				"account_map":    accountMap,
			})); err == nil {
				t.Fatal("expected account map to be rejected")
			}
		})
	}
	if _, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{
		"account_map": valid["account_map"],
	})); err == nil {
		t.Fatal("expected account mapping on the v1 binding contract to be rejected")
	}
}

func TestTransformMySQLDumpRejectsUnmappedDefiner(t *testing.T) {
	binding, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{
		"schema_version": mysqlBindingSchemaV2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = transformMySQLDump(
		strings.NewReader("CREATE DEFINER=`unmapped`@`%` VIEW `fixture`.`unsafe_view` AS SELECT 1;\n"),
		&output,
		binding,
		"mysql",
		"mariadb",
		"utf8mb4_unicode_ci",
	)
	if err == nil || output.Len() != 0 {
		t.Fatalf("expected an unmapped definer to fail closed, output=%q err=%v", output.String(), err)
	}
}

func TestTransformMySQLDumpRejectsUnterminatedSQLSegments(t *testing.T) {
	binding, err := parseMySQLBinding(mysqlBindingJSON(map[string]any{
		"schema_version": mysqlBindingSchemaV2,
	}))
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"quote":   "INSERT INTO `fixture`.`widgets` VALUES ('unterminated);",
		"comment": "/* unterminated",
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := transformMySQLDump(strings.NewReader(input), &output, binding, "mysql", "mariadb", "utf8mb4_unicode_ci"); err == nil {
				t.Fatal("expected malformed SQL segment to be rejected")
			}
		})
	}
}

func TestMySQLGrantStatementsAreBoundedToSupportedScopes(t *testing.T) {
	tests := []struct {
		name     string
		grant    mysqlGrantManifest
		expected string
	}{
		{"database", mysqlGrantManifest{Scope: "database", Principal: "app@%", Privilege: "SELECT"}, "grant SELECT on `fixture`.* to 'app'@'%'"},
		{"table", mysqlGrantManifest{Scope: "table", Object: "widgets", Principal: "app@%", Privilege: "INSERT", Grantable: true}, "grant INSERT on `fixture`.`widgets` to 'app'@'%' with grant option"},
		{"column", mysqlGrantManifest{Scope: "column", Object: "widgets", Column: "name", Principal: "app@%", Privilege: "SELECT"}, "grant SELECT (`name`) on `fixture`.`widgets` to 'app'@'%'"},
		{"routine", mysqlGrantManifest{Scope: "routine", Object: "count_widgets", RoutineType: "PROCEDURE", Principal: "app@%", Privilege: "EXECUTE"}, "grant EXECUTE on PROCEDURE `fixture`.`count_widgets` to 'app'@'%'"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := mysqlGrantStatement(test.grant, "fixture", false)
			if err != nil || actual != test.expected {
				t.Fatalf("grant statement mismatch: actual=%q expected=%q err=%v", actual, test.expected, err)
			}
		})
	}
	optionRevoke, err := mysqlGrantOptionRevokeStatement(mysqlGrantManifest{
		Scope: "column", Object: "widgets", Column: "name", Principal: "app@%", Privilege: "SELECT", Grantable: true,
	}, "fixture")
	if err != nil || optionRevoke != "revoke grant option on `fixture`.`widgets` from 'app'@'%'" {
		t.Fatalf("grant-option revoke mismatch: statement=%q err=%v", optionRevoke, err)
	}
	for name, grant := range map[string]mysqlGrantManifest{
		"unknown scope":        {Scope: "global", Principal: "app@%", Privilege: "SELECT"},
		"invalid privilege":    {Scope: "database", Principal: "app@%", Privilege: "SELECT; DROP DATABASE fixture"},
		"invalid object":       {Scope: "table", Object: "widgets;drop", Principal: "app@%", Privilege: "SELECT"},
		"invalid routine kind": {Scope: "routine", Object: "count_widgets", RoutineType: "EVENT", Principal: "app@%", Privilege: "EXECUTE"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mysqlGrantStatement(grant, "fixture", false); err == nil {
				t.Fatal("expected unsupported grant statement to be rejected")
			}
		})
	}
}

func TestMySQLRowDigestIsOrderIndependentAndContentSensitive(t *testing.T) {
	digest := func(chunks ...string) (string, int64) {
		writer := &mysqlRowDigestWriter{}
		for _, chunk := range chunks {
			if _, err := writer.Write([]byte(chunk)); err != nil {
				t.Fatal(err)
			}
		}
		value, rows, err := writer.finish()
		if err != nil {
			t.Fatal(err)
		}
		return value, rows
	}
	first, firstRows := digest("alpha\nbravo\ncharlie\n")
	reordered, reorderedRows := digest("charlie\n", "alpha\nbravo\n")
	changed, changedRows := digest("alpha\nbravo\ndelta\n")
	if firstRows != 3 || reorderedRows != 3 || changedRows != 3 || first != reordered || first == changed {
		t.Fatalf("row multiset contract failed: first=%s reordered=%s changed=%s rows=%d/%d/%d", first, reordered, changed, firstRows, reorderedRows, changedRows)
	}
}

func TestMySQLCompatibilityAllowsOnlyTheBoundedCrossEnginePair(t *testing.T) {
	target := mysqlBinding{Mode: "target"}
	inspection := mysqlInspection{Engine: "mariadb", ServerSeries: "11.4", CharacterSet: "utf8mb4", Collation: "utf8mb4_unicode_ci", SQLMode: "STRICT_TRANS_TABLES"}
	if err := verifyMySQLCompatibility(target, map[string]any{
		"required_source_engine": "mysql", "required_source_series": "8.4",
		"required_character_set": "utf8mb4", "required_collation": "utf8mb4_0900_ai_ci",
		"required_sql_mode": "STRICT_TRANS_TABLES",
	}, inspection); err != nil {
		t.Fatalf("bounded MySQL to MariaDB conversion was rejected: %v", err)
	}
	if err := verifyMySQLCompatibility(target, map[string]any{
		"required_source_engine": "postgresql", "required_source_series": "16",
		"required_character_set": "utf8mb4", "required_collation": "utf8mb4_unicode_ci", "required_sql_mode": "",
	}, inspection); err == nil {
		t.Fatal("expected a non-MySQL-family source to be rejected")
	}
	sameEngine := map[string]any{
		"required_source_engine": "mariadb", "required_source_series": "10.11",
		"required_character_set": "utf8mb4", "required_collation": "utf8mb4_unicode_ci",
		"required_sql_mode": "STRICT_TRANS_TABLES",
	}
	if err := verifyMySQLCompatibility(target, sameEngine, inspection); err == nil {
		t.Fatal("expected a same-engine version-series mismatch to be rejected")
	}
}
