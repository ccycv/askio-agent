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

const mongodbDisposableIntegrationGate = "disposable-same-major-cycle"

func TestMongoDBOfflineMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_MONGODB_INTEGRATION") != mongodbDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_MONGODB_INTEGRATION=disposable-same-major-cycle inside the disposable fixture")
	}
	sourcePort, sourceErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MONGODB_SOURCE_PORT"))
	targetPort, targetErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MONGODB_TARGET_PORT"))
	password := os.Getenv("ASKIO_MIGRATION_MONGODB_PASSWORD")
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
		sourceBindingID = "71111111-1111-4111-8111-111111111111"
		targetBindingID = "72222222-2222-4222-8222-222222222222"
		sourceDatabase  = "askio_fixture_source"
		targetDatabase  = "askio_mig_fixture"
	)
	bindingJSON := func(mode string, port int, database string, reset bool) []byte {
		value := map[string]any{
			"schema_version": mongodbBindingSchema, "mode": mode,
			"host": "127.0.0.1", "port": port, "database": database, "auth_database": "admin",
			"username": "root", "password": password, "ssl_mode": "disable",
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
	source, err := parseMongoDBBinding(sourceJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer source.clear()
	target, err := parseMongoDBBinding(targetJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer target.clear()
	fixtureBody := `
const fixture = askioConnection.getDB("askio_fixture_source");
fixture.dropDatabase();
fixture.widgets.insertMany([
  {_id: 1, name: "alpha", tags: ["one", "two"], nested: {enabled: true}},
  {_id: 2, name: "bravo", tags: [], nested: {enabled: false}},
  {_id: 3, name: "unicode-șț", binary: BinData(0, "AAEC/w==")}
]);
fixture.events.insertMany([{widget_id: 1, event: "created"}, {widget_id: 2, event: "created"}, {widget_id: 3, event: "created"}]);
fixture.widgets.createIndex({name: 1}, {unique: true});
fixture.events.createIndex({widget_id: 1});
print("ASKIO_JSON:" + EJSON.stringify({ok: true}, {relaxed: true}));`
	var fixtureResult struct {
		OK bool `json:"ok"`
	}
	if err := executor.runMongoDBShell(ctx, source, fixtureBody, &fixtureResult); err != nil || !fixtureResult.OK {
		t.Fatalf("source fixture setup failed: %v", err)
	}
	clearTargetBody := "askioConnection.getDB(" + strconv.Quote(targetDatabase) + ").dropDatabase();\n" +
		"print('ASKIO_JSON:' + EJSON.stringify({ok: true}, {relaxed: true}));"
	if err := executor.runMongoDBShell(ctx, target, clearTargetBody, &fixtureResult); err != nil {
		t.Fatalf("target fixture setup failed: %v", err)
	}
	task := TaskEnvelope{MigrationID: "73333333-3333-4333-8333-333333333333", AttemptID: "74444444-4444-4444-8444-444444444444"}
	progress := func(string, int64, *int64) error { return nil }
	sourceOutputs, err := executor.mongodbInspect(ctx, task, map[string]any{"database_binding_id": sourceBindingID})
	if err != nil {
		t.Fatalf("source inspection failed: %v", err)
	}
	targetOutputs, err := executor.mongodbInspect(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "require_empty_target": true,
		"required_source_major":  sourceOutputs["server_major"],
		"required_source_fcv":    sourceOutputs["feature_compatibility_version"],
		"required_tools_version": sourceOutputs["tools_version"],
	})
	if err != nil {
		t.Fatalf("target compatibility inspection failed: %v", err)
	}
	dumpOutputs, err := executor.mongodbDump(ctx, task, map[string]any{
		"database_binding_id": sourceBindingID, "staging_root_handle": "source_staging",
	}, progress)
	if err != nil {
		t.Fatalf("source dump failed: %v", err)
	}
	stagingRelative := mustStringOutput(t, dumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, stagingRelative), filepath.Join(targetStaging, stagingRelative))
	if _, err := executor.mongodbReset(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_empty_target_digest": mustStringOutput(t, targetOutputs, "empty_target_digest"),
	}); err != nil {
		t.Fatalf("target reset failed: %v", err)
	}
	if _, err := executor.mongodbRestore(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "staging_root_handle": "target_staging",
		"dump_staging_relative_handle": stagingRelative,
		"dump_artifact_handle":         mustStringOutput(t, dumpOutputs, "dump_artifact_handle"),
		"dump_artifact_digest":         mustStringOutput(t, dumpOutputs, "dump_artifact_digest"),
		"identity_artifact_handle":     mustStringOutput(t, dumpOutputs, "identity_artifact_handle"),
		"identity_artifact_digest":     mustStringOutput(t, dumpOutputs, "identity_artifact_digest"),
		"oplog_artifact_handle":        mustStringOutput(t, dumpOutputs, "oplog_artifact_handle"),
		"oplog_artifact_digest":        mustStringOutput(t, dumpOutputs, "oplog_artifact_digest"),
		"source_database":              mustStringOutput(t, dumpOutputs, "source_database"),
		"expected_manifest_digest":     mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}, progress); err != nil {
		t.Fatalf("target restore failed: %v", err)
	}
	if _, err := executor.mongodbVerify(ctx, task, map[string]any{
		"database_binding_id": targetBindingID, "expected_manifest_digest": mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	}); err != nil {
		t.Fatalf("target verification failed: %v", err)
	}
	targetInspection, err := executor.inspectMongoDB(ctx, targetBindingID, target)
	if err != nil {
		t.Fatal(err)
	}
	if targetInspection.TotalDocuments != 6 || len(targetInspection.Manifest.Collections) != 2 {
		t.Fatalf("restored MongoDB fixture diverged: %+v", targetInspection)
	}
}

func TestMongoDBAdvancedMigrationCycle(t *testing.T) {
	if os.Getenv("ASKIO_MIGRATION_MONGODB_INTEGRATION") != mongodbDisposableIntegrationGate {
		t.Skip("set ASKIO_MIGRATION_MONGODB_INTEGRATION=disposable-same-major-cycle inside the disposable fixture")
	}
	sourcePort, sourceErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MONGODB_SOURCE_PORT"))
	targetPort, targetErr := strconv.Atoi(os.Getenv("ASKIO_MIGRATION_MONGODB_TARGET_PORT"))
	password := os.Getenv("ASKIO_MIGRATION_MONGODB_PASSWORD")
	if sourceErr != nil || targetErr != nil || sourcePort == targetPort || password == "" {
		t.Fatal("the disposable fixture requires distinct source and target ports plus a password")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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
		"source_staging": sourceStaging, "target_staging": targetStaging,
	}, filepath.Join(workspace, "unused-broker.sock"), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	executor.capacityCheck = func(string, int64) error { return nil }
	const (
		sourceBindingID = "81111111-1111-4111-8111-111111111111"
		targetBindingID = "82222222-2222-4222-8222-222222222222"
		sourceDatabase  = "askio_advanced_source"
		targetDatabase  = "askio_mig_advanced"
	)
	features := map[string]any{
		"users_and_roles": true, "views_and_system_collections": true,
		"oplog_replay": true, "queryable_encryption": true,
	}
	userMap := []map[string]string{{"source": "application", "target": "askio_application"}}
	roleMap := []map[string]string{{"source": "applicationRole", "target": "askioApplicationRole"}}
	bindingJSON := func(mode string, port int, database string, reset bool) []byte {
		value := map[string]any{
			"schema_version": mongodbBindingSchemaV2, "mode": mode,
			"host": "127.0.0.1", "port": port, "database": database, "auth_database": "admin",
			"username": "root", "password": password, "ssl_mode": "disable",
			"features": features, "user_map": userMap, "role_map": roleMap,
			"allowed_system_collections":                []string{"system.js"},
			"queryable_encryption_key_vault_collection": "keyVault",
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
	sourceJSON := bindingJSON("source", sourcePort, sourceDatabase, false)
	targetJSON := bindingJSON("target", targetPort, targetDatabase, true)
	executor.SetBindingResolver(func(_ context.Context, _ TaskEnvelope, bindingID string) ([]byte, error) {
		switch bindingID {
		case sourceBindingID:
			return append([]byte(nil), sourceJSON...), nil
		case targetBindingID:
			return append([]byte(nil), targetJSON...), nil
		default:
			return nil, errors.New("unexpected advanced MongoDB integration binding")
		}
	})
	source, err := parseMongoDBBinding(sourceJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer source.clear()
	target, err := parseMongoDBBinding(targetJSON)
	if err != nil {
		t.Fatal(err)
	}
	defer target.clear()
	fixtureBody := `
const fixture = askioConnection.getDB("askio_advanced_source");
const admin = askioConnection.getDB("admin");
fixture.dropDatabase();
try { admin.dropUser("application"); } catch (_) {}
fixture.createRole({role: "applicationRole", privileges: [{resource: {db: "askio_advanced_source", collection: "widgets"}, actions: ["find", "insert", "update"]}], roles: [{role: "read", db: "askio_advanced_source"}]});
admin.createUser({user: "application", pwd: "application-source-password", roles: [{role: "applicationRole", db: "askio_advanced_source"}]});
fixture.widgets.insertMany([
  {_id: 1, name: "alpha", active: true},
  {_id: 2, name: "bravo", active: false},
  {_id: 3, name: "charlie", active: true}
]);
fixture.createView("activeWidgets", "widgets", [{$match: {active: true}}]);
fixture.getCollection("system.js").insertOne({_id: "fixtureHelper", value: "function(value) { return value; }"});
const keyId = UUID("12345678-1234-4234-8234-123456789abc");
fixture.keyVault.insertOne({_id: keyId, keyMaterial: BinData(0, "AAECAwQFBgcICQoLDA0ODw=="), creationDate: new Date(), updateDate: new Date(), status: 1, masterKey: {provider: "local"}});
const encryptedResult = fixture.runCommand({create: "patients", encryptedFields: {
  escCollection: "enxcol_.patients.esc", ecocCollection: "enxcol_.patients.ecoc",
  fields: [{path: "ssn", bsonType: "string", keyId, queries: {queryType: "equality", contention: 0}}]
}});
if (encryptedResult.ok !== 1) throw new Error("encrypted collection fixture failed: " + EJSON.stringify(encryptedResult));
fixture.createCollection("enxcol_.patients.esc");
fixture.createCollection("enxcol_.patients.ecoc");
fixture.patients.insertOne({_id: 1, name: "ciphertext-preserved", note: "no server-side decryption is requested"});
print("ASKIO_JSON:" + EJSON.stringify({ok: true}, {relaxed: true}));`
	var fixtureResult struct {
		OK bool `json:"ok"`
	}
	if err := executor.runMongoDBShell(ctx, source, fixtureBody, &fixtureResult); err != nil || !fixtureResult.OK {
		t.Fatalf("advanced source fixture setup failed: %v", err)
	}
	targetFixtureBody := `
const fixture = askioConnection.getDB("askio_mig_advanced");
const admin = askioConnection.getDB("admin");
fixture.dropDatabase();
try { admin.dropUser("askio_application"); } catch (_) {}
admin.createUser({user: "askio_application", pwd: "application-target-password", roles: []});
print("ASKIO_JSON:" + EJSON.stringify({ok: true}, {relaxed: true}));`
	if err := executor.runMongoDBShell(ctx, target, targetFixtureBody, &fixtureResult); err != nil || !fixtureResult.OK {
		t.Fatalf("advanced target fixture setup failed: %v", err)
	}
	contract := map[string]any{
		"schema_version": "operations.migration.database-contract.v1",
		"source_engine":  "mongodb", "target_engine": "mongodb",
		"database_mappings": []map[string]string{{"source_database": sourceDatabase, "target_database": targetDatabase}},
		"features":          features, "user_map": userMap, "role_map": roleMap,
		"allowed_system_collections":                []string{"system.js"},
		"queryable_encryption_key_vault_collection": "keyVault",
	}
	task := TaskEnvelope{MigrationID: "83333333-3333-4333-8333-333333333333", AttemptID: "84444444-4444-4444-8444-444444444444"}
	progress := func(string, int64, *int64) error { return nil }
	sourceInputs := map[string]any{"database_binding_id": sourceBindingID, "database_contract": contract}
	targetInputs := map[string]any{"database_binding_id": targetBindingID, "database_contract": contract}
	sourceOutputs, err := executor.mongodbInspect(ctx, task, sourceInputs)
	if err != nil {
		var inventory map[string]any
		diagnosticBody := `
const fixture = askioConnection.getDB("askio_advanced_source");
print("ASKIO_JSON:" + EJSON.stringify({collections: fixture.getCollectionInfos({}).map(info => ({name: info.name, type: info.type, option_keys: Object.keys(info.options || {}).sort()}))}, {relaxed: true}));`
		diagnosticErr := executor.runMongoDBShell(ctx, source, diagnosticBody, &inventory)
		t.Fatalf("advanced source inspection failed: %v; inventory=%#v diagnostic=%v", err, inventory, diagnosticErr)
	}
	if sourceOutputs["user_count"] != 1 || sourceOutputs["custom_role_count"] != 1 || sourceOutputs["view_count"] != 1 || sourceOutputs["encrypted_state_collection_count"] != 2 {
		t.Fatalf("advanced source inventory is incomplete: %#v", sourceOutputs)
	}
	targetInspectInputs := clonePostgresIntegrationInputs(targetInputs)
	targetInspectInputs["require_empty_target"] = true
	targetInspectInputs["required_source_major"] = sourceOutputs["server_major"]
	targetInspectInputs["required_source_fcv"] = sourceOutputs["feature_compatibility_version"]
	targetInspectInputs["required_tools_version"] = sourceOutputs["tools_version"]
	targetOutputs, err := executor.mongodbInspect(ctx, task, targetInspectInputs)
	if err != nil || targetOutputs["empty"] != true {
		t.Fatalf("advanced target compatibility inspection failed: %#v %v", targetOutputs, err)
	}
	executor.oplogWindowHookForTest = func(hookContext context.Context, binding mongodbBinding) error {
		body := `
const fixture = askioConnection.getDB("askio_advanced_source");
fixture.widgets.updateOne({_id: 1}, {$set: {name: "alpha-after-window"}});
fixture.widgets.deleteOne({_id: 2});
fixture.widgets.insertOne({_id: 4, name: "delta", active: true});
print("ASKIO_JSON:" + EJSON.stringify({ok: true}, {relaxed: true}));`
		return executor.runMongoDBShell(hookContext, binding, body, &fixtureResult)
	}
	dumpInputs := clonePostgresIntegrationInputs(sourceInputs)
	dumpInputs["staging_root_handle"] = "source_staging"
	dumpOutputs, err := executor.mongodbDump(ctx, task, dumpInputs, progress)
	executor.oplogWindowHookForTest = nil
	if err != nil {
		var oplogInventory map[string]any
		diagnosticBody := `
const entries = askioConnection.getDB("local").getCollection("oplog.rs").find({ns: /^askio_advanced_source\./}).sort({$natural: -1}).limit(20).toArray().map(entry => ({op: entry.op, ns: entry.ns, has_o2: Boolean(entry.o2), command_keys: entry.op === "c" ? Object.keys(entry.o || {}).sort() : []}));
print("ASKIO_JSON:" + EJSON.stringify({entries}, {relaxed: true}));`
		diagnosticErr := executor.runMongoDBShell(ctx, source, diagnosticBody, &oplogInventory)
		t.Fatalf("advanced source dump failed: %v; oplog=%#v diagnostic=%v", err, oplogInventory, diagnosticErr)
	}
	if dumpOutputs["oplog_replay_enabled"] != true || dumpOutputs["oplog_mutation_count"] != 3 {
		t.Fatalf("bounded oplog delta was not captured: %#v", dumpOutputs)
	}
	stagingRelative := mustStringOutput(t, dumpOutputs, "dump_staging_relative_handle")
	copyPostgresIntegrationDirectory(t, filepath.Join(sourceStaging, stagingRelative), filepath.Join(targetStaging, stagingRelative))
	resetInputs := clonePostgresIntegrationInputs(targetInputs)
	resetInputs["expected_empty_target_digest"] = mustStringOutput(t, targetOutputs, "empty_target_digest")
	if _, err := executor.mongodbReset(ctx, task, resetInputs); err != nil {
		t.Fatalf("advanced target reset failed: %v", err)
	}
	restoreInputs := clonePostgresIntegrationInputs(targetInputs)
	for key, value := range map[string]any{
		"staging_root_handle": "target_staging", "dump_staging_relative_handle": stagingRelative,
		"dump_artifact_handle":     mustStringOutput(t, dumpOutputs, "dump_artifact_handle"),
		"dump_artifact_digest":     mustStringOutput(t, dumpOutputs, "dump_artifact_digest"),
		"identity_artifact_handle": mustStringOutput(t, dumpOutputs, "identity_artifact_handle"),
		"identity_artifact_digest": mustStringOutput(t, dumpOutputs, "identity_artifact_digest"),
		"oplog_artifact_handle":    mustStringOutput(t, dumpOutputs, "oplog_artifact_handle"),
		"oplog_artifact_digest":    mustStringOutput(t, dumpOutputs, "oplog_artifact_digest"),
		"source_database":          mustStringOutput(t, dumpOutputs, "source_database"),
		"expected_manifest_digest": mustStringOutput(t, dumpOutputs, "database_manifest_digest"),
	} {
		restoreInputs[key] = value
	}
	_, restoreErr := executor.mongodbRestore(ctx, task, restoreInputs, progress)
	if restoreErr != nil {
		sourceInspection, sourceInspectionErr := executor.inspectMongoDB(ctx, sourceBindingID, source)
		targetInspection, targetInspectionErr := executor.inspectMongoDB(ctx, targetBindingID, target)
		var sourceDocuments map[string]any
		var targetDocuments map[string]any
		documentsBody := func(database string) string {
			return `const documents=askioConnection.getDB(` + strconv.Quote(database) + `).widgets.find({}).sort({_id:1}).toArray(); print("ASKIO_JSON:"+EJSON.stringify({documents},{relaxed:false}));`
		}
		sourceDocumentsErr := executor.runMongoDBShell(ctx, source, documentsBody(sourceDatabase), &sourceDocuments)
		targetDocumentsErr := executor.runMongoDBShell(ctx, target, documentsBody(targetDatabase), &targetDocuments)
		t.Fatalf("advanced target restore failed: %v; source=%#v source_err=%v target=%#v target_err=%v source_docs=%#v source_docs_err=%v target_docs=%#v target_docs_err=%v", restoreErr, sourceInspection.Manifest, sourceInspectionErr, targetInspection.Manifest, targetInspectionErr, sourceDocuments, sourceDocumentsErr, targetDocuments, targetDocumentsErr)
	}
	verifyInputs := clonePostgresIntegrationInputs(targetInputs)
	verifyInputs["expected_manifest_digest"] = mustStringOutput(t, dumpOutputs, "database_manifest_digest")
	if _, err := executor.mongodbVerify(ctx, task, verifyInputs); err != nil {
		t.Fatalf("advanced target verification failed: %v", err)
	}
	assertionBody := `
const fixture = askioConnection.getDB("askio_mig_advanced");
const admin = askioConnection.getDB("admin");
const user = admin.runCommand({usersInfo: {user: "askio_application", db: "admin"}, showCredentials: false}).users[0];
const role = fixture.runCommand({rolesInfo: {role: "askioApplicationRole", db: "askio_mig_advanced"}, showPrivileges: true}).roles[0];
const infos = new Set(fixture.getCollectionInfos({}).map(info => info.name));
const patientInfo = fixture.getCollectionInfos({name: "patients"})[0];
print("ASKIO_JSON:" + EJSON.stringify({
  ok: fixture.widgets.countDocuments({}) === 3 && fixture.widgets.findOne({_id: 1}).name === "alpha-after-window" && fixture.widgets.findOne({_id: 2}) === null && fixture.widgets.findOne({_id: 4}).name === "delta",
  view_ok: fixture.activeWidgets.countDocuments({}) === 3,
  system_js_ok: fixture.getCollection("system.js").countDocuments({_id: "fixtureHelper"}) === 1,
  qe_ok: Boolean(patientInfo.options && patientInfo.options.encryptedFields) && infos.has("keyVault") && infos.has("enxcol_.patients.esc") && infos.has("enxcol_.patients.ecoc"),
  identity_ok: user.roles.some(entry => entry.role === "askioApplicationRole" && entry.db === "askio_mig_advanced") && role.privileges.some(entry => entry.resource.db === "askio_mig_advanced" && entry.resource.collection === "widgets")
}, {relaxed: true}));`
	var assertion struct {
		OK         bool `json:"ok"`
		ViewOK     bool `json:"view_ok"`
		SystemJSOK bool `json:"system_js_ok"`
		QEOK       bool `json:"qe_ok"`
		IdentityOK bool `json:"identity_ok"`
	}
	if err := executor.runMongoDBShell(ctx, target, assertionBody, &assertion); err != nil || !assertion.OK || !assertion.ViewOK || !assertion.SystemJSOK || !assertion.QEOK || !assertion.IdentityOK {
		t.Fatalf("advanced restored MongoDB contract diverged: %+v %v", assertion, err)
	}
}
