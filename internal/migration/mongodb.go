package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	mongodbBindingSchema = "operations.migration.mongodb-binding.v1"
	maximumMongoDBBytes  = int64(500 * 1024 * 1024 * 1024)
)

var (
	mongodbDatabasePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	mongodbVersionPattern  = regexp.MustCompile(`([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`)
)

type mongodbBinding struct {
	SchemaVersion  string `json:"schema_version"`
	Mode           string `json:"mode"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	AuthDatabase   string `json:"auth_database"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	SSLMode        string `json:"ssl_mode"`
	SSLRootCertPEM string `json:"ssl_root_cert_pem,omitempty"`
	ResetAllowed   bool   `json:"reset_allowed,omitempty"`
}

func (b *mongodbBinding) clear() {
	b.Password = ""
	b.SSLRootCertPEM = ""
}

func validateMongoDBHost(host, sslMode string) error {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t") || filepath.IsAbs(host) {
		return errors.New("MongoDB binding host is invalid")
	}
	if sslMode == "disable" {
		address := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (address == nil || !address.IsLoopback()) {
			return errors.New("unencrypted MongoDB is allowed only over loopback")
		}
	}
	return nil
}

func parseMongoDBBinding(raw []byte) (mongodbBinding, error) {
	var binding mongodbBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return mongodbBinding{}, errors.New("MongoDB binding JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return mongodbBinding{}, errors.New("MongoDB binding contains trailing data")
	}
	if binding.SchemaVersion != mongodbBindingSchema || (binding.Mode != "source" && binding.Mode != "target") {
		return mongodbBinding{}, errors.New("MongoDB binding contract is unsupported")
	}
	if binding.Port < 1 || binding.Port > 65535 || !mongodbDatabasePattern.MatchString(binding.Database) ||
		!mongodbDatabasePattern.MatchString(binding.AuthDatabase) || binding.Username == "" || len(binding.Username) > 128 ||
		strings.ContainsAny(binding.Username, "\x00\r\n\t") {
		return mongodbBinding{}, errors.New("MongoDB binding contains an invalid identifier or port")
	}
	if binding.Database == "admin" || binding.Database == "local" || binding.Database == "config" {
		return mongodbBinding{}, errors.New("MongoDB system databases are outside the migration scope")
	}
	if strings.ContainsAny(binding.Password, "\x00\r\n") || len(binding.Password) > 16*1024 {
		return mongodbBinding{}, errors.New("MongoDB binding credential is invalid")
	}
	switch binding.SSLMode {
	case "disable", "require":
	case "verify-ca", "verify-full":
		if !strings.Contains(binding.SSLRootCertPEM, "BEGIN CERTIFICATE") || len(binding.SSLRootCertPEM) > 64*1024 {
			return mongodbBinding{}, errors.New("verified MongoDB TLS requires a bounded CA certificate")
		}
	default:
		return mongodbBinding{}, errors.New("MongoDB binding ssl_mode is unsupported")
	}
	if err := validateMongoDBHost(binding.Host, binding.SSLMode); err != nil {
		return mongodbBinding{}, err
	}
	if binding.Mode == "source" && binding.ResetAllowed {
		return mongodbBinding{}, errors.New("source MongoDB binding contains target-only controls")
	}
	return binding, nil
}

func fixedMongoDBExecutable(name string) (string, error) {
	if name != "mongosh" && name != "mongodump" && name != "mongorestore" {
		return "", errors.New("MongoDB executable is unsupported")
	}
	return fixedExecutable(filepath.Join("/usr/bin", name), filepath.Join("/usr/local/bin", name))
}

func mongodbURI(binding mongodbBinding, caPath string) string {
	authority := url.UserPassword(binding.Username, binding.Password).String() + "@" + net.JoinHostPort(binding.Host, strconv.Itoa(binding.Port))
	query := url.Values{}
	query.Set("authSource", binding.AuthDatabase)
	query.Set("directConnection", "true")
	if binding.SSLMode != "disable" {
		query.Set("tls", "true")
	}
	if caPath != "" {
		query.Set("tlsCAFile", caPath)
	}
	if binding.SSLMode == "verify-ca" {
		query.Set("tlsAllowInvalidHostnames", "true")
	}
	return "mongodb://" + authority + "/?" + query.Encode()
}

func stageMongoDBConnection(stateDir string, binding mongodbBinding) (string, string, func(), error) {
	temporaryDir, err := os.MkdirTemp(stateDir, ".mongodb-secret-")
	if err != nil {
		return "", "", nil, errors.New("database credential staging failed")
	}
	cleanup := func() { _ = os.RemoveAll(temporaryDir) }
	if err := os.Chmod(temporaryDir, 0o700); err != nil {
		cleanup()
		return "", "", nil, errors.New("database credential staging failed")
	}
	caPath := ""
	if binding.SSLRootCertPEM != "" {
		caPath = filepath.Join(temporaryDir, "root.crt")
		if err := os.WriteFile(caPath, []byte(binding.SSLRootCertPEM), 0o600); err != nil {
			cleanup()
			return "", "", nil, errors.New("database TLS staging failed")
		}
	}
	uri := mongodbURI(binding, caPath)
	return temporaryDir, uri, cleanup, nil
}

func (e *NativeExecutor) runMongoDBShell(ctx context.Context, binding mongodbBinding, body string, result any) error {
	temporaryDir, uri, cleanup, err := stageMongoDBConnection(e.stateDir, binding)
	if err != nil {
		return err
	}
	defer cleanup()
	scriptPath := filepath.Join(temporaryDir, "inspect.js")
	script := "const askioConnection = new Mongo(" + strconv.Quote(uri) + ");\n" + body + "\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return errors.New("MongoDB inspection staging failed")
	}
	defer func() {
		data, readErr := os.ReadFile(scriptPath)
		if readErr == nil {
			zeroBytes(data)
			_ = os.WriteFile(scriptPath, data, 0o600)
		}
	}()
	mongosh, err := fixedMongoDBExecutable("mongosh")
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, mongosh, "--quiet", "--nodb", "--file", scriptPath)
	command.Dir = "/"
	command.Env = migrationCommandEnvironment()
	var stdout, stderr cappedBuffer
	stdout.limit = 8 * 1024 * 1024
	stderr.limit = 32 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		return errors.New("typed MongoDB inspection failed")
	}
	const marker = "ASKIO_JSON:"
	output := stdout.buffer.String()
	index := strings.LastIndex(output, marker)
	if index < 0 {
		return errors.New("MongoDB inspection returned no typed result")
	}
	encoded := strings.TrimSpace(output[index+len(marker):])
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return errors.New("MongoDB inspection result is invalid")
	}
	return nil
}

func mongodbToolsVersion(ctx context.Context) (string, error) {
	dumpVersion := ""
	for _, name := range []string{"mongodump", "mongorestore", "mongosh"} {
		binary, err := fixedMongoDBExecutable(name)
		if err != nil {
			return "", errors.New("required MongoDB tools are unavailable")
		}
		version, ok := safeCommandVersion(ctx, []string{binary}, "--version")
		if !ok || mongodbVersionPattern.FindString(version) == "" {
			return "", errors.New("required MongoDB tool version is unavailable")
		}
		if name == "mongodump" {
			dumpVersion = mongodbVersionPattern.FindString(version)
		}
	}
	return dumpVersion, nil
}

func (e *NativeExecutor) runMongoDBTool(ctx context.Context, binding mongodbBinding, name string, args []string, stdout io.Writer) error {
	temporaryDir, uri, cleanup, err := stageMongoDBConnection(e.stateDir, binding)
	if err != nil {
		return err
	}
	defer cleanup()
	configPath := filepath.Join(temporaryDir, "tool.yml")
	config := "uri: " + strconv.Quote(uri) + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return errors.New("MongoDB tool credential staging failed")
	}
	defer func() {
		data, readErr := os.ReadFile(configPath)
		if readErr == nil {
			zeroBytes(data)
			_ = os.WriteFile(configPath, data, 0o600)
		}
	}()
	binary, err := fixedMongoDBExecutable(name)
	if err != nil {
		return err
	}
	commandArgs := append([]string{"--config=" + configPath}, args...)
	command := exec.CommandContext(ctx, binary, commandArgs...)
	command.Dir = "/"
	command.Env = migrationCommandEnvironment()
	command.Stdout = stdout
	var stderr cappedBuffer
	stderr.limit = 32 * 1024
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		return errors.New("typed MongoDB archive operation failed")
	}
	return nil
}

type mongodbCollectionObservation struct {
	Name    string           `json:"name"`
	Count   int64            `json:"count"`
	Hash    string           `json:"hash"`
	Options map[string]any   `json:"options"`
	Indexes []map[string]any `json:"indexes"`
}

type mongodbShellObservation struct {
	ServerVersion string                         `json:"server_version"`
	FCV           string                         `json:"fcv"`
	Topology      string                         `json:"topology"`
	Writable      bool                           `json:"writable"`
	DatabaseBytes int64                          `json:"database_bytes"`
	DatabaseHash  string                         `json:"database_hash"`
	Collections   []mongodbCollectionObservation `json:"collections"`
	Unsupported   []string                       `json:"unsupported"`
}

type mongodbCollectionManifest struct {
	Name           string `json:"name"`
	Count          int64  `json:"count"`
	Hash           string `json:"hash"`
	MetadataDigest string `json:"metadata_digest"`
}

type mongodbManifest struct {
	SchemaVersion string                      `json:"schema_version"`
	ServerMajor   int                         `json:"server_major"`
	FCV           string                      `json:"feature_compatibility_version"`
	DatabaseHash  string                      `json:"database_hash"`
	Collections   []mongodbCollectionManifest `json:"collections"`
}

type mongodbInspection struct {
	Exists            bool
	Empty             bool
	ServerVersion     string
	ServerMajor       int
	FCV               string
	ToolsVersion      string
	Topology          string
	DatabaseBytes     int64
	TotalDocuments    int64
	Manifest          mongodbManifest
	ManifestDigest    string
	EmptyTargetDigest string
}

func (e *NativeExecutor) inspectMongoDB(ctx context.Context, bindingID string, binding mongodbBinding) (mongodbInspection, error) {
	toolsVersion, err := mongodbToolsVersion(ctx)
	if err != nil {
		return mongodbInspection{}, err
	}
	databaseName := strconv.Quote(binding.Database)
	body := `
const askioAdmin = askioConnection.getDB("admin");
const askioDatabase = askioConnection.getDB(` + databaseName + `);
const askioBuild = askioAdmin.runCommand({buildInfo: 1});
const askioHello = askioAdmin.runCommand({hello: 1});
const askioFCVResult = askioAdmin.runCommand({getParameter: 1, featureCompatibilityVersion: 1});
if (askioBuild.ok !== 1 || askioHello.ok !== 1 || askioFCVResult.ok !== 1) throw new Error("bounded server metadata unavailable");
const askioFCV = askioFCVResult.featureCompatibilityVersion.version;
const askioInfos = askioDatabase.getCollectionInfos({});
const askioUnsupported = [];
for (const info of askioInfos) {
  if (info.type !== "collection" || info.name.startsWith("system.") || (info.options && info.options.encryptedFields)) askioUnsupported.push(info.name);
}
let askioHash = {ok: 1, md5: "", collections: {}};
let askioStats = {ok: 1, dataSize: 0, indexSize: 0};
const askioCollections = [];
if (askioUnsupported.length === 0) {
  askioHash = askioDatabase.runCommand({dbHash: 1});
  askioStats = askioDatabase.runCommand({dbStats: 1, scale: 1});
  if (askioHash.ok !== 1 || askioStats.ok !== 1) throw new Error("bounded database hash unavailable");
  for (const info of askioInfos.sort((a, b) => a.name.localeCompare(b.name))) {
    const collection = askioDatabase.getCollection(info.name);
    const indexes = collection.getIndexes().map(index => ({
      name: index.name, key: index.key, unique: index.unique === true, sparse: index.sparse === true,
      expireAfterSeconds: index.expireAfterSeconds, partialFilterExpression: index.partialFilterExpression,
      collation: index.collation
    }));
    askioCollections.push({name: info.name, count: collection.countDocuments({}), hash: askioHash.collections[info.name] || "", options: info.options || {}, indexes});
  }
}
const askioTopology = askioHello.msg === "isdbgrid" ? "sharded" : (askioHello.setName ? "replica-set-primary" : "standalone");
const askioResult = {
  server_version: askioBuild.version, fcv: askioFCV, topology: askioTopology,
  writable: askioHello.isWritablePrimary === true || askioHello.ismaster === true,
  database_bytes: Number(askioStats.dataSize || 0) + Number(askioStats.indexSize || 0),
  database_hash: askioHash.md5 || "", collections: askioCollections, unsupported: askioUnsupported
};
print("ASKIO_JSON:" + EJSON.stringify(askioResult, {relaxed: true}));`
	var observed mongodbShellObservation
	if err := e.runMongoDBShell(ctx, binding, body, &observed); err != nil {
		return mongodbInspection{}, err
	}
	match := mongodbVersionPattern.FindStringSubmatch(observed.ServerVersion)
	if len(match) < 2 {
		return mongodbInspection{}, errors.New("MongoDB server version is invalid")
	}
	major, _ := strconv.Atoi(match[1])
	if major < 6 || major > 8 || !observed.Writable || (observed.Topology != "standalone" && observed.Topology != "replica-set-primary") {
		return mongodbInspection{}, errors.New("MongoDB version or topology is outside the supported offline matrix")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(observed.FCV) {
		return mongodbInspection{}, errors.New("MongoDB feature compatibility version is invalid")
	}
	if len(observed.Unsupported) != 0 {
		return mongodbInspection{}, errors.New("MongoDB views, system collections, and encrypted collections are outside the offline MVP")
	}
	if observed.DatabaseBytes < 0 || observed.DatabaseBytes > maximumMongoDBBytes || len(observed.Collections) > 2048 {
		return mongodbInspection{}, errors.New("MongoDB database is outside the supported size or collection limit")
	}
	inspection := mongodbInspection{
		Exists: len(observed.Collections) > 0, Empty: len(observed.Collections) == 0,
		ServerVersion: observed.ServerVersion, ServerMajor: major, FCV: observed.FCV,
		ToolsVersion: toolsVersion, Topology: observed.Topology, DatabaseBytes: observed.DatabaseBytes,
	}
	manifest := mongodbManifest{
		SchemaVersion: "operations.migration.mongodb-manifest.v1", ServerMajor: major,
		FCV: observed.FCV, DatabaseHash: observed.DatabaseHash, Collections: []mongodbCollectionManifest{},
	}
	for _, collection := range observed.Collections {
		if collection.Name == "" || len(collection.Name) > 255 || strings.ContainsRune(collection.Name, '\x00') || collection.Count < 0 || collection.Hash == "" {
			return mongodbInspection{}, errors.New("MongoDB collection manifest is invalid")
		}
		inspection.TotalDocuments += collection.Count
		metadataDigest, err := Digest(map[string]any{"options": collection.Options, "indexes": collection.Indexes})
		if err != nil {
			return mongodbInspection{}, err
		}
		manifest.Collections = append(manifest.Collections, mongodbCollectionManifest{
			Name: collection.Name, Count: collection.Count, Hash: collection.Hash, MetadataDigest: metadataDigest,
		})
	}
	inspection.Manifest = manifest
	inspection.ManifestDigest, err = Digest(manifest)
	if err != nil {
		return mongodbInspection{}, err
	}
	inspection.EmptyTargetDigest, err = Digest(map[string]any{
		"schema_version": "operations.migration.mongodb-empty-target.v1", "binding_id": bindingID,
		"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database}),
		"empty":             inspection.Empty, "server_major": major, "feature_compatibility_version": observed.FCV,
		"tools_version": toolsVersion, "topology": observed.Topology,
	})
	return inspection, err
}

func mongodbInspectionOutputs(inspection mongodbInspection) map[string]any {
	return map[string]any{
		"exists": inspection.Exists, "empty": inspection.Empty, "server_version": inspection.ServerVersion,
		"server_major": inspection.ServerMajor, "feature_compatibility_version": inspection.FCV,
		"tools_version": inspection.ToolsVersion, "topology": inspection.Topology,
		"collection_count": len(inspection.Manifest.Collections), "total_documents": inspection.TotalDocuments,
		"database_bytes": inspection.DatabaseBytes, "database_manifest_digest": inspection.ManifestDigest,
		"empty_target_digest": inspection.EmptyTargetDigest,
	}
}

func (e *NativeExecutor) resolveMongoDBBinding(ctx context.Context, task TaskEnvelope, inputs map[string]any) (string, mongodbBinding, error) {
	bindingID, err := stringInput(inputs, "database_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return "", mongodbBinding{}, errors.New("database binding identifier is invalid")
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return "", mongodbBinding{}, err
	}
	defer zeroBytes(raw)
	binding, err := parseMongoDBBinding(raw)
	return bindingID, binding, err
}

func verifyMongoDBCompatibility(binding mongodbBinding, inputs map[string]any, inspection mongodbInspection) error {
	requiredMajor, hasMajor := inputs["required_source_major"]
	requiredFCV, hasFCV := inputs["required_source_fcv"].(string)
	requiredTools, hasTools := inputs["required_tools_version"].(string)
	if !hasMajor && !hasFCV && !hasTools {
		return nil
	}
	major, err := boundedIntegerInput(map[string]any{"major": requiredMajor}, "major", 6, 8)
	if binding.Mode != "target" || err != nil || int64(inspection.ServerMajor) != major ||
		requiredFCV != inspection.FCV || requiredTools != inspection.ToolsVersion {
		return errors.New("target MongoDB major, FCV, and Database Tools must exactly match the source contract")
	}
	return nil
}

func (e *NativeExecutor) mongodbInspect(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveMongoDBBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	inspection, err := e.inspectMongoDB(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if err := verifyMongoDBCompatibility(binding, inputs, inspection); err != nil {
		return nil, err
	}
	if requireEmpty, ok := inputs["require_empty_target"].(bool); ok && requireEmpty {
		if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") || !inspection.Empty {
			return nil, errors.New("target MongoDB database must be empty and constrained to the migration namespace")
		}
	}
	return mongodbInspectionOutputs(inspection), nil
}

func (e *NativeExecutor) mongodbDump(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolveMongoDBBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("MongoDB dump requires a source binding")
	}
	inspection, err := e.inspectMongoDB(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return nil, err
	}
	stagingRoot, err := e.resolver.Resolve(stagingHandle, ".", false)
	if err != nil {
		return nil, err
	}
	if err := e.ensureCapacity(stagingRoot, inspection.DatabaseBytes); err != nil {
		return nil, err
	}
	relative, directory, err := mysqlArtifactLocation(e, task, stagingHandle, "mongodb", inspection.ManifestDigest)
	if err != nil {
		return nil, err
	}
	artifactHandle := "database.archive.gz"
	partial := filepath.Join(directory, artifactHandle+".partial")
	if err := e.runMongoDBTool(ctx, binding, "mongodump", []string{
		"--db=" + binding.Database, "--archive=" + partial, "--gzip", "--numParallelCollections=1",
	}, io.Discard); err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	if err := os.Chmod(partial, 0o600); err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	digest, archiveSize, err := fileSHA256(partial)
	if err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	artifactPath := filepath.Join(directory, artifactHandle)
	if err := os.Rename(partial, artifactPath); err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	transferManifest, err := buildFileManifest(ctx, directory, nil)
	if err != nil {
		return nil, err
	}
	if err := progress("mongodb_dump_complete", archiveSize, &archiveSize); err != nil {
		return nil, err
	}
	return map[string]any{
		"dump_artifact_handle": artifactHandle, "dump_staging_relative_handle": relative,
		"dump_artifact_digest": digest, "dump_transfer_manifest_digest": transferManifest.Digest,
		"dump_size_bytes": transferManifest.TotalBytes, "dump_archive_size_bytes": archiveSize,
		"database_manifest_digest": inspection.ManifestDigest, "source_database": binding.Database,
		"server_major": inspection.ServerMajor, "feature_compatibility_version": inspection.FCV,
		"tools_version": inspection.ToolsVersion,
	}, nil
}

type mongodbResetMarker struct {
	SchemaVersion      string `json:"schema_version"`
	MigrationID        string `json:"migration_id"`
	BindingID          string `json:"binding_id"`
	DatabaseIdentity   string `json:"database_identity"`
	InitialEmptyDigest string `json:"initial_empty_digest"`
	Generation         int    `json:"generation"`
	UpdatedAt          string `json:"updated_at"`
}

func (e *NativeExecutor) mongodbMarkerPath(bindingID string) string {
	digest := sha256.Sum256([]byte(bindingID))
	return filepath.Join(e.stateDir, "mongodb-reset-markers", hex.EncodeToString(digest[:16])+".json")
}

func (e *NativeExecutor) loadMongoDBMarker(bindingID string) (mongodbResetMarker, error) {
	data, err := os.ReadFile(e.mongodbMarkerPath(bindingID))
	if err != nil {
		return mongodbResetMarker{}, err
	}
	var marker mongodbResetMarker
	if json.Unmarshal(data, &marker) != nil || marker.SchemaVersion != "operations.migration.mongodb-reset-marker.v1" {
		return mongodbResetMarker{}, errors.New("target database ownership marker is invalid")
	}
	return marker, nil
}

func (e *NativeExecutor) saveMongoDBMarker(bindingID string, marker mongodbResetMarker) error {
	path := e.mongodbMarkerPath(bindingID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".marker-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (e *NativeExecutor) mongodbReset(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveMongoDBBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") {
		return nil, errors.New("target MongoDB database reset is not explicitly constrained")
	}
	expectedDigest, err := stringInput(inputs, "expected_empty_target_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("expected empty target digest is invalid")
	}
	inspection, err := e.inspectMongoDB(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	marker, markerErr := e.loadMongoDBMarker(bindingID)
	databaseIdentity := MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database})
	ownedByRun := markerErr == nil && marker.MigrationID == task.MigrationID && marker.BindingID == bindingID &&
		marker.DatabaseIdentity == databaseIdentity && marker.InitialEmptyDigest == expectedDigest
	if (!inspection.Empty || inspection.EmptyTargetDigest != expectedDigest) && !ownedByRun {
		return nil, errors.New("target MongoDB database is not the approved empty target and is not owned by this migration")
	}
	body := "const askioResult = askioConnection.getDB(" + strconv.Quote(binding.Database) + ").dropDatabase();\n" +
		"if (askioResult.ok !== 1) throw new Error('target reset failed');\n" +
		"print('ASKIO_JSON:' + EJSON.stringify({ok: true}, {relaxed: true}));"
	var resetResult struct {
		OK bool `json:"ok"`
	}
	if err := e.runMongoDBShell(ctx, binding, body, &resetResult); err != nil || !resetResult.OK {
		return nil, errors.New("target MongoDB reset failed safely")
	}
	generation := 1
	initialDigest := expectedDigest
	if ownedByRun {
		generation = marker.Generation + 1
		initialDigest = marker.InitialEmptyDigest
	}
	marker = mongodbResetMarker{
		SchemaVersion: "operations.migration.mongodb-reset-marker.v1", MigrationID: task.MigrationID,
		BindingID: bindingID, DatabaseIdentity: databaseIdentity, InitialEmptyDigest: initialDigest,
		Generation: generation, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := e.saveMongoDBMarker(bindingID, marker); err != nil {
		return nil, err
	}
	return map[string]any{"database_identity_digest": databaseIdentity, "reset_generation": generation, "empty": true}, nil
}

func (e *NativeExecutor) mongodbRestore(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolveMongoDBBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" {
		return nil, errors.New("MongoDB restore requires a target binding")
	}
	marker, err := e.loadMongoDBMarker(bindingID)
	if err != nil || marker.MigrationID != task.MigrationID {
		return nil, errors.New("target MongoDB reset ownership is unproven")
	}
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return nil, err
	}
	stagingRelative, err := stringInput(inputs, "dump_staging_relative_handle")
	if err != nil || strings.Contains(stagingRelative, "/") || !fileNamePattern.MatchString(stagingRelative) {
		return nil, errors.New("database dump staging relative handle is invalid")
	}
	artifactHandle, err := stringInput(inputs, "dump_artifact_handle")
	if err != nil || strings.Contains(artifactHandle, "/") || !fileNamePattern.MatchString(artifactHandle) {
		return nil, errors.New("database dump artifact handle is invalid")
	}
	artifactPath, err := e.resolver.Resolve(stagingHandle, filepath.Join(stagingRelative, artifactHandle), false)
	if err != nil {
		return nil, err
	}
	expectedArtifactDigest, err := stringInput(inputs, "dump_artifact_digest")
	if err != nil {
		return nil, err
	}
	actualDigest, size, err := fileSHA256(artifactPath)
	if err != nil || actualDigest != expectedArtifactDigest {
		return nil, errors.New("MongoDB archive digest verification failed")
	}
	sourceDatabase, err := stringInput(inputs, "source_database")
	if err != nil || !mongodbDatabasePattern.MatchString(sourceDatabase) || sourceDatabase == "admin" || sourceDatabase == "local" || sourceDatabase == "config" {
		return nil, errors.New("MongoDB source namespace is invalid")
	}
	expectedManifestDigest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedManifestDigest) {
		return nil, errors.New("expected MongoDB manifest digest is invalid")
	}
	before, err := e.inspectMongoDB(ctx, bindingID, binding)
	if err != nil || !before.Empty {
		return nil, errors.New("target MongoDB database is not empty before restore")
	}
	if err := progress("mongodb_restore", 0, &size); err != nil {
		return nil, err
	}
	if err := e.runMongoDBTool(ctx, binding, "mongorestore", []string{
		"--archive=" + artifactPath, "--gzip", "--stopOnError", "--numParallelCollections=1",
		"--nsFrom=" + sourceDatabase + ".*", "--nsTo=" + binding.Database + ".*",
	}, io.Discard); err != nil {
		return nil, err
	}
	after, err := e.inspectMongoDB(ctx, bindingID, binding)
	if err != nil || after.ManifestDigest != expectedManifestDigest {
		return nil, errors.New("restored MongoDB manifest does not match the source manifest")
	}
	if err := progress("mongodb_restore_verified", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"database_manifest_digest": after.ManifestDigest, "dump_artifact_digest": actualDigest,
		"restored_size_bytes": size, "collection_count": len(after.Manifest.Collections), "total_documents": after.TotalDocuments,
	}, nil
}

func (e *NativeExecutor) mongodbVerify(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveMongoDBBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	expectedDigest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil {
		return nil, err
	}
	inspection, err := e.inspectMongoDB(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if inspection.ManifestDigest != expectedDigest {
		return nil, errors.New("MongoDB database verification manifest mismatch")
	}
	return map[string]any{
		"verified": true, "database_manifest_digest": inspection.ManifestDigest,
		"collection_count": len(inspection.Manifest.Collections), "total_documents": inspection.TotalDocuments,
	}, nil
}
