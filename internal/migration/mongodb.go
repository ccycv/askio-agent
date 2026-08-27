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
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	mongodbBindingSchema          = "operations.migration.mongodb-binding.v1"
	mongodbBindingSchemaV2        = "operations.migration.mongodb-binding.v2"
	mongodbIdentityArtifactHandle = "database.identities.json"
	mongodbOplogArtifactHandle    = "database.oplog-delta.json"
	maximumMongoDBBytes           = int64(500 * 1024 * 1024 * 1024)
	maximumMongoDeltaBytes        = int64(6 * 1024 * 1024)
	maximumMongoDeltaItems        = 10_000
)

var (
	mongodbDatabasePattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	mongodbPrincipalPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	mongodbCollectionPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,254}$`)
	mongodbVersionPattern    = regexp.MustCompile(`([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`)
)

type mongodbIdentityMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type mongodbFeatures struct {
	UsersAndRoles             bool `json:"users_and_roles"`
	ViewsAndSystemCollections bool `json:"views_and_system_collections"`
	OplogReplay               bool `json:"oplog_replay"`
	QueryableEncryption       bool `json:"queryable_encryption"`
}

type mongodbBinding struct {
	SchemaVersion                         string                   `json:"schema_version"`
	Mode                                  string                   `json:"mode"`
	Host                                  string                   `json:"host"`
	Port                                  int                      `json:"port"`
	Database                              string                   `json:"database"`
	AuthDatabase                          string                   `json:"auth_database"`
	Username                              string                   `json:"username"`
	Password                              string                   `json:"password"`
	SSLMode                               string                   `json:"ssl_mode"`
	SSLRootCertPEM                        string                   `json:"ssl_root_cert_pem,omitempty"`
	ResetAllowed                          bool                     `json:"reset_allowed,omitempty"`
	Features                              mongodbFeatures          `json:"features,omitempty"`
	UserMap                               []mongodbIdentityMapping `json:"user_map,omitempty"`
	RoleMap                               []mongodbIdentityMapping `json:"role_map,omitempty"`
	AllowedSystemCollections              []string                 `json:"allowed_system_collections,omitempty"`
	QueryableEncryptionKeyVaultCollection string                   `json:"queryable_encryption_key_vault_collection,omitempty"`
}

type mongodbDatabaseMapping struct {
	SourceDatabase string `json:"source_database"`
	TargetDatabase string `json:"target_database"`
}

type mongodbDatabaseContract struct {
	SchemaVersion                         string                   `json:"schema_version"`
	SourceEngine                          string                   `json:"source_engine"`
	TargetEngine                          string                   `json:"target_engine"`
	DatabaseMappings                      []mongodbDatabaseMapping `json:"database_mappings"`
	Features                              mongodbFeatures          `json:"features"`
	UserMap                               []mongodbIdentityMapping `json:"user_map"`
	RoleMap                               []mongodbIdentityMapping `json:"role_map"`
	AllowedSystemCollections              []string                 `json:"allowed_system_collections"`
	QueryableEncryptionKeyVaultCollection string                   `json:"queryable_encryption_key_vault_collection,omitempty"`
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
	if (binding.SchemaVersion != mongodbBindingSchema && binding.SchemaVersion != mongodbBindingSchemaV2) || (binding.Mode != "source" && binding.Mode != "target") {
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
	advanced := binding.Features.UsersAndRoles || binding.Features.ViewsAndSystemCollections || binding.Features.OplogReplay || binding.Features.QueryableEncryption ||
		len(binding.UserMap) > 0 || len(binding.RoleMap) > 0 || len(binding.AllowedSystemCollections) > 0 || binding.QueryableEncryptionKeyVaultCollection != ""
	if binding.SchemaVersion == mongodbBindingSchema && advanced {
		return mongodbBinding{}, errors.New("advanced MongoDB controls require binding contract v2")
	}
	if err := validateMongoDBAdvancedBinding(binding); err != nil {
		return mongodbBinding{}, err
	}
	return binding, nil
}

func validateMongoDBIdentityMap(entries []mongodbIdentityMapping, label string) error {
	if len(entries) > 128 {
		return errors.New(label + " map exceeds its safety limit")
	}
	previous := ""
	sources := map[string]struct{}{}
	targets := map[string]struct{}{}
	for _, entry := range entries {
		if !mongodbPrincipalPattern.MatchString(entry.Source) || !mongodbPrincipalPattern.MatchString(entry.Target) || entry.Source <= previous {
			return errors.New(label + " map is invalid or non-canonical")
		}
		if _, exists := sources[entry.Source]; exists {
			return errors.New(label + " map contains a duplicate source")
		}
		if _, exists := targets[entry.Target]; exists {
			return errors.New(label + " map must be one-to-one")
		}
		sources[entry.Source] = struct{}{}
		targets[entry.Target] = struct{}{}
		previous = entry.Source
	}
	return nil
}

func validateMongoDBAdvancedBinding(binding mongodbBinding) error {
	if err := validateMongoDBIdentityMap(binding.UserMap, "MongoDB user"); err != nil {
		return err
	}
	if err := validateMongoDBIdentityMap(binding.RoleMap, "MongoDB role"); err != nil {
		return err
	}
	if binding.Features.UsersAndRoles {
		if len(binding.UserMap) == 0 {
			return errors.New("MongoDB users and roles require an explicit user map")
		}
	} else if len(binding.UserMap) != 0 || len(binding.RoleMap) != 0 {
		return errors.New("MongoDB identity maps require users-and-roles support")
	}
	if len(binding.AllowedSystemCollections) > 32 {
		return errors.New("MongoDB system collection allowlist exceeds its safety limit")
	}
	previous := ""
	for _, name := range binding.AllowedSystemCollections {
		if name != "system.js" || name <= previous {
			return errors.New("only canonical system.js is directly migratable")
		}
		previous = name
	}
	if len(binding.AllowedSystemCollections) > 0 && !binding.Features.ViewsAndSystemCollections {
		return errors.New("MongoDB system collection declarations require views-and-system-collections support")
	}
	if binding.Features.QueryableEncryption {
		if !mongodbCollectionPattern.MatchString(binding.QueryableEncryptionKeyVaultCollection) ||
			strings.HasPrefix(binding.QueryableEncryptionKeyVaultCollection, "system.") ||
			strings.HasPrefix(binding.QueryableEncryptionKeyVaultCollection, "enxcol_") {
			return errors.New("Queryable Encryption requires a bounded same-database key-vault collection")
		}
	} else if binding.QueryableEncryptionKeyVaultCollection != "" {
		return errors.New("a Queryable Encryption key vault requires Queryable Encryption support")
	}
	return nil
}

func validateMongoDBDatabaseContract(inputs map[string]any, binding mongodbBinding) error {
	raw, provided := inputs["database_contract"]
	if !provided {
		if binding.SchemaVersion == mongodbBindingSchemaV2 {
			return errors.New("advanced MongoDB bindings require a database contract")
		}
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 64*1024 {
		return errors.New("MongoDB database contract is invalid")
	}
	var contract mongodbDatabaseContract
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return errors.New("MongoDB database contract is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("MongoDB database contract contains trailing data")
	}
	if contract.SchemaVersion != "operations.migration.database-contract.v1" || contract.SourceEngine != "mongodb" || contract.TargetEngine != "mongodb" ||
		len(contract.DatabaseMappings) != 1 || !mongodbDatabasePattern.MatchString(contract.DatabaseMappings[0].SourceDatabase) ||
		!mongodbDatabasePattern.MatchString(contract.DatabaseMappings[0].TargetDatabase) || !strings.HasPrefix(contract.DatabaseMappings[0].TargetDatabase, "askio_mig_") {
		return errors.New("MongoDB database contract identity is invalid")
	}
	if binding.Mode == "source" && contract.DatabaseMappings[0].SourceDatabase != binding.Database {
		return errors.New("MongoDB source binding does not match the database contract")
	}
	if binding.Mode == "target" && contract.DatabaseMappings[0].TargetDatabase != binding.Database {
		return errors.New("MongoDB target binding does not match the database contract")
	}
	if MustDigest(contract.Features) != MustDigest(binding.Features) || MustDigest(contract.UserMap) != MustDigest(binding.UserMap) ||
		MustDigest(contract.RoleMap) != MustDigest(binding.RoleMap) || MustDigest(contract.AllowedSystemCollections) != MustDigest(binding.AllowedSystemCollections) ||
		contract.QueryableEncryptionKeyVaultCollection != binding.QueryableEncryptionKeyVaultCollection {
		return errors.New("MongoDB binding capabilities do not match the database contract")
	}
	return nil
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
	Type    string           `json:"type"`
	Count   int64            `json:"count"`
	Hash    string           `json:"hash"`
	Options map[string]any   `json:"options"`
	Indexes []map[string]any `json:"indexes"`
}

type mongodbRoleReference struct {
	Role string `json:"role"`
	DB   string `json:"db"`
}

type mongodbPrivilegeObservation struct {
	Resource map[string]any `json:"resource"`
	Actions  []string       `json:"actions"`
}

type mongodbUserObservation struct {
	User  string                 `json:"user"`
	Roles []mongodbRoleReference `json:"roles"`
}

type mongodbRoleObservation struct {
	Role                       string                        `json:"role"`
	Roles                      []mongodbRoleReference        `json:"roles"`
	Privileges                 []mongodbPrivilegeObservation `json:"privileges"`
	AuthenticationRestrictions []any                         `json:"authentication_restrictions"`
}

type mongodbShellObservation struct {
	ServerVersion string                         `json:"server_version"`
	FCV           string                         `json:"fcv"`
	Topology      string                         `json:"topology"`
	Writable      bool                           `json:"writable"`
	DatabaseBytes int64                          `json:"database_bytes"`
	DatabaseHash  string                         `json:"database_hash"`
	Collections   []mongodbCollectionObservation `json:"collections"`
	Users         []mongodbUserObservation       `json:"users"`
	Roles         []mongodbRoleObservation       `json:"roles"`
	Unsupported   []string                       `json:"unsupported"`
}

type mongodbCollectionManifest struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Count          int64  `json:"count"`
	Hash           string `json:"hash"`
	MetadataDigest string `json:"metadata_digest"`
}

type mongodbUserManifest struct {
	User  string                 `json:"user"`
	Roles []mongodbRoleReference `json:"roles"`
}

type mongodbRoleManifest struct {
	Role       string                        `json:"role"`
	Roles      []mongodbRoleReference        `json:"roles"`
	Privileges []mongodbPrivilegeObservation `json:"privileges"`
}

type mongodbIdentityManifest struct {
	SchemaVersion string                `json:"schema_version"`
	Enabled       bool                  `json:"enabled"`
	Users         []mongodbUserManifest `json:"users"`
	Roles         []mongodbRoleManifest `json:"roles"`
}

type mongodbManifest struct {
	SchemaVersion string                      `json:"schema_version"`
	ServerMajor   int                         `json:"server_major"`
	FCV           string                      `json:"feature_compatibility_version"`
	Collections   []mongodbCollectionManifest `json:"collections"`
	Identities    mongodbIdentityManifest     `json:"identities"`
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
	IdentityDigest    string
}

var mongodbBuiltinDatabaseRoles = map[string]struct{}{
	"read": {}, "readWrite": {}, "dbAdmin": {}, "dbOwner": {},
}

func mongodbMappedPrincipal(name string, mappings []mongodbIdentityMapping, source bool) (string, bool) {
	for _, mapping := range mappings {
		if source && mapping.Source == name {
			return mapping.Target, true
		}
		if !source && mapping.Target == name {
			return name, true
		}
	}
	return "", false
}

func normalizeMongoDBRoleReference(reference mongodbRoleReference, binding mongodbBinding) (mongodbRoleReference, error) {
	if reference.DB != binding.Database || !mongodbPrincipalPattern.MatchString(reference.Role) {
		return mongodbRoleReference{}, errors.New("MongoDB role assignment escapes the selected application database")
	}
	if mapped, ok := mongodbMappedPrincipal(reference.Role, binding.RoleMap, binding.Mode == "source"); ok {
		return mongodbRoleReference{Role: mapped, DB: "application"}, nil
	}
	if _, ok := mongodbBuiltinDatabaseRoles[reference.Role]; !ok {
		return mongodbRoleReference{}, errors.New("MongoDB role assignment is neither built-in nor explicitly mapped")
	}
	return mongodbRoleReference{Role: reference.Role, DB: "application"}, nil
}

func normalizeMongoDBIdentities(observed mongodbShellObservation, binding mongodbBinding) (mongodbIdentityManifest, error) {
	manifest := mongodbIdentityManifest{
		SchemaVersion: "operations.migration.mongodb-identities.v1", Enabled: binding.Features.UsersAndRoles,
		Users: []mongodbUserManifest{}, Roles: []mongodbRoleManifest{},
	}
	if !binding.Features.UsersAndRoles {
		return manifest, nil
	}
	users := make(map[string]mongodbUserObservation, len(observed.Users))
	for _, user := range observed.Users {
		users[user.User] = user
	}
	for _, mapping := range binding.UserMap {
		lookup := mapping.Source
		if binding.Mode == "target" {
			lookup = mapping.Target
		}
		user, exists := users[lookup]
		if !exists {
			return mongodbIdentityManifest{}, errors.New("a declared MongoDB user is not pre-created on the endpoint")
		}
		normalized := mongodbUserManifest{User: mapping.Target, Roles: []mongodbRoleReference{}}
		for _, role := range user.Roles {
			if role.DB != binding.Database {
				return mongodbIdentityManifest{}, errors.New("a declared MongoDB user has a cross-database role assignment")
			}
			normalizedRole, err := normalizeMongoDBRoleReference(role, binding)
			if err != nil {
				return mongodbIdentityManifest{}, err
			}
			normalized.Roles = append(normalized.Roles, normalizedRole)
		}
		sort.Slice(normalized.Roles, func(left, right int) bool { return normalized.Roles[left].Role < normalized.Roles[right].Role })
		manifest.Users = append(manifest.Users, normalized)
	}
	roles := make(map[string]mongodbRoleObservation, len(observed.Roles))
	for _, role := range observed.Roles {
		roles[role.Role] = role
	}
	for _, mapping := range binding.RoleMap {
		lookup := mapping.Source
		if binding.Mode == "target" {
			lookup = mapping.Target
		}
		role, exists := roles[lookup]
		if !exists && binding.Mode == "target" {
			manifest.Roles = append(manifest.Roles, mongodbRoleManifest{Role: mapping.Target, Roles: []mongodbRoleReference{}, Privileges: []mongodbPrivilegeObservation{}})
			continue
		}
		if !exists || len(role.AuthenticationRestrictions) != 0 {
			return mongodbIdentityManifest{}, errors.New("a declared MongoDB custom role is missing or has unsupported authentication restrictions")
		}
		normalized := mongodbRoleManifest{Role: mapping.Target, Roles: []mongodbRoleReference{}, Privileges: []mongodbPrivilegeObservation{}}
		for _, inherited := range role.Roles {
			normalizedRole, err := normalizeMongoDBRoleReference(inherited, binding)
			if err != nil {
				return mongodbIdentityManifest{}, err
			}
			normalized.Roles = append(normalized.Roles, normalizedRole)
		}
		for _, privilege := range role.Privileges {
			db, dbOK := privilege.Resource["db"].(string)
			collection, collectionOK := privilege.Resource["collection"].(string)
			if !dbOK || db != binding.Database || !collectionOK || len(collection) > 255 || strings.ContainsRune(collection, '\x00') ||
				len(privilege.Resource) != 2 || len(privilege.Actions) == 0 || len(privilege.Actions) > 128 {
				return mongodbIdentityManifest{}, errors.New("MongoDB custom role privilege escapes the selected database")
			}
			actions := append([]string{}, privilege.Actions...)
			sort.Strings(actions)
			for index, action := range actions {
				if !mongodbPrincipalPattern.MatchString(action) || (index > 0 && action == actions[index-1]) {
					return mongodbIdentityManifest{}, errors.New("MongoDB custom role action set is invalid")
				}
			}
			normalized.Privileges = append(normalized.Privileges, mongodbPrivilegeObservation{
				Resource: map[string]any{"db": "application", "collection": collection}, Actions: actions,
			})
		}
		sort.Slice(normalized.Roles, func(left, right int) bool { return normalized.Roles[left].Role < normalized.Roles[right].Role })
		sort.Slice(normalized.Privileges, func(left, right int) bool {
			leftDigest, _ := Digest(normalized.Privileges[left])
			rightDigest, _ := Digest(normalized.Privileges[right])
			return leftDigest < rightDigest
		})
		manifest.Roles = append(manifest.Roles, normalized)
	}
	return manifest, nil
}

func (e *NativeExecutor) inspectMongoDB(ctx context.Context, bindingID string, binding mongodbBinding) (mongodbInspection, error) {
	toolsVersion, err := mongodbToolsVersion(ctx)
	if err != nil {
		return mongodbInspection{}, err
	}
	databaseName := strconv.Quote(binding.Database)
	authDatabaseName := strconv.Quote(binding.AuthDatabase)
	allowedSystemJSON, _ := json.Marshal(binding.AllowedSystemCollections)
	featuresJSON, _ := json.Marshal(binding.Features)
	body := `
const askioAdmin = askioConnection.getDB("admin");
const askioDatabase = askioConnection.getDB(` + databaseName + `);
const askioAuthDatabase = askioConnection.getDB(` + authDatabaseName + `);
const askioFeatures = EJSON.parse(` + strconv.Quote(string(featuresJSON)) + `);
const askioAllowedSystem = new Set(EJSON.parse(` + strconv.Quote(string(allowedSystemJSON)) + `));
const askioBuild = askioAdmin.runCommand({buildInfo: 1});
const askioHello = askioAdmin.runCommand({hello: 1});
const askioFCVResult = askioAdmin.runCommand({getParameter: 1, featureCompatibilityVersion: 1});
if (askioBuild.ok !== 1 || askioHello.ok !== 1 || askioFCVResult.ok !== 1) throw new Error("bounded server metadata unavailable");
const askioFCV = askioFCVResult.featureCompatibilityVersion.version;
const askioInfos = askioDatabase.getCollectionInfos({});
const askioUnsupported = [];
const askioNames = new Set(askioInfos.map(info => info.name));
const askioTimeSeries = new Set(askioInfos.filter(info => info.type === "timeseries" || (info.options && info.options.timeseries)).map(info => info.name));
const askioEncrypted = [];
for (const info of askioInfos) {
  const isView = info.type === "view";
  const isTimeSeries = info.type === "timeseries" || (info.options && info.options.timeseries);
  const isManagedViews = info.name === "system.views";
  const isBucket = info.name.startsWith("system.buckets.") && askioTimeSeries.has(info.name.slice("system.buckets.".length));
  const isAllowedSystem = info.name === "system.js" && askioAllowedSystem.has(info.name);
  const hasEncryptedFields = Boolean(info.options && info.options.encryptedFields);
  const isEncryptedState = info.name.startsWith("enxcol_");
  if (!["collection", "view", "timeseries"].includes(info.type)) askioUnsupported.push("type:" + info.name);
  if ((isView || isTimeSeries || isManagedViews || isBucket || info.name.startsWith("system.")) && !askioFeatures.views_and_system_collections) askioUnsupported.push("view-or-system:" + info.name);
  if (info.name.startsWith("system.") && !isManagedViews && !isBucket && !isAllowedSystem) askioUnsupported.push("system:" + info.name);
  if ((hasEncryptedFields || isEncryptedState) && !askioFeatures.queryable_encryption) askioUnsupported.push("queryable-encryption:" + info.name);
  if (hasEncryptedFields) askioEncrypted.push(info.name);
}
if (askioFeatures.queryable_encryption && askioInfos.length > 0) {
  const keyVault = ` + strconv.Quote(binding.QueryableEncryptionKeyVaultCollection) + `;
  if (!askioNames.has(keyVault)) askioUnsupported.push("missing-key-vault:" + keyVault);
  for (const name of askioEncrypted) {
    for (const suffix of ["esc", "ecoc"]) {
      const stateName = "enxcol_." + name + "." + suffix;
      if (!askioNames.has(stateName)) askioUnsupported.push("missing-encrypted-state:" + stateName);
    }
  }
}
let askioHash = {ok: 1, md5: "", collections: {}};
let askioStats = {ok: 1, dataSize: 0, indexSize: 0};
const askioCollections = [];
if (askioUnsupported.length === 0) {
  askioHash = askioDatabase.runCommand({dbHash: 1});
  askioStats = askioDatabase.runCommand({dbStats: 1, scale: 1});
  if (askioHash.ok !== 1 || askioStats.ok !== 1) throw new Error("bounded database hash unavailable");
  for (const info of askioInfos.sort((a, b) => a.name.localeCompare(b.name))) {
    if (info.name === "system.views") continue;
    const collection = askioDatabase.getCollection(info.name);
    const isView = info.type === "view";
    const indexes = isView ? [] : collection.getIndexes().map(index => ({
      name: index.name, key: index.key, unique: index.unique === true, sparse: index.sparse === true,
      expireAfterSeconds: index.expireAfterSeconds, partialFilterExpression: index.partialFilterExpression,
      collation: index.collation
    }));
    askioCollections.push({name: info.name, type: info.type, count: isView ? 0 : collection.countDocuments({}), hash: isView ? "" : (askioHash.collections[info.name] || ""), options: info.options || {}, indexes});
  }
}
let askioUsers = [];
let askioRoles = [];
if (askioFeatures.users_and_roles && askioUnsupported.length === 0) {
  const userResult = askioAuthDatabase.runCommand({usersInfo: 1, showCredentials: false, showPrivileges: false});
  const roleResult = askioDatabase.runCommand({rolesInfo: 1, showPrivileges: true, showBuiltinRoles: false});
  if (userResult.ok !== 1 || roleResult.ok !== 1) throw new Error("bounded identity metadata unavailable");
  askioUsers = (userResult.users || []).map(user => ({user: user.user, roles: user.roles || []}));
  askioRoles = (roleResult.roles || []).map(role => ({
    role: role.role, roles: role.roles || [], privileges: role.privileges || [],
    authentication_restrictions: role.authenticationRestrictions || []
  }));
}
const askioTopology = askioHello.msg === "isdbgrid" ? "sharded" : (askioHello.setName ? "replica-set-primary" : "standalone");
const askioResult = {
  server_version: askioBuild.version, fcv: askioFCV, topology: askioTopology,
  writable: askioHello.isWritablePrimary === true || askioHello.ismaster === true,
  database_bytes: Number(askioStats.dataSize || 0) + Number(askioStats.indexSize || 0),
  database_hash: askioHash.md5 || "", collections: askioCollections, users: askioUsers, roles: askioRoles,
  unsupported: Array.from(new Set(askioUnsupported)).sort()
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
	if binding.Features.QueryableEncryption && observed.Topology != "replica-set-primary" {
		return mongodbInspection{}, errors.New("MongoDB Queryable Encryption migration requires a replica-set primary on both endpoints")
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(observed.FCV) {
		return mongodbInspection{}, errors.New("MongoDB feature compatibility version is invalid")
	}
	if len(observed.Unsupported) != 0 {
		return mongodbInspection{}, errors.New("MongoDB contains undeclared or unsupported advanced objects")
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
		SchemaVersion: "operations.migration.mongodb-manifest.v2", ServerMajor: major,
		FCV: observed.FCV, Collections: []mongodbCollectionManifest{},
	}
	manifest.Identities, err = normalizeMongoDBIdentities(observed, binding)
	if err != nil {
		return mongodbInspection{}, err
	}
	for _, collection := range observed.Collections {
		if collection.Name == "" || len(collection.Name) > 255 || strings.ContainsRune(collection.Name, '\x00') || collection.Count < 0 ||
			(collection.Type != "view" && collection.Hash == "") || (collection.Type == "view" && (collection.Count != 0 || collection.Hash != "")) {
			return mongodbInspection{}, errors.New("MongoDB collection manifest is invalid")
		}
		inspection.TotalDocuments += collection.Count
		metadataDigest, err := Digest(map[string]any{"options": collection.Options, "indexes": collection.Indexes})
		if err != nil {
			return mongodbInspection{}, err
		}
		manifest.Collections = append(manifest.Collections, mongodbCollectionManifest{
			Name: collection.Name, Type: collection.Type, Count: collection.Count, Hash: collection.Hash, MetadataDigest: metadataDigest,
		})
	}
	inspection.Manifest = manifest
	inspection.IdentityDigest, err = Digest(manifest.Identities)
	if err != nil {
		return mongodbInspection{}, err
	}
	inspection.ManifestDigest, err = Digest(manifest)
	if err != nil {
		return mongodbInspection{}, err
	}
	inspection.EmptyTargetDigest, err = Digest(map[string]any{
		"schema_version": "operations.migration.mongodb-empty-target.v1", "binding_id": bindingID,
		"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database}),
		"empty":             inspection.Empty, "server_major": major, "feature_compatibility_version": observed.FCV,
		"tools_version": toolsVersion, "topology": observed.Topology,
		"feature_digest": MustDigest(binding.Features), "identity_map_digest": MustDigest(map[string]any{"users": binding.UserMap, "roles": binding.RoleMap}),
	})
	return inspection, err
}

func mongodbInspectionOutputs(inspection mongodbInspection) map[string]any {
	viewCount := 0
	encryptedCollectionCount := 0
	for _, collection := range inspection.Manifest.Collections {
		if collection.Type == "view" {
			viewCount++
		}
		if collection.Type != "view" && strings.HasPrefix(collection.Name, "enxcol_") {
			encryptedCollectionCount++
		}
	}
	return map[string]any{
		"exists": inspection.Exists, "empty": inspection.Empty, "server_version": inspection.ServerVersion,
		"server_major": inspection.ServerMajor, "feature_compatibility_version": inspection.FCV,
		"tools_version": inspection.ToolsVersion, "topology": inspection.Topology,
		"collection_count": len(inspection.Manifest.Collections), "total_documents": inspection.TotalDocuments,
		"database_bytes": inspection.DatabaseBytes, "database_manifest_digest": inspection.ManifestDigest,
		"empty_target_digest": inspection.EmptyTargetDigest, "identity_manifest_digest": inspection.IdentityDigest,
		"user_count": len(inspection.Manifest.Identities.Users), "custom_role_count": len(inspection.Manifest.Identities.Roles),
		"view_count": viewCount, "encrypted_state_collection_count": encryptedCollectionCount,
	}
}

type mongodbIdentityArtifact struct {
	SchemaVersion     string                  `json:"schema_version"`
	BaseArchiveDigest string                  `json:"base_archive_digest"`
	IdentityMapDigest string                  `json:"identity_map_digest"`
	Manifest          mongodbIdentityManifest `json:"manifest"`
}

type mongodbOplogTimestamp struct {
	Seconds   int64 `json:"seconds"`
	Increment int64 `json:"increment"`
}

func parseMongoDBExtendedInteger(raw json.RawMessage) (int64, error) {
	var value int64
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, nil
	}
	var extended struct {
		NumberInt  string `json:"$numberInt"`
		NumberLong string `json:"$numberLong"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&extended); err != nil {
		return 0, errors.New("MongoDB timestamp integer is invalid")
	}
	encoded := extended.NumberLong
	if encoded == "" {
		encoded = extended.NumberInt
	}
	if encoded == "" {
		return 0, errors.New("MongoDB timestamp integer is invalid")
	}
	value, err := strconv.ParseInt(encoded, 10, 64)
	if err != nil {
		return 0, errors.New("MongoDB timestamp integer is invalid")
	}
	return value, nil
}

func (timestamp *mongodbOplogTimestamp) UnmarshalJSON(raw []byte) error {
	var encoded struct {
		Seconds   json.RawMessage `json:"seconds"`
		Increment json.RawMessage `json:"increment"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&encoded); err != nil || len(encoded.Seconds) == 0 || len(encoded.Increment) == 0 {
		return errors.New("MongoDB timestamp is invalid")
	}
	seconds, err := parseMongoDBExtendedInteger(encoded.Seconds)
	if err != nil {
		return err
	}
	increment, err := parseMongoDBExtendedInteger(encoded.Increment)
	if err != nil {
		return err
	}
	timestamp.Seconds = seconds
	timestamp.Increment = increment
	return nil
}

type mongodbOplogMutation struct {
	Collection string          `json:"collection"`
	ID         json.RawMessage `json:"id"`
	Document   json.RawMessage `json:"document"`
}

type mongodbOplogDelta struct {
	SchemaVersion     string                 `json:"schema_version"`
	Enabled           bool                   `json:"enabled"`
	BaseArchiveDigest string                 `json:"base_archive_digest"`
	SourceDatabase    string                 `json:"source_database"`
	Start             mongodbOplogTimestamp  `json:"start"`
	End               mongodbOplogTimestamp  `json:"end"`
	Mutations         []mongodbOplogMutation `json:"mutations"`
}

func writeMongoDBJSONArtifact(directory, handle string, value any, maximumBytes int64) (string, int64, error) {
	data, err := json.Marshal(value)
	if err != nil || int64(len(data)) < 1 || int64(len(data)) > maximumBytes {
		return "", 0, errors.New("MongoDB metadata artifact exceeds its safety limit")
	}
	data = append(data, '\n')
	path := filepath.Join(directory, handle)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", 0, err
	}
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", 0, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", 0, err
	}
	if err := file.Close(); err != nil {
		return "", 0, err
	}
	digest, size, err := fileSHA256(path)
	if err != nil {
		return "", 0, err
	}
	remove = false
	return digest, size, nil
}

func readMongoDBJSONArtifact(path, expectedDigest string, maximumBytes int64, value any) error {
	digest, _, err := fileSHA256(path)
	if err != nil || digest != expectedDigest {
		return errors.New("MongoDB metadata artifact digest verification failed")
	}
	file, info, err := openRegularNoFollow(path)
	if err != nil || info.Size() < 1 || info.Size() > maximumBytes {
		if file != nil {
			_ = file.Close()
		}
		return errors.New("MongoDB metadata artifact is unsafe")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("MongoDB metadata artifact is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("MongoDB metadata artifact contains trailing data")
	}
	return nil
}

func (e *NativeExecutor) captureMongoDBOplogTimestamp(ctx context.Context, binding mongodbBinding) (mongodbOplogTimestamp, error) {
	body := `
const askioHello = askioConnection.getDB("admin").runCommand({hello: 1});
if (!askioHello.setName || !(askioHello.isWritablePrimary === true || askioHello.ismaster === true)) throw new Error("replica-set primary required");
const askioLast = askioConnection.getDB("local").getCollection("oplog.rs").find({}).sort({$natural: -1}).limit(1).next();
if (!askioLast || !askioLast.ts) throw new Error("oplog timestamp unavailable");
print("ASKIO_JSON:" + EJSON.stringify({seconds: Number(askioLast.ts.getHighBits()), increment: Number(askioLast.ts.getLowBitsUnsigned())}, {relaxed: true}));`
	var timestamp mongodbOplogTimestamp
	if err := e.runMongoDBShell(ctx, binding, body, &timestamp); err != nil || timestamp.Seconds < 1 || timestamp.Increment < 0 {
		return mongodbOplogTimestamp{}, errors.New("bounded MongoDB oplog timestamp is unavailable")
	}
	return timestamp, nil
}

func (e *NativeExecutor) captureMongoDBOplogDelta(ctx context.Context, binding mongodbBinding, start mongodbOplogTimestamp, baseArchiveDigest string) (mongodbOplogDelta, error) {
	if !binding.Features.OplogReplay {
		return mongodbOplogDelta{
			SchemaVersion: "operations.migration.mongodb-oplog-delta.v1", Enabled: false,
			BaseArchiveDigest: baseArchiveDigest, SourceDatabase: binding.Database,
			Mutations: []mongodbOplogMutation{},
		}, nil
	}
	if !fileDigestPattern.MatchString(baseArchiveDigest) {
		return mongodbOplogDelta{}, errors.New("MongoDB base archive digest is invalid")
	}
	body := `
try {
const askioDatabaseName = ` + strconv.Quote(binding.Database) + `;
const askioAuthDatabaseName = ` + strconv.Quote(binding.AuthDatabase) + `;
const askioOplog = askioConnection.getDB("local").getCollection("oplog.rs");
const askioStart = Timestamp(` + strconv.FormatInt(start.Seconds, 10) + `, ` + strconv.FormatInt(start.Increment, 10) + `);
const askioFirst = askioOplog.find({}).sort({$natural: 1}).limit(1).next();
const askioLast = askioOplog.find({}).sort({$natural: -1}).limit(1).next();
if (!askioFirst || !askioLast || askioFirst.ts.compare(askioStart) > 0) throw new Error("oplog window rolled over");
const askioEnd = askioLast.ts;
const askioEntries = askioOplog.find({ts: {$gt: askioStart, $lte: askioEnd}}).sort({$natural: 1}).limit(` + strconv.Itoa(maximumMongoDeltaItems+1) + `).toArray();
if (askioEntries.length > ` + strconv.Itoa(maximumMongoDeltaItems) + `) throw new Error("oplog window exceeds entry limit");
const askioChanged = new Map();
const askioUnsupported = [];
const askioTrack = (entry) => {
  const prefix = askioDatabaseName + ".";
  if (typeof entry.ns !== "string" || !entry.ns.startsWith(prefix)) return;
  const collection = entry.ns.slice(prefix.length);
  if (!collection || collection === "$cmd") { askioUnsupported.push(entry.op + ":" + entry.ns); return; }
  if (!["i", "u", "d"].includes(entry.op)) { askioUnsupported.push(entry.op + ":" + entry.ns); return; }
  const id = entry.op === "u" ? entry.o2 && entry.o2._id : entry.o && entry.o._id;
  if (id === undefined) { askioUnsupported.push("missing-id:" + entry.ns); return; }
  askioChanged.set(collection + "\u0000" + EJSON.stringify(id, {relaxed: false}), {collection, id});
};
for (const entry of askioEntries) {
  if (entry.ns === askioDatabaseName + ".$cmd" || entry.ns === askioAuthDatabaseName + ".$cmd") askioUnsupported.push("command:" + entry.ns);
  if (entry.ns === "admin.$cmd" && entry.o && Array.isArray(entry.o.applyOps)) {
    for (const nested of entry.o.applyOps) {
      if (typeof nested.ns === "string" && nested.ns.startsWith(askioDatabaseName + ".")) askioUnsupported.push("transaction:" + nested.ns);
    }
  }
  askioTrack(entry);
}
if (askioUnsupported.length) throw new Error("unsupported scoped oplog operation");
const askioDatabase = askioConnection.getDB(askioDatabaseName);
const askioMutations = [];
for (const changed of Array.from(askioChanged.values()).sort((a, b) => (a.collection + EJSON.stringify(a.id)).localeCompare(b.collection + EJSON.stringify(b.id)))) {
  const document = askioDatabase.getCollection(changed.collection).findOne({_id: changed.id});
  askioMutations.push({collection: changed.collection, id: changed.id, document: document || null});
}
const askioChangedAfterEnd = askioOplog.find({ts: {$gt: askioEnd}, $or: [
  {ns: {$regex: "^" + askioDatabaseName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\."}},
  {ns: {$in: [askioDatabaseName + ".$cmd", askioAuthDatabaseName + ".$cmd", "admin.$cmd"]}}
]}).limit(1).hasNext();
if (askioChangedAfterEnd) throw new Error("source changed while the bounded oplog delta was materialized");
const askioDelta = {
  schema_version: "operations.migration.mongodb-oplog-delta.v1", enabled: true,
  base_archive_digest: ` + strconv.Quote(baseArchiveDigest) + `, source_database: askioDatabaseName,
  start: {seconds: ` + strconv.FormatInt(start.Seconds, 10) + `, increment: ` + strconv.FormatInt(start.Increment, 10) + `},
  end: {seconds: Number(askioEnd.getHighBits()), increment: Number(askioEnd.getLowBitsUnsigned())}, mutations: askioMutations
};
print("ASKIO_JSON:" + EJSON.stringify({ok: true, error_code: "", delta: askioDelta}, {relaxed: false}));
} catch (error) {
  const message = String(error && error.message ? error.message : "");
  const allowed = new Set(["oplog window rolled over", "oplog window exceeds entry limit", "unsupported scoped oplog operation", "source changed while the bounded oplog delta was materialized"]);
  print("ASKIO_JSON:" + EJSON.stringify({ok: false, error_code: allowed.has(message) ? message : "internal", delta: null}, {relaxed: true}));
}`
	var result struct {
		OK        bool              `json:"ok"`
		ErrorCode string            `json:"error_code"`
		Delta     mongodbOplogDelta `json:"delta"`
	}
	if err := e.runMongoDBShell(ctx, binding, body, &result); err != nil {
		return mongodbOplogDelta{}, errors.New("bounded MongoDB oplog replay capture failed")
	}
	if !result.OK {
		return mongodbOplogDelta{}, errors.New("bounded MongoDB oplog replay capture failed: " + result.ErrorCode)
	}
	delta := result.Delta
	if err := validateMongoDBOplogDelta(delta, binding, baseArchiveDigest, binding.Database); err != nil {
		return mongodbOplogDelta{}, err
	}
	return delta, nil
}

func (e *NativeExecutor) verifyMongoDBOplogStableAfter(ctx context.Context, binding mongodbBinding, end mongodbOplogTimestamp) error {
	if !binding.Features.OplogReplay || end.Seconds < 1 || end.Increment < 0 {
		return nil
	}
	body := `
const askioDatabaseName = ` + strconv.Quote(binding.Database) + `;
const askioAuthDatabaseName = ` + strconv.Quote(binding.AuthDatabase) + `;
const askioEnd = Timestamp(` + strconv.FormatInt(end.Seconds, 10) + `, ` + strconv.FormatInt(end.Increment, 10) + `);
const askioChanged = askioConnection.getDB("local").getCollection("oplog.rs").find({ts: {$gt: askioEnd}, $or: [
  {ns: {$regex: "^" + askioDatabaseName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\."}},
  {ns: {$in: [askioDatabaseName + ".$cmd", askioAuthDatabaseName + ".$cmd", "admin.$cmd"]}}
]}).limit(1).hasNext();
print("ASKIO_JSON:" + EJSON.stringify({stable: !askioChanged}, {relaxed: true}));`
	var result struct {
		Stable bool `json:"stable"`
	}
	if err := e.runMongoDBShell(ctx, binding, body, &result); err != nil || !result.Stable {
		return errors.New("source changed after the bounded MongoDB oplog window")
	}
	return nil
}

func validateMongoDBOplogDelta(delta mongodbOplogDelta, binding mongodbBinding, baseArchiveDigest, expectedSourceDatabase string) error {
	if delta.SchemaVersion != "operations.migration.mongodb-oplog-delta.v1" || delta.Enabled != binding.Features.OplogReplay ||
		delta.BaseArchiveDigest != baseArchiveDigest || delta.SourceDatabase != expectedSourceDatabase ||
		!mongodbDatabasePattern.MatchString(expectedSourceDatabase) || len(delta.Mutations) > maximumMongoDeltaItems {
		return errors.New("MongoDB oplog delta contract is invalid")
	}
	seen := map[string]struct{}{}
	for _, mutation := range delta.Mutations {
		if !mongodbCollectionPattern.MatchString(mutation.Collection) {
			return errors.New("MongoDB oplog delta mutation is invalid")
		}
		id, err := decodeMongoDBOplogValue(mutation.ID, false)
		if err != nil {
			return errors.New("MongoDB oplog delta identity is invalid")
		}
		if _, array := id.([]any); array {
			return errors.New("MongoDB oplog delta identity is invalid")
		}
		keyDigest, err := Digest(map[string]any{"collection": mutation.Collection, "id": id})
		if err != nil {
			return errors.New("MongoDB oplog delta identity is invalid")
		}
		if _, exists := seen[keyDigest]; exists {
			return errors.New("MongoDB oplog delta contains a duplicate document identity")
		}
		seen[keyDigest] = struct{}{}
		document, err := decodeMongoDBOplogValue(mutation.Document, true)
		if err != nil {
			return errors.New("MongoDB oplog delta document is invalid")
		}
		if document != nil {
			record, ok := document.(map[string]any)
			documentID, hasID := record["_id"]
			documentIDDigest, digestErr := Digest(documentID)
			idDigest, idDigestErr := Digest(id)
			if !ok || !hasID || digestErr != nil || idDigestErr != nil || documentIDDigest != idDigest {
				return errors.New("MongoDB oplog delta document identity changed")
			}
		}
	}
	return nil
}

func decodeMongoDBOplogValue(raw json.RawMessage, allowNull bool) (any, error) {
	if len(raw) == 0 || len(raw) > int(maximumMongoDeltaBytes) {
		return nil, errors.New("MongoDB oplog value is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || (!allowNull && value == nil) {
		return nil, errors.New("MongoDB oplog value is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("MongoDB oplog value contains trailing data")
	}
	return value, nil
}

func validateMongoDBIdentityArtifact(artifact mongodbIdentityArtifact, binding mongodbBinding, baseArchiveDigest string) error {
	if artifact.SchemaVersion != "operations.migration.mongodb-identity-artifact.v1" || artifact.BaseArchiveDigest != baseArchiveDigest ||
		artifact.IdentityMapDigest != MustDigest(map[string]any{"users": binding.UserMap, "roles": binding.RoleMap}) ||
		artifact.Manifest.SchemaVersion != "operations.migration.mongodb-identities.v1" || artifact.Manifest.Enabled != binding.Features.UsersAndRoles ||
		len(artifact.Manifest.Users) != len(binding.UserMap) || len(artifact.Manifest.Roles) != len(binding.RoleMap) {
		return errors.New("MongoDB identity artifact contract is invalid")
	}
	userTargets := map[string]struct{}{}
	for _, mapping := range binding.UserMap {
		userTargets[mapping.Target] = struct{}{}
	}
	roleTargets := map[string]struct{}{}
	for _, mapping := range binding.RoleMap {
		roleTargets[mapping.Target] = struct{}{}
	}
	for _, user := range artifact.Manifest.Users {
		if _, ok := userTargets[user.User]; !ok || len(user.Roles) > 128 {
			return errors.New("MongoDB identity artifact contains an undeclared user")
		}
		for _, role := range user.Roles {
			if role.DB != "application" {
				return errors.New("MongoDB identity artifact contains a cross-database role")
			}
			if _, custom := roleTargets[role.Role]; !custom {
				if _, builtin := mongodbBuiltinDatabaseRoles[role.Role]; !builtin {
					return errors.New("MongoDB identity artifact contains an undeclared role")
				}
			}
		}
	}
	for _, role := range artifact.Manifest.Roles {
		if _, ok := roleTargets[role.Role]; !ok || len(role.Roles) > 128 || len(role.Privileges) > 1_024 {
			return errors.New("MongoDB identity artifact contains an undeclared custom role")
		}
		for _, inherited := range role.Roles {
			if inherited.DB != "application" {
				return errors.New("MongoDB identity artifact contains a cross-database inherited role")
			}
			if _, custom := roleTargets[inherited.Role]; !custom {
				if _, builtin := mongodbBuiltinDatabaseRoles[inherited.Role]; !builtin {
					return errors.New("MongoDB identity artifact contains an undeclared inherited role")
				}
			}
		}
		for _, privilege := range role.Privileges {
			db, dbOK := privilege.Resource["db"].(string)
			collection, collectionOK := privilege.Resource["collection"].(string)
			if len(privilege.Resource) != 2 || !dbOK || db != "application" || !collectionOK || len(collection) > 255 || len(privilege.Actions) == 0 || len(privilege.Actions) > 128 {
				return errors.New("MongoDB identity artifact privilege is invalid")
			}
		}
	}
	return nil
}

func (e *NativeExecutor) applyMongoDBIdentities(ctx context.Context, binding mongodbBinding, artifact mongodbIdentityArtifact) error {
	if !artifact.Manifest.Enabled {
		return nil
	}
	encoded, err := json.Marshal(artifact.Manifest)
	if err != nil || int64(len(encoded)) > maximumMongoDeltaBytes {
		return errors.New("MongoDB identity application exceeds its safety limit")
	}
	body := `
const askioManifest = EJSON.parse(` + strconv.Quote(string(encoded)) + `);
const askioDatabase = askioConnection.getDB(` + strconv.Quote(binding.Database) + `);
const askioAuthDatabase = askioConnection.getDB(` + strconv.Quote(binding.AuthDatabase) + `);
for (const role of askioManifest.roles) {
  const existing = askioDatabase.runCommand({rolesInfo: {role: role.role, db: ` + strconv.Quote(binding.Database) + `}, showPrivileges: false});
  const result = existing.ok === 1 && (existing.roles || []).length === 1
    ? {ok: 1}
    : askioDatabase.runCommand({createRole: role.role, privileges: [], roles: []});
  if (result.ok !== 1) throw new Error("mapped custom role application failed");
}
for (const role of askioManifest.roles) {
  const roles = role.roles.map(entry => ({role: entry.role, db: ` + strconv.Quote(binding.Database) + `}));
  const privileges = role.privileges.map(entry => ({resource: {db: ` + strconv.Quote(binding.Database) + `, collection: entry.resource.collection}, actions: entry.actions}));
  const result = askioDatabase.runCommand({updateRole: role.role, privileges, roles});
  if (result.ok !== 1) throw new Error("mapped custom role definition failed");
}
for (const user of askioManifest.users) {
  const existing = askioAuthDatabase.runCommand({usersInfo: {user: user.user, db: ` + strconv.Quote(binding.AuthDatabase) + `}, showCredentials: false});
  if (existing.ok !== 1 || (existing.users || []).length !== 1) throw new Error("mapped target user is not pre-created");
  const roles = user.roles.map(entry => ({role: entry.role, db: ` + strconv.Quote(binding.Database) + `}));
  const result = askioAuthDatabase.runCommand({updateUser: user.user, roles});
  if (result.ok !== 1) throw new Error("mapped target user role assignment failed");
}
print("ASKIO_JSON:" + EJSON.stringify({ok: true}, {relaxed: true}));`
	var result struct {
		OK bool `json:"ok"`
	}
	if err := e.runMongoDBShell(ctx, binding, body, &result); err != nil || !result.OK {
		return errors.New("MongoDB identity application failed safely")
	}
	return nil
}

func (e *NativeExecutor) applyMongoDBOplogDelta(ctx context.Context, binding mongodbBinding, delta mongodbOplogDelta) error {
	if !delta.Enabled {
		return nil
	}
	encoded, err := json.Marshal(delta)
	if err != nil || int64(len(encoded)) > maximumMongoDeltaBytes {
		return errors.New("MongoDB oplog delta application exceeds its safety limit")
	}
	body := `
const askioDelta = EJSON.parse(` + strconv.Quote(string(encoded)) + `);
const askioDatabase = askioConnection.getDB(` + strconv.Quote(binding.Database) + `);
let askioApplied = 0;
for (const mutation of askioDelta.mutations) {
  const collection = askioDatabase.getCollection(mutation.collection);
  if (mutation.document === null) collection.deleteOne({_id: mutation.id});
  else collection.replaceOne({_id: mutation.id}, mutation.document, {upsert: true});
  askioApplied += 1;
}
print("ASKIO_JSON:" + EJSON.stringify({ok: true, applied: askioApplied}, {relaxed: true}));`
	var result struct {
		OK      bool `json:"ok"`
		Applied int  `json:"applied"`
	}
	if err := e.runMongoDBShell(ctx, binding, body, &result); err != nil || !result.OK || result.Applied != len(delta.Mutations) {
		return errors.New("MongoDB oplog delta application failed safely")
	}
	return nil
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
	if err != nil {
		return "", mongodbBinding{}, err
	}
	if err := validateMongoDBDatabaseContract(inputs, binding); err != nil {
		binding.clear()
		return "", mongodbBinding{}, err
	}
	return bindingID, binding, nil
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
	var oplogStart mongodbOplogTimestamp
	if binding.Features.OplogReplay {
		if inspection.Topology != "replica-set-primary" {
			return nil, errors.New("bounded MongoDB oplog replay requires a replica-set primary")
		}
		oplogStart, err = e.captureMongoDBOplogTimestamp(ctx, binding)
		if err != nil {
			return nil, err
		}
		if e.oplogWindowHookForTest != nil {
			if err := e.oplogWindowHookForTest(ctx, binding); err != nil {
				return nil, errors.New("bounded MongoDB oplog window hook failed")
			}
		}
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
	delta, err := e.captureMongoDBOplogDelta(ctx, binding, oplogStart, digest)
	if err != nil {
		return nil, err
	}
	finalInspection := inspection
	if delta.Enabled {
		finalInspection, err = e.inspectMongoDB(ctx, bindingID, binding)
		if err != nil {
			return nil, err
		}
		if err := e.verifyMongoDBOplogStableAfter(ctx, binding, delta.End); err != nil {
			return nil, err
		}
	}
	identityArtifact := mongodbIdentityArtifact{
		SchemaVersion: "operations.migration.mongodb-identity-artifact.v1", BaseArchiveDigest: digest,
		IdentityMapDigest: MustDigest(map[string]any{"users": binding.UserMap, "roles": binding.RoleMap}),
		Manifest:          finalInspection.Manifest.Identities,
	}
	if err := validateMongoDBIdentityArtifact(identityArtifact, binding, digest); err != nil {
		return nil, err
	}
	identityDigest, identitySize, err := writeMongoDBJSONArtifact(directory, mongodbIdentityArtifactHandle, identityArtifact, maximumMongoDeltaBytes)
	if err != nil {
		return nil, err
	}
	deltaDigest, deltaSize, err := writeMongoDBJSONArtifact(directory, mongodbOplogArtifactHandle, delta, maximumMongoDeltaBytes)
	if err != nil {
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
		"identity_artifact_handle": mongodbIdentityArtifactHandle, "identity_artifact_digest": identityDigest,
		"identity_artifact_size_bytes": identitySize, "oplog_artifact_handle": mongodbOplogArtifactHandle,
		"oplog_artifact_digest": deltaDigest, "oplog_artifact_size_bytes": deltaSize,
		"oplog_replay_enabled": delta.Enabled, "oplog_mutation_count": len(delta.Mutations),
		"database_manifest_digest": finalInspection.ManifestDigest, "source_database": binding.Database,
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
	identityHandle, err := stringInput(inputs, "identity_artifact_handle")
	if err != nil || identityHandle != mongodbIdentityArtifactHandle {
		return nil, errors.New("MongoDB identity artifact handle is invalid")
	}
	identityDigest, err := stringInput(inputs, "identity_artifact_digest")
	if err != nil || !fileDigestPattern.MatchString(identityDigest) {
		return nil, errors.New("MongoDB identity artifact digest is invalid")
	}
	identityPath, err := e.resolver.Resolve(stagingHandle, filepath.Join(stagingRelative, identityHandle), false)
	if err != nil {
		return nil, err
	}
	var identityArtifact mongodbIdentityArtifact
	if err := readMongoDBJSONArtifact(identityPath, identityDigest, maximumMongoDeltaBytes, &identityArtifact); err != nil {
		return nil, err
	}
	if err := validateMongoDBIdentityArtifact(identityArtifact, binding, actualDigest); err != nil {
		return nil, err
	}
	oplogHandle, err := stringInput(inputs, "oplog_artifact_handle")
	if err != nil || oplogHandle != mongodbOplogArtifactHandle {
		return nil, errors.New("MongoDB oplog artifact handle is invalid")
	}
	oplogDigest, err := stringInput(inputs, "oplog_artifact_digest")
	if err != nil || !fileDigestPattern.MatchString(oplogDigest) {
		return nil, errors.New("MongoDB oplog artifact digest is invalid")
	}
	oplogPath, err := e.resolver.Resolve(stagingHandle, filepath.Join(stagingRelative, oplogHandle), false)
	if err != nil {
		return nil, err
	}
	var oplogDelta mongodbOplogDelta
	if err := readMongoDBJSONArtifact(oplogPath, oplogDigest, maximumMongoDeltaBytes, &oplogDelta); err != nil {
		return nil, err
	}
	sourceDatabase, err := stringInput(inputs, "source_database")
	if err != nil || !mongodbDatabasePattern.MatchString(sourceDatabase) || sourceDatabase == "admin" || sourceDatabase == "local" || sourceDatabase == "config" {
		return nil, errors.New("MongoDB source namespace is invalid")
	}
	if err := validateMongoDBOplogDelta(oplogDelta, binding, actualDigest, sourceDatabase); err != nil {
		return nil, err
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
	if err := e.applyMongoDBOplogDelta(ctx, binding, oplogDelta); err != nil {
		return nil, err
	}
	if err := e.applyMongoDBIdentities(ctx, binding, identityArtifact); err != nil {
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
		"identity_artifact_digest": identityDigest, "oplog_artifact_digest": oplogDigest,
		"oplog_mutation_count": len(oplogDelta.Mutations), "restored_size_bytes": size,
		"collection_count": len(after.Manifest.Collections), "total_documents": after.TotalDocuments,
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
