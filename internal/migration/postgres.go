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
	postgresBindingSchema     = "operations.migration.postgres-binding.v1"
	postgresACLArtifactSchema = "operations.migration.postgres-acl.v1"
	postgresACLArtifactHandle = "database.acl.json"
	maximumPostgresACLBytes   = int64(16 * 1024 * 1024)
	maximumPostgresBytes      = int64(500 * 1024 * 1024 * 1024)
)

var (
	postgresIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	postgresExtensionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}@[A-Za-z0-9][A-Za-z0-9_.+~-]{0,127}$`)
	opaqueBindingPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

type postgresBinding struct {
	SchemaVersion       string            `json:"schema_version"`
	Mode                string            `json:"mode"`
	Host                string            `json:"host"`
	Port                int               `json:"port"`
	Database            string            `json:"database"`
	MaintenanceDatabase string            `json:"maintenance_database"`
	Username            string            `json:"username"`
	Password            string            `json:"password"`
	SSLMode             string            `json:"ssl_mode"`
	SSLRootCertPEM      string            `json:"ssl_root_cert_pem,omitempty"`
	RoleMap             map[string]string `json:"role_map"`
	TargetRole          string            `json:"target_role,omitempty"`
	ResetAllowed        bool              `json:"reset_allowed,omitempty"`
	TargetEncoding      string            `json:"target_encoding,omitempty"`
	TargetCollation     string            `json:"target_collation,omitempty"`
	TargetCType         string            `json:"target_ctype,omitempty"`
}

func (b *postgresBinding) clear() {
	b.Password = ""
	b.SSLRootCertPEM = ""
}

func validatePostgresHost(host, sslMode string) error {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t") {
		return errors.New("database binding host is invalid")
	}
	if filepath.IsAbs(host) {
		if filepath.Clean(host) != host || sslMode != "disable" {
			return errors.New("database Unix socket binding is invalid")
		}
		return nil
	}
	if sslMode == "disable" {
		address := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (address == nil || !address.IsLoopback()) {
			return errors.New("unencrypted PostgreSQL is allowed only over loopback or a Unix socket")
		}
	}
	return nil
}

func parsePostgresBinding(raw []byte) (postgresBinding, error) {
	var binding postgresBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return postgresBinding{}, errors.New("database binding JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return postgresBinding{}, errors.New("database binding contains trailing data")
	}
	if binding.SchemaVersion != postgresBindingSchema || (binding.Mode != "source" && binding.Mode != "target") {
		return postgresBinding{}, errors.New("database binding contract is unsupported")
	}
	if binding.Port < 1 || binding.Port > 65535 || !postgresIdentifierPattern.MatchString(binding.Database) ||
		!postgresIdentifierPattern.MatchString(binding.MaintenanceDatabase) || !postgresIdentifierPattern.MatchString(binding.Username) {
		return postgresBinding{}, errors.New("database binding contains an invalid identifier or port")
	}
	if strings.ContainsAny(binding.Password, "\x00\r\n") || len(binding.Password) > 16*1024 {
		return postgresBinding{}, errors.New("database binding credential is invalid")
	}
	switch binding.SSLMode {
	case "disable", "require":
	case "verify-ca", "verify-full":
		if !strings.Contains(binding.SSLRootCertPEM, "BEGIN CERTIFICATE") || len(binding.SSLRootCertPEM) > 64*1024 {
			return postgresBinding{}, errors.New("verified PostgreSQL TLS requires a bounded CA certificate")
		}
	default:
		return postgresBinding{}, errors.New("database binding ssl_mode is unsupported")
	}
	if err := validatePostgresHost(binding.Host, binding.SSLMode); err != nil {
		return postgresBinding{}, err
	}
	if len(binding.RoleMap) == 0 || len(binding.RoleMap) > 64 {
		return postgresBinding{}, errors.New("database binding requires a bounded explicit role map")
	}
	for source, target := range binding.RoleMap {
		if !postgresIdentifierPattern.MatchString(source) || !postgresIdentifierPattern.MatchString(target) {
			return postgresBinding{}, errors.New("database binding role map contains an invalid role")
		}
	}
	if binding.Mode == "target" {
		if !postgresIdentifierPattern.MatchString(binding.TargetRole) {
			return postgresBinding{}, errors.New("target database binding requires a target role")
		}
		for _, target := range binding.RoleMap {
			if target != binding.TargetRole {
				return postgresBinding{}, errors.New("the offline MVP requires every source role to map to the single target owner")
			}
		}
	}
	return binding, nil
}

type cappedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		if len(value) > remaining {
			value = value[:remaining]
		}
		_, _ = b.buffer.Write(value)
	}
	return original, nil
}

func fixedPostgresExecutable(name string) (string, error) {
	candidates := []string{filepath.Join("/usr/bin", name), filepath.Join("/usr/local/bin", name)}
	for major := 18; major >= 12; major-- {
		candidates = append(candidates, filepath.Join("/usr/lib/postgresql", strconv.Itoa(major), "bin", name))
	}
	return fixedExecutable(candidates...)
}

func pgpassEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, ":", `\:`)
}

func (e *NativeExecutor) runPostgres(ctx context.Context, binding postgresBinding, database, binary string, args ...string) ([]byte, error) {
	temporaryDir, err := os.MkdirTemp(e.stateDir, ".postgres-secret-")
	if err != nil {
		return nil, errors.New("database credential staging failed")
	}
	defer os.RemoveAll(temporaryDir)
	if err := os.Chmod(temporaryDir, 0o700); err != nil {
		return nil, errors.New("database credential staging failed")
	}
	passFile := filepath.Join(temporaryDir, "pgpass")
	passLine := strings.Join([]string{pgpassEscape(binding.Host), strconv.Itoa(binding.Port), pgpassEscape(database), pgpassEscape(binding.Username), pgpassEscape(binding.Password)}, ":") + "\n"
	if err := os.WriteFile(passFile, []byte(passLine), 0o600); err != nil {
		return nil, errors.New("database credential staging failed")
	}
	defer func() {
		data, readErr := os.ReadFile(passFile)
		if readErr == nil {
			zeroBytes(data)
			_ = os.WriteFile(passFile, data, 0o600)
		}
	}()
	environment := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent",
		"PGHOST=" + binding.Host, "PGPORT=" + strconv.Itoa(binding.Port), "PGDATABASE=" + database,
		"PGUSER=" + binding.Username, "PGPASSFILE=" + passFile, "PGSSLMODE=" + binding.SSLMode,
		"PGCONNECT_TIMEOUT=10", "PGAPPNAME=askio-migration-agent",
	}
	if binding.SSLRootCertPEM != "" {
		rootCert := filepath.Join(temporaryDir, "root.crt")
		if err := os.WriteFile(rootCert, []byte(binding.SSLRootCertPEM), 0o600); err != nil {
			return nil, errors.New("database TLS staging failed")
		}
		environment = append(environment, "PGSSLROOTCERT="+rootCert)
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	var stdout, stderr cappedBuffer
	stdout.limit = 8 * 1024 * 1024
	stderr.limit = 32 * 1024
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		return nil, errors.New("typed PostgreSQL operation failed")
	}
	return append([]byte{}, stdout.buffer.Bytes()...), nil
}

func (e *NativeExecutor) queryPostgres(ctx context.Context, binding postgresBinding, database, query string) ([][]string, error) {
	psql, err := fixedPostgresExecutable("psql")
	if err != nil {
		return nil, err
	}
	output, err := e.runPostgres(ctx, binding, database, psql,
		"--no-psqlrc", "--tuples-only", "--no-align", "--field-separator=\t", "--set=ON_ERROR_STOP=1", "--command", query)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(output))
	zeroBytes(output)
	if text == "" {
		return nil, nil
	}
	rows := [][]string{}
	for _, line := range strings.Split(text, "\n") {
		rows = append(rows, strings.Split(strings.TrimSuffix(line, "\r"), "\t"))
	}
	return rows, nil
}

func quotePostgresIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func quotePostgresLiteral(value string) string {
	return `'` + strings.ReplaceAll(value, `'`, `''`) + `'`
}

type postgresTableManifest struct {
	Schema         string `json:"schema"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	RowCount       int64  `json:"row_count"`
	SampleChecksum string `json:"sample_checksum"`
}

type postgresSequenceManifest struct {
	Schema   string `json:"schema"`
	Name     string `json:"name"`
	Last     string `json:"last_value"`
	IsCalled bool   `json:"is_called"`
}

type postgresPrivilegeManifest struct {
	ObjectType string `json:"object_type"`
	Schema     string `json:"schema"`
	Name       string `json:"name,omitempty"`
	Grantee    string `json:"grantee"`
	Privilege  string `json:"privilege"`
	Grantable  bool   `json:"grantable"`
}

type postgresManifest struct {
	SchemaVersion      string                      `json:"schema_version"`
	ServerMajor        int                         `json:"server_major"`
	Encoding           string                      `json:"encoding"`
	Collation          string                      `json:"collation"`
	CType              string                      `json:"ctype"`
	Extensions         []string                    `json:"extensions"`
	Tables             []postgresTableManifest     `json:"tables"`
	Sequences          []postgresSequenceManifest  `json:"sequences"`
	ObjectCounts       map[string]int64            `json:"object_counts"`
	NormalizedOwners   []string                    `json:"normalized_owners"`
	NormalizedGrantees []string                    `json:"normalized_grantees"`
	Privileges         []postgresPrivilegeManifest `json:"privileges"`
}

type postgresACLArtifact struct {
	SchemaVersion string                      `json:"schema_version"`
	RoleMapDigest string                      `json:"role_map_digest"`
	Privileges    []postgresPrivilegeManifest `json:"privileges"`
}

type postgresInspection struct {
	Exists                    bool
	Empty                     bool
	ServerVersionNumber       int
	Manifest                  postgresManifest
	ManifestDigest            string
	EmptyTargetDigest         string
	RoleMapDigest             string
	NonDefaultTablespaceCount int64
	TotalRows                 int64
	DatabaseBytes             int64
}

func normalizePostgresRole(role string, roleMap map[string]string) string {
	if mapped, ok := roleMap[role]; ok {
		return mapped
	}
	for _, mapped := range roleMap {
		if role == mapped {
			return role
		}
	}
	return role
}

func validPostgresPrivilege(objectType, privilege string) bool {
	allowed := map[string]map[string]struct{}{
		"TABLE": {
			"SELECT": {}, "INSERT": {}, "UPDATE": {}, "DELETE": {}, "TRUNCATE": {}, "REFERENCES": {}, "TRIGGER": {}, "MAINTAIN": {},
		},
		"SEQUENCE": {"SELECT": {}, "UPDATE": {}, "USAGE": {}},
		"SCHEMA":   {"CREATE": {}, "USAGE": {}},
	}
	privileges, ok := allowed[objectType]
	if !ok {
		return false
	}
	_, ok = privileges[privilege]
	return ok
}

func postgresPrivilegeKey(privilege postgresPrivilegeManifest, includeGrantable bool) string {
	key := strings.Join([]string{privilege.ObjectType, privilege.Schema, privilege.Name, privilege.Grantee, privilege.Privilege}, "\x00")
	if includeGrantable {
		key += "\x00" + strconv.FormatBool(privilege.Grantable)
	}
	return key
}

func normalizePostgresACLGrantee(role string, binding postgresBinding, databaseOwner string) (string, error) {
	if role == "PUBLIC" {
		return role, nil
	}
	if role == "pg_database_owner" {
		return databaseOwner, nil
	}
	if !postgresIdentifierPattern.MatchString(role) || strings.HasPrefix(role, "pg_") {
		return "", errors.New("database privilege inventory contains an unsupported role")
	}
	if binding.Mode == "source" {
		mapped, declared := binding.RoleMap[role]
		if !declared {
			return "", errors.New("database grantee is missing from the explicit role map")
		}
		return mapped, nil
	}
	normalized := normalizePostgresRole(role, binding.RoleMap)
	if normalized != binding.TargetRole {
		return "", errors.New("database grantee is missing from the explicit role map")
	}
	return normalized, nil
}

func parseSingleInt(rows [][]string) (int64, error) {
	if len(rows) != 1 || len(rows[0]) != 1 {
		return 0, errors.New("PostgreSQL returned an invalid bounded result")
	}
	return strconv.ParseInt(rows[0][0], 10, 64)
}

func invalidCatalogIdentifier(value string) bool {
	return value == "" || len(value) > 63 || strings.ContainsAny(value, "\x00\r\n\t")
}

func (e *NativeExecutor) inspectPostgres(ctx context.Context, bindingID string, binding postgresBinding) (postgresInspection, error) {
	roleMapDigest, err := Digest(binding.RoleMap)
	if err != nil {
		return postgresInspection{}, err
	}
	databaseRow, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase,
		"select encoding::text,datcollate,datctype from pg_database where datname="+quotePostgresLiteral(binding.Database))
	if err != nil {
		return postgresInspection{}, err
	}
	versionRows, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase, "show server_version_num")
	if err != nil {
		return postgresInspection{}, err
	}
	versionValue, err := parseSingleInt(versionRows)
	if err != nil {
		return postgresInspection{}, err
	}
	inspection := postgresInspection{Exists: len(databaseRow) == 1, ServerVersionNumber: int(versionValue), RoleMapDigest: roleMapDigest}
	if len(databaseRow) > 1 || (len(databaseRow) == 1 && len(databaseRow[0]) != 3) {
		return postgresInspection{}, errors.New("database catalog identity is ambiguous")
	}
	if !inspection.Exists {
		inspection.Empty = true
		inspection.EmptyTargetDigest, err = Digest(map[string]any{
			"schema_version": "operations.migration.postgres-empty-target.v1", "binding_id": bindingID,
			"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database}),
			"exists":            false, "server_major": inspection.ServerVersionNumber / 10000, "role_map_digest": roleMapDigest,
		})
		return inspection, err
	}
	metadataRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select current_setting('server_version_num'),pg_encoding_to_char(encoding),datcollate,datctype from pg_database where datname=current_database()")
	if err != nil || len(metadataRows) != 1 || len(metadataRows[0]) != 4 {
		return postgresInspection{}, errors.New("database metadata inspection failed")
	}
	sizeRows, err := e.queryPostgres(ctx, binding, binding.Database, "select pg_database_size(current_database())")
	if err != nil {
		return postgresInspection{}, err
	}
	inspection.DatabaseBytes, err = parseSingleInt(sizeRows)
	if err != nil || inspection.DatabaseBytes < 0 {
		return postgresInspection{}, errors.New("database size inspection failed")
	}
	serverVersion, parseErr := strconv.Atoi(metadataRows[0][0])
	if parseErr != nil {
		return postgresInspection{}, errors.New("database server version is invalid")
	}
	manifest := postgresManifest{
		SchemaVersion: "operations.migration.postgres-manifest.v1", ServerMajor: serverVersion / 10000,
		Encoding: metadataRows[0][1], Collation: metadataRows[0][2], CType: metadataRows[0][3],
		Extensions: []string{}, Tables: []postgresTableManifest{}, Sequences: []postgresSequenceManifest{},
		ObjectCounts: map[string]int64{}, NormalizedOwners: []string{}, NormalizedGrantees: []string{}, Privileges: []postgresPrivilegeManifest{},
	}
	extensionRows, err := e.queryPostgres(ctx, binding, binding.Database, "select extname,extversion from pg_extension order by extname")
	if err != nil {
		return postgresInspection{}, err
	}
	for _, row := range extensionRows {
		extension := ""
		if len(row) == 2 {
			extension = row[0] + "@" + row[1]
		}
		if !postgresExtensionPattern.MatchString(extension) {
			return postgresInspection{}, errors.New("database extension inventory is unsafe")
		}
		manifest.Extensions = append(manifest.Extensions, extension)
	}
	tableRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select n.nspname,c.relname,c.relkind::text from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and c.relkind in('r','p','m','f') order by n.nspname,c.relname")
	if err != nil {
		return postgresInspection{}, err
	}
	if len(tableRows) > 2048 {
		return postgresInspection{}, errors.New("database exceeds the 2048-table safety limit")
	}
	for _, row := range tableRows {
		if len(row) != 3 || invalidCatalogIdentifier(row[0]) || invalidCatalogIdentifier(row[1]) {
			return postgresInspection{}, errors.New("database object identifier is unsupported")
		}
		qualified := quotePostgresIdentifier(row[0]) + "." + quotePostgresIdentifier(row[1])
		checksumQuery := "select (select count(*) from " + qualified + ")::text," +
			"(select coalesce(md5(string_agg(row_hash,'' order by row_hash)),md5('')) from (select md5(row_to_json(sample_row)::text) row_hash from " + qualified + " sample_row order by 1 limit 1000) sampled)::text"
		checksumRows, queryErr := e.queryPostgres(ctx, binding, binding.Database, checksumQuery)
		if queryErr != nil || len(checksumRows) != 1 || len(checksumRows[0]) != 2 {
			return postgresInspection{}, errors.New("database table manifest calculation failed")
		}
		rowCount, parseErr := strconv.ParseInt(checksumRows[0][0], 10, 64)
		if parseErr != nil || len(checksumRows[0][1]) != 32 {
			return postgresInspection{}, errors.New("database table manifest result is invalid")
		}
		inspection.TotalRows += rowCount
		manifest.Tables = append(manifest.Tables, postgresTableManifest{Schema: row[0], Name: row[1], Kind: row[2], RowCount: rowCount, SampleChecksum: checksumRows[0][1]})
	}
	sequenceRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select sequence_schema,sequence_name from information_schema.sequences where sequence_schema not in('pg_catalog','information_schema') order by sequence_schema,sequence_name")
	if err != nil {
		return postgresInspection{}, err
	}
	if len(sequenceRows) > 4096 {
		return postgresInspection{}, errors.New("database exceeds the 4096-sequence safety limit")
	}
	for _, row := range sequenceRows {
		if len(row) != 2 || invalidCatalogIdentifier(row[0]) || invalidCatalogIdentifier(row[1]) {
			return postgresInspection{}, errors.New("database sequence identifier is unsupported")
		}
		valueRows, queryErr := e.queryPostgres(ctx, binding, binding.Database,
			"select last_value::text,case when is_called then 't' else 'f' end from "+quotePostgresIdentifier(row[0])+"."+quotePostgresIdentifier(row[1]))
		if queryErr != nil || len(valueRows) != 1 || len(valueRows[0]) != 2 {
			return postgresInspection{}, errors.New("database sequence manifest calculation failed")
		}
		manifest.Sequences = append(manifest.Sequences, postgresSequenceManifest{Schema: row[0], Name: row[1], Last: valueRows[0][0], IsCalled: valueRows[0][1] == "t"})
	}
	countQueries := map[string]string{
		"constraints": "select count(*) from pg_constraint c join pg_namespace n on n.oid=c.connamespace where n.nspname not in('pg_catalog','information_schema')",
		"functions":   "select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast'",
		"indexes":     "select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='i' and n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast'",
		"schemas":     "select count(*) from pg_namespace where nspname not in('pg_catalog','information_schema','public') and nspname !~ '^pg_toast'",
		"triggers":    "select count(*) from pg_trigger t join pg_class c on c.oid=t.tgrelid join pg_namespace n on n.oid=c.relnamespace where not t.tgisinternal and n.nspname not in('pg_catalog','information_schema')",
	}
	for key, query := range countQueries {
		rows, queryErr := e.queryPostgres(ctx, binding, binding.Database, query)
		value, parseErr := parseSingleInt(rows)
		if queryErr != nil || parseErr != nil {
			return postgresInspection{}, errors.New("database object inventory failed")
		}
		manifest.ObjectCounts[key] = value
	}
	databaseOwnerRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select pg_get_userbyid(datdba) from pg_database where datname=current_database()")
	if err != nil || len(databaseOwnerRows) != 1 || len(databaseOwnerRows[0]) != 1 || !postgresIdentifierPattern.MatchString(databaseOwnerRows[0][0]) {
		return postgresInspection{}, errors.New("database owner inventory is invalid")
	}
	databaseOwner := databaseOwnerRows[0][0]
	if binding.Mode == "source" {
		mapped, declared := binding.RoleMap[databaseOwner]
		if !declared {
			return postgresInspection{}, errors.New("database owner is missing from the explicit role map")
		}
		databaseOwner = mapped
	} else {
		databaseOwner = normalizePostgresRole(databaseOwner, binding.RoleMap)
		if databaseOwner != binding.TargetRole {
			return postgresInspection{}, errors.New("target database owner does not match the declared target role")
		}
	}
	ownerRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select distinct role_name from (select pg_get_userbyid(c.relowner) role_name from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' union select pg_get_userbyid(p.proowner) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast') roles where role_name !~ '^pg_' order by role_name")
	if err != nil {
		return postgresInspection{}, err
	}
	ownerSet := map[string]struct{}{databaseOwner: {}}
	for _, row := range ownerRows {
		if len(row) != 1 || !postgresIdentifierPattern.MatchString(row[0]) {
			return postgresInspection{}, errors.New("database owner inventory contains an unsupported role")
		}
		if binding.Mode == "source" {
			if _, declared := binding.RoleMap[row[0]]; !declared {
				return postgresInspection{}, errors.New("database owner is missing from the explicit role map")
			}
		}
		ownerSet[normalizePostgresRole(row[0], binding.RoleMap)] = struct{}{}
	}
	for role := range ownerSet {
		manifest.NormalizedOwners = append(manifest.NormalizedOwners, role)
	}
	sort.Strings(manifest.NormalizedOwners)
	customFunctionACLRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and p.proacl is not null")
	if err != nil {
		return postgresInspection{}, err
	}
	customFunctionACLCount, err := parseSingleInt(customFunctionACLRows)
	if err != nil || customFunctionACLCount != 0 {
		return postgresInspection{}, errors.New("custom function privileges are outside the offline MVP")
	}
	defaultACLRows, err := e.queryPostgres(ctx, binding, binding.Database, "select count(*) from pg_default_acl")
	if err != nil {
		return postgresInspection{}, err
	}
	defaultACLCount, err := parseSingleInt(defaultACLRows)
	if err != nil || defaultACLCount != 0 {
		return postgresInspection{}, errors.New("custom default privileges are outside the offline MVP")
	}
	granteeRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select object_type,object_schema,object_name,grantee,privilege_type,case when is_grantable then 't' else 'f' end from (select case when c.relkind='S' then 'SEQUENCE' else 'TABLE' end object_type,n.nspname object_schema,c.relname object_name,case when acl.grantee=0 then 'PUBLIC' else pg_get_userbyid(acl.grantee) end grantee,acl.privilege_type,acl.is_grantable from pg_class c join pg_namespace n on n.oid=c.relnamespace cross join lateral aclexplode(coalesce(c.relacl,acldefault(case when c.relkind='S' then 's'::\"char\" else 'r'::\"char\" end,c.relowner))) acl where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and c.relkind in('r','p','v','m','f','S') union all select 'SCHEMA',n.nspname,'',case when acl.grantee=0 then 'PUBLIC' else pg_get_userbyid(acl.grantee) end,acl.privilege_type,acl.is_grantable from pg_namespace n cross join lateral aclexplode(coalesce(n.nspacl,acldefault('n'::\"char\",n.nspowner))) acl where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast') privileges order by object_type,object_schema,object_name,grantee,privilege_type,is_grantable")
	if err != nil {
		return postgresInspection{}, err
	}
	if len(granteeRows) > 100_000 {
		return postgresInspection{}, errors.New("database privilege manifest exceeds the 100000-entry limit")
	}
	granteeSet := map[string]struct{}{}
	normalizedPrivileges := map[string]postgresPrivilegeManifest{}
	for _, row := range granteeRows {
		if len(row) != 6 || !validPostgresPrivilege(row[0], row[4]) || invalidCatalogIdentifier(row[1]) ||
			(row[0] != "SCHEMA" && invalidCatalogIdentifier(row[2])) ||
			(row[0] == "SCHEMA" && row[2] != "") || (row[5] != "t" && row[5] != "f") {
			return postgresInspection{}, errors.New("database privilege inventory contains an unsupported role")
		}
		normalizedGrantee, normalizeErr := normalizePostgresACLGrantee(row[3], binding, databaseOwner)
		if normalizeErr != nil {
			return postgresInspection{}, normalizeErr
		}
		granteeSet[normalizedGrantee] = struct{}{}
		privilege := postgresPrivilegeManifest{
			ObjectType: row[0], Schema: row[1], Name: row[2], Grantee: normalizedGrantee,
			Privilege: row[4], Grantable: row[5] == "t",
		}
		key := postgresPrivilegeKey(privilege, false)
		if existing, present := normalizedPrivileges[key]; present {
			privilege.Grantable = privilege.Grantable || existing.Grantable
		}
		normalizedPrivileges[key] = privilege
	}
	for _, privilege := range normalizedPrivileges {
		manifest.Privileges = append(manifest.Privileges, privilege)
	}
	sort.Slice(manifest.Privileges, func(left, right int) bool {
		return postgresPrivilegeKey(manifest.Privileges[left], true) < postgresPrivilegeKey(manifest.Privileges[right], true)
	})
	for role := range granteeSet {
		manifest.NormalizedGrantees = append(manifest.NormalizedGrantees, role)
	}
	sort.Strings(manifest.NormalizedGrantees)
	tablespaceRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_class c join pg_tablespace t on t.oid=c.reltablespace where t.spcname not in('pg_default','pg_global')")
	if err != nil {
		return postgresInspection{}, err
	}
	inspection.NonDefaultTablespaceCount, err = parseSingleInt(tablespaceRows)
	if err != nil {
		return postgresInspection{}, err
	}
	inspection.Manifest = manifest
	inspection.ManifestDigest, err = Digest(manifest)
	if err != nil {
		return postgresInspection{}, err
	}
	inspection.Empty = len(manifest.Tables) == 0 && len(manifest.Sequences) == 0 && manifest.ObjectCounts["functions"] == 0 && manifest.ObjectCounts["schemas"] == 0
	inspection.EmptyTargetDigest, err = Digest(map[string]any{
		"schema_version": "operations.migration.postgres-empty-target.v1", "binding_id": bindingID,
		"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database}),
		"exists":            true, "empty": inspection.Empty, "server_major": manifest.ServerMajor,
		"encoding": manifest.Encoding, "collation": manifest.Collation, "ctype": manifest.CType,
		"role_map_digest": roleMapDigest,
	})
	return inspection, err
}

func postgresInspectionOutputs(inspection postgresInspection) map[string]any {
	extensionsDigest, _ := Digest(inspection.Manifest.Extensions)
	return map[string]any{
		"exists": inspection.Exists, "empty": inspection.Empty,
		"server_version_number": inspection.ServerVersionNumber, "server_major": inspection.ServerVersionNumber / 10000,
		"encoding": inspection.Manifest.Encoding, "collation_digest": MustDigest(map[string]any{"collation": inspection.Manifest.Collation, "ctype": inspection.Manifest.CType}),
		"extension_set_digest": extensionsDigest, "required_extensions": append([]string{}, inspection.Manifest.Extensions...),
		"table_count": len(inspection.Manifest.Tables), "total_rows": inspection.TotalRows,
		"database_bytes":           inspection.DatabaseBytes,
		"database_manifest_digest": inspection.ManifestDigest, "empty_target_digest": inspection.EmptyTargetDigest,
		"role_map_digest": inspection.RoleMapDigest, "non_default_tablespace_count": inspection.NonDefaultTablespaceCount,
	}
}

func requiredPostgresExtensionsInput(inputs map[string]any) ([]string, error) {
	raw, present := inputs["required_extensions"]
	if !present {
		return nil, nil
	}
	values := []string{}
	switch entries := raw.(type) {
	case []any:
		for _, entry := range entries {
			value, ok := entry.(string)
			if !ok {
				return nil, errors.New("required PostgreSQL extension set is invalid")
			}
			values = append(values, value)
		}
	case []string:
		values = append(values, entries...)
	default:
		return nil, errors.New("required PostgreSQL extension set is invalid")
	}
	if len(values) == 0 || len(values) > 128 {
		return nil, errors.New("required PostgreSQL extension set is invalid")
	}
	previous := ""
	for _, value := range values {
		if !postgresExtensionPattern.MatchString(value) || value <= previous {
			return nil, errors.New("required PostgreSQL extension set is not canonical")
		}
		previous = value
	}
	return values, nil
}

func (e *NativeExecutor) verifyPostgresCompatibility(ctx context.Context, binding postgresBinding, inputs map[string]any, inspection postgresInspection) error {
	rawMajor, hasMajor := inputs["required_source_major"]
	requiredExtensions, extensionsErr := requiredPostgresExtensionsInput(inputs)
	if !hasMajor && requiredExtensions == nil && extensionsErr == nil {
		return nil
	}
	if binding.Mode != "target" {
		return errors.New("PostgreSQL compatibility verification requires a target binding")
	}
	if extensionsErr != nil {
		return extensionsErr
	}
	requiredMajor, err := boundedIntegerInput(map[string]any{"major": rawMajor}, "major", 14, 17)
	if err != nil || inspection.ServerVersionNumber/10000 < int(requiredMajor) || inspection.ServerVersionNumber/10000 > 17 {
		return errors.New("target PostgreSQL major is outside the supported compatibility range")
	}
	conditions := make([]string, 0, len(requiredExtensions))
	for _, extension := range requiredExtensions {
		parts := strings.SplitN(extension, "@", 2)
		conditions = append(conditions, "(name="+quotePostgresLiteral(parts[0])+" and version="+quotePostgresLiteral(parts[1])+")")
	}
	rows, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase,
		"select name,version from pg_available_extension_versions where "+strings.Join(conditions, " or ")+" order by name,version")
	if err != nil || len(rows) != len(requiredExtensions) {
		return errors.New("required PostgreSQL extension versions are not preinstalled on the target")
	}
	for index, row := range rows {
		if len(row) != 2 || row[0]+"@"+row[1] != requiredExtensions[index] {
			return errors.New("required PostgreSQL extension versions are not preinstalled on the target")
		}
	}
	return nil
}

func fileSHA256(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), size, nil
}

type postgresResetMarker struct {
	SchemaVersion      string `json:"schema_version"`
	MigrationID        string `json:"migration_id"`
	BindingID          string `json:"binding_id"`
	DatabaseIdentity   string `json:"database_identity"`
	InitialEmptyDigest string `json:"initial_empty_digest"`
	Generation         int    `json:"generation"`
	UpdatedAt          string `json:"updated_at"`
}

func (e *NativeExecutor) postgresMarkerPath(bindingID string) string {
	digest := sha256.Sum256([]byte(bindingID))
	return filepath.Join(e.stateDir, "postgres-reset-markers", hex.EncodeToString(digest[:16])+".json")
}

func (e *NativeExecutor) loadPostgresMarker(bindingID string) (postgresResetMarker, error) {
	data, err := os.ReadFile(e.postgresMarkerPath(bindingID))
	if err != nil {
		return postgresResetMarker{}, err
	}
	var marker postgresResetMarker
	if json.Unmarshal(data, &marker) != nil || marker.SchemaVersion != "operations.migration.postgres-reset-marker.v1" {
		return postgresResetMarker{}, errors.New("target database ownership marker is invalid")
	}
	return marker, nil
}

func (e *NativeExecutor) savePostgresMarker(bindingID string, marker postgresResetMarker) error {
	path := e.postgresMarkerPath(bindingID)
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
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func writePostgresACLArtifact(directory string, inspection postgresInspection) (string, int64, error) {
	artifact := postgresACLArtifact{
		SchemaVersion: postgresACLArtifactSchema,
		RoleMapDigest: inspection.RoleMapDigest,
		Privileges:    inspection.Manifest.Privileges,
	}
	data, err := json.Marshal(artifact)
	if err != nil || int64(len(data)) > maximumPostgresACLBytes {
		return "", 0, errors.New("database privilege artifact exceeds its safety limit")
	}
	data = append(data, '\n')
	path := filepath.Join(directory, postgresACLArtifactHandle)
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

func readPostgresACLArtifact(path string, expectedDigest, expectedRoleMapDigest, targetRole string) (postgresACLArtifact, error) {
	digest, _, err := fileSHA256(path)
	if err != nil || digest != expectedDigest {
		return postgresACLArtifact{}, errors.New("database privilege artifact digest verification failed")
	}
	file, info, err := openRegularNoFollow(path)
	if err != nil {
		return postgresACLArtifact{}, errors.New("database privilege artifact is unsafe")
	}
	defer file.Close()
	if info.Size() < 1 || info.Size() > maximumPostgresACLBytes {
		return postgresACLArtifact{}, errors.New("database privilege artifact exceeds its safety limit")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximumPostgresACLBytes+1))
	decoder.DisallowUnknownFields()
	var artifact postgresACLArtifact
	if err := decoder.Decode(&artifact); err != nil {
		return postgresACLArtifact{}, errors.New("database privilege artifact is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return postgresACLArtifact{}, errors.New("database privilege artifact contains trailing data")
	}
	if artifact.SchemaVersion != postgresACLArtifactSchema || artifact.RoleMapDigest != expectedRoleMapDigest || len(artifact.Privileges) > 100_000 {
		return postgresACLArtifact{}, errors.New("database privilege artifact contract is invalid")
	}
	previous := ""
	for index, privilege := range artifact.Privileges {
		if !validPostgresPrivilege(privilege.ObjectType, privilege.Privilege) || invalidCatalogIdentifier(privilege.Schema) ||
			(privilege.ObjectType == "SCHEMA" && privilege.Name != "") ||
			(privilege.ObjectType != "SCHEMA" && invalidCatalogIdentifier(privilege.Name)) ||
			(privilege.Grantee != "PUBLIC" && privilege.Grantee != targetRole) {
			return postgresACLArtifact{}, errors.New("database privilege artifact contains an unsupported grant")
		}
		key := postgresPrivilegeKey(privilege, true)
		if index > 0 && key <= previous {
			return postgresACLArtifact{}, errors.New("database privilege artifact is not canonical")
		}
		previous = key
	}
	return artifact, nil
}

func postgresPrivilegeObjectSQL(privilege postgresPrivilegeManifest) string {
	if privilege.ObjectType == "SCHEMA" {
		return "SCHEMA " + quotePostgresIdentifier(privilege.Schema)
	}
	return privilege.ObjectType + " " + quotePostgresIdentifier(privilege.Schema) + "." + quotePostgresIdentifier(privilege.Name)
}

func (e *NativeExecutor) applyPostgresACL(ctx context.Context, binding postgresBinding, artifact postgresACLArtifact) error {
	var script strings.Builder
	script.WriteString("SET LOCAL ROLE ")
	script.WriteString(quotePostgresIdentifier(binding.TargetRole))
	script.WriteString(";\n")
	objects := map[string]postgresPrivilegeManifest{}
	for _, privilege := range artifact.Privileges {
		key := strings.Join([]string{privilege.ObjectType, privilege.Schema, privilege.Name}, "\x00")
		objects[key] = privilege
	}
	objectKeys := make([]string, 0, len(objects))
	for key := range objects {
		objectKeys = append(objectKeys, key)
	}
	sort.Strings(objectKeys)
	for _, key := range objectKeys {
		script.WriteString("REVOKE ALL PRIVILEGES ON ")
		script.WriteString(postgresPrivilegeObjectSQL(objects[key]))
		script.WriteString(" FROM PUBLIC;\n")
	}
	for _, privilege := range artifact.Privileges {
		script.WriteString("GRANT ")
		script.WriteString(privilege.Privilege)
		script.WriteString(" ON ")
		script.WriteString(postgresPrivilegeObjectSQL(privilege))
		script.WriteString(" TO ")
		if privilege.Grantee == "PUBLIC" {
			script.WriteString("PUBLIC")
		} else {
			script.WriteString(quotePostgresIdentifier(privilege.Grantee))
		}
		if privilege.Grantable {
			script.WriteString(" WITH GRANT OPTION")
		}
		script.WriteString(";\n")
		if int64(script.Len()) > maximumPostgresACLBytes {
			return errors.New("database privilege application exceeds its safety limit")
		}
	}
	file, err := os.CreateTemp(e.stateDir, ".postgres-acl-*.sql")
	if err != nil {
		return errors.New("database privilege staging failed")
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return errors.New("database privilege staging failed")
	}
	if _, err := file.WriteString(script.String()); err != nil {
		_ = file.Close()
		return errors.New("database privilege staging failed")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("database privilege staging failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("database privilege staging failed")
	}
	psql, err := fixedPostgresExecutable("psql")
	if err != nil {
		return err
	}
	if _, err := e.runPostgres(ctx, binding, binding.Database, psql,
		"--no-psqlrc", "--set=ON_ERROR_STOP=1", "--single-transaction", "--file="+path); err != nil {
		return errors.New("database privilege application failed")
	}
	return nil
}

func (e *NativeExecutor) resolvePostgresBinding(ctx context.Context, task TaskEnvelope, inputs map[string]any) (string, postgresBinding, error) {
	bindingID, err := stringInput(inputs, "database_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return "", postgresBinding{}, errors.New("database binding identifier is invalid")
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return "", postgresBinding{}, err
	}
	defer zeroBytes(raw)
	binding, err := parsePostgresBinding(raw)
	return bindingID, binding, err
}

func (e *NativeExecutor) postgresInspect(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	inspection, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if inspection.NonDefaultTablespaceCount > 0 {
		return nil, errors.New("non-default PostgreSQL tablespaces are unsupported")
	}
	serverMajor := inspection.ServerVersionNumber / 10000
	if serverMajor < 14 || serverMajor > 17 || inspection.DatabaseBytes > maximumPostgresBytes {
		return nil, errors.New("PostgreSQL version or database size is outside the supported offline matrix")
	}
	if err := e.verifyPostgresCompatibility(ctx, binding, inputs, inspection); err != nil {
		return nil, err
	}
	if requireEmpty, ok := inputs["require_empty_target"].(bool); ok && requireEmpty {
		if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") {
			return nil, errors.New("target database is not constrained to the migration namespace")
		}
		if !inspection.Empty {
			return nil, errors.New("target database must be new or empty before any migration mutation")
		}
	}
	return postgresInspectionOutputs(inspection), nil
}

func (e *NativeExecutor) postgresDump(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("PostgreSQL dump requires a source binding")
	}
	inspection, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if !inspection.Exists || inspection.NonDefaultTablespaceCount > 0 {
		return nil, errors.New("source database is missing or uses unsupported tablespaces")
	}
	if err := progress("postgres_manifest", int64(len(inspection.Manifest.Tables)), nil); err != nil {
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
	// Custom-format archives are usually smaller than the live database, but
	// reserve against the full inspected size so a dump cannot consume the
	// staging filesystem's safety margin.
	if err := e.ensureCapacity(stagingRoot, inspection.DatabaseBytes); err != nil {
		return nil, err
	}
	attemptToken := strings.ReplaceAll(task.AttemptID, "-", "")
	if len(attemptToken) > 12 {
		attemptToken = attemptToken[:12]
	}
	manifestToken := strings.TrimPrefix(inspection.ManifestDigest, "sha256:")
	artifactDirectoryHandle := "postgres-" + manifestToken[:16] + "-" + attemptToken
	artifactDirectory, err := e.resolver.Resolve(stagingHandle, artifactDirectoryHandle, true)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(artifactDirectory) != stagingRoot {
		return nil, errors.New("database dump artifact escaped its staging root")
	}
	if _, err := os.Lstat(artifactDirectory); err == nil {
		return nil, errors.New("database dump artifact collision")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Mkdir(artifactDirectory, 0o700); err != nil {
		return nil, err
	}
	artifactHandle := "database.dump"
	artifactPath := filepath.Join(artifactDirectory, artifactHandle)
	partialPath := artifactPath + ".partial"
	if err := os.Remove(partialPath); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	pgDump, err := fixedPostgresExecutable("pg_dump")
	if err != nil {
		return nil, err
	}
	if _, err := e.runPostgres(ctx, binding, binding.Database, pgDump,
		"--format=custom", "--compress=6", "--no-owner", "--no-privileges", "--lock-wait-timeout=5000", "--file="+partialPath); err != nil {
		_ = os.Remove(partialPath)
		return nil, err
	}
	if err := os.Chmod(partialPath, 0o600); err != nil {
		_ = os.Remove(partialPath)
		return nil, err
	}
	digest, size, err := fileSHA256(partialPath)
	if err != nil {
		_ = os.Remove(partialPath)
		return nil, err
	}
	if err := os.Rename(partialPath, artifactPath); err != nil {
		_ = os.Remove(partialPath)
		return nil, err
	}
	aclDigest, aclSize, err := writePostgresACLArtifact(artifactDirectory, inspection)
	if err != nil {
		return nil, err
	}
	transferManifest, err := buildFileManifest(ctx, artifactDirectory, nil)
	if err != nil {
		return nil, err
	}
	if err := progress("postgres_dump_complete", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"dump_artifact_handle": artifactHandle, "dump_staging_relative_handle": artifactDirectoryHandle,
		"dump_artifact_digest": digest, "dump_transfer_manifest_digest": transferManifest.Digest, "dump_size_bytes": transferManifest.TotalBytes,
		"dump_archive_size_bytes": size, "acl_artifact_handle": postgresACLArtifactHandle,
		"acl_artifact_digest": aclDigest, "acl_artifact_size_bytes": aclSize,
		"database_manifest_digest": inspection.ManifestDigest, "role_map_digest": inspection.RoleMapDigest,
		"server_major": inspection.Manifest.ServerMajor,
	}, nil
}

func (e *NativeExecutor) postgresReset(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") {
		return nil, errors.New("target database reset is not explicitly constrained")
	}
	expectedDigest, err := stringInput(inputs, "expected_empty_target_digest")
	if err != nil || !strings.HasPrefix(expectedDigest, "sha256:") {
		return nil, errors.New("expected empty target digest is invalid")
	}
	inspection, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	marker, markerErr := e.loadPostgresMarker(bindingID)
	databaseIdentity := MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database})
	ownedByRun := markerErr == nil && marker.MigrationID == task.MigrationID && marker.BindingID == bindingID && marker.DatabaseIdentity == databaseIdentity && marker.InitialEmptyDigest == expectedDigest
	if (!inspection.Empty || inspection.EmptyTargetDigest != expectedDigest) && !ownedByRun {
		return nil, errors.New("target database is not the approved empty target and is not owned by this migration")
	}
	roleRows, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase, "select count(*) from pg_roles where rolname="+quotePostgresLiteral(binding.TargetRole))
	if err != nil {
		return nil, err
	}
	roleCount, err := parseSingleInt(roleRows)
	if err != nil || roleCount != 1 {
		return nil, errors.New("declared target role is not pre-created")
	}
	if inspection.Exists {
		if _, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase,
			"select pg_terminate_backend(pid) from pg_stat_activity where datname="+quotePostgresLiteral(binding.Database)+" and pid<>pg_backend_pid()"); err != nil {
			return nil, err
		}
		if _, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase, "drop database "+quotePostgresIdentifier(binding.Database)); err != nil {
			return nil, err
		}
	}
	create := "create database " + quotePostgresIdentifier(binding.Database) + " with owner " + quotePostgresIdentifier(binding.TargetRole) + " template template0"
	if binding.TargetEncoding != "" {
		if len(binding.TargetEncoding) > 32 || strings.ContainsAny(binding.TargetEncoding, "\x00\r\n") {
			return nil, errors.New("target database encoding is invalid")
		}
		create += " encoding " + quotePostgresLiteral(binding.TargetEncoding)
	}
	if binding.TargetCollation != "" || binding.TargetCType != "" {
		if binding.TargetCollation == "" || binding.TargetCType == "" || len(binding.TargetCollation) > 128 || len(binding.TargetCType) > 128 || strings.ContainsAny(binding.TargetCollation+binding.TargetCType, "\x00\r\n") {
			return nil, errors.New("target database locale is invalid")
		}
		create += " lc_collate " + quotePostgresLiteral(binding.TargetCollation) + " lc_ctype " + quotePostgresLiteral(binding.TargetCType)
	}
	if _, err := e.queryPostgres(ctx, binding, binding.MaintenanceDatabase, create); err != nil {
		return nil, err
	}
	generation := 1
	initialDigest := expectedDigest
	if ownedByRun {
		generation = marker.Generation + 1
		initialDigest = marker.InitialEmptyDigest
	}
	marker = postgresResetMarker{
		SchemaVersion: "operations.migration.postgres-reset-marker.v1", MigrationID: task.MigrationID,
		BindingID: bindingID, DatabaseIdentity: databaseIdentity, InitialEmptyDigest: initialDigest,
		Generation: generation, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := e.savePostgresMarker(bindingID, marker); err != nil {
		return nil, err
	}
	return map[string]any{"database_identity_digest": databaseIdentity, "reset_generation": generation, "empty": true}, nil
}

func (e *NativeExecutor) postgresRestore(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" {
		return nil, errors.New("PostgreSQL restore requires a target binding")
	}
	marker, err := e.loadPostgresMarker(bindingID)
	if err != nil || marker.MigrationID != task.MigrationID {
		return nil, errors.New("target database reset ownership is unproven")
	}
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return nil, err
	}
	artifactHandle, err := stringInput(inputs, "dump_artifact_handle")
	if err != nil || strings.Contains(artifactHandle, "/") || !fileNamePattern.MatchString(artifactHandle) {
		return nil, errors.New("database dump artifact handle is invalid")
	}
	stagingRelative, err := stringInput(inputs, "dump_staging_relative_handle")
	if err != nil || strings.Contains(stagingRelative, "/") || !fileNamePattern.MatchString(stagingRelative) {
		return nil, errors.New("database dump staging relative handle is invalid")
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
		return nil, errors.New("database dump artifact digest verification failed")
	}
	expectedRoleMapDigest, err := stringInput(inputs, "role_map_digest")
	if err != nil || expectedRoleMapDigest != MustDigest(binding.RoleMap) {
		return nil, errors.New("database role map digest changed")
	}
	aclArtifactHandle, err := stringInput(inputs, "acl_artifact_handle")
	if err != nil || aclArtifactHandle != postgresACLArtifactHandle {
		return nil, errors.New("database privilege artifact handle is invalid")
	}
	expectedACLDigest, err := stringInput(inputs, "acl_artifact_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedACLDigest) {
		return nil, errors.New("database privilege artifact digest is invalid")
	}
	aclPath, err := e.resolver.Resolve(stagingHandle, filepath.Join(stagingRelative, aclArtifactHandle), false)
	if err != nil {
		return nil, err
	}
	aclArtifact, err := readPostgresACLArtifact(aclPath, expectedACLDigest, expectedRoleMapDigest, binding.TargetRole)
	if err != nil {
		return nil, err
	}
	expectedManifestDigest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil {
		return nil, err
	}
	before, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil || !before.Empty {
		return nil, errors.New("target database is not empty before restore")
	}
	pgRestore, err := fixedPostgresExecutable("pg_restore")
	if err != nil {
		return nil, err
	}
	if _, err := e.runPostgres(ctx, binding, binding.Database, pgRestore,
		"--list", artifactPath); err != nil {
		return nil, errors.New("database dump archive validation failed")
	}
	if err := progress("postgres_restore", 0, &size); err != nil {
		return nil, err
	}
	if _, err := e.runPostgres(ctx, binding, binding.Database, pgRestore,
		"--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges", "--role="+binding.TargetRole, "--dbname="+binding.Database, artifactPath); err != nil {
		return nil, err
	}
	if err := e.applyPostgresACL(ctx, binding, aclArtifact); err != nil {
		return nil, err
	}
	after, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if after.ManifestDigest != expectedManifestDigest {
		return nil, errors.New("restored database manifest does not match the source manifest")
	}
	if err := progress("postgres_restore_verified", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"database_manifest_digest": after.ManifestDigest, "dump_artifact_digest": actualDigest,
		"acl_artifact_digest": expectedACLDigest, "restored_size_bytes": size,
		"table_count": len(after.Manifest.Tables), "total_rows": after.TotalRows,
	}, nil
}

func (e *NativeExecutor) postgresVerify(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" {
		return nil, errors.New("PostgreSQL verification requires a target binding")
	}
	expectedDigest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil {
		return nil, err
	}
	inspection, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if inspection.ManifestDigest != expectedDigest {
		return nil, errors.New("target database verification manifest mismatch")
	}
	return map[string]any{
		"verified": true, "database_manifest_digest": inspection.ManifestDigest,
		"table_count": len(inspection.Manifest.Tables), "total_rows": inspection.TotalRows,
	}, nil
}
