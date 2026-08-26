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
	mysqlBindingSchema = "operations.migration.mysql-binding.v1"
	maximumMySQLBytes  = int64(500 * 1024 * 1024 * 1024)
)

var (
	mysqlDatabasePattern  = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	mysqlCharacterPattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
	mysqlVersionPattern   = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)
)

type mysqlBinding struct {
	SchemaVersion      string `json:"schema_version"`
	Engine             string `json:"engine"`
	Mode               string `json:"mode"`
	Host               string `json:"host"`
	Port               int    `json:"port"`
	Database           string `json:"database"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	SSLMode            string `json:"ssl_mode"`
	SSLRootCertPEM     string `json:"ssl_root_cert_pem,omitempty"`
	ResetAllowed       bool   `json:"reset_allowed,omitempty"`
	TargetCharacterSet string `json:"target_character_set,omitempty"`
	TargetCollation    string `json:"target_collation,omitempty"`
}

func (b *mysqlBinding) clear() {
	b.Password = ""
	b.SSLRootCertPEM = ""
}

func validateMySQLHost(host, sslMode string) error {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t") || filepath.IsAbs(host) {
		return errors.New("MySQL binding host is invalid")
	}
	if sslMode == "disable" {
		address := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (address == nil || !address.IsLoopback()) {
			return errors.New("unencrypted MySQL or MariaDB is allowed only over loopback")
		}
	}
	return nil
}

func parseMySQLBinding(raw []byte) (mysqlBinding, error) {
	var binding mysqlBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return mysqlBinding{}, errors.New("MySQL binding JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return mysqlBinding{}, errors.New("MySQL binding contains trailing data")
	}
	if binding.SchemaVersion != mysqlBindingSchema || (binding.Engine != "mysql" && binding.Engine != "mariadb") ||
		(binding.Mode != "source" && binding.Mode != "target") {
		return mysqlBinding{}, errors.New("MySQL binding contract is unsupported")
	}
	if binding.Port < 1 || binding.Port > 65535 || !mysqlDatabasePattern.MatchString(binding.Database) ||
		binding.Username == "" || len(binding.Username) > 128 || strings.ContainsAny(binding.Username, "\x00\r\n\t") {
		return mysqlBinding{}, errors.New("MySQL binding contains an invalid identifier or port")
	}
	if strings.ContainsAny(binding.Password, "\x00\r\n") || len(binding.Password) > 16*1024 {
		return mysqlBinding{}, errors.New("MySQL binding credential is invalid")
	}
	switch binding.SSLMode {
	case "disable", "require":
	case "verify-ca", "verify-full":
		if !strings.Contains(binding.SSLRootCertPEM, "BEGIN CERTIFICATE") || len(binding.SSLRootCertPEM) > 64*1024 {
			return mysqlBinding{}, errors.New("verified MySQL TLS requires a bounded CA certificate")
		}
	default:
		return mysqlBinding{}, errors.New("MySQL binding ssl_mode is unsupported")
	}
	if err := validateMySQLHost(binding.Host, binding.SSLMode); err != nil {
		return mysqlBinding{}, err
	}
	if binding.TargetCharacterSet != "" && !mysqlCharacterPattern.MatchString(binding.TargetCharacterSet) {
		return mysqlBinding{}, errors.New("target MySQL character set is invalid")
	}
	if binding.TargetCollation != "" && !mysqlCharacterPattern.MatchString(binding.TargetCollation) {
		return mysqlBinding{}, errors.New("target MySQL collation is invalid")
	}
	if binding.Mode == "source" && (binding.ResetAllowed || binding.TargetCharacterSet != "" || binding.TargetCollation != "") {
		return mysqlBinding{}, errors.New("source MySQL binding contains target-only controls")
	}
	return binding, nil
}

func fixedMySQLExecutable(engine, purpose string) (string, error) {
	name := ""
	switch engine + ":" + purpose {
	case "mysql:client":
		name = "mysql"
	case "mysql:dump":
		name = "mysqldump"
	case "mariadb:client":
		name = "mariadb"
	case "mariadb:dump":
		name = "mariadb-dump"
	default:
		return "", errors.New("database executable family is unsupported")
	}
	return fixedExecutable(filepath.Join("/usr/bin", name), filepath.Join("/usr/local/bin", name))
}

func mysqlOptionFileValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func (e *NativeExecutor) mysqlCommand(ctx context.Context, binding mysqlBinding, binary string, args []string, stdin io.Reader, stdout io.Writer) error {
	temporaryDir, err := os.MkdirTemp(e.stateDir, ".mysql-secret-")
	if err != nil {
		return errors.New("database credential staging failed")
	}
	defer os.RemoveAll(temporaryDir)
	if err := os.Chmod(temporaryDir, 0o700); err != nil {
		return errors.New("database credential staging failed")
	}
	optionFile := filepath.Join(temporaryDir, "client.cnf")
	optionText := "[client]\n" +
		"host=" + mysqlOptionFileValue(binding.Host) + "\n" +
		"port=" + strconv.Itoa(binding.Port) + "\n" +
		"user=" + mysqlOptionFileValue(binding.Username) + "\n" +
		"password=" + mysqlOptionFileValue(binding.Password) + "\n" +
		"protocol=TCP\n"
	if err := os.WriteFile(optionFile, []byte(optionText), 0o600); err != nil {
		return errors.New("database credential staging failed")
	}
	defer func() {
		data, readErr := os.ReadFile(optionFile)
		if readErr == nil {
			zeroBytes(data)
			_ = os.WriteFile(optionFile, data, 0o600)
		}
	}()
	tlsArgs := []string{}
	switch binding.SSLMode {
	case "disable":
		if binding.Engine == "mysql" {
			tlsArgs = append(tlsArgs, "--ssl-mode=DISABLED")
		} else {
			tlsArgs = append(tlsArgs, "--skip-ssl")
		}
	case "require":
		if binding.Engine == "mysql" {
			tlsArgs = append(tlsArgs, "--ssl-mode=REQUIRED")
		} else {
			tlsArgs = append(tlsArgs, "--ssl")
		}
	case "verify-ca", "verify-full":
		rootCert := filepath.Join(temporaryDir, "root.crt")
		if err := os.WriteFile(rootCert, []byte(binding.SSLRootCertPEM), 0o600); err != nil {
			return errors.New("database TLS staging failed")
		}
		if binding.Engine == "mysql" {
			mode := "VERIFY_CA"
			if binding.SSLMode == "verify-full" {
				mode = "VERIFY_IDENTITY"
			}
			tlsArgs = append(tlsArgs, "--ssl-mode="+mode, "--ssl-ca="+rootCert)
		} else {
			tlsArgs = append(tlsArgs, "--ssl", "--ssl-verify-server-cert", "--ssl-ca="+rootCert)
		}
	}
	commandArgs := append([]string{"--defaults-extra-file=" + optionFile}, tlsArgs...)
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, binary, commandArgs...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	command.Stdin = stdin
	command.Stdout = stdout
	var stderr cappedBuffer
	stderr.limit = 32 * 1024
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		diagnostic := strings.TrimSpace(stderr.buffer.String())
		if diagnostic == "" {
			diagnostic = "client returned a non-zero status"
		}
		return errors.New("typed MySQL or MariaDB operation failed: " + diagnostic)
	}
	return nil
}

func (e *NativeExecutor) queryMySQL(ctx context.Context, binding mysqlBinding, database, query string) ([][]string, error) {
	client, err := fixedMySQLExecutable(binding.Engine, "client")
	if err != nil {
		return nil, err
	}
	// Batch mode escapes tabs, newlines, and backslashes inside fields. Keeping
	// that escaping enabled is essential for one-row metadata such as SHOW
	// CREATE TABLE; raw mode would make a single DDL value look like many rows.
	args := []string{"--connect-timeout=10", "--batch", "--skip-column-names", "--execute=" + query}
	if database != "" {
		args = append(args, "--database="+database)
	}
	var output cappedBuffer
	output.limit = 8 * 1024 * 1024
	if err := e.mysqlCommand(ctx, binding, client, args, nil, &output); err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(output.buffer.String(), "\n")
	text = strings.TrimSuffix(text, "\r")
	if text == "" {
		return nil, nil
	}
	rows := [][]string{}
	for _, line := range strings.Split(text, "\n") {
		rows = append(rows, strings.Split(strings.TrimSuffix(line, "\r"), "\t"))
	}
	return rows, nil
}

func quoteMySQLIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "``") + "`"
}

func quoteMySQLLiteral(value string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), "'", "''") + "'"
}

func canonicalMySQLMode(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.ToUpper(strings.TrimSpace(parts[index]))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func normalizeMySQLCreateDDL(value, databaseCharacterSet string) string {
	// A logical restore can make an inherited column character set explicit
	// while preserving the exact effective schema. SHOW CREATE then differs
	// textually even though INFORMATION_SCHEMA reports identical semantics.
	// Collapse only that one equivalent spelling; all other DDL stays bound.
	return strings.ReplaceAll(value, " CHARACTER SET "+databaseCharacterSet+" COLLATE ", " COLLATE ")
}

func mysqlServerSeries(version string) (string, error) {
	match := mysqlVersionPattern.FindStringSubmatch(version)
	if len(match) != 3 {
		return "", errors.New("database server version is invalid")
	}
	return match[1] + "." + match[2], nil
}

type mysqlTableManifest struct {
	Name         string `json:"name"`
	RowCount     int64  `json:"row_count"`
	Checksum     string `json:"checksum"`
	CreateDigest string `json:"create_digest"`
}

type mysqlManifest struct {
	SchemaVersion string               `json:"schema_version"`
	Engine        string               `json:"engine"`
	ServerSeries  string               `json:"server_series"`
	CharacterSet  string               `json:"character_set"`
	Collation     string               `json:"collation"`
	Tables        []mysqlTableManifest `json:"tables"`
}

type mysqlInspection struct {
	Exists            bool
	Empty             bool
	Engine            string
	ServerVersion     string
	ServerSeries      string
	CharacterSet      string
	Collation         string
	SQLMode           string
	Manifest          mysqlManifest
	ManifestDigest    string
	EmptyTargetDigest string
	DatabaseBytes     int64
	TotalRows         int64
	UnsupportedCount  int64
}

func parseMySQLSingleInt(rows [][]string) (int64, error) {
	if len(rows) != 1 || len(rows[0]) != 1 {
		return 0, errors.New("MySQL returned an invalid bounded result")
	}
	return strconv.ParseInt(rows[0][0], 10, 64)
}

func (e *NativeExecutor) inspectMySQL(ctx context.Context, bindingID string, binding mysqlBinding) (mysqlInspection, error) {
	serverRows, err := e.queryMySQL(ctx, binding, "", "select @@version,@@version_comment,@@sql_mode,@@character_set_server,@@collation_server")
	if err != nil || len(serverRows) != 1 || len(serverRows[0]) != 5 {
		return mysqlInspection{}, errors.New("MySQL server metadata inspection failed")
	}
	version, comment := serverRows[0][0], serverRows[0][1]
	detectedEngine := "mysql"
	combined := strings.ToLower(version + " " + comment)
	if strings.Contains(combined, "mariadb") {
		detectedEngine = "mariadb"
	} else if strings.Contains(combined, "percona") {
		return mysqlInspection{}, errors.New("Percona Server is outside the bounded MySQL recipe")
	}
	if detectedEngine != binding.Engine {
		return mysqlInspection{}, errors.New("database binding engine does not match the live server")
	}
	series, err := mysqlServerSeries(version)
	if err != nil {
		return mysqlInspection{}, err
	}
	allowedSeries := map[string]map[string]struct{}{
		"mysql":   {"8.0": {}, "8.4": {}},
		"mariadb": {"10.11": {}, "11.4": {}},
	}
	if _, ok := allowedSeries[detectedEngine][series]; !ok {
		return mysqlInspection{}, errors.New("MySQL or MariaDB version is outside the supported offline matrix")
	}
	inspection := mysqlInspection{
		Engine: detectedEngine, ServerVersion: version, ServerSeries: series,
		CharacterSet: serverRows[0][3], Collation: serverRows[0][4], SQLMode: canonicalMySQLMode(serverRows[0][2]),
	}
	databaseRows, err := e.queryMySQL(ctx, binding, "", "select default_character_set_name,default_collation_name from information_schema.schemata where schema_name="+quoteMySQLLiteral(binding.Database))
	if err != nil || len(databaseRows) > 1 || (len(databaseRows) == 1 && len(databaseRows[0]) != 2) {
		return mysqlInspection{}, errors.New("MySQL database identity is ambiguous")
	}
	inspection.Exists = len(databaseRows) == 1
	if inspection.Exists {
		inspection.CharacterSet = databaseRows[0][0]
		inspection.Collation = databaseRows[0][1]
	} else if binding.Mode == "target" {
		if binding.TargetCharacterSet != "" {
			inspection.CharacterSet = binding.TargetCharacterSet
		}
		if binding.TargetCollation != "" {
			inspection.Collation = binding.TargetCollation
		}
	}
	if !mysqlCharacterPattern.MatchString(inspection.CharacterSet) || !mysqlCharacterPattern.MatchString(inspection.Collation) {
		return mysqlInspection{}, errors.New("MySQL database character contract is invalid")
	}
	if !inspection.Exists {
		inspection.Empty = true
		inspection.EmptyTargetDigest, err = Digest(map[string]any{
			"schema_version": "operations.migration.mysql-empty-target.v1", "binding_id": bindingID,
			"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database, "engine": binding.Engine}),
			"exists":            false, "engine": inspection.Engine, "server_series": inspection.ServerSeries,
			"character_set": inspection.CharacterSet, "collation": inspection.Collation, "sql_mode": inspection.SQLMode,
		})
		return inspection, err
	}
	sizeRows, err := e.queryMySQL(ctx, binding, "", "select coalesce(sum(data_length+index_length),0) from information_schema.tables where table_schema="+quoteMySQLLiteral(binding.Database))
	if err != nil {
		return mysqlInspection{}, err
	}
	inspection.DatabaseBytes, err = parseMySQLSingleInt(sizeRows)
	if err != nil || inspection.DatabaseBytes < 0 || inspection.DatabaseBytes > maximumMySQLBytes {
		return mysqlInspection{}, errors.New("MySQL database size is outside the supported offline matrix")
	}
	unsupportedRows, err := e.queryMySQL(ctx, binding, "", "select (select count(*) from information_schema.views where table_schema="+quoteMySQLLiteral(binding.Database)+")+(select count(*) from information_schema.triggers where trigger_schema="+quoteMySQLLiteral(binding.Database)+")+(select count(*) from information_schema.routines where routine_schema="+quoteMySQLLiteral(binding.Database)+")+(select count(*) from information_schema.events where event_schema="+quoteMySQLLiteral(binding.Database)+")")
	if err != nil {
		return mysqlInspection{}, err
	}
	inspection.UnsupportedCount, err = parseMySQLSingleInt(unsupportedRows)
	if err != nil || inspection.UnsupportedCount != 0 {
		return mysqlInspection{}, errors.New("MySQL views, triggers, routines, and events are outside the offline MVP")
	}
	tableRows, err := e.queryMySQL(ctx, binding, "", "select table_name,coalesce(engine,'') from information_schema.tables where table_schema="+quoteMySQLLiteral(binding.Database)+" and table_type='BASE TABLE' order by table_name")
	if err != nil || len(tableRows) > 2048 {
		return mysqlInspection{}, errors.New("MySQL table inventory is outside the 2048-table safety limit")
	}
	manifest := mysqlManifest{
		SchemaVersion: "operations.migration.mysql-manifest.v1", Engine: inspection.Engine,
		ServerSeries: inspection.ServerSeries, CharacterSet: inspection.CharacterSet, Collation: inspection.Collation,
		Tables: []mysqlTableManifest{},
	}
	for _, row := range tableRows {
		if len(row) != 2 || !mysqlDatabasePattern.MatchString(row[0]) || !strings.EqualFold(row[1], "InnoDB") {
			return mysqlInspection{}, errors.New("only bounded InnoDB tables are supported")
		}
		qualified := quoteMySQLIdentifier(binding.Database) + "." + quoteMySQLIdentifier(row[0])
		countRows, queryErr := e.queryMySQL(ctx, binding, binding.Database, "select count(*) from "+qualified)
		if queryErr != nil {
			return mysqlInspection{}, errors.New("MySQL table row-count inspection failed")
		}
		rowCount, parseErr := parseMySQLSingleInt(countRows)
		checksumRows, checksumErr := e.queryMySQL(ctx, binding, binding.Database, "checksum table "+qualified+" extended")
		createRows, createErr := e.queryMySQL(ctx, binding, binding.Database, "show create table "+qualified)
		if parseErr != nil || checksumErr != nil || len(checksumRows) != 1 || len(checksumRows[0]) != 2 || checksumRows[0][1] == "NULL" ||
			createErr != nil || len(createRows) != 1 || len(createRows[0]) != 2 {
			return mysqlInspection{}, errors.New("MySQL table manifest calculation failed")
		}
		inspection.TotalRows += rowCount
		manifest.Tables = append(manifest.Tables, mysqlTableManifest{
			Name: row[0], RowCount: rowCount, Checksum: checksumRows[0][1],
			CreateDigest: MustDigest(normalizeMySQLCreateDDL(createRows[0][1], inspection.CharacterSet)),
		})
	}
	inspection.Manifest = manifest
	inspection.ManifestDigest, err = Digest(manifest)
	if err != nil {
		return mysqlInspection{}, err
	}
	inspection.Empty = len(manifest.Tables) == 0
	inspection.EmptyTargetDigest, err = Digest(map[string]any{
		"schema_version": "operations.migration.mysql-empty-target.v1", "binding_id": bindingID,
		"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database, "engine": binding.Engine}),
		"exists":            true, "empty": inspection.Empty, "engine": inspection.Engine, "server_series": inspection.ServerSeries,
		"character_set": inspection.CharacterSet, "collation": inspection.Collation, "sql_mode": inspection.SQLMode,
	})
	return inspection, err
}

func mysqlInspectionOutputs(inspection mysqlInspection) map[string]any {
	return map[string]any{
		"exists": inspection.Exists, "empty": inspection.Empty, "engine": inspection.Engine,
		"server_version": inspection.ServerVersion, "server_series": inspection.ServerSeries,
		"character_set": inspection.CharacterSet, "collation": inspection.Collation, "sql_mode": inspection.SQLMode,
		"table_count": len(inspection.Manifest.Tables), "total_rows": inspection.TotalRows,
		"database_bytes": inspection.DatabaseBytes, "database_manifest_digest": inspection.ManifestDigest,
		"empty_target_digest": inspection.EmptyTargetDigest, "unsupported_object_count": inspection.UnsupportedCount,
	}
}

func (e *NativeExecutor) resolveMySQLBinding(ctx context.Context, task TaskEnvelope, inputs map[string]any) (string, mysqlBinding, error) {
	bindingID, err := stringInput(inputs, "database_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return "", mysqlBinding{}, errors.New("database binding identifier is invalid")
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return "", mysqlBinding{}, err
	}
	defer zeroBytes(raw)
	binding, err := parseMySQLBinding(raw)
	return bindingID, binding, err
}

func verifyMySQLCompatibility(binding mysqlBinding, inputs map[string]any, inspection mysqlInspection) error {
	requiredEngine, hasEngine := inputs["required_source_engine"].(string)
	requiredSeries, hasSeries := inputs["required_source_series"].(string)
	requiredCharacterSet, hasCharacterSet := inputs["required_character_set"].(string)
	requiredCollation, hasCollation := inputs["required_collation"].(string)
	requiredSQLMode, hasSQLMode := inputs["required_sql_mode"].(string)
	if !hasEngine && !hasSeries && !hasCharacterSet && !hasCollation && !hasSQLMode {
		return nil
	}
	if binding.Mode != "target" || requiredEngine != inspection.Engine || requiredSeries != inspection.ServerSeries ||
		requiredCharacterSet != inspection.CharacterSet || requiredCollation != inspection.Collation || canonicalMySQLMode(requiredSQLMode) != inspection.SQLMode {
		return errors.New("target MySQL or MariaDB compatibility does not exactly match the source contract")
	}
	return nil
}

func (e *NativeExecutor) mysqlInspect(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveMySQLBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	inspection, err := e.inspectMySQL(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if err := verifyMySQLCompatibility(binding, inputs, inspection); err != nil {
		return nil, err
	}
	if requireEmpty, ok := inputs["require_empty_target"].(bool); ok && requireEmpty {
		if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") || !inspection.Empty {
			return nil, errors.New("target MySQL database must be new, empty, and constrained to the migration namespace")
		}
	}
	return mysqlInspectionOutputs(inspection), nil
}

func mysqlArtifactLocation(e *NativeExecutor, task TaskEnvelope, stagingHandle, prefix, manifestDigest string) (string, string, error) {
	stagingRoot, err := e.resolver.Resolve(stagingHandle, ".", false)
	if err != nil {
		return "", "", err
	}
	attemptToken := strings.ReplaceAll(task.AttemptID, "-", "")
	if len(attemptToken) > 12 {
		attemptToken = attemptToken[:12]
	}
	manifestToken := strings.TrimPrefix(manifestDigest, "sha256:")
	if len(manifestToken) < 16 {
		return "", "", errors.New("database manifest digest is invalid")
	}
	relative := prefix + "-" + manifestToken[:16] + "-" + attemptToken
	directory, err := e.resolver.Resolve(stagingHandle, relative, true)
	if err != nil {
		return "", "", err
	}
	if filepath.Dir(directory) != stagingRoot {
		return "", "", errors.New("database dump artifact escaped its staging root")
	}
	if _, err := os.Lstat(directory); err == nil {
		return "", "", errors.New("database dump artifact collision")
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return "", "", err
	}
	return relative, directory, nil
}

func (e *NativeExecutor) mysqlDump(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolveMySQLBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("MySQL dump requires a source binding")
	}
	inspection, err := e.inspectMySQL(ctx, bindingID, binding)
	if err != nil || !inspection.Exists {
		return nil, errors.New("source MySQL database is missing or unsupported")
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
	relative, directory, err := mysqlArtifactLocation(e, task, stagingHandle, binding.Engine, inspection.ManifestDigest)
	if err != nil {
		return nil, err
	}
	artifactHandle := "database.sql"
	partial := filepath.Join(directory, artifactHandle+".partial")
	file, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	dump, err := fixedMySQLExecutable(binding.Engine, "dump")
	if err != nil {
		_ = file.Close()
		_ = os.Remove(partial)
		return nil, err
	}
	args := []string{"--single-transaction", "--quick", "--skip-lock-tables", "--hex-blob", "--skip-triggers", "--skip-routines", "--skip-events"}
	if binding.Engine == "mysql" {
		args = append(args, "--no-tablespaces", "--set-gtid-purged=OFF")
	}
	args = append(args, binding.Database)
	commandErr := e.mysqlCommand(ctx, binding, dump, args, nil, file)
	syncErr := file.Sync()
	closeErr := file.Close()
	if commandErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(partial)
		if commandErr != nil {
			return nil, commandErr
		}
		return nil, errors.New("database dump artifact could not be finalized")
	}
	artifactPath := filepath.Join(directory, artifactHandle)
	digest, archiveSize, err := fileSHA256(partial)
	if err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	if err := os.Rename(partial, artifactPath); err != nil {
		_ = os.Remove(partial)
		return nil, err
	}
	transferManifest, err := buildFileManifest(ctx, directory, nil)
	if err != nil {
		return nil, err
	}
	if err := progress("mysql_dump_complete", archiveSize, &archiveSize); err != nil {
		return nil, err
	}
	return map[string]any{
		"dump_artifact_handle": artifactHandle, "dump_staging_relative_handle": relative,
		"dump_artifact_digest": digest, "dump_transfer_manifest_digest": transferManifest.Digest,
		"dump_size_bytes": transferManifest.TotalBytes, "dump_archive_size_bytes": archiveSize,
		"database_manifest_digest": inspection.ManifestDigest, "engine": inspection.Engine,
		"server_series": inspection.ServerSeries,
	}, nil
}

type mysqlResetMarker struct {
	SchemaVersion      string `json:"schema_version"`
	MigrationID        string `json:"migration_id"`
	BindingID          string `json:"binding_id"`
	DatabaseIdentity   string `json:"database_identity"`
	InitialEmptyDigest string `json:"initial_empty_digest"`
	Generation         int    `json:"generation"`
	UpdatedAt          string `json:"updated_at"`
}

func (e *NativeExecutor) mysqlMarkerPath(bindingID string) string {
	digest := sha256.Sum256([]byte(bindingID))
	return filepath.Join(e.stateDir, "mysql-reset-markers", hex.EncodeToString(digest[:16])+".json")
}

func (e *NativeExecutor) loadMySQLMarker(bindingID string) (mysqlResetMarker, error) {
	data, err := os.ReadFile(e.mysqlMarkerPath(bindingID))
	if err != nil {
		return mysqlResetMarker{}, err
	}
	var marker mysqlResetMarker
	if json.Unmarshal(data, &marker) != nil || marker.SchemaVersion != "operations.migration.mysql-reset-marker.v1" {
		return mysqlResetMarker{}, errors.New("target database ownership marker is invalid")
	}
	return marker, nil
}

func (e *NativeExecutor) saveMySQLMarker(bindingID string, marker mysqlResetMarker) error {
	path := e.mysqlMarkerPath(bindingID)
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

func (e *NativeExecutor) mysqlReset(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveMySQLBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") {
		return nil, errors.New("target MySQL database reset is not explicitly constrained")
	}
	expectedDigest, err := stringInput(inputs, "expected_empty_target_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("expected empty target digest is invalid")
	}
	inspection, err := e.inspectMySQL(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	marker, markerErr := e.loadMySQLMarker(bindingID)
	databaseIdentity := MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database, "engine": binding.Engine})
	ownedByRun := markerErr == nil && marker.MigrationID == task.MigrationID && marker.BindingID == bindingID &&
		marker.DatabaseIdentity == databaseIdentity && marker.InitialEmptyDigest == expectedDigest
	if (!inspection.Empty || inspection.EmptyTargetDigest != expectedDigest) && !ownedByRun {
		return nil, errors.New("target MySQL database is not the approved empty target and is not owned by this migration")
	}
	if inspection.Exists {
		if _, err := e.queryMySQL(ctx, binding, "", "drop database "+quoteMySQLIdentifier(binding.Database)); err != nil {
			return nil, err
		}
	}
	create := "create database " + quoteMySQLIdentifier(binding.Database) + " character set " + quoteMySQLIdentifier(inspection.CharacterSet) + " collate " + quoteMySQLIdentifier(inspection.Collation)
	if _, err := e.queryMySQL(ctx, binding, "", create); err != nil {
		return nil, err
	}
	generation := 1
	initialDigest := expectedDigest
	if ownedByRun {
		generation = marker.Generation + 1
		initialDigest = marker.InitialEmptyDigest
	}
	marker = mysqlResetMarker{
		SchemaVersion: "operations.migration.mysql-reset-marker.v1", MigrationID: task.MigrationID,
		BindingID: bindingID, DatabaseIdentity: databaseIdentity, InitialEmptyDigest: initialDigest,
		Generation: generation, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := e.saveMySQLMarker(bindingID, marker); err != nil {
		return nil, err
	}
	return map[string]any{"database_identity_digest": databaseIdentity, "reset_generation": generation, "empty": true}, nil
}

func (e *NativeExecutor) mysqlRestore(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolveMySQLBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" {
		return nil, errors.New("MySQL restore requires a target binding")
	}
	marker, err := e.loadMySQLMarker(bindingID)
	if err != nil || marker.MigrationID != task.MigrationID {
		return nil, errors.New("target MySQL database reset ownership is unproven")
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
		return nil, errors.New("database dump artifact digest verification failed")
	}
	expectedManifestDigest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedManifestDigest) {
		return nil, errors.New("expected database manifest digest is invalid")
	}
	before, err := e.inspectMySQL(ctx, bindingID, binding)
	if err != nil || !before.Empty {
		return nil, errors.New("target MySQL database is not empty before restore")
	}
	file, err := os.Open(artifactPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	client, err := fixedMySQLExecutable(binding.Engine, "client")
	if err != nil {
		return nil, err
	}
	if err := progress("mysql_restore", 0, &size); err != nil {
		return nil, err
	}
	if err := e.mysqlCommand(ctx, binding, client, []string{"--connect-timeout=10", "--binary-mode", "--database=" + binding.Database}, file, io.Discard); err != nil {
		return nil, err
	}
	after, err := e.inspectMySQL(ctx, bindingID, binding)
	if err != nil || after.ManifestDigest != expectedManifestDigest {
		return nil, errors.New("restored MySQL database manifest does not match the source manifest")
	}
	if err := progress("mysql_restore_verified", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"database_manifest_digest": after.ManifestDigest, "dump_artifact_digest": actualDigest,
		"restored_size_bytes": size, "table_count": len(after.Manifest.Tables), "total_rows": after.TotalRows,
	}, nil
}

func (e *NativeExecutor) mysqlVerify(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveMySQLBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	expectedDigest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil {
		return nil, err
	}
	inspection, err := e.inspectMySQL(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if inspection.ManifestDigest != expectedDigest {
		return nil, errors.New("MySQL database verification manifest mismatch")
	}
	return map[string]any{
		"verified": true, "database_manifest_digest": inspection.ManifestDigest,
		"table_count": len(inspection.Manifest.Tables), "total_rows": inspection.TotalRows,
	}, nil
}
