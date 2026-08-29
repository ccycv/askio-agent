package migration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	mysqlBindingSchema   = "operations.migration.mysql-binding.v1"
	mysqlBindingSchemaV2 = "operations.migration.mysql-binding.v2"
	maximumMySQLBytes    = int64(500 * 1024 * 1024 * 1024)
	maximumMySQLRowBytes = 64 * 1024 * 1024
)

var (
	mysqlDatabasePattern         = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	mysqlCharacterPattern        = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
	mysqlVersionPattern          = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)
	mysqlAccountPattern          = regexp.MustCompile(`^[A-Za-z0-9_.$%-]{1,128}$`)
	mysqlHostPattern             = regexp.MustCompile(`^[A-Za-z0-9_.:%-]{1,255}$`)
	mysqlPrivilegePattern        = regexp.MustCompile(`^[A-Z][A-Z ]{1,63}$`)
	mysqlDefinerPattern          = regexp.MustCompile("(?i)DEFINER\\s*=\\s*`([^`]*)`@`([^`]*)`")
	mysqlCollationPattern        = regexp.MustCompile(`(?i)COLLATE(?:=|\s+)[A-Za-z0-9_]+`)
	mysqlAriaEnginePattern       = regexp.MustCompile(`(?i)ENGINE=Aria\b`)
	mysqlSQLModeStatementPattern = regexp.MustCompile(`(?i)^\s*(?:/\*(?:M!|!)?[0-9]*\s+)?SET\s+(?:SESSION\s+)?sql_mode\s*=`)
	mysqlRemovedSQLModePatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?i)NO_AUTO_CREATE_USER,`),
		regexp.MustCompile(`(?i),NO_AUTO_CREATE_USER`),
		regexp.MustCompile(`(?i)NO_AUTO_CREATE_USER`),
	}
	mysqlMariaTableOptionPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\s+PAGE_CHECKSUM=[0-9]+`),
		regexp.MustCompile(`(?i)\s+TRANSACTIONAL=[01]`),
		regexp.MustCompile(`(?i)\s+TABLE_CHECKSUM=[01]`),
	}
)

type mysqlAccountMapping struct {
	SourceUser string `json:"source_user"`
	SourceHost string `json:"source_host"`
	TargetUser string `json:"target_user"`
	TargetHost string `json:"target_host"`
}

type mysqlBinding struct {
	SchemaVersion      string                `json:"schema_version"`
	Engine             string                `json:"engine"`
	Mode               string                `json:"mode"`
	Host               string                `json:"host"`
	Port               int                   `json:"port"`
	Database           string                `json:"database"`
	Username           string                `json:"username"`
	Password           string                `json:"password"`
	SSLMode            string                `json:"ssl_mode"`
	SSLRootCertPEM     string                `json:"ssl_root_cert_pem,omitempty"`
	ResetAllowed       bool                  `json:"reset_allowed,omitempty"`
	TargetCharacterSet string                `json:"target_character_set,omitempty"`
	TargetCollation    string                `json:"target_collation,omitempty"`
	AccountMap         []mysqlAccountMapping `json:"account_map,omitempty"`
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
	if (binding.SchemaVersion != mysqlBindingSchema && binding.SchemaVersion != mysqlBindingSchemaV2) ||
		(binding.Engine != "mysql" && binding.Engine != "mariadb") ||
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
	if binding.SchemaVersion == mysqlBindingSchema && len(binding.AccountMap) > 0 {
		return mysqlBinding{}, errors.New("MySQL account mapping requires the v2 binding contract")
	}
	if len(binding.AccountMap) > 128 {
		return mysqlBinding{}, errors.New("MySQL account mapping exceeds the 128-account limit")
	}
	seenSource := map[string]struct{}{}
	seenTarget := map[string]struct{}{}
	for _, mapping := range binding.AccountMap {
		if !mysqlAccountPattern.MatchString(mapping.SourceUser) || !mysqlHostPattern.MatchString(mapping.SourceHost) ||
			!mysqlAccountPattern.MatchString(mapping.TargetUser) || !mysqlHostPattern.MatchString(mapping.TargetHost) {
			return mysqlBinding{}, errors.New("MySQL account mapping contains an invalid account identifier")
		}
		sourceKey := mysqlAccountKey(mapping.SourceUser, mapping.SourceHost)
		targetKey := mysqlAccountKey(mapping.TargetUser, mapping.TargetHost)
		if _, exists := seenSource[sourceKey]; exists {
			return mysqlBinding{}, errors.New("MySQL account mapping contains a duplicate source account")
		}
		if _, exists := seenTarget[targetKey]; exists {
			return mysqlBinding{}, errors.New("MySQL account mapping must remain one-to-one")
		}
		if isReservedMySQLTargetAccount(mapping.TargetUser) {
			return mysqlBinding{}, errors.New("MySQL account mapping cannot target a system or root account")
		}
		seenSource[sourceKey] = struct{}{}
		seenTarget[targetKey] = struct{}{}
	}
	return binding, nil
}

func mysqlAccountKey(user, host string) string {
	return user + "@" + host
}

func isReservedMySQLTargetAccount(user string) bool {
	lower := strings.ToLower(user)
	return lower == "root" || lower == "mariadb.sys" || strings.HasPrefix(lower, "mysql.")
}

func (b mysqlBinding) sourceAccountMap() map[string]mysqlAccountMapping {
	result := make(map[string]mysqlAccountMapping, len(b.AccountMap))
	for _, mapping := range b.AccountMap {
		result[mysqlAccountKey(mapping.SourceUser, mapping.SourceHost)] = mapping
	}
	return result
}

func (b mysqlBinding) targetAccountMap() map[string]mysqlAccountMapping {
	result := make(map[string]mysqlAccountMapping, len(b.AccountMap))
	for _, mapping := range b.AccountMap {
		result[mysqlAccountKey(mapping.TargetUser, mapping.TargetHost)] = mapping
	}
	return result
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
	Name            string `json:"name"`
	RowCount        int64  `json:"row_count"`
	DataDigest      string `json:"data_digest"`
	StructureDigest string `json:"structure_digest"`
}

type mysqlObjectManifest struct {
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	Parent       string `json:"parent,omitempty"`
	Action       string `json:"action,omitempty"`
	Timing       string `json:"timing,omitempty"`
	SecurityType string `json:"security_type,omitempty"`
	Definer      string `json:"definer"`
}

type mysqlGrantManifest struct {
	Scope       string `json:"scope"`
	Object      string `json:"object,omitempty"`
	Column      string `json:"column,omitempty"`
	RoutineType string `json:"routine_type,omitempty"`
	Principal   string `json:"principal"`
	Privilege   string `json:"privilege"`
	Grantable   bool   `json:"grantable"`
}

type mysqlManifest struct {
	SchemaVersion string                `json:"schema_version"`
	Tables        []mysqlTableManifest  `json:"tables"`
	Objects       []mysqlObjectManifest `json:"objects"`
	Grants        []mysqlGrantManifest  `json:"grants"`
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
	NonInnoDBCount    int64
	StorageEngines    []string
}

func parseMySQLSingleInt(rows [][]string) (int64, error) {
	if len(rows) != 1 || len(rows[0]) != 1 {
		return 0, errors.New("MySQL returned an invalid bounded result")
	}
	return strconv.ParseInt(rows[0][0], 10, 64)
}

type mysqlRowDigestWriter struct {
	pending []byte
	xor     [sha256.Size]byte
	sum     [sha256.Size / 8]uint64
	rows    int64
}

func (w *mysqlRowDigestWriter) addRow(row []byte) {
	row = bytes.TrimSuffix(row, []byte("\r"))
	digest := sha256.Sum256(row)
	for index, value := range digest {
		w.xor[index] ^= value
	}
	for index := range w.sum {
		w.sum[index] += binary.BigEndian.Uint64(digest[index*8 : (index+1)*8])
	}
	w.rows++
}

func (w *mysqlRowDigestWriter) Write(value []byte) (int, error) {
	originalLength := len(value)
	for len(value) > 0 {
		newline := bytes.IndexByte(value, '\n')
		if newline < 0 {
			w.pending = append(w.pending, value...)
			if len(w.pending) > maximumMySQLRowBytes {
				return 0, errors.New("MySQL row exceeds the 64 MiB portable verification limit")
			}
			return originalLength, nil
		}
		w.pending = append(w.pending, value[:newline]...)
		if len(w.pending) > maximumMySQLRowBytes {
			return 0, errors.New("MySQL row exceeds the 64 MiB portable verification limit")
		}
		w.addRow(w.pending)
		w.pending = w.pending[:0]
		value = value[newline+1:]
	}
	return originalLength, nil
}

func (w *mysqlRowDigestWriter) finish() (string, int64, error) {
	if len(w.pending) > 0 {
		w.addRow(w.pending)
		w.pending = nil
	}
	sums := make([]string, len(w.sum))
	for index, value := range w.sum {
		sums[index] = strconv.FormatUint(value, 16)
	}
	digest, err := Digest(map[string]any{
		"schema_version": "operations.migration.mysql-row-multiset.v1",
		"rows":           w.rows, "xor": hex.EncodeToString(w.xor[:]), "sum": sums,
	})
	return digest, w.rows, err
}

func (e *NativeExecutor) mysqlTableDataDigest(ctx context.Context, binding mysqlBinding, table string) (string, int64, error) {
	client, err := fixedMySQLExecutable(binding.Engine, "client")
	if err != nil {
		return "", 0, err
	}
	writer := &mysqlRowDigestWriter{}
	query := "select * from " + quoteMySQLIdentifier(binding.Database) + "." + quoteMySQLIdentifier(table)
	args := []string{"--connect-timeout=10", "--batch", "--skip-column-names", "--quick", "--execute=" + query, "--database=" + binding.Database}
	if err := e.mysqlCommand(ctx, binding, client, args, nil, writer); err != nil {
		return "", 0, err
	}
	return writer.finish()
}

func normalizeMySQLColumnType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	integerDisplayWidth := regexp.MustCompile(`\b(tinyint|smallint|mediumint|int|integer|bigint)\([0-9]+\)`)
	value = integerDisplayWidth.ReplaceAllString(value, "$1")
	return strings.Join(strings.Fields(value), " ")
}

func normalizeMySQLExtra(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "DEFAULT_GENERATED", "")
	value = strings.ReplaceAll(value, "PERSISTENT GENERATED", "STORED GENERATED")
	return strings.Join(strings.Fields(value), " ")
}

func (e *NativeExecutor) mysqlTableStructureDigest(ctx context.Context, binding mysqlBinding, table string) (string, error) {
	database := quoteMySQLLiteral(binding.Database)
	tableLiteral := quoteMySQLLiteral(table)
	columnRows, err := e.queryMySQL(ctx, binding, "", "select ordinal_position,column_name,data_type,column_type,is_nullable,coalesce(character_maximum_length,''),coalesce(numeric_precision,''),coalesce(numeric_scale,''),coalesce(datetime_precision,''),coalesce(extra,''),coalesce(generation_expression,'') from information_schema.columns where table_schema="+database+" and table_name="+tableLiteral+" order by ordinal_position")
	if err != nil {
		return "", err
	}
	columns := make([][]string, 0, len(columnRows))
	for _, row := range columnRows {
		if len(row) != 11 || !mysqlDatabasePattern.MatchString(row[1]) {
			return "", errors.New("MySQL column inventory is invalid")
		}
		row[2] = strings.ToLower(row[2])
		row[3] = normalizeMySQLColumnType(row[3])
		row[4] = strings.ToUpper(row[4])
		row[9] = normalizeMySQLExtra(row[9])
		row[10] = strings.Join(strings.Fields(strings.ToLower(row[10])), " ")
		columns = append(columns, row)
	}
	indexRows, err := e.queryMySQL(ctx, binding, "", "select index_name,non_unique,seq_in_index,column_name,coalesce(sub_part,''),index_type from information_schema.statistics where table_schema="+database+" and table_name="+tableLiteral+" order by index_name,seq_in_index")
	if err != nil {
		return "", err
	}
	for _, row := range indexRows {
		if len(row) != 6 {
			return "", errors.New("MySQL index inventory is invalid")
		}
		row[5] = strings.ToUpper(row[5])
	}
	foreignKeyRows, err := e.queryMySQL(ctx, binding, "", "select k.constraint_name,k.ordinal_position,k.column_name,k.referenced_table_name,k.referenced_column_name,r.update_rule,r.delete_rule from information_schema.key_column_usage k join information_schema.referential_constraints r on r.constraint_schema=k.constraint_schema and r.constraint_name=k.constraint_name where k.table_schema="+database+" and k.table_name="+tableLiteral+" and k.referenced_table_name is not null order by k.constraint_name,k.ordinal_position")
	if err != nil {
		return "", err
	}
	for _, row := range foreignKeyRows {
		if len(row) != 7 {
			return "", errors.New("MySQL foreign-key inventory is invalid")
		}
		row[5], row[6] = strings.ToUpper(row[5]), strings.ToUpper(row[6])
	}
	return Digest(map[string]any{
		"schema_version": "operations.migration.mysql-table-structure.v1",
		"columns":        columns, "indexes": indexRows, "foreign_keys": foreignKeyRows,
	})
}

func parseMySQLGrantee(value string) (string, string, error) {
	separator := strings.Index(value, "'@'")
	if separator < 2 || !strings.HasPrefix(value, "'") || !strings.HasSuffix(value, "'") {
		return "", "", errors.New("MySQL grant principal is outside the bounded account syntax")
	}
	user := value[1:separator]
	host := value[separator+3 : len(value)-1]
	if !mysqlAccountPattern.MatchString(user) || !mysqlHostPattern.MatchString(host) {
		return "", "", errors.New("MySQL grant principal is outside the bounded account syntax")
	}
	return user, host, nil
}

func mapMySQLPrincipal(binding mysqlBinding, user, host string) (string, error) {
	key := mysqlAccountKey(user, host)
	if binding.Mode == "source" {
		mapping, ok := binding.sourceAccountMap()[key]
		if !ok {
			return "", errors.New("source MySQL account or object definer is missing from the explicit account map")
		}
		return mysqlAccountKey(mapping.TargetUser, mapping.TargetHost), nil
	}
	if _, ok := binding.targetAccountMap()[key]; !ok {
		return "", errors.New("target MySQL database contains an account outside the explicit account map")
	}
	return key, nil
}

func mapMySQLDefiner(binding mysqlBinding, value string) (string, error) {
	separator := strings.LastIndex(value, "@")
	if separator < 1 || separator == len(value)-1 {
		return "", errors.New("MySQL object definer is invalid")
	}
	return mapMySQLPrincipal(binding, value[:separator], value[separator+1:])
}

func validateMySQLPrivilege(value string) (string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if !mysqlPrivilegePattern.MatchString(value) {
		return "", errors.New("MySQL privilege is outside the bounded database-scoped grant syntax")
	}
	return value, nil
}

func (e *NativeExecutor) mysqlGrantInventory(ctx context.Context, binding mysqlBinding) ([]mysqlGrantManifest, error) {
	database := quoteMySQLLiteral(binding.Database)
	type grantQuery struct {
		scope string
		query string
		width int
	}
	queries := []grantQuery{
		{"database", "select grantee,privilege_type,is_grantable from information_schema.schema_privileges where table_schema=" + database + " order by grantee,privilege_type", 3},
		{"table", "select grantee,table_name,privilege_type,is_grantable from information_schema.table_privileges where table_schema=" + database + " order by grantee,table_name,privilege_type", 4},
		{"column", "select grantee,table_name,column_name,privilege_type,is_grantable from information_schema.column_privileges where table_schema=" + database + " order by grantee,table_name,column_name,privilege_type", 5},
		{"routine", "select concat(char(39),User,char(39),'@',char(39),Host,char(39)),Routine_name,Routine_type,Proc_priv from mysql.procs_priv where Db=" + database + " order by User,Host,Routine_name,Routine_type", 4},
	}
	grants := []mysqlGrantManifest{}
	for _, item := range queries {
		rows, err := e.queryMySQL(ctx, binding, "", item.query)
		if err != nil {
			return nil, err
		}
		if len(rows) > 100_000 {
			return nil, errors.New("MySQL database-scoped grants exceed the 100000-entry safety limit")
		}
		for _, row := range rows {
			if len(row) != item.width {
				return nil, errors.New("MySQL grant inventory is invalid")
			}
			user, host, err := parseMySQLGrantee(row[0])
			if err != nil {
				return nil, err
			}
			principal, err := mapMySQLPrincipal(binding, user, host)
			if err != nil {
				return nil, err
			}
			entry := mysqlGrantManifest{Scope: item.scope, Principal: principal}
			switch item.scope {
			case "database":
				entry.Privilege, err = validateMySQLPrivilege(row[1])
				entry.Grantable = strings.EqualFold(row[2], "YES")
			case "table":
				entry.Object = row[1]
				entry.Privilege, err = validateMySQLPrivilege(row[2])
				entry.Grantable = strings.EqualFold(row[3], "YES")
			case "column":
				entry.Object, entry.Column = row[1], row[2]
				entry.Privilege, err = validateMySQLPrivilege(row[3])
				entry.Grantable = strings.EqualFold(row[4], "YES")
			case "routine":
				entry.Object, entry.RoutineType = row[1], strings.ToUpper(row[2])
				privileges := strings.Split(row[3], ",")
				grantable := false
				for _, privilege := range privileges {
					if strings.EqualFold(strings.TrimSpace(privilege), "Grant") {
						grantable = true
					}
				}
				for _, privilege := range privileges {
					if strings.EqualFold(strings.TrimSpace(privilege), "Grant") {
						continue
					}
					validated, validateErr := validateMySQLPrivilege(privilege)
					if validateErr != nil || !mysqlDatabasePattern.MatchString(entry.Object) || (entry.RoutineType != "FUNCTION" && entry.RoutineType != "PROCEDURE") {
						return nil, errors.New("MySQL routine grant inventory contains an unsupported privilege")
					}
					grants = append(grants, mysqlGrantManifest{
						Scope: "routine", Object: entry.Object, RoutineType: entry.RoutineType,
						Principal: principal, Privilege: validated, Grantable: grantable,
					})
				}
				continue
			}
			if err != nil || (entry.Object != "" && !mysqlDatabasePattern.MatchString(entry.Object)) ||
				(entry.Column != "" && !mysqlDatabasePattern.MatchString(entry.Column)) ||
				(entry.RoutineType != "" && entry.RoutineType != "FUNCTION" && entry.RoutineType != "PROCEDURE") {
				return nil, errors.New("MySQL grant inventory contains an unsupported object or privilege")
			}
			grants = append(grants, entry)
		}
	}
	sort.Slice(grants, func(left, right int) bool {
		leftJSON, _ := json.Marshal(grants[left])
		rightJSON, _ := json.Marshal(grants[right])
		return bytes.Compare(leftJSON, rightJSON) < 0
	})
	return grants, nil
}

func (e *NativeExecutor) mysqlObjectInventory(ctx context.Context, binding mysqlBinding) ([]mysqlObjectManifest, error) {
	database := quoteMySQLLiteral(binding.Database)
	objects := []mysqlObjectManifest{}
	appendObjects := func(kind string, rows [][]string, width int, convert func([]string, string) mysqlObjectManifest) error {
		if len(rows) > 4096 {
			return errors.New("MySQL programmable-object inventory exceeds the 4096-object safety limit")
		}
		for _, row := range rows {
			if len(row) != width || !mysqlDatabasePattern.MatchString(row[0]) {
				return errors.New("MySQL programmable-object inventory is invalid")
			}
			definer, err := mapMySQLDefiner(binding, row[1])
			if err != nil {
				return err
			}
			object := convert(row, definer)
			object.Kind = kind
			objects = append(objects, object)
		}
		return nil
	}
	viewRows, err := e.queryMySQL(ctx, binding, "", "select table_name,definer,security_type from information_schema.views where table_schema="+database+" order by table_name")
	if err != nil || appendObjects("view", viewRows, 3, func(row []string, definer string) mysqlObjectManifest {
		return mysqlObjectManifest{Name: row[0], SecurityType: strings.ToUpper(row[2]), Definer: definer}
	}) != nil {
		return nil, errors.New("MySQL view inventory failed or contains an unmapped definer")
	}
	triggerRows, err := e.queryMySQL(ctx, binding, "", "select trigger_name,definer,event_object_table,event_manipulation,action_timing from information_schema.triggers where trigger_schema="+database+" order by trigger_name")
	if err != nil || appendObjects("trigger", triggerRows, 5, func(row []string, definer string) mysqlObjectManifest {
		return mysqlObjectManifest{Name: row[0], Parent: row[2], Action: strings.ToUpper(row[3]), Timing: strings.ToUpper(row[4]), Definer: definer}
	}) != nil {
		return nil, errors.New("MySQL trigger inventory failed or contains an unmapped definer")
	}
	routineRows, err := e.queryMySQL(ctx, binding, "", "select routine_name,definer,routine_type,security_type from information_schema.routines where routine_schema="+database+" order by routine_type,routine_name")
	if err != nil {
		return nil, err
	}
	for _, row := range routineRows {
		if len(row) != 4 || !mysqlDatabasePattern.MatchString(row[0]) {
			return nil, errors.New("MySQL routine inventory is invalid")
		}
		definer, mapErr := mapMySQLDefiner(binding, row[1])
		if mapErr != nil {
			return nil, mapErr
		}
		kind := "routine:" + strings.ToLower(row[2])
		if kind != "routine:function" && kind != "routine:procedure" {
			return nil, errors.New("MySQL routine type is unsupported")
		}
		objects = append(objects, mysqlObjectManifest{Kind: kind, Name: row[0], SecurityType: strings.ToUpper(row[3]), Definer: definer})
	}
	eventRows, err := e.queryMySQL(ctx, binding, "", "select event_name,definer,status from information_schema.events where event_schema="+database+" order by event_name")
	if err != nil || appendObjects("event", eventRows, 3, func(row []string, definer string) mysqlObjectManifest {
		return mysqlObjectManifest{Name: row[0], Action: strings.ToUpper(row[2]), Definer: definer}
	}) != nil {
		return nil, errors.New("MySQL event inventory failed or contains an unmapped definer")
	}
	sort.Slice(objects, func(left, right int) bool {
		if objects[left].Kind != objects[right].Kind {
			return objects[left].Kind < objects[right].Kind
		}
		return objects[left].Name < objects[right].Name
	})
	return objects, nil
}

func (e *NativeExecutor) verifyMySQLTargetAccounts(ctx context.Context, binding mysqlBinding) error {
	if binding.Mode != "target" {
		return nil
	}
	for _, mapping := range binding.AccountMap {
		rows, err := e.queryMySQL(ctx, binding, "", "select count(*) from mysql.user where user="+quoteMySQLLiteral(mapping.TargetUser)+" and host="+quoteMySQLLiteral(mapping.TargetHost))
		if err != nil {
			return errors.New("target account verification requires permission to inspect mysql.user")
		}
		count, err := parseMySQLSingleInt(rows)
		if err != nil || count != 1 {
			return errors.New("every mapped target MySQL or MariaDB account must be pre-created exactly once")
		}
	}
	return nil
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
	if err := e.verifyMySQLTargetAccounts(ctx, binding); err != nil {
		return mysqlInspection{}, err
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
		inspection.Manifest = mysqlManifest{
			SchemaVersion: "operations.migration.mysql-portable-manifest.v2",
			Tables:        []mysqlTableManifest{}, Objects: []mysqlObjectManifest{}, Grants: []mysqlGrantManifest{},
		}
		inspection.Manifest.Grants, err = e.mysqlGrantInventory(ctx, binding)
		if err != nil {
			return mysqlInspection{}, err
		}
		inspection.ManifestDigest, err = Digest(inspection.Manifest)
		if err != nil {
			return mysqlInspection{}, err
		}
		inspection.Empty = len(inspection.Manifest.Grants) == 0
		inspection.EmptyTargetDigest, err = Digest(map[string]any{
			"schema_version": "operations.migration.mysql-empty-target.v1", "binding_id": bindingID,
			"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database, "engine": binding.Engine}),
			"exists":            false, "engine": inspection.Engine, "server_series": inspection.ServerSeries,
			"character_set": inspection.CharacterSet, "collation": inspection.Collation, "sql_mode": inspection.SQLMode,
			"grant_count": len(inspection.Manifest.Grants), "account_map": binding.AccountMap,
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
	tableRows, err := e.queryMySQL(ctx, binding, "", "select table_name,coalesce(engine,'') from information_schema.tables where table_schema="+quoteMySQLLiteral(binding.Database)+" and table_type='BASE TABLE' order by table_name")
	if err != nil || len(tableRows) > 2048 {
		return mysqlInspection{}, errors.New("MySQL table inventory is outside the 2048-table safety limit")
	}
	manifest := mysqlManifest{
		SchemaVersion: "operations.migration.mysql-portable-manifest.v2",
		Tables:        []mysqlTableManifest{}, Objects: []mysqlObjectManifest{}, Grants: []mysqlGrantManifest{},
	}
	storageEngines := map[string]struct{}{}
	for _, row := range tableRows {
		if len(row) != 2 || !mysqlDatabasePattern.MatchString(row[0]) {
			return mysqlInspection{}, errors.New("MySQL table inventory contains an unsupported identifier")
		}
		engine := strings.ToLower(row[1])
		allowed := engine == "innodb" || engine == "myisam" || (inspection.Engine == "mariadb" && engine == "aria")
		if !allowed {
			return mysqlInspection{}, errors.New("MySQL storage engine is outside the bounded InnoDB, MyISAM, and Aria contract")
		}
		if engine != "innodb" {
			inspection.NonInnoDBCount++
		}
		storageEngines[row[1]] = struct{}{}
		dataDigest, rowCount, dataErr := e.mysqlTableDataDigest(ctx, binding, row[0])
		structureDigest, structureErr := e.mysqlTableStructureDigest(ctx, binding, row[0])
		if dataErr != nil || structureErr != nil {
			return mysqlInspection{}, errors.New("MySQL table manifest calculation failed")
		}
		inspection.TotalRows += rowCount
		manifest.Tables = append(manifest.Tables, mysqlTableManifest{
			Name: row[0], RowCount: rowCount, DataDigest: dataDigest, StructureDigest: structureDigest,
		})
	}
	sort.Slice(manifest.Tables, func(left, right int) bool {
		return manifest.Tables[left].Name < manifest.Tables[right].Name
	})
	manifest.Objects, err = e.mysqlObjectInventory(ctx, binding)
	if err != nil {
		return mysqlInspection{}, err
	}
	manifest.Grants, err = e.mysqlGrantInventory(ctx, binding)
	if err != nil {
		return mysqlInspection{}, err
	}
	inspection.StorageEngines = make([]string, 0, len(storageEngines))
	for engine := range storageEngines {
		inspection.StorageEngines = append(inspection.StorageEngines, engine)
	}
	sort.Strings(inspection.StorageEngines)
	inspection.Manifest = manifest
	inspection.ManifestDigest, err = Digest(manifest)
	if err != nil {
		return mysqlInspection{}, err
	}
	inspection.Empty = len(manifest.Tables) == 0 && len(manifest.Objects) == 0
	inspection.EmptyTargetDigest, err = Digest(map[string]any{
		"schema_version": "operations.migration.mysql-empty-target.v1", "binding_id": bindingID,
		"database_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "database": binding.Database, "engine": binding.Engine}),
		"exists":            true, "empty": inspection.Empty, "engine": inspection.Engine, "server_series": inspection.ServerSeries,
		"character_set": inspection.CharacterSet, "collation": inspection.Collation, "sql_mode": inspection.SQLMode,
		"grant_count": len(manifest.Grants), "account_map": binding.AccountMap,
	})
	return inspection, err
}

func mysqlInspectionOutputs(inspection mysqlInspection) map[string]any {
	return map[string]any{
		"exists": inspection.Exists, "empty": inspection.Empty, "engine": inspection.Engine,
		"server_version": inspection.ServerVersion, "server_series": inspection.ServerSeries,
		"character_set": inspection.CharacterSet, "collation": inspection.Collation, "sql_mode": inspection.SQLMode,
		"table_count": len(inspection.Manifest.Tables), "total_rows": inspection.TotalRows,
		"object_count": len(inspection.Manifest.Objects), "grant_count": len(inspection.Manifest.Grants),
		"non_innodb_table_count": inspection.NonInnoDBCount, "storage_engines": inspection.StorageEngines,
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
	if binding.Mode != "target" || (requiredEngine != "mysql" && requiredEngine != "mariadb") ||
		requiredCharacterSet != inspection.CharacterSet {
		return errors.New("target MySQL or MariaDB compatibility does not match the source character contract")
	}
	if requiredEngine == inspection.Engine {
		if requiredSeries != inspection.ServerSeries || requiredCollation != inspection.Collation || canonicalMySQLMode(requiredSQLMode) != inspection.SQLMode {
			return errors.New("same-engine MySQL or MariaDB targets must exactly match the source series, collation, and SQL mode")
		}
		return nil
	}
	if !((requiredEngine == "mysql" && inspection.Engine == "mariadb") || (requiredEngine == "mariadb" && inspection.Engine == "mysql")) {
		return errors.New("only MySQL to MariaDB or MariaDB to MySQL conversion is supported")
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
		if binding.Mode != "target" || !binding.ResetAllowed || !strings.HasPrefix(binding.Database, "askio_mig_") || !inspection.Empty || len(inspection.Manifest.Grants) != 0 {
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

type mysqlMigrationMetadata struct {
	SchemaVersion    string               `json:"schema_version"`
	SourceEngine     string               `json:"source_engine"`
	TargetEngine     string               `json:"target_engine"`
	ManifestDigest   string               `json:"manifest_digest"`
	AccountMapDigest string               `json:"account_map_digest"`
	Grants           []mysqlGrantManifest `json:"grants"`
}

func splitMySQLAccountKey(value string) (string, string, error) {
	separator := strings.LastIndex(value, "@")
	if separator < 1 || separator == len(value)-1 {
		return "", "", errors.New("MySQL account key is invalid")
	}
	user, host := value[:separator], value[separator+1:]
	if !mysqlAccountPattern.MatchString(user) || !mysqlHostPattern.MatchString(host) {
		return "", "", errors.New("MySQL account key is invalid")
	}
	return user, host, nil
}

type mysqlDumpTransformState struct {
	quote             byte
	blockComment      bool
	executableComment bool
}

func transformMySQLDumpCode(code string, binding mysqlBinding, sourceEngine, targetEngine, targetCollation string) (string, error) {
	matches := mysqlDefinerPattern.FindAllStringSubmatch(code, -1)
	for _, match := range matches {
		if len(match) != 3 {
			return "", errors.New("MySQL dump contains an invalid definer")
		}
		entry, ok := binding.sourceAccountMap()[mysqlAccountKey(match[1], match[2])]
		if !ok {
			return "", errors.New("MySQL dump contains a definer outside the explicit account map")
		}
		replacement := "DEFINER=`" + entry.TargetUser + "`@`" + entry.TargetHost + "`"
		code = strings.ReplaceAll(code, match[0], replacement)
	}
	code = strings.ReplaceAll(code, quoteMySQLIdentifier(binding.Database)+".", "")
	if sourceEngine != targetEngine {
		code = mysqlCollationPattern.ReplaceAllString(code, "COLLATE "+targetCollation)
		if targetEngine == "mysql" {
			code = mysqlAriaEnginePattern.ReplaceAllString(code, "ENGINE=InnoDB")
			for _, pattern := range mysqlMariaTableOptionPatterns {
				code = pattern.ReplaceAllString(code, "")
			}
		}
	}
	return code, nil
}

func transformMySQLDumpLine(line string, state *mysqlDumpTransformState, binding mysqlBinding, sourceEngine, targetEngine, targetCollation string) (string, error) {
	var output strings.Builder
	output.Grow(len(line))
	writeCode := func(start, end int) error {
		if end <= start {
			return nil
		}
		transformed, err := transformMySQLDumpCode(line[start:end], binding, sourceEngine, targetEngine, targetCollation)
		if err != nil {
			return err
		}
		_, err = output.WriteString(transformed)
		return err
	}
	index := 0
	for index < len(line) {
		if state.blockComment {
			closing := strings.Index(line[index:], "*/")
			if closing < 0 {
				output.WriteString(line[index:])
				return output.String(), nil
			}
			closing += index + 2
			output.WriteString(line[index:closing])
			index = closing
			state.blockComment = false
			continue
		}
		if state.quote != 0 {
			start := index
			for index < len(line) {
				if line[index] == '\\' && index+1 < len(line) {
					index += 2
					continue
				}
				if line[index] == state.quote {
					if index+1 < len(line) && line[index+1] == state.quote {
						index += 2
						continue
					}
					index++
					state.quote = 0
					break
				}
				index++
			}
			output.WriteString(line[start:index])
			continue
		}

		codeStart := index
		for index < len(line) {
			if state.executableComment && index+1 < len(line) && line[index:index+2] == "*/" {
				index += 2
				state.executableComment = false
				continue
			}
			if line[index] == '\'' || line[index] == '"' {
				if err := writeCode(codeStart, index); err != nil {
					return "", err
				}
				state.quote = line[index]
				output.WriteByte(line[index])
				index++
				break
			}
			if !state.executableComment && index+1 < len(line) && line[index:index+2] == "/*" {
				executable := strings.HasPrefix(line[index:], "/*!") || strings.HasPrefix(line[index:], "/*M!")
				if executable {
					state.executableComment = true
					index += 3
					continue
				}
				if err := writeCode(codeStart, index); err != nil {
					return "", err
				}
				state.blockComment = true
				break
			}
			if !state.executableComment && (line[index] == '#' ||
				(index+2 < len(line) && line[index:index+2] == "--" && (line[index+2] == ' ' || line[index+2] == '\t' || line[index+2] == '\r' || line[index+2] == '\n'))) {
				if err := writeCode(codeStart, index); err != nil {
					return "", err
				}
				output.WriteString(line[index:])
				return output.String(), nil
			}
			index++
		}
		if index > codeStart && state.quote == 0 && !state.blockComment {
			if err := writeCode(codeStart, index); err != nil {
				return "", err
			}
		}
	}
	return output.String(), nil
}

func transformMySQLDump(reader io.Reader, writer io.Writer, binding mysqlBinding, sourceEngine, targetEngine, targetCollation string) error {
	buffered := bufio.NewReaderSize(reader, 256*1024)
	state := &mysqlDumpTransformState{}
	for {
		line, readErr := buffered.ReadString('\n')
		if len(line) > maximumMySQLRowBytes {
			return errors.New("MySQL dump statement exceeds the 64 MiB transformation limit")
		}
		if strings.Contains(strings.ToLower(line), "enable the sandbox mode") {
			line = ""
		}
		if targetEngine == "mysql" && sourceEngine != targetEngine && mysqlSQLModeStatementPattern.MatchString(line) {
			for _, pattern := range mysqlRemovedSQLModePatterns {
				line = pattern.ReplaceAllString(line, "")
			}
		}
		if line != "" {
			transformed, transformErr := transformMySQLDumpLine(line, state, binding, sourceEngine, targetEngine, targetCollation)
			if transformErr != nil {
				return transformErr
			}
			line = transformed
		}
		if line != "" {
			if _, err := io.WriteString(writer, line); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			if state.quote != 0 || state.blockComment || state.executableComment {
				return errors.New("MySQL dump ended inside a quoted or commented SQL segment")
			}
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
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
	targetEngine, err := stringInput(inputs, "target_engine")
	if err != nil || (targetEngine != "mysql" && targetEngine != "mariadb") {
		return nil, errors.New("target MySQL engine is invalid")
	}
	targetCharacterSet, err := stringInput(inputs, "target_character_set")
	if err != nil || targetCharacterSet != inspection.CharacterSet {
		return nil, errors.New("target MySQL character set must match the source")
	}
	targetCollation, err := stringInput(inputs, "target_collation")
	if err != nil || !mysqlCharacterPattern.MatchString(targetCollation) {
		return nil, errors.New("target MySQL collation is invalid")
	}
	if targetEngine == inspection.Engine && targetCollation != inspection.Collation {
		return nil, errors.New("same-engine MySQL dumps require the source collation")
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
	args := []string{"--quick", "--hex-blob", "--triggers", "--routines", "--events", "--skip-extended-insert", "--skip-add-locks"}
	if inspection.NonInnoDBCount > 0 {
		args = append(args, "--lock-all-tables")
	} else {
		args = append(args, "--single-transaction", "--skip-lock-tables")
	}
	if binding.Engine == "mysql" {
		args = append(args, "--no-tablespaces", "--set-gtid-purged=OFF")
	}
	args = append(args, binding.Database)
	pipeReader, pipeWriter := io.Pipe()
	commandResult := make(chan error, 1)
	go func() {
		commandErr := e.mysqlCommand(ctx, binding, dump, args, nil, pipeWriter)
		_ = pipeWriter.CloseWithError(commandErr)
		commandResult <- commandErr
	}()
	transformErr := transformMySQLDump(pipeReader, file, binding, inspection.Engine, targetEngine, targetCollation)
	if transformErr != nil {
		_ = pipeReader.CloseWithError(transformErr)
	}
	commandErr := <-commandResult
	syncErr := file.Sync()
	closeErr := file.Close()
	if commandErr != nil || transformErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(partial)
		if commandErr != nil {
			return nil, commandErr
		}
		if transformErr != nil {
			return nil, transformErr
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
	metadata := mysqlMigrationMetadata{
		SchemaVersion: "operations.migration.mysql-conversion-metadata.v1",
		SourceEngine:  inspection.Engine, TargetEngine: targetEngine,
		ManifestDigest: inspection.ManifestDigest, AccountMapDigest: MustDigest(binding.AccountMap),
		Grants: inspection.Manifest.Grants,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	metadataPath := filepath.Join(directory, "database.metadata.json")
	if err := os.WriteFile(metadataPath, metadataBytes, 0o600); err != nil {
		return nil, err
	}
	metadataDigest, _, err := fileSHA256(metadataPath)
	if err != nil {
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
		"server_series": inspection.ServerSeries, "target_engine": targetEngine,
		"migration_metadata_digest": metadataDigest, "object_count": len(inspection.Manifest.Objects),
		"grant_count": len(inspection.Manifest.Grants), "non_innodb_table_count": inspection.NonInnoDBCount,
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

func mysqlGrantStatement(entry mysqlGrantManifest, database string, revoke bool) (string, error) {
	user, host, err := splitMySQLAccountKey(entry.Principal)
	if err != nil {
		return "", err
	}
	privilege, err := validateMySQLPrivilege(entry.Privilege)
	if err != nil {
		return "", err
	}
	scope := ""
	switch entry.Scope {
	case "database":
		scope = quoteMySQLIdentifier(database) + ".*"
	case "table":
		if !mysqlDatabasePattern.MatchString(entry.Object) {
			return "", errors.New("MySQL table grant object is invalid")
		}
		scope = quoteMySQLIdentifier(database) + "." + quoteMySQLIdentifier(entry.Object)
	case "column":
		if !mysqlDatabasePattern.MatchString(entry.Object) || !mysqlDatabasePattern.MatchString(entry.Column) {
			return "", errors.New("MySQL column grant object is invalid")
		}
		privilege += " (" + quoteMySQLIdentifier(entry.Column) + ")"
		scope = quoteMySQLIdentifier(database) + "." + quoteMySQLIdentifier(entry.Object)
	case "routine":
		if !mysqlDatabasePattern.MatchString(entry.Object) || (entry.RoutineType != "FUNCTION" && entry.RoutineType != "PROCEDURE") {
			return "", errors.New("MySQL routine grant object is invalid")
		}
		scope = entry.RoutineType + " " + quoteMySQLIdentifier(database) + "." + quoteMySQLIdentifier(entry.Object)
	default:
		return "", errors.New("MySQL grant scope is invalid")
	}
	account := quoteMySQLLiteral(user) + "@" + quoteMySQLLiteral(host)
	if revoke {
		return "revoke " + privilege + " on " + scope + " from " + account, nil
	}
	statement := "grant " + privilege + " on " + scope + " to " + account
	if entry.Grantable {
		statement += " with grant option"
	}
	return statement, nil
}

func mysqlGrantOptionRevokeStatement(entry mysqlGrantManifest, database string) (string, error) {
	user, host, err := splitMySQLAccountKey(entry.Principal)
	if err != nil {
		return "", err
	}
	scope := ""
	switch entry.Scope {
	case "database":
		scope = quoteMySQLIdentifier(database) + ".*"
	case "table", "column":
		if !mysqlDatabasePattern.MatchString(entry.Object) {
			return "", errors.New("MySQL table grant object is invalid")
		}
		scope = quoteMySQLIdentifier(database) + "." + quoteMySQLIdentifier(entry.Object)
	case "routine":
		if !mysqlDatabasePattern.MatchString(entry.Object) || (entry.RoutineType != "FUNCTION" && entry.RoutineType != "PROCEDURE") {
			return "", errors.New("MySQL routine grant object is invalid")
		}
		scope = entry.RoutineType + " " + quoteMySQLIdentifier(database) + "." + quoteMySQLIdentifier(entry.Object)
	default:
		return "", errors.New("MySQL grant scope is invalid")
	}
	account := quoteMySQLLiteral(user) + "@" + quoteMySQLLiteral(host)
	return "revoke grant option on " + scope + " from " + account, nil
}

func (e *NativeExecutor) applyMySQLGrants(ctx context.Context, binding mysqlBinding, grants []mysqlGrantManifest, revoke bool) error {
	statements := make([]string, 0, len(grants))
	grantOptionRevokes := map[string]struct{}{}
	for _, grant := range grants {
		if _, ok := binding.targetAccountMap()[grant.Principal]; !ok {
			return errors.New("MySQL grant metadata references an account outside the target map")
		}
		statement, err := mysqlGrantStatement(grant, binding.Database, revoke)
		if err != nil {
			return err
		}
		statements = append(statements, statement)
		if revoke && grant.Grantable {
			grantOptionStatement, optionErr := mysqlGrantOptionRevokeStatement(grant, binding.Database)
			if optionErr != nil {
				return optionErr
			}
			grantOptionRevokes[grantOptionStatement] = struct{}{}
		}
	}
	if revoke {
		ordered := make([]string, 0, len(grantOptionRevokes))
		for statement := range grantOptionRevokes {
			ordered = append(ordered, statement)
		}
		sort.Strings(ordered)
		for _, statement := range ordered {
			if _, err := e.queryMySQL(ctx, binding, "", statement); err != nil {
				return errors.New("target MySQL grant-option revocation failed")
			}
		}
	}
	for _, statement := range statements {
		if _, err := e.queryMySQL(ctx, binding, "", statement); err != nil {
			return errors.New("target MySQL database-scoped grant application failed")
		}
	}
	return nil
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
	if !ownedByRun && len(inspection.Manifest.Grants) > 0 {
		return nil, errors.New("unowned target MySQL database grants cannot be revoked by reset")
	}
	if (!inspection.Empty || inspection.EmptyTargetDigest != expectedDigest) && !ownedByRun {
		return nil, errors.New("target MySQL database is not the approved empty target and is not owned by this migration")
	}
	if ownedByRun && len(inspection.Manifest.Grants) > 0 {
		if err := e.applyMySQLGrants(ctx, binding, inspection.Manifest.Grants, true); err != nil {
			return nil, err
		}
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
	expectedMetadataDigest, err := stringInput(inputs, "migration_metadata_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedMetadataDigest) {
		return nil, errors.New("expected MySQL conversion metadata digest is invalid")
	}
	metadataPath, err := e.resolver.Resolve(stagingHandle, filepath.Join(stagingRelative, "database.metadata.json"), false)
	if err != nil {
		return nil, err
	}
	actualMetadataDigest, _, err := fileSHA256(metadataPath)
	if err != nil || actualMetadataDigest != expectedMetadataDigest {
		return nil, errors.New("MySQL conversion metadata digest verification failed")
	}
	metadataFile, err := os.Open(metadataPath)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(metadataFile)
	decoder.DisallowUnknownFields()
	var metadata mysqlMigrationMetadata
	decodeErr := decoder.Decode(&metadata)
	var trailing any
	trailingErr := decoder.Decode(&trailing)
	closeErr := metadataFile.Close()
	if decodeErr != nil || !errors.Is(trailingErr, io.EOF) || closeErr != nil || metadata.SchemaVersion != "operations.migration.mysql-conversion-metadata.v1" ||
		metadata.TargetEngine != binding.Engine || metadata.ManifestDigest != expectedManifestDigest ||
		metadata.AccountMapDigest != MustDigest(binding.AccountMap) || len(metadata.Grants) > 100_000 {
		return nil, errors.New("MySQL conversion metadata contract is invalid")
	}
	if metadata.SourceEngine != "mysql" && metadata.SourceEngine != "mariadb" {
		return nil, errors.New("MySQL conversion metadata source engine is invalid")
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
	if err := e.applyMySQLGrants(ctx, binding, metadata.Grants, false); err != nil {
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
		"migration_metadata_digest": actualMetadataDigest, "restored_size_bytes": size,
		"table_count": len(after.Manifest.Tables), "total_rows": after.TotalRows,
		"object_count": len(after.Manifest.Objects), "grant_count": len(after.Manifest.Grants),
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
		"object_count": len(inspection.Manifest.Objects), "grant_count": len(inspection.Manifest.Grants),
		"non_innodb_table_count": inspection.NonInnoDBCount,
	}, nil
}
