package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	postgresLogicalBindingSchema    = "operations.migration.postgres-logical-source-binding.v1"
	postgresLogicalMarkerSchema     = "operations.migration.postgres-logical-marker.v1"
	postgresLogicalFinalStateSchema = "operations.migration.postgres-logical-final-state.v1"
	postgresLogicalSchemaHandle     = "database.schema.sql"
	postgresLogicalFinalStateHandle = "database.final-state.json"
	maximumPostgresLogicalSchema    = int64(64 * 1024 * 1024)
	maximumPostgresLogicalState     = int64(8 * 1024 * 1024)
	minimumPostgresLogicalWAL       = int64(64 * 1024 * 1024)
	maximumPostgresLogicalWAL       = int64(64 * 1024 * 1024 * 1024)
)

var postgresLSNPattern = regexp.MustCompile(`^[0-9A-F]+/[0-9A-F]+$`)

// postgresLogicalContract is deliberately small. Anything that changes the
// replication topology or expands object support belongs in a new contract.
type postgresLogicalContract struct {
	Mode                  string `json:"mode"`
	ReplicationRole       string `json:"replication_role"`
	MaximumCatchupSeconds int    `json:"maximum_catchup_seconds"`
	MaximumSlotWALBytes   int64  `json:"maximum_slot_wal_bytes"`
}

type postgresLogicalSourceBinding struct {
	SchemaVersion         string `json:"schema_version"`
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	Database              string `json:"database"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	SSLMode               string `json:"ssl_mode"`
	SSLRootCertPEM        string `json:"ssl_root_cert_pem"`
	ServerSSLRootCertPath string `json:"server_ssl_root_cert_path"`
}

func (b *postgresLogicalSourceBinding) clear() {
	b.Password = ""
	b.SSLRootCertPEM = ""
}

func validatePostgresLogicalContract(contract *postgresLogicalContract, binding postgresBinding, mappings []postgresDatabaseMapping) error {
	if contract == nil {
		return nil
	}
	if contract.Mode != "lower-downtime" || !postgresIdentifierPattern.MatchString(contract.ReplicationRole) ||
		strings.HasPrefix(contract.ReplicationRole, "pg_") || contract.MaximumCatchupSeconds < 60 ||
		contract.MaximumCatchupSeconds > 7200 || contract.MaximumSlotWALBytes < minimumPostgresLogicalWAL ||
		contract.MaximumSlotWALBytes > maximumPostgresLogicalWAL {
		return errors.New("PostgreSQL lower-downtime contract is outside the bounded V1 profile")
	}
	if len(mappings) != 1 || len(binding.Databases) != 1 {
		return errors.New("PostgreSQL lower-downtime V1 supports exactly one database")
	}
	return nil
}

func postgresLogicalContractFromInputs(inputs map[string]any, binding postgresBinding) (postgresLogicalContract, error) {
	raw, ok := inputs["database_contract"]
	if !ok {
		return postgresLogicalContract{}, errors.New("PostgreSQL lower-downtime operation requires a database contract")
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 64*1024 {
		return postgresLogicalContract{}, errors.New("PostgreSQL lower-downtime database contract is invalid")
	}
	var contract postgresDatabaseContract
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return postgresLogicalContract{}, errors.New("PostgreSQL lower-downtime database contract is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return postgresLogicalContract{}, errors.New("PostgreSQL lower-downtime database contract contains trailing data")
	}
	if contract.LogicalReplication == nil {
		return postgresLogicalContract{}, errors.New("PostgreSQL lower-downtime contract is missing")
	}
	if err := validatePostgresLogicalContract(contract.LogicalReplication, binding, contract.DatabaseMappings); err != nil {
		return postgresLogicalContract{}, err
	}
	return *contract.LogicalReplication, nil
}

func parsePostgresLogicalSourceBinding(raw []byte, contract postgresLogicalContract) (postgresLogicalSourceBinding, error) {
	var binding postgresLogicalSourceBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return postgresLogicalSourceBinding{}, errors.New("PostgreSQL logical source binding JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return postgresLogicalSourceBinding{}, errors.New("PostgreSQL logical source binding contains trailing data")
	}
	if binding.SchemaVersion != postgresLogicalBindingSchema || binding.Port < 1 || binding.Port > 65535 ||
		!postgresIdentifierPattern.MatchString(binding.Database) || binding.Database == "postgres" ||
		!postgresIdentifierPattern.MatchString(binding.Username) || binding.Username != contract.ReplicationRole ||
		binding.SSLMode != "verify-full" || !strings.Contains(binding.SSLRootCertPEM, "BEGIN CERTIFICATE") ||
		len(binding.SSLRootCertPEM) > 64*1024 || strings.ContainsAny(binding.Password, "\x00\r\n") || len(binding.Password) > 16*1024 {
		return postgresLogicalSourceBinding{}, errors.New("PostgreSQL logical source binding is outside the bounded V1 profile")
	}
	if err := validatePostgresHost(binding.Host, binding.SSLMode); err != nil {
		return postgresLogicalSourceBinding{}, err
	}
	clean := filepath.Clean(binding.ServerSSLRootCertPath)
	allowed := strings.HasPrefix(clean, "/etc/ssl/certs/") || strings.HasPrefix(clean, "/var/lib/askio-migrations/")
	if clean != binding.ServerSSLRootCertPath || !allowed || strings.ContainsAny(clean, "\x00\r\n\t") {
		return postgresLogicalSourceBinding{}, errors.New("PostgreSQL target-server CA path is outside the approved roots")
	}
	return binding, nil
}

func (b postgresLogicalSourceBinding) postgresBinding() postgresBinding {
	return postgresBinding{
		SchemaVersion: postgresBindingSchema, Mode: "source", Host: b.Host, Port: b.Port,
		Database: b.Database, Databases: []string{b.Database}, MaintenanceDatabase: b.Database,
		Username: b.Username, Password: b.Password, SSLMode: b.SSLMode, SSLRootCertPEM: b.SSLRootCertPEM,
		RoleMap: map[string]string{b.Username: b.Username},
	}
}

func (e *NativeExecutor) resolvePostgresLogicalSourceBinding(ctx context.Context, task TaskEnvelope, inputs map[string]any, contract postgresLogicalContract) (string, postgresLogicalSourceBinding, error) {
	bindingID, err := stringInput(inputs, "logical_source_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return "", postgresLogicalSourceBinding{}, errors.New("PostgreSQL logical source binding identifier is invalid")
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return "", postgresLogicalSourceBinding{}, err
	}
	defer zeroBytes(raw)
	binding, err := parsePostgresLogicalSourceBinding(raw, contract)
	return bindingID, binding, err
}

type postgresLogicalNames struct {
	Publication  string `json:"publication"`
	Slot         string `json:"slot"`
	Subscription string `json:"subscription"`
}

func postgresLogicalObjectNames(migrationID, sourceDatabase string) (postgresLogicalNames, error) {
	if !opaqueBindingPattern.MatchString(migrationID) || !postgresIdentifierPattern.MatchString(sourceDatabase) {
		return postgresLogicalNames{}, errors.New("PostgreSQL logical object identity is invalid")
	}
	digest := sha256.Sum256([]byte(migrationID + "\x00" + sourceDatabase))
	token := hex.EncodeToString(digest[:10])
	return postgresLogicalNames{
		Publication: "askio_pub_" + token, Slot: "askio_slot_" + token, Subscription: "askio_sub_" + token,
	}, nil
}

type postgresLogicalMarker struct {
	SchemaVersion     string               `json:"schema_version"`
	MigrationID       string               `json:"migration_id"`
	PlanDigest        string               `json:"plan_digest"`
	EndpointRole      string               `json:"endpoint_role"`
	DatabaseBindingID string               `json:"database_binding_id"`
	LogicalBindingID  string               `json:"logical_binding_id,omitempty"`
	Database          string               `json:"database"`
	Names             postgresLogicalNames `json:"names"`
	SchemaDigest      string               `json:"schema_digest,omitempty"`
	FinalStateDigest  string               `json:"final_state_digest,omitempty"`
	Status            string               `json:"status"`
	UpdatedAt         string               `json:"updated_at"`
}

func taskPlanDigest(task TaskEnvelope) string {
	if task.PlanDigest == nil {
		return ""
	}
	return *task.PlanDigest
}

func (e *NativeExecutor) postgresLogicalMarkerPath(bindingID, endpointRole string) string {
	digest := sha256.Sum256([]byte(endpointRole + "\x00" + bindingID))
	return filepath.Join(e.stateDir, "postgres-logical-markers", hex.EncodeToString(digest[:16])+".json")
}

func (e *NativeExecutor) loadPostgresLogicalMarker(bindingID, endpointRole string) (postgresLogicalMarker, error) {
	var marker postgresLogicalMarker
	if err := loadJSONFile(e.postgresLogicalMarkerPath(bindingID, endpointRole), &marker); err != nil {
		return marker, err
	}
	if marker.SchemaVersion != postgresLogicalMarkerSchema || marker.EndpointRole != endpointRole {
		return postgresLogicalMarker{}, errors.New("PostgreSQL logical ownership marker is invalid")
	}
	return marker, nil
}

func (e *NativeExecutor) savePostgresLogicalMarker(bindingID, endpointRole string, marker postgresLogicalMarker) error {
	marker.SchemaVersion = postgresLogicalMarkerSchema
	marker.EndpointRole = endpointRole
	marker.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return atomicJSONFile(e.postgresLogicalMarkerPath(bindingID, endpointRole), marker)
}

func validatePostgresLogicalMarker(marker postgresLogicalMarker, task TaskEnvelope, databaseBindingID, logicalBindingID, endpointRole, database string, names postgresLogicalNames) error {
	if marker.MigrationID != task.MigrationID || marker.PlanDigest != taskPlanDigest(task) || marker.EndpointRole != endpointRole ||
		marker.DatabaseBindingID != databaseBindingID || marker.LogicalBindingID != logicalBindingID || marker.Database != database ||
		marker.Names != names {
		return errors.New("PostgreSQL logical object ownership is unproven")
	}
	return nil
}

func postgresBool(rows [][]string) (bool, error) {
	if len(rows) != 1 || len(rows[0]) != 1 {
		return false, errors.New("PostgreSQL returned an invalid boolean result")
	}
	switch rows[0][0] {
	case "t", "true":
		return true, nil
	case "f", "false":
		return false, nil
	default:
		return false, errors.New("PostgreSQL returned an invalid boolean result")
	}
}

func requirePostgresSuperuser(ctx context.Context, e *NativeExecutor, binding postgresBinding) error {
	rows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select rolsuper::text from pg_roles where rolname=current_user")
	if err != nil {
		return err
	}
	value, err := postgresBool(rows)
	if err != nil || !value {
		return errors.New("PostgreSQL lower-downtime V1 requires a superuser control binding")
	}
	return nil
}

type postgresLogicalEligibility struct {
	ServerMajor  int
	TableCount   int64
	SchemaDigest string
}

func (e *NativeExecutor) inspectPostgresLogicalEligibility(ctx context.Context, binding postgresBinding, contract postgresLogicalContract, requireSourceSettings, allowEmpty bool) (postgresLogicalEligibility, error) {
	if err := requirePostgresSuperuser(ctx, e, binding); err != nil {
		return postgresLogicalEligibility{}, err
	}
	versionRows, err := e.queryPostgres(ctx, binding, binding.Database, "show server_version_num")
	version, parseErr := parseSingleInt(versionRows)
	major := int(version / 10000)
	if err != nil || parseErr != nil || major < 14 || major > 17 {
		return postgresLogicalEligibility{}, errors.New("PostgreSQL lower-downtime V1 requires PostgreSQL 14-17")
	}
	unsupportedRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace "+
			"where n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and "+
			"c.relkind in('r','p','m','f') and "+
			"(c.relkind<>'r' or c.relpersistence<>'p' or c.relispartition or c.relrowsecurity or c.relforcerowsecurity "+
			"or not exists(select 1 from pg_index i where i.indrelid=c.oid and i.indisprimary) "+
			"or exists(select 1 from pg_attribute a where a.attrelid=c.oid and a.attnum>0 and not a.attisdropped and a.attgenerated<>'') "+
			"or exists(select 1 from pg_depend d where d.classid='pg_class'::regclass and d.objid=c.oid and d.deptype='e'))")
	unsupported, unsupportedParseErr := parseSingleInt(unsupportedRows)
	if err != nil || unsupportedParseErr != nil || unsupported != 0 {
		return postgresLogicalEligibility{}, errors.New("PostgreSQL lower-downtime V1 requires ordinary permanent primary-keyed tables without RLS, generated columns, partitions, or extension ownership")
	}
	extensionRows, err := e.queryPostgres(ctx, binding, binding.Database, "select count(*) from pg_extension where extname<>'plpgsql'")
	extensions, extensionParseErr := parseSingleInt(extensionRows)
	if err != nil || extensionParseErr != nil || extensions != 0 {
		return postgresLogicalEligibility{}, errors.New("PostgreSQL extensions are outside lower-downtime V1")
	}
	largeObjectRows, err := e.queryPostgres(ctx, binding, binding.Database, "select count(*) from pg_largeobject_metadata")
	largeObjects, largeObjectParseErr := parseSingleInt(largeObjectRows)
	if err != nil || largeObjectParseErr != nil || largeObjects != 0 {
		return postgresLogicalEligibility{}, errors.New("PostgreSQL large objects are outside lower-downtime V1")
	}
	tableRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='r' and n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast'")
	tableCount, tableParseErr := parseSingleInt(tableRows)
	if err != nil || tableParseErr != nil || tableCount > 2048 || (!allowEmpty && tableCount < 1) {
		return postgresLogicalEligibility{}, errors.New("PostgreSQL lower-downtime V1 requires a bounded eligible table set")
	}
	if requireSourceSettings {
		settings, err := e.queryPostgres(ctx, binding, binding.Database,
			"select current_setting('wal_level'),current_setting('max_replication_slots')::int::text,current_setting('max_wal_senders')::int::text")
		if err != nil || len(settings) != 1 || len(settings[0]) != 3 || settings[0][0] != "logical" {
			return postgresLogicalEligibility{}, errors.New("PostgreSQL source requires wal_level=logical and available replication capacity")
		}
		slots, slotErr := strconv.Atoi(settings[0][1])
		senders, senderErr := strconv.Atoi(settings[0][2])
		usedSlotRows, usedSlotErr := e.queryPostgres(ctx, binding, binding.Database, "select count(*) from pg_replication_slots")
		usedSlots, usedSlotParseErr := parseSingleInt(usedSlotRows)
		if slotErr != nil || senderErr != nil || usedSlotErr != nil || usedSlotParseErr != nil || slots-int(usedSlots) < 1 || senders < 1 {
			return postgresLogicalEligibility{}, errors.New("PostgreSQL source has no bounded logical replication capacity")
		}
		roleQuery := "select (rolcanlogin and rolreplication and rolbypassrls and not rolsuper and not rolcreatedb and not rolcreaterole)::text from pg_roles where rolname=" + quotePostgresLiteral(contract.ReplicationRole)
		roleRows, err := e.queryPostgres(ctx, binding, binding.Database, roleQuery)
		roleOK, roleErr := postgresBool(roleRows)
		if err != nil || roleErr != nil || !roleOK {
			return postgresLogicalEligibility{}, errors.New("dedicated PostgreSQL replication role is missing or over-privileged")
		}
		privilegeQuery := "select (has_database_privilege(" + quotePostgresLiteral(contract.ReplicationRole) + ",current_database(),'CONNECT') and not exists(" +
			"select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='r' and n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' and " +
			"(not has_schema_privilege(" + quotePostgresLiteral(contract.ReplicationRole) + ",n.oid,'USAGE') or not has_table_privilege(" + quotePostgresLiteral(contract.ReplicationRole) + ",c.oid,'SELECT'))))::text"
		privilegeRows, err := e.queryPostgres(ctx, binding, binding.Database, privilegeQuery)
		privilegeOK, privilegeErr := postgresBool(privilegeRows)
		if err != nil || privilegeErr != nil || !privilegeOK {
			return postgresLogicalEligibility{}, errors.New("dedicated PostgreSQL replication role lacks CONNECT, USAGE, or SELECT")
		}
	}
	return postgresLogicalEligibility{ServerMajor: major, TableCount: tableCount}, nil
}

func postgresExecutableMajor(ctx context.Context, binary string) (int, error) {
	command := exec.CommandContext(ctx, binary, "--version")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	output, err := command.Output()
	if err != nil {
		return 0, errors.New("PostgreSQL client version inspection failed")
	}
	fields := strings.Fields(string(output))
	for _, field := range fields {
		part := strings.Trim(field, "()")
		if index := strings.IndexByte(part, '.'); index > 0 {
			part = part[:index]
		}
		if major, parseErr := strconv.Atoi(part); parseErr == nil && major >= 12 && major <= 99 {
			return major, nil
		}
	}
	return 0, errors.New("PostgreSQL client version is invalid")
}

func postgresLogicalMappingFromInputs(inputs map[string]any) (postgresDatabaseMapping, error) {
	raw, ok := inputs["database_contract"]
	if !ok {
		return postgresDatabaseMapping{}, errors.New("PostgreSQL lower-downtime database contract is missing")
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 64*1024 {
		return postgresDatabaseMapping{}, errors.New("PostgreSQL lower-downtime database contract is invalid")
	}
	var contract postgresDatabaseContract
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil || len(contract.DatabaseMappings) != 1 {
		return postgresDatabaseMapping{}, errors.New("PostgreSQL lower-downtime V1 requires exactly one database mapping")
	}
	return contract.DatabaseMappings[0], nil
}

func normalizePostgresLogicalSchema(data []byte) ([]byte, error) {
	if int64(len(data)) < 1 || int64(len(data)) > maximumPostgresLogicalSchema || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("PostgreSQL logical schema artifact exceeds its safety limit")
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(text, "\n")
	normalized := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "-- Dumped from database version") ||
			strings.HasPrefix(trimmed, "-- Dumped by pg_dump version") ||
			strings.HasPrefix(trimmed, `\restrict `) || strings.HasPrefix(trimmed, `\unrestrict `) {
			continue
		}
		normalized = append(normalized, strings.TrimRight(line, " \t"))
	}
	for len(normalized) > 0 && normalized[len(normalized)-1] == "" {
		normalized = normalized[:len(normalized)-1]
	}
	result := []byte(strings.Join(normalized, "\n") + "\n")
	if int64(len(result)) > maximumPostgresLogicalSchema {
		return nil, errors.New("PostgreSQL logical schema artifact exceeds its safety limit")
	}
	return result, nil
}

func postgresBytesDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (e *NativeExecutor) dumpPostgresLogicalSchema(ctx context.Context, binding postgresBinding, serverMajor int) ([]byte, string, error) {
	pgDump, err := fixedPostgresExecutable("pg_dump")
	if err != nil {
		return nil, "", err
	}
	clientMajor, err := postgresExecutableMajor(ctx, pgDump)
	if err != nil || clientMajor != serverMajor {
		return nil, "", errors.New("PostgreSQL lower-downtime V1 requires pg_dump to match the server major")
	}
	directory, err := os.MkdirTemp(e.stateDir, ".postgres-logical-schema-")
	if err != nil {
		return nil, "", errors.New("PostgreSQL logical schema staging failed")
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "schema.sql")
	if _, err := e.runPostgres(ctx, binding, binding.Database, pgDump,
		"--schema-only", "--no-owner", "--no-privileges", "--no-publications", "--no-subscriptions",
		"--quote-all-identifiers", "--lock-wait-timeout=5000", "--file="+path); err != nil {
		return nil, "", err
	}
	info, err := os.Stat(path)
	if err != nil || info.Size() < 1 || info.Size() > maximumPostgresLogicalSchema {
		return nil, "", errors.New("PostgreSQL logical schema dump is unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", errors.New("PostgreSQL logical schema dump could not be read")
	}
	normalized, err := normalizePostgresLogicalSchema(raw)
	zeroBytes(raw)
	if err != nil {
		return nil, "", err
	}
	return normalized, postgresBytesDigest(normalized), nil
}

func writePostgresLogicalArtifact(directory, handle string, data []byte, maximum int64) (string, int64, error) {
	if !fileNamePattern.MatchString(handle) || strings.Contains(handle, "/") || int64(len(data)) < 1 || int64(len(data)) > maximum {
		return "", 0, errors.New("PostgreSQL logical artifact is unsafe")
	}
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
	remove = false
	return postgresBytesDigest(data), int64(len(data)), nil
}

func readPostgresLogicalArtifact(path, expectedDigest string, maximum int64) ([]byte, error) {
	actualDigest, size, err := fileSHA256(path)
	if err != nil || actualDigest != expectedDigest || size < 1 || size > maximum {
		return nil, errors.New("PostgreSQL logical artifact digest verification failed")
	}
	data, err := os.ReadFile(path)
	if err != nil || int64(len(data)) != size {
		return nil, errors.New("PostgreSQL logical artifact could not be read")
	}
	return data, nil
}

func (e *NativeExecutor) postgresLogicalPreflight(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	contract, err := postgresLogicalContractFromInputs(inputs, binding)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	if (binding.Mode == "source" && binding.Database != mapping.SourceDatabase) ||
		(binding.Mode == "target" && binding.Database != mapping.TargetDatabase) {
		return nil, errors.New("PostgreSQL logical database binding does not match its mapping")
	}
	eligibility, err := e.inspectPostgresLogicalEligibility(ctx, binding, contract, binding.Mode == "source", binding.Mode == "target")
	if err != nil {
		return nil, err
	}
	outputs := map[string]any{
		"eligible": true, "server_major": eligibility.ServerMajor, "table_count": eligibility.TableCount,
		"database_binding_id": bindingID, "mode": binding.Mode,
	}
	if binding.Mode == "target" {
		logicalBindingID, logicalBinding, err := e.resolvePostgresLogicalSourceBinding(ctx, task, inputs, contract)
		if err != nil {
			return nil, err
		}
		defer logicalBinding.clear()
		if logicalBinding.Database != mapping.SourceDatabase {
			return nil, errors.New("PostgreSQL logical source binding database does not match the mapping")
		}
		remote := logicalBinding.postgresBinding()
		defer remote.clear()
		versionRows, err := e.queryPostgres(ctx, remote, remote.Database, "show server_version_num")
		version, parseErr := parseSingleInt(versionRows)
		if err != nil || parseErr != nil || int(version/10000) != eligibility.ServerMajor {
			return nil, errors.New("PostgreSQL lower-downtime V1 requires the same source and target major")
		}
		roleRows, err := e.queryPostgres(ctx, remote, remote.Database,
			"select (rolcanlogin and rolreplication and rolbypassrls and not rolsuper and not rolcreatedb and not rolcreaterole)::text from pg_roles where rolname=current_user")
		roleOK, roleErr := postgresBool(roleRows)
		if err != nil || roleErr != nil || !roleOK {
			return nil, errors.New("PostgreSQL logical source binding is not the bounded replication role")
		}
		outputs["logical_source_binding_id"] = logicalBindingID
		outputs["tls_verified"] = true
	}
	return outputs, nil
}

func (e *NativeExecutor) postgresLogicalSchemaDump(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("PostgreSQL logical schema dump requires a source binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, binding)
	if err != nil {
		return nil, err
	}
	eligibility, err := e.inspectPostgresLogicalEligibility(ctx, binding, contract, true, false)
	if err != nil {
		return nil, err
	}
	schema, schemaDigest, err := e.dumpPostgresLogicalSchema(ctx, binding, eligibility.ServerMajor)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(schema)
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return nil, err
	}
	relative, directory, err := mysqlArtifactLocation(e, task, stagingHandle, "postgres-logical-schema", schemaDigest)
	if err != nil {
		return nil, err
	}
	digest, size, err := writePostgresLogicalArtifact(directory, postgresLogicalSchemaHandle, schema, maximumPostgresLogicalSchema)
	if err != nil {
		return nil, err
	}
	manifest, err := buildFileManifest(ctx, directory, nil)
	if err != nil {
		return nil, err
	}
	if err := progress("postgres_logical_schema_dump_complete", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"schema_artifact_handle": postgresLogicalSchemaHandle, "schema_staging_relative_handle": relative,
		"schema_artifact_digest": digest, "schema_transfer_manifest_digest": manifest.Digest,
		"schema_size_bytes": size, "schema_digest": schemaDigest, "server_major": eligibility.ServerMajor,
		"database_binding_id": bindingID,
	}, nil
}

func postgresLogicalStagedArtifactPath(e *NativeExecutor, inputs map[string]any, relativeKey, handleKey, expectedHandle string) (string, error) {
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return "", err
	}
	relative, err := stringInput(inputs, relativeKey)
	if err != nil || strings.Contains(relative, "/") || !fileNamePattern.MatchString(relative) {
		return "", errors.New("PostgreSQL logical artifact staging handle is invalid")
	}
	handle, err := stringInput(inputs, handleKey)
	if err != nil || handle != expectedHandle {
		return "", errors.New("PostgreSQL logical artifact handle is invalid")
	}
	return e.resolver.Resolve(stagingHandle, filepath.Join(relative, handle), false)
}

func (e *NativeExecutor) postgresLogicalRestoreSchema(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" || !binding.ResetAllowed {
		return nil, errors.New("PostgreSQL logical schema restore requires a constrained target binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, binding)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	logicalBindingID, err := stringInput(inputs, "logical_source_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(logicalBindingID) {
		return nil, errors.New("PostgreSQL logical source binding identifier is invalid")
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	resetMarker, err := e.loadPostgresMarker(bindingID)
	if err != nil || resetMarker.MigrationID != task.MigrationID {
		return nil, errors.New("target database reset ownership is unproven")
	}
	path, err := postgresLogicalStagedArtifactPath(e, inputs, "schema_staging_relative_handle", "schema_artifact_handle", postgresLogicalSchemaHandle)
	if err != nil {
		return nil, err
	}
	expectedDigest, err := stringInput(inputs, "schema_artifact_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("PostgreSQL logical schema digest is invalid")
	}
	schema, err := readPostgresLogicalArtifact(path, expectedDigest, maximumPostgresLogicalSchema)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(schema)
	normalized, err := normalizePostgresLogicalSchema(schema)
	if err != nil || postgresBytesDigest(normalized) != expectedDigest {
		zeroBytes(normalized)
		return nil, errors.New("PostgreSQL logical schema artifact is not canonical")
	}
	zeroBytes(normalized)
	eligibility, err := e.inspectPostgresLogicalEligibility(ctx, binding, contract, false, true)
	if err != nil {
		return nil, err
	}
	if existing, markerErr := e.loadPostgresLogicalMarker(bindingID, "target"); markerErr == nil {
		if err := validatePostgresLogicalMarker(existing, task, bindingID, logicalBindingID, "target", binding.Database, names); err != nil {
			return nil, err
		}
		current, currentDigest, err := e.dumpPostgresLogicalSchema(ctx, binding, eligibility.ServerMajor)
		zeroBytes(current)
		if err == nil && currentDigest == expectedDigest && existing.SchemaDigest == expectedDigest {
			return map[string]any{"restored": true, "schema_digest": expectedDigest, "idempotent": true}, nil
		}
		return nil, errors.New("marked PostgreSQL logical target schema drifted")
	}
	tableRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in('r','p','m','f') and n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast'")
	tableCount, parseErr := parseSingleInt(tableRows)
	if err != nil || parseErr != nil || tableCount != 0 {
		return nil, errors.New("PostgreSQL logical target must be empty before schema restore")
	}
	psql, err := fixedPostgresExecutable("psql")
	if err != nil {
		return nil, err
	}
	script := append([]byte("SET ROLE "+quotePostgresIdentifier(binding.TargetRole)+";\n"), schema...)
	if _, err := e.runPostgresInput(ctx, binding, binding.Database, psql, script,
		"--no-psqlrc", "--set=ON_ERROR_STOP=1", "--single-transaction"); err != nil {
		zeroBytes(script)
		return nil, errors.New("PostgreSQL logical schema restore failed")
	}
	zeroBytes(script)
	afterSchema, afterDigest, err := e.dumpPostgresLogicalSchema(ctx, binding, eligibility.ServerMajor)
	zeroBytes(afterSchema)
	if err != nil || afterDigest != expectedDigest {
		return nil, errors.New("restored PostgreSQL logical schema does not match the source")
	}
	marker := postgresLogicalMarker{
		MigrationID: task.MigrationID, PlanDigest: taskPlanDigest(task), DatabaseBindingID: bindingID,
		LogicalBindingID: logicalBindingID, Database: binding.Database, Names: names,
		SchemaDigest: expectedDigest, Status: "schema-restored",
	}
	if err := e.savePostgresLogicalMarker(bindingID, "target", marker); err != nil {
		return nil, err
	}
	return map[string]any{"restored": true, "schema_digest": expectedDigest, "server_major": eligibility.ServerMajor}, nil
}

func (e *NativeExecutor) postgresLogicalPrepareSource(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("PostgreSQL logical source preparation requires a source binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, binding)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	eligibility, err := e.inspectPostgresLogicalEligibility(ctx, binding, contract, true, false)
	if err != nil {
		return nil, err
	}
	expectedSchemaDigest, err := stringInput(inputs, "expected_schema_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedSchemaDigest) {
		return nil, errors.New("expected PostgreSQL logical schema digest is invalid")
	}
	schema, schemaDigest, err := e.dumpPostgresLogicalSchema(ctx, binding, eligibility.ServerMajor)
	zeroBytes(schema)
	if err != nil || schemaDigest != expectedSchemaDigest {
		return nil, errors.New("PostgreSQL source schema changed before publication preparation")
	}
	publicationRows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_publication where pubname="+quotePostgresLiteral(names.Publication))
	publicationCount, publicationParseErr := parseSingleInt(publicationRows)
	slotRows, slotErr := e.queryPostgres(ctx, binding, binding.Database,
		"select count(*) from pg_replication_slots where slot_name="+quotePostgresLiteral(names.Slot))
	slotCount, slotParseErr := parseSingleInt(slotRows)
	if err != nil || publicationParseErr != nil || slotErr != nil || slotParseErr != nil || publicationCount > 1 || slotCount > 1 {
		return nil, errors.New("PostgreSQL logical object inventory is invalid")
	}
	marker, markerErr := e.loadPostgresLogicalMarker(bindingID, "source")
	if markerErr == nil {
		if err := validatePostgresLogicalMarker(marker, task, bindingID, "", "source", binding.Database, names); err != nil {
			return nil, err
		}
		if marker.SchemaDigest != expectedSchemaDigest {
			return nil, errors.New("marked PostgreSQL source schema digest changed")
		}
	} else if publicationCount != 0 || slotCount != 0 {
		return nil, errors.New("PostgreSQL logical object exists without Askio ownership")
	} else {
		marker = postgresLogicalMarker{
			MigrationID: task.MigrationID, PlanDigest: taskPlanDigest(task), DatabaseBindingID: bindingID,
			Database: binding.Database, Names: names, SchemaDigest: expectedSchemaDigest, Status: "preparing",
		}
		if err := e.savePostgresLogicalMarker(bindingID, "source", marker); err != nil {
			return nil, err
		}
	}
	if publicationCount == 0 {
		tableRows, err := e.queryPostgres(ctx, binding, binding.Database,
			"select n.nspname,c.relname from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind='r' and n.nspname not in('pg_catalog','information_schema') and n.nspname !~ '^pg_toast' order by n.nspname,c.relname")
		if err != nil || len(tableRows) < 1 || len(tableRows) > 2048 {
			return nil, errors.New("PostgreSQL publication table inventory is invalid")
		}
		tables := make([]string, 0, len(tableRows))
		for _, row := range tableRows {
			if len(row) != 2 || invalidCatalogIdentifier(row[0]) || invalidCatalogIdentifier(row[1]) {
				return nil, errors.New("PostgreSQL publication contains an invalid table")
			}
			tables = append(tables, quotePostgresIdentifier(row[0])+"."+quotePostgresIdentifier(row[1]))
		}
		query := "create publication " + quotePostgresIdentifier(names.Publication) + " for table " + strings.Join(tables, ",") +
			" with (publish='insert,update,delete,truncate',publish_via_partition_root=false)"
		if _, err := e.queryPostgres(ctx, binding, binding.Database, query); err != nil {
			return nil, errors.New("PostgreSQL logical publication creation failed")
		}
	}
	marker.Status = "publication-ready"
	if err := e.savePostgresLogicalMarker(bindingID, "source", marker); err != nil {
		return nil, err
	}
	return map[string]any{
		"prepared": true, "publication_name": names.Publication, "slot_name": names.Slot,
		"schema_digest": expectedSchemaDigest, "table_count": eligibility.TableCount,
	}, nil
}

func postgresConninfoValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func postgresLogicalConninfo(binding postgresLogicalSourceBinding) string {
	parts := []string{
		"host=" + postgresConninfoValue(binding.Host), "port=" + strconv.Itoa(binding.Port),
		"dbname=" + postgresConninfoValue(binding.Database), "user=" + postgresConninfoValue(binding.Username),
		"password=" + postgresConninfoValue(binding.Password), "sslmode=verify-full",
		"sslrootcert=" + postgresConninfoValue(binding.ServerSSLRootCertPath),
		"connect_timeout=10", "application_name=" + postgresConninfoValue("askio-logical-migration"),
	}
	return strings.Join(parts, " ")
}

func (e *NativeExecutor) postgresLogicalSlotWALBytes(ctx context.Context, binding postgresBinding, slot string) (int64, bool, error) {
	rows, err := e.queryPostgres(ctx, binding, binding.Database,
		"select coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn),0)::bigint::text,active::text from pg_replication_slots where slot_name="+quotePostgresLiteral(slot))
	if err != nil {
		return 0, false, err
	}
	if len(rows) == 0 {
		return 0, false, nil
	}
	if len(rows) != 1 || len(rows[0]) != 2 {
		return 0, false, errors.New("PostgreSQL logical slot inventory is invalid")
	}
	value, err := strconv.ParseInt(rows[0][0], 10, 64)
	active, activeErr := postgresBool([][]string{{rows[0][1]}})
	if err != nil || value < 0 || activeErr != nil {
		return 0, false, errors.New("PostgreSQL logical slot state is invalid")
	}
	return value, active, nil
}

func postgresLogicalAppliedLSNQuery(subscription, lsn string) string {
	return "select coalesce((select greatest(coalesce(o.remote_lsn,'0/0'::pg_lsn),coalesce(s.latest_end_lsn,'0/0'::pg_lsn)) >= " +
		quotePostgresLiteral(lsn) + "::pg_lsn from pg_subscription sub " +
		"left join pg_replication_origin_status o on o.external_id='pg_'||sub.oid::text " +
		"left join pg_stat_subscription s on s.subid=sub.oid and s.relid is null " +
		"where sub.subname=" + quotePostgresLiteral(subscription) + "),false)::text"
}

func (e *NativeExecutor) waitPostgresLogicalApply(ctx context.Context, target postgresBinding, source postgresBinding, names postgresLogicalNames, contract postgresLogicalContract, requireTablesReady bool) (string, int64, error) {
	deadline := time.Now().Add(time.Duration(contract.MaximumCatchupSeconds) * time.Second)
	for {
		lsnRows, err := e.queryPostgres(ctx, source, source.Database, "select pg_current_wal_lsn()::text")
		if err != nil || len(lsnRows) != 1 || len(lsnRows[0]) != 1 || !postgresLSNPattern.MatchString(lsnRows[0][0]) {
			return "", 0, errors.New("PostgreSQL source LSN inspection failed")
		}
		sourceLSN := lsnRows[0][0]
		ready := true
		if requireTablesReady {
			readyRows, err := e.queryPostgres(ctx, target, target.Database,
				"select (exists(select 1 from pg_subscription_rel sr join pg_subscription s on s.oid=sr.srsubid where s.subname="+quotePostgresLiteral(names.Subscription)+") and not exists(select 1 from pg_subscription_rel sr join pg_subscription s on s.oid=sr.srsubid where s.subname="+quotePostgresLiteral(names.Subscription)+" and sr.srsubstate<>'r'))::text")
			ready, _ = postgresBool(readyRows)
			if err != nil {
				return "", 0, err
			}
		}
		applyRows, err := e.queryPostgres(ctx, target, target.Database,
			postgresLogicalAppliedLSNQuery(names.Subscription, sourceLSN))
		applied, applyParseErr := postgresBool(applyRows)
		walBytes, _, walErr := e.postgresLogicalSlotWALBytes(ctx, source, names.Slot)
		if err != nil || applyParseErr != nil || walErr != nil {
			return "", 0, errors.New("PostgreSQL logical catch-up inspection failed")
		}
		if walBytes > contract.MaximumSlotWALBytes {
			return "", walBytes, errors.New("PostgreSQL logical slot exceeded the approved WAL retention ceiling")
		}
		if ready && applied {
			return sourceLSN, walBytes, nil
		}
		if time.Now().After(deadline) {
			return "", walBytes, errors.New("PostgreSQL logical catch-up exceeded the approved time limit")
		}
		select {
		case <-ctx.Done():
			return "", walBytes, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (e *NativeExecutor) postgresLogicalStartSubscription(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, target, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer target.clear()
	if target.Mode != "target" {
		return nil, errors.New("PostgreSQL logical subscription requires a target binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, target)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	logicalBindingID, logicalBinding, err := e.resolvePostgresLogicalSourceBinding(ctx, task, inputs, contract)
	if err != nil {
		return nil, err
	}
	defer logicalBinding.clear()
	if logicalBinding.Database != mapping.SourceDatabase || target.Database != mapping.TargetDatabase {
		return nil, errors.New("PostgreSQL logical subscription database mapping changed")
	}
	source := logicalBinding.postgresBinding()
	defer source.clear()
	marker, err := e.loadPostgresLogicalMarker(bindingID, "target")
	if err != nil || validatePostgresLogicalMarker(marker, task, bindingID, logicalBindingID, "target", target.Database, names) != nil {
		return nil, errors.New("PostgreSQL logical target ownership is unproven")
	}
	expectedSchemaDigest, err := stringInput(inputs, "expected_schema_digest")
	if err != nil || marker.SchemaDigest != expectedSchemaDigest {
		return nil, errors.New("PostgreSQL logical target schema digest changed")
	}
	publicationRows, err := e.queryPostgres(ctx, source, source.Database,
		"select count(*) from pg_publication where pubname="+quotePostgresLiteral(names.Publication))
	publicationCount, publicationParseErr := parseSingleInt(publicationRows)
	if err != nil || publicationParseErr != nil || publicationCount != 1 {
		return nil, errors.New("marked PostgreSQL logical publication is unavailable")
	}
	subscriptionRows, err := e.queryPostgres(ctx, target, target.Database,
		"select subslotname,array_to_string(subpublications,',') from pg_subscription where subname="+quotePostgresLiteral(names.Subscription))
	if err != nil || len(subscriptionRows) > 1 {
		return nil, errors.New("PostgreSQL logical subscription inventory is invalid")
	}
	if len(subscriptionRows) == 1 {
		if len(subscriptionRows[0]) != 2 || subscriptionRows[0][0] != names.Slot || subscriptionRows[0][1] != names.Publication {
			return nil, errors.New("existing PostgreSQL logical subscription is not owned by this plan")
		}
	} else {
		slotRows, err := e.queryPostgres(ctx, source, source.Database,
			"select count(*) from pg_replication_slots where slot_name="+quotePostgresLiteral(names.Slot))
		slotCount, slotParseErr := parseSingleInt(slotRows)
		if err != nil || slotParseErr != nil || slotCount > 1 {
			return nil, errors.New("PostgreSQL logical slot inventory is invalid")
		}
		walBytes, active, err := e.postgresLogicalSlotWALBytes(ctx, source, names.Slot)
		if err != nil {
			return nil, err
		}
		if walBytes > contract.MaximumSlotWALBytes {
			return nil, errors.New("PostgreSQL logical slot exceeded the approved WAL retention ceiling")
		}
		if slotCount == 1 {
			if active {
				return nil, errors.New("marked PostgreSQL logical slot is unexpectedly active")
			}
			if _, err := e.queryPostgres(ctx, source, source.Database,
				"select pg_drop_replication_slot("+quotePostgresLiteral(names.Slot)+")"); err != nil {
				return nil, errors.New("orphaned marked PostgreSQL logical slot could not be reset")
			}
		}
		conninfo := postgresLogicalConninfo(logicalBinding)
		sql := "set log_statement='none'; set log_min_duration_statement=-1; set log_min_error_statement='panic';\n" +
			"create subscription " + quotePostgresIdentifier(names.Subscription) + " connection " + quotePostgresLiteral(conninfo) +
			" publication " + quotePostgresIdentifier(names.Publication) + " with (copy_data=true,create_slot=true,enabled=true,slot_name=" +
			quotePostgresLiteral(names.Slot) + ",binary=false,streaming=on,synchronous_commit=off);\n"
		psql, err := fixedPostgresExecutable("psql")
		if err != nil {
			zeroBytes([]byte(conninfo))
			zeroBytes([]byte(sql))
			return nil, err
		}
		if _, err := e.runPostgresInput(ctx, target, target.Database, psql, []byte(sql),
			"--no-psqlrc", "--set=ON_ERROR_STOP=1"); err != nil {
			zeroBytes([]byte(conninfo))
			zeroBytes([]byte(sql))
			return nil, errors.New("PostgreSQL logical subscription creation failed")
		}
		zeroBytes([]byte(conninfo))
		zeroBytes([]byte(sql))
		marker.Status = "subscription-created"
		if err := e.savePostgresLogicalMarker(bindingID, "target", marker); err != nil {
			return nil, err
		}
	}
	if err := progress("postgres_logical_initial_copy", 0, nil); err != nil {
		return nil, err
	}
	lsn, walBytes, err := e.waitPostgresLogicalApply(ctx, target, source, names, contract, true)
	if err != nil {
		return nil, err
	}
	marker.Status = "replicating"
	if err := e.savePostgresLogicalMarker(bindingID, "target", marker); err != nil {
		return nil, err
	}
	if err := progress("postgres_logical_initial_copy_complete", 1, func() *int64 { value := int64(1); return &value }()); err != nil {
		return nil, err
	}
	return map[string]any{
		"replicating": true, "publication_name": names.Publication, "slot_name": names.Slot,
		"subscription_name": names.Subscription, "caught_up_lsn": lsn, "retained_wal_bytes": walBytes,
	}, nil
}

type postgresLogicalFinalState struct {
	SchemaVersion  string                     `json:"schema_version"`
	MigrationID    string                     `json:"migration_id"`
	PlanDigest     string                     `json:"plan_digest"`
	SourceDatabase string                     `json:"source_database"`
	TargetDatabase string                     `json:"target_database"`
	Names          postgresLogicalNames       `json:"names"`
	SchemaDigest   string                     `json:"schema_digest"`
	ManifestDigest string                     `json:"manifest_digest"`
	FinalLSN       string                     `json:"final_lsn"`
	Sequences      []postgresSequenceManifest `json:"sequences"`
}

func validatePostgresLogicalFinalState(state postgresLogicalFinalState, task TaskEnvelope, mapping postgresDatabaseMapping, names postgresLogicalNames) error {
	if state.SchemaVersion != postgresLogicalFinalStateSchema || state.MigrationID != task.MigrationID ||
		state.PlanDigest != taskPlanDigest(task) || state.SourceDatabase != mapping.SourceDatabase ||
		state.TargetDatabase != mapping.TargetDatabase || state.Names != names ||
		!fileDigestPattern.MatchString(state.SchemaDigest) || !fileDigestPattern.MatchString(state.ManifestDigest) ||
		!postgresLSNPattern.MatchString(state.FinalLSN) || len(state.Sequences) > 4096 {
		return errors.New("PostgreSQL logical final-state contract is invalid")
	}
	previous := ""
	for _, sequence := range state.Sequences {
		identity := sequence.Schema + "\x00" + sequence.Name
		if invalidCatalogIdentifier(sequence.Schema) || invalidCatalogIdentifier(sequence.Name) || identity <= previous {
			return errors.New("PostgreSQL logical final-state sequence inventory is invalid")
		}
		if _, err := strconv.ParseInt(sequence.Last, 10, 64); err != nil {
			return errors.New("PostgreSQL logical final-state sequence value is invalid")
		}
		previous = identity
	}
	return nil
}

func (e *NativeExecutor) postgresLogicalFinalizeSource(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("PostgreSQL logical final-state capture requires a source binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, binding)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	marker, err := e.loadPostgresLogicalMarker(bindingID, "source")
	if err != nil || validatePostgresLogicalMarker(marker, task, bindingID, "", "source", binding.Database, names) != nil {
		return nil, errors.New("PostgreSQL logical source ownership is unproven")
	}
	eligibility, err := e.inspectPostgresLogicalEligibility(ctx, binding, contract, true, false)
	if err != nil {
		return nil, err
	}
	schema, schemaDigest, err := e.dumpPostgresLogicalSchema(ctx, binding, eligibility.ServerMajor)
	zeroBytes(schema)
	if err != nil || schemaDigest != marker.SchemaDigest {
		return nil, errors.New("PostgreSQL schema changed during logical replication")
	}
	inspection, err := e.inspectPostgres(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	lsnRows, err := e.queryPostgres(ctx, binding, binding.Database, "select pg_current_wal_lsn()::text")
	if err != nil || len(lsnRows) != 1 || len(lsnRows[0]) != 1 || !postgresLSNPattern.MatchString(lsnRows[0][0]) {
		return nil, errors.New("PostgreSQL final source LSN capture failed")
	}
	sequences := append([]postgresSequenceManifest{}, inspection.Manifest.Sequences...)
	sort.Slice(sequences, func(i, j int) bool {
		return sequences[i].Schema+"\x00"+sequences[i].Name < sequences[j].Schema+"\x00"+sequences[j].Name
	})
	state := postgresLogicalFinalState{
		SchemaVersion: postgresLogicalFinalStateSchema, MigrationID: task.MigrationID, PlanDigest: taskPlanDigest(task),
		SourceDatabase: mapping.SourceDatabase, TargetDatabase: mapping.TargetDatabase, Names: names,
		SchemaDigest: schemaDigest, ManifestDigest: inspection.ManifestDigest, FinalLSN: lsnRows[0][0], Sequences: sequences,
	}
	if err := validatePostgresLogicalFinalState(state, task, mapping, names); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(state)
	if err != nil || int64(len(encoded)) > maximumPostgresLogicalState {
		return nil, errors.New("PostgreSQL logical final-state artifact exceeds its safety limit")
	}
	encoded = append(encoded, '\n')
	defer zeroBytes(encoded)
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return nil, err
	}
	relative, directory, err := mysqlArtifactLocation(e, task, stagingHandle, "postgres-logical-final", inspection.ManifestDigest)
	if err != nil {
		return nil, err
	}
	digest, size, err := writePostgresLogicalArtifact(directory, postgresLogicalFinalStateHandle, encoded, maximumPostgresLogicalState)
	if err != nil {
		return nil, err
	}
	manifest, err := buildFileManifest(ctx, directory, nil)
	if err != nil {
		return nil, err
	}
	marker.FinalStateDigest = digest
	marker.Status = "final-state-captured"
	if err := e.savePostgresLogicalMarker(bindingID, "source", marker); err != nil {
		return nil, err
	}
	if err := progress("postgres_logical_final_state_captured", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"final_state_artifact_handle": postgresLogicalFinalStateHandle, "final_state_staging_relative_handle": relative,
		"final_state_artifact_digest": digest, "final_state_transfer_manifest_digest": manifest.Digest,
		"final_state_size_bytes": size, "final_lsn": state.FinalLSN,
		"final_manifest_digest": state.ManifestDigest, "schema_digest": state.SchemaDigest,
	}, nil
}

func (e *NativeExecutor) waitPostgresLogicalFinalLSN(ctx context.Context, target, source postgresBinding, names postgresLogicalNames, contract postgresLogicalContract, finalLSN string) (int64, error) {
	deadline := time.Now().Add(time.Duration(contract.MaximumCatchupSeconds) * time.Second)
	for {
		applyRows, err := e.queryPostgres(ctx, target, target.Database,
			postgresLogicalAppliedLSNQuery(names.Subscription, finalLSN))
		applied, applyErr := postgresBool(applyRows)
		walBytes, _, walErr := e.postgresLogicalSlotWALBytes(ctx, source, names.Slot)
		if err != nil || applyErr != nil || walErr != nil {
			return 0, errors.New("PostgreSQL final logical catch-up inspection failed")
		}
		if walBytes > contract.MaximumSlotWALBytes {
			return walBytes, errors.New("PostgreSQL logical slot exceeded the approved WAL retention ceiling")
		}
		if applied {
			return walBytes, nil
		}
		if time.Now().After(deadline) {
			return walBytes, errors.New("PostgreSQL final logical catch-up exceeded the approved time limit")
		}
		select {
		case <-ctx.Done():
			return walBytes, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func readPostgresLogicalFinalState(path, expectedDigest string, task TaskEnvelope, mapping postgresDatabaseMapping, names postgresLogicalNames) (postgresLogicalFinalState, error) {
	data, err := readPostgresLogicalArtifact(path, expectedDigest, maximumPostgresLogicalState)
	if err != nil {
		return postgresLogicalFinalState{}, err
	}
	defer zeroBytes(data)
	var state postgresLogicalFinalState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return postgresLogicalFinalState{}, errors.New("PostgreSQL logical final-state artifact is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return postgresLogicalFinalState{}, errors.New("PostgreSQL logical final-state artifact contains trailing data")
	}
	if err := validatePostgresLogicalFinalState(state, task, mapping, names); err != nil {
		return postgresLogicalFinalState{}, err
	}
	return state, nil
}

func (e *NativeExecutor) waitPostgresSubscriptionWorkerStopped(ctx context.Context, target postgresBinding, subscription string, maximumSeconds int) error {
	deadline := time.Now().Add(time.Duration(maximumSeconds) * time.Second)
	for {
		rows, err := e.queryPostgres(ctx, target, target.Database,
			"select count(*) from pg_stat_subscription where subname="+quotePostgresLiteral(subscription)+" and pid is not null")
		count, parseErr := parseSingleInt(rows)
		if err != nil || parseErr != nil {
			return errors.New("PostgreSQL logical subscription worker state is invalid")
		}
		if count == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("PostgreSQL logical subscription worker did not stop")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (e *NativeExecutor) postgresLogicalFinalizeTarget(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, target, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer target.clear()
	if target.Mode != "target" {
		return nil, errors.New("PostgreSQL logical finalization requires a target binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, target)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	logicalBindingID, logicalBinding, err := e.resolvePostgresLogicalSourceBinding(ctx, task, inputs, contract)
	if err != nil {
		return nil, err
	}
	defer logicalBinding.clear()
	source := logicalBinding.postgresBinding()
	defer source.clear()
	marker, err := e.loadPostgresLogicalMarker(bindingID, "target")
	if err != nil || validatePostgresLogicalMarker(marker, task, bindingID, logicalBindingID, "target", target.Database, names) != nil {
		return nil, errors.New("PostgreSQL logical target ownership is unproven")
	}
	path, err := postgresLogicalStagedArtifactPath(e, inputs, "final_state_staging_relative_handle", "final_state_artifact_handle", postgresLogicalFinalStateHandle)
	if err != nil {
		return nil, err
	}
	expectedDigest, err := stringInput(inputs, "final_state_artifact_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("PostgreSQL logical final-state artifact digest is invalid")
	}
	state, err := readPostgresLogicalFinalState(path, expectedDigest, task, mapping, names)
	if err != nil {
		return nil, err
	}
	if state.SchemaDigest != marker.SchemaDigest {
		return nil, errors.New("PostgreSQL logical final-state schema digest changed")
	}
	subscriptionRows, err := e.queryPostgres(ctx, target, target.Database,
		"select subenabled::text,coalesce(subslotname,'') from pg_subscription where subname="+quotePostgresLiteral(names.Subscription))
	if err != nil || len(subscriptionRows) != 1 || len(subscriptionRows[0]) != 2 || subscriptionRows[0][1] != names.Slot {
		return nil, errors.New("marked PostgreSQL logical subscription is unavailable")
	}
	enabled, enabledErr := postgresBool([][]string{{subscriptionRows[0][0]}})
	if enabledErr != nil {
		return nil, errors.New("PostgreSQL logical subscription state is invalid")
	}
	if !enabled {
		if _, err := e.queryPostgres(ctx, target, target.Database,
			"alter subscription "+quotePostgresIdentifier(names.Subscription)+" enable"); err != nil {
			return nil, errors.New("PostgreSQL logical subscription could not resume for final catch-up")
		}
	}
	if err := progress("postgres_logical_final_catchup", 0, nil); err != nil {
		return nil, err
	}
	walBytes, err := e.waitPostgresLogicalFinalLSN(ctx, target, source, names, contract, state.FinalLSN)
	if err != nil {
		return nil, err
	}
	if _, err := e.queryPostgres(ctx, target, target.Database,
		"alter subscription "+quotePostgresIdentifier(names.Subscription)+" disable"); err != nil {
		return nil, errors.New("PostgreSQL logical subscription could not be disabled")
	}
	if err := e.waitPostgresSubscriptionWorkerStopped(ctx, target, names.Subscription, contract.MaximumCatchupSeconds); err != nil {
		return nil, err
	}
	for _, sequence := range state.Sequences {
		qualified := quotePostgresIdentifier(sequence.Schema) + "." + quotePostgresIdentifier(sequence.Name)
		query := "select setval(" + quotePostgresLiteral(qualified) + "::regclass," + sequence.Last + "," + fmt.Sprintf("%t", sequence.IsCalled) + ")"
		if _, err := e.queryPostgres(ctx, target, target.Database, query); err != nil {
			return nil, errors.New("PostgreSQL logical sequence finalization failed")
		}
	}
	inspection, err := e.inspectPostgres(ctx, bindingID, target)
	if err != nil || inspection.ManifestDigest != state.ManifestDigest {
		return nil, errors.New("PostgreSQL logical target does not match the fenced source manifest")
	}
	if _, err := e.queryPostgres(ctx, target, target.Database,
		"alter subscription "+quotePostgresIdentifier(names.Subscription)+" set (slot_name=none)"); err != nil {
		return nil, errors.New("PostgreSQL logical subscription could not detach its slot")
	}
	if _, err := e.queryPostgres(ctx, target, target.Database,
		"drop subscription "+quotePostgresIdentifier(names.Subscription)); err != nil {
		return nil, errors.New("PostgreSQL logical subscription cleanup failed")
	}
	marker.FinalStateDigest = expectedDigest
	marker.Status = "target-finalized"
	if err := e.savePostgresLogicalMarker(bindingID, "target", marker); err != nil {
		return nil, err
	}
	if err := progress("postgres_logical_finalized", 1, func() *int64 { value := int64(1); return &value }()); err != nil {
		return nil, err
	}
	return map[string]any{
		"verified": true, "database_manifest_digest": inspection.ManifestDigest,
		"final_state_artifact_digest": expectedDigest, "final_lsn": state.FinalLSN,
		"retained_wal_bytes": walBytes, "subscription_detached": true,
	}, nil
}

func (e *NativeExecutor) postgresLogicalCleanupTarget(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, target, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer target.clear()
	if target.Mode != "target" {
		return nil, errors.New("PostgreSQL logical target cleanup requires a target binding")
	}
	contract, err := postgresLogicalContractFromInputs(inputs, target)
	if err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	logicalBindingID, err := stringInput(inputs, "logical_source_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(logicalBindingID) {
		return nil, errors.New("PostgreSQL logical source binding identifier is invalid")
	}
	subscriptionRows, err := e.queryPostgres(ctx, target, target.Database,
		"select subenabled::text,coalesce(subslotname,'') from pg_subscription where subname="+quotePostgresLiteral(names.Subscription))
	if err != nil || len(subscriptionRows) > 1 {
		return nil, errors.New("PostgreSQL logical subscription inventory is invalid")
	}
	marker, markerErr := e.loadPostgresLogicalMarker(bindingID, "target")
	if markerErr != nil {
		if len(subscriptionRows) == 0 {
			return map[string]any{"clean": true, "idempotent": true}, nil
		}
		return nil, errors.New("PostgreSQL logical subscription exists without Askio ownership")
	}
	if err := validatePostgresLogicalMarker(marker, task, bindingID, logicalBindingID, "target", target.Database, names); err != nil {
		return nil, err
	}
	if len(subscriptionRows) == 1 {
		if len(subscriptionRows[0]) != 2 || (subscriptionRows[0][1] != "" && subscriptionRows[0][1] != names.Slot) {
			return nil, errors.New("PostgreSQL logical subscription is not owned by this plan")
		}
		enabled, enabledErr := postgresBool([][]string{{subscriptionRows[0][0]}})
		if enabledErr != nil {
			return nil, errors.New("PostgreSQL logical subscription state is invalid")
		}
		if enabled {
			if _, err := e.queryPostgres(ctx, target, target.Database,
				"alter subscription "+quotePostgresIdentifier(names.Subscription)+" disable"); err != nil {
				return nil, errors.New("PostgreSQL logical subscription could not be disabled")
			}
		}
		if err := e.waitPostgresSubscriptionWorkerStopped(ctx, target, names.Subscription, contract.MaximumCatchupSeconds); err != nil {
			return nil, err
		}
		if subscriptionRows[0][1] != "" {
			if _, err := e.queryPostgres(ctx, target, target.Database,
				"alter subscription "+quotePostgresIdentifier(names.Subscription)+" set (slot_name=none)"); err != nil {
				return nil, errors.New("PostgreSQL logical subscription could not detach its slot")
			}
		}
		if _, err := e.queryPostgres(ctx, target, target.Database,
			"drop subscription "+quotePostgresIdentifier(names.Subscription)); err != nil {
			return nil, errors.New("PostgreSQL logical subscription cleanup failed")
		}
	}
	marker.Status = "target-cleaned"
	if err := e.savePostgresLogicalMarker(bindingID, "target", marker); err != nil {
		return nil, err
	}
	return map[string]any{"clean": true, "subscription_detached": true}, nil
}

func (e *NativeExecutor) postgresLogicalCleanupSource(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, source, err := e.resolvePostgresBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer source.clear()
	if source.Mode != "source" {
		return nil, errors.New("PostgreSQL logical source cleanup requires a source binding")
	}
	if _, err := postgresLogicalContractFromInputs(inputs, source); err != nil {
		return nil, err
	}
	mapping, err := postgresLogicalMappingFromInputs(inputs)
	if err != nil {
		return nil, err
	}
	names, err := postgresLogicalObjectNames(task.MigrationID, mapping.SourceDatabase)
	if err != nil {
		return nil, err
	}
	publicationRows, err := e.queryPostgres(ctx, source, source.Database,
		"select count(*) from pg_publication where pubname="+quotePostgresLiteral(names.Publication))
	publicationCount, publicationParseErr := parseSingleInt(publicationRows)
	slotRows, slotErr := e.queryPostgres(ctx, source, source.Database,
		"select active::text from pg_replication_slots where slot_name="+quotePostgresLiteral(names.Slot))
	if err != nil || publicationParseErr != nil || slotErr != nil || publicationCount > 1 || len(slotRows) > 1 {
		return nil, errors.New("PostgreSQL logical source object inventory is invalid")
	}
	marker, markerErr := e.loadPostgresLogicalMarker(bindingID, "source")
	if markerErr != nil {
		if publicationCount == 0 && len(slotRows) == 0 {
			return map[string]any{"clean": true, "idempotent": true}, nil
		}
		return nil, errors.New("PostgreSQL logical source objects exist without Askio ownership")
	}
	if err := validatePostgresLogicalMarker(marker, task, bindingID, "", "source", source.Database, names); err != nil {
		return nil, err
	}
	if len(slotRows) == 1 {
		if len(slotRows[0]) != 1 {
			return nil, errors.New("PostgreSQL logical slot state is invalid")
		}
		active, activeErr := postgresBool([][]string{{slotRows[0][0]}})
		if activeErr != nil {
			return nil, errors.New("PostgreSQL logical slot state is invalid")
		}
		if active {
			return nil, errors.New("PostgreSQL logical slot is still active")
		}
		if _, err := e.queryPostgres(ctx, source, source.Database,
			"select pg_drop_replication_slot("+quotePostgresLiteral(names.Slot)+")"); err != nil {
			return nil, errors.New("PostgreSQL logical slot cleanup failed")
		}
	}
	if publicationCount == 1 {
		if _, err := e.queryPostgres(ctx, source, source.Database,
			"drop publication "+quotePostgresIdentifier(names.Publication)); err != nil {
			return nil, errors.New("PostgreSQL logical publication cleanup failed")
		}
	}
	marker.Status = "source-cleaned"
	if err := e.savePostgresLogicalMarker(bindingID, "source", marker); err != nil {
		return nil, err
	}
	return map[string]any{"clean": true, "slot_removed": true, "publication_removed": true}, nil
}
