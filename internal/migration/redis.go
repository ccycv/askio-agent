package migration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
)

const (
	redisBindingSchema          = "operations.migration.redis-binding.v1"
	redisDatabaseContractSchema = "operations.migration.database-contract.v1"
	redisArchiveSchema          = "operations.migration.redis-archive.v1"
	redisArchiveHandle          = "database.redis"
	redisArchiveMagic           = "ASKIO-REDIS-V1\n"
	maximumRedisBytes           = int64(500 * 1024 * 1024 * 1024)
	maximumRedisKeys            = 1_000_000
	maximumRedisKeyBytes        = 1024 * 1024
	maximumRedisKeyIndexBytes   = int64(64 * 1024 * 1024)
	maximumRedisValueBytes      = 64 * 1024 * 1024
	maximumRedisDatabases       = 8
	maximumRedisTrailerBytes    = 64 * 1024
	maximumRedisArchiveBytes    = maximumRedisBytes + int64(maximumRedisKeys*23+maximumRedisTrailerBytes+len(redisArchiveMagic)+5)
	redisExpiryTolerance        = int64(2_000)
	redisMinimumRestoreTTL      = 30 * time.Second
)

var (
	redisPrincipalPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	redisVersionPattern   = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?`)
	redisSupportedSeries  = map[string]map[string]struct{}{
		"redis":  {"7.2": {}, "7.4": {}, "8.2": {}},
		"valkey": {"7.2": {}, "8.1": {}, "9.1": {}},
	}
)

type redisACLMapping struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

type redisBinding struct {
	SchemaVersion   string            `json:"schema_version"`
	Engine          string            `json:"engine"`
	Mode            string            `json:"mode"`
	Host            string            `json:"host"`
	Port            int               `json:"port"`
	Username        string            `json:"username"`
	Password        string            `json:"password"`
	TLSMode         string            `json:"tls_mode"`
	TLSRootCertPEM  string            `json:"tls_root_cert_pem,omitempty"`
	StateMode       string            `json:"state_mode"`
	DatabaseIndexes []int             `json:"database_indexes"`
	ACLMap          []redisACLMapping `json:"acl_map"`
	ResetAllowed    bool              `json:"reset_allowed,omitempty"`
}

type redisDatabaseContract struct {
	SchemaVersion   string            `json:"schema_version"`
	SourceEngine    string            `json:"source_engine"`
	TargetEngine    string            `json:"target_engine"`
	StateMode       string            `json:"state_mode"`
	DatabaseIndexes []int             `json:"database_indexes"`
	ACLMap          []redisACLMapping `json:"acl_map"`
}

type redisKeyRecord struct {
	DatabaseIndex int
	ExpiryUnixMS  int64
	Key           []byte
	Value         []byte
}

type redisScanSummary struct {
	KeyCount               int64
	PersistentKeyCount     int64
	VolatileKeyCount       int64
	DatabaseBytes          int64
	AllRecordDigest        string
	PersistentRecordDigest string
}

type redisServerFacts struct {
	Engine          string
	Version         string
	VersionSeries   string
	PersistenceMode string
	LoadedModules   int
}

type redisInspection struct {
	Exists             bool
	Empty              bool
	Engine             string
	ServerVersion      string
	ServerSeries       string
	StateMode          string
	PersistenceMode    string
	LoadedModules      int
	DatabaseIndexes    []int
	KeyCount           int64
	PersistentKeyCount int64
	VolatileKeyCount   int64
	DatabaseBytes      int64
	ACLPolicyDigest    string
	ManifestDigest     string
	EmptyTargetDigest  string
}

type redisArchiveTrailer struct {
	SchemaVersion          string `json:"schema_version"`
	Engine                 string `json:"engine"`
	SourceVersionSeries    string `json:"source_version_series"`
	StateMode              string `json:"state_mode"`
	PersistenceMode        string `json:"persistence_mode"`
	DatabaseIndexes        []int  `json:"database_indexes"`
	ACLPolicyDigest        string `json:"acl_policy_digest"`
	RecordCount            int64  `json:"record_count"`
	ExcludedCacheKeyCount  int64  `json:"excluded_cache_key_count"`
	PersistentRecordCount  int64  `json:"persistent_record_count"`
	VolatileRecordCount    int64  `json:"volatile_record_count"`
	AllRecordDigest        string `json:"all_record_digest"`
	PersistentRecordDigest string `json:"persistent_record_digest"`
	ManifestDigest         string `json:"manifest_digest"`
}

func (b *redisBinding) clear() {
	b.Password = ""
	b.TLSRootCertPEM = ""
}

func validRedisDatabaseIndexes(indexes []int) bool {
	if len(indexes) < 1 || len(indexes) > maximumRedisDatabases {
		return false
	}
	previous := -1
	for _, index := range indexes {
		if index < 0 || index > 15 || index <= previous {
			return false
		}
		previous = index
	}
	return true
}

func validRedisACLMap(entries []redisACLMapping) bool {
	if len(entries) < 1 || len(entries) > 64 {
		return false
	}
	previous := ""
	targets := map[string]struct{}{}
	for _, entry := range entries {
		if !redisPrincipalPattern.MatchString(entry.Source) || !redisPrincipalPattern.MatchString(entry.Target) || entry.Source <= previous {
			return false
		}
		if _, exists := targets[entry.Target]; exists {
			return false
		}
		targets[entry.Target] = struct{}{}
		previous = entry.Source
	}
	return true
}

func validateRedisHost(host, tlsMode string) error {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t") || filepath.IsAbs(host) {
		return errors.New("Redis binding host is invalid")
	}
	if tlsMode == "disable" {
		address := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (address == nil || !address.IsLoopback()) {
			return errors.New("unencrypted Redis or Valkey is allowed only over loopback")
		}
	}
	return nil
}

func parseRedisBinding(raw []byte) (redisBinding, error) {
	var binding redisBinding
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&binding); err != nil {
		return redisBinding{}, errors.New("Redis binding JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return redisBinding{}, errors.New("Redis binding contains trailing data")
	}
	if binding.SchemaVersion != redisBindingSchema || (binding.Engine != "redis" && binding.Engine != "valkey") ||
		(binding.Mode != "source" && binding.Mode != "target") || (binding.StateMode != "cache" && binding.StateMode != "durable") {
		return redisBinding{}, errors.New("Redis binding contract is unsupported")
	}
	if binding.Port < 1 || binding.Port > 65535 || !redisPrincipalPattern.MatchString(binding.Username) ||
		strings.ContainsAny(binding.Password, "\x00\r\n") || len(binding.Password) > 16*1024 ||
		!validRedisDatabaseIndexes(binding.DatabaseIndexes) || !validRedisACLMap(binding.ACLMap) {
		return redisBinding{}, errors.New("Redis binding contains an invalid identifier, scope, or credential")
	}
	switch binding.TLSMode {
	case "disable":
		if binding.TLSRootCertPEM != "" {
			return redisBinding{}, errors.New("unencrypted Redis binding cannot contain a CA certificate")
		}
	case "verify-ca", "verify-full":
		if !strings.Contains(binding.TLSRootCertPEM, "BEGIN CERTIFICATE") || len(binding.TLSRootCertPEM) > 64*1024 {
			return redisBinding{}, errors.New("verified Redis TLS requires a bounded CA certificate")
		}
	default:
		return redisBinding{}, errors.New("Redis binding tls_mode is unsupported")
	}
	if err := validateRedisHost(binding.Host, binding.TLSMode); err != nil {
		return redisBinding{}, err
	}
	if binding.Mode == "source" && binding.ResetAllowed {
		return redisBinding{}, errors.New("source Redis binding contains target-only controls")
	}
	return binding, nil
}

func validateRedisDatabaseContract(inputs map[string]any, binding redisBinding) error {
	raw, provided := inputs["database_contract"]
	if !provided {
		return errors.New("Redis and Valkey bindings require a database contract")
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) > 64*1024 {
		return errors.New("Redis database contract is invalid")
	}
	var contract redisDatabaseContract
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return errors.New("Redis database contract is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Redis database contract contains trailing data")
	}
	if contract.SchemaVersion != redisDatabaseContractSchema || contract.SourceEngine != binding.Engine || contract.TargetEngine != binding.Engine ||
		contract.SourceEngine != contract.TargetEngine || contract.StateMode != binding.StateMode ||
		!validRedisDatabaseIndexes(contract.DatabaseIndexes) || !validRedisACLMap(contract.ACLMap) ||
		MustDigest(contract.DatabaseIndexes) != MustDigest(binding.DatabaseIndexes) || MustDigest(contract.ACLMap) != MustDigest(binding.ACLMap) {
		return errors.New("Redis binding does not match the reviewed database contract")
	}
	return nil
}

func (b redisBinding) tlsConfig() (*tls.Config, error) {
	if b.TLSMode == "disable" {
		return nil, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.TLSRootCertPEM)) {
		return nil, errors.New("Redis TLS root certificate is invalid")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	if b.TLSMode == "verify-full" {
		config.ServerName = b.Host
	} else {
		config.InsecureSkipVerify = true // Certificate chains are verified below while hostnames are intentionally not.
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("Redis TLS peer certificate is missing")
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: func() *x509.CertPool {
				pool := x509.NewCertPool()
				for _, certificate := range state.PeerCertificates[1:] {
					pool.AddCert(certificate)
				}
				return pool
			}()})
			return err
		}
	}
	return config, nil
}

func (b redisBinding) client(database int) (*redis.Client, error) {
	tlsConfig, err := b.tlsConfig()
	if err != nil {
		return nil, err
	}
	return redis.NewClient(&redis.Options{
		Addr: net.JoinHostPort(b.Host, strconv.Itoa(b.Port)), Username: b.Username, Password: b.Password,
		DB: database, Protocol: 2, TLSConfig: tlsConfig, DialTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, PoolSize: 2, MaxRetries: 0,
	}), nil
}

func parseRedisInfo(value string) map[string]string {
	result := map[string]string{}
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, entry, found := strings.Cut(line, ":")
		if found {
			result[key] = entry
		}
	}
	return result
}

func redisSeries(version string) (string, bool) {
	match := redisVersionPattern.FindStringSubmatch(version)
	if len(match) < 3 {
		return "", false
	}
	return match[1] + "." + match[2], true
}

func redisValueSlice(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, true
	case nil:
		return []any{}, true
	default:
		return nil, false
	}
}

func inspectRedisServer(ctx context.Context, binding redisBinding) (redisServerFacts, error) {
	client, err := binding.client(binding.DatabaseIndexes[0])
	if err != nil {
		return redisServerFacts{}, err
	}
	defer client.Close()
	if err := client.Ping(ctx).Err(); err != nil {
		return redisServerFacts{}, errors.New("Redis or Valkey endpoint is unavailable")
	}
	infoText, err := client.Info(ctx, "server", "replication", "persistence").Result()
	if err != nil {
		return redisServerFacts{}, errors.New("Redis or Valkey server facts are unavailable")
	}
	info := parseRedisInfo(infoText)
	engine := "redis"
	version := info["redis_version"]
	if info["valkey_version"] != "" || strings.EqualFold(info["server_name"], "valkey") {
		engine = "valkey"
		if info["valkey_version"] != "" {
			version = info["valkey_version"]
		}
	}
	series, ok := redisSeries(version)
	if !ok || engine != binding.Engine {
		return redisServerFacts{}, errors.New("Redis or Valkey engine identity does not match its binding")
	}
	if _, supported := redisSupportedSeries[engine][series]; !supported {
		return redisServerFacts{}, errors.New("Redis or Valkey version is outside the supported V1 matrix")
	}
	mode := info["redis_mode"]
	if mode == "" {
		mode = info["server_mode"]
	}
	if mode != "standalone" {
		return redisServerFacts{}, errors.New("Redis Cluster or Sentinel is outside the supported V1 topology")
	}
	roleValue, err := client.Do(ctx, "ROLE").Result()
	roleEntries, roleOK := redisValueSlice(roleValue)
	role := ""
	if roleOK && len(roleEntries) > 0 {
		role, _ = roleEntries[0].(string)
	}
	if err != nil || (role != "master" && role != "primary") {
		return redisServerFacts{}, errors.New("Redis or Valkey V1 requires a standalone primary")
	}
	replicas := info["connected_slaves"]
	if replicas == "" {
		replicas = info["connected_replicas"]
	}
	if replicas != "" && replicas != "0" {
		return redisServerFacts{}, errors.New("Redis or Valkey V1 rejects active replica topology")
	}
	modules, err := client.Do(ctx, "MODULE", "LIST").Result()
	moduleEntries, moduleOK := redisValueSlice(modules)
	if err != nil || !moduleOK || len(moduleEntries) > 64 {
		return redisServerFacts{}, errors.New("Redis or Valkey module inventory is unavailable or outside its safety limit")
	}
	saveConfig, saveErr := client.ConfigGet(ctx, "save").Result()
	appendOnlyConfig, appendOnlyErr := client.ConfigGet(ctx, "appendonly").Result()
	if saveErr != nil || appendOnlyErr != nil {
		return redisServerFacts{}, errors.New("Redis or Valkey persistence configuration is unavailable")
	}
	aofEnabled := strings.EqualFold(appendOnlyConfig["appendonly"], "yes") || info["aof_enabled"] == "1"
	rdbEnabled := strings.TrimSpace(saveConfig["save"]) != ""
	persistenceMode := ""
	if aofEnabled {
		persistenceMode = "aof"
	} else if rdbEnabled {
		persistenceMode = "rdb"
	} else {
		return redisServerFacts{}, errors.New("Redis or Valkey V1 requires RDB or AOF persistence")
	}
	return redisServerFacts{Engine: engine, Version: version, VersionSeries: series, PersistenceMode: persistenceMode, LoadedModules: len(moduleEntries)}, nil
}

func supportedRedisCoreType(valueType string) bool {
	switch valueType {
	case "string", "list", "set", "zset", "hash", "stream":
		return true
	default:
		return false
	}
}

func sanitizeRedisACLRule(rule, username string) ([]string, error) {
	tokens := strings.Fields(rule)
	if len(tokens) < 3 || tokens[0] != "user" || tokens[1] != username || len(tokens) > 512 {
		return nil, errors.New("Redis ACL rule is invalid")
	}
	result := make([]string, 0, len(tokens)-2)
	for _, token := range tokens[2:] {
		if strings.ContainsAny(token, "()\x00\r\n") {
			return nil, errors.New("Redis ACL selectors are outside the supported V1 contract")
		}
		if strings.HasPrefix(token, "#") || strings.HasPrefix(token, ">") || strings.HasPrefix(token, "<") || strings.HasPrefix(token, "!") {
			continue
		}
		result = append(result, token)
	}
	if len(result) == 0 {
		return nil, errors.New("Redis ACL rule has no non-secret policy")
	}
	return result, nil
}

func redisACLPolicyDigest(ctx context.Context, binding redisBinding) (string, error) {
	client, err := binding.client(binding.DatabaseIndexes[0])
	if err != nil {
		return "", err
	}
	defer client.Close()
	rules, err := client.Do(ctx, "ACL", "LIST").StringSlice()
	if err != nil || len(rules) == 0 || len(rules) > 512 {
		return "", errors.New("Redis ACL policy is unavailable or outside its safety limit")
	}
	byUser := map[string]string{}
	for _, rule := range rules {
		fields := strings.Fields(rule)
		if len(fields) >= 2 && fields[0] == "user" {
			byUser[fields[1]] = rule
		}
	}
	type policyEntry struct {
		Target string   `json:"target"`
		Rules  []string `json:"rules"`
	}
	manifest := make([]policyEntry, 0, len(binding.ACLMap))
	for _, mapping := range binding.ACLMap {
		username := mapping.Source
		if binding.Mode == "target" {
			username = mapping.Target
		}
		rule, exists := byUser[username]
		if !exists {
			return "", errors.New("mapped Redis ACL user is not pre-created")
		}
		sanitized, err := sanitizeRedisACLRule(rule, username)
		if err != nil {
			return "", err
		}
		manifest = append(manifest, policyEntry{Target: mapping.Target, Rules: sanitized})
	}
	return Digest(map[string]any{"schema_version": "operations.migration.redis-acl-policy.v1", "users": manifest})
}

func updateRedisRecordDigest(target hash.Hash, record redisKeyRecord) {
	var fixed [18]byte
	binary.BigEndian.PutUint16(fixed[0:2], uint16(record.DatabaseIndex))
	binary.BigEndian.PutUint64(fixed[2:10], uint64(record.ExpiryUnixMS))
	binary.BigEndian.PutUint32(fixed[10:14], uint32(len(record.Key)))
	binary.BigEndian.PutUint32(fixed[14:18], uint32(len(record.Value)))
	_, _ = target.Write(fixed[:])
	_, _ = target.Write(record.Key)
	_, _ = target.Write(record.Value)
}

func redisDigestString(target hash.Hash) string {
	return "sha256:" + hex.EncodeToString(target.Sum(nil))
}

func canonicalRedisKeys(keys []string) []string {
	sort.Slice(keys, func(left, right int) bool { return keys[left] < keys[right] })
	uniqueKeys := keys[:0]
	for _, key := range keys {
		if len(uniqueKeys) == 0 || key != uniqueKeys[len(uniqueKeys)-1] {
			uniqueKeys = append(uniqueKeys, key)
		}
	}
	return uniqueKeys
}

func (e *NativeExecutor) scanRedisRecords(ctx context.Context, binding redisBinding, visit func(redisKeyRecord) error) (redisScanSummary, error) {
	allHash := sha256.New()
	persistentHash := sha256.New()
	summary := redisScanSummary{}
	keyIndexBytes := int64(0)
	for _, database := range binding.DatabaseIndexes {
		client, err := binding.client(database)
		if err != nil {
			return redisScanSummary{}, err
		}
		if binding.StateMode == "cache" {
			count, sizeErr := client.DBSize(ctx).Result()
			_ = client.Close()
			if sizeErr != nil || count < 0 || summary.KeyCount > maximumRedisKeys-count {
				return redisScanSummary{}, errors.New("Redis cache keyspace is outside its safety limit")
			}
			summary.KeyCount += count
			continue
		}
		keys := make([]string, 0)
		var cursor uint64
		for {
			batch, next, scanErr := client.Scan(ctx, cursor, "*", 1_000).Result()
			if scanErr != nil {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis keyspace scan failed")
			}
			keys = append(keys, batch...)
			if len(keys) > maximumRedisKeys || summary.KeyCount+int64(len(keys)) > maximumRedisKeys {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis keyspace exceeds the V1 key limit")
			}
			for _, key := range batch {
				keyIndexBytes += int64(len(key))
				if keyIndexBytes > maximumRedisKeyIndexBytes {
					_ = client.Close()
					return redisScanSummary{}, errors.New("Redis key index exceeds the V1 memory-safety limit")
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		keys = canonicalRedisKeys(keys)
		for _, key := range keys {
			if len(key) < 1 || len(key) > maximumRedisKeyBytes {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis key exceeds the V1 key-size limit")
			}
			valueType, typeErr := client.Type(ctx, key).Result()
			if typeErr == redis.Nil || valueType == "none" {
				continue
			}
			if typeErr != nil || !supportedRedisCoreType(valueType) {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis module-backed or unknown value type is outside the durable V1 contract")
			}
			value, dumpErr := client.Dump(ctx, key).Result()
			if dumpErr == redis.Nil {
				continue
			}
			if dumpErr != nil || len(value) < 1 || len(value) > maximumRedisValueBytes {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis serialized value exceeds the V1 value-size limit")
			}
			expiry, expiryErr := client.Do(ctx, "PEXPIRETIME", key).Int64()
			if expiryErr == redis.Nil || expiry == -2 {
				continue
			}
			if expiryErr != nil || expiry < -1 {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis absolute expiration is unavailable")
			}
			record := redisKeyRecord{DatabaseIndex: database, ExpiryUnixMS: expiry, Key: []byte(key), Value: []byte(value)}
			updateRedisRecordDigest(allHash, record)
			if expiry == -1 {
				updateRedisRecordDigest(persistentHash, record)
				summary.PersistentKeyCount++
			} else {
				summary.VolatileKeyCount++
			}
			summary.KeyCount++
			summary.DatabaseBytes += int64(len(record.Key) + len(record.Value))
			if summary.DatabaseBytes > maximumRedisBytes {
				_ = client.Close()
				return redisScanSummary{}, errors.New("Redis migration payload exceeds the V1 byte limit")
			}
			if visit != nil {
				if err := visit(record); err != nil {
					_ = client.Close()
					return redisScanSummary{}, err
				}
			}
		}
		_ = client.Close()
	}
	summary.AllRecordDigest = redisDigestString(allHash)
	summary.PersistentRecordDigest = redisDigestString(persistentHash)
	return summary, nil
}

func redisManifestDigest(facts redisServerFacts, binding redisBinding, aclDigest string, summary redisScanSummary) (string, error) {
	recordDigest := summary.AllRecordDigest
	recordCount := summary.KeyCount
	if binding.StateMode == "cache" {
		empty := sha256.Sum256(nil)
		recordDigest = "sha256:" + hex.EncodeToString(empty[:])
		recordCount = 0
	}
	return Digest(map[string]any{
		"schema_version": "operations.migration.redis-manifest.v1", "engine": facts.Engine,
		"version_series": facts.VersionSeries, "state_mode": binding.StateMode,
		"persistence_mode": facts.PersistenceMode, "database_indexes": binding.DatabaseIndexes,
		"acl_policy_digest": aclDigest, "record_count": recordCount,
		"record_digest": recordDigest,
	})
}

func (e *NativeExecutor) inspectRedis(ctx context.Context, bindingID string, binding redisBinding) (redisInspection, error) {
	facts, err := inspectRedisServer(ctx, binding)
	if err != nil {
		return redisInspection{}, err
	}
	aclDigest, err := redisACLPolicyDigest(ctx, binding)
	if err != nil {
		return redisInspection{}, err
	}
	summary, err := e.scanRedisRecords(ctx, binding, nil)
	if err != nil {
		return redisInspection{}, err
	}
	manifestDigest, err := redisManifestDigest(facts, binding, aclDigest, summary)
	if err != nil {
		return redisInspection{}, err
	}
	emptyDigest, err := Digest(map[string]any{
		"schema_version": "operations.migration.redis-empty-target.v1", "binding_id": bindingID,
		"instance_identity": MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "engine": binding.Engine, "databases": binding.DatabaseIndexes}),
		"empty":             summary.KeyCount == 0, "version_series": facts.VersionSeries, "state_mode": binding.StateMode,
		"persistence_mode": facts.PersistenceMode, "acl_policy_digest": aclDigest,
	})
	if err != nil {
		return redisInspection{}, err
	}
	return redisInspection{
		Exists: true, Empty: summary.KeyCount == 0, Engine: facts.Engine, ServerVersion: facts.Version,
		ServerSeries: facts.VersionSeries, StateMode: binding.StateMode, PersistenceMode: facts.PersistenceMode,
		LoadedModules:   facts.LoadedModules,
		DatabaseIndexes: append([]int(nil), binding.DatabaseIndexes...), KeyCount: summary.KeyCount,
		PersistentKeyCount: summary.PersistentKeyCount, VolatileKeyCount: summary.VolatileKeyCount,
		DatabaseBytes: summary.DatabaseBytes, ACLPolicyDigest: aclDigest,
		ManifestDigest: manifestDigest, EmptyTargetDigest: emptyDigest,
	}, nil
}

func redisInspectionOutputs(inspection redisInspection) map[string]any {
	return map[string]any{
		"exists": inspection.Exists, "empty": inspection.Empty, "engine": inspection.Engine,
		"server_version": inspection.ServerVersion, "server_series": inspection.ServerSeries,
		"state_mode": inspection.StateMode, "persistence_mode": inspection.PersistenceMode,
		"loaded_module_count": inspection.LoadedModules,
		"database_indexes":    append([]int(nil), inspection.DatabaseIndexes...), "key_count": inspection.KeyCount,
		"persistent_key_count": inspection.PersistentKeyCount, "volatile_key_count": inspection.VolatileKeyCount,
		"database_bytes": inspection.DatabaseBytes, "acl_policy_digest": inspection.ACLPolicyDigest,
		"database_manifest_digest": inspection.ManifestDigest, "empty_target_digest": inspection.EmptyTargetDigest,
	}
}

func (e *NativeExecutor) resolveRedisBinding(ctx context.Context, task TaskEnvelope, inputs map[string]any) (string, redisBinding, error) {
	bindingID, err := stringInput(inputs, "database_binding_id")
	if err != nil || !opaqueBindingPattern.MatchString(bindingID) {
		return "", redisBinding{}, errors.New("database binding identifier is invalid")
	}
	raw, err := e.resolveBinding(ctx, task, bindingID)
	if err != nil {
		return "", redisBinding{}, err
	}
	defer zeroBytes(raw)
	binding, err := parseRedisBinding(raw)
	if err != nil {
		return "", redisBinding{}, err
	}
	if err := validateRedisDatabaseContract(inputs, binding); err != nil {
		binding.clear()
		return "", redisBinding{}, err
	}
	return bindingID, binding, nil
}

func verifyRedisCompatibility(binding redisBinding, inputs map[string]any, inspection redisInspection) error {
	requiredEngine, hasEngine := inputs["required_source_engine"].(string)
	requiredSeries, hasSeries := inputs["required_source_series"].(string)
	requiredPersistence, hasPersistence := inputs["required_persistence_mode"].(string)
	if !hasEngine && !hasSeries && !hasPersistence {
		return nil
	}
	if binding.Mode != "target" || !hasEngine || !hasSeries || !hasPersistence || requiredEngine != binding.Engine ||
		inspection.Engine != requiredEngine || inspection.ServerSeries != requiredSeries || inspection.PersistenceMode != requiredPersistence {
		return errors.New("target Redis or Valkey engine, version series, and persistence mode must exactly match the source")
	}
	return nil
}

func (e *NativeExecutor) redisInspect(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	_, binding, err := e.resolveRedisBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	bindingID, _ := stringInput(inputs, "database_binding_id")
	inspection, err := e.inspectRedis(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if err := verifyRedisCompatibility(binding, inputs, inspection); err != nil {
		return nil, err
	}
	if requireEmpty, ok := inputs["require_empty_target"].(bool); ok && requireEmpty {
		if binding.Mode != "target" || !binding.ResetAllowed || !inspection.Empty {
			return nil, errors.New("target Redis or Valkey logical databases must be empty and explicitly resettable")
		}
	}
	return redisInspectionOutputs(inspection), nil
}

func writeRedisRecord(writer io.Writer, record redisKeyRecord) (int64, error) {
	if len(record.Key) < 1 || len(record.Key) > maximumRedisKeyBytes || len(record.Value) < 1 || len(record.Value) > maximumRedisValueBytes {
		return 0, errors.New("Redis archive record exceeds its safety limit")
	}
	if _, err := writer.Write([]byte{1}); err != nil {
		return 0, err
	}
	var fixed [22]byte
	binary.BigEndian.PutUint16(fixed[0:2], uint16(record.DatabaseIndex))
	binary.BigEndian.PutUint64(fixed[2:10], uint64(record.ExpiryUnixMS))
	binary.BigEndian.PutUint32(fixed[10:14], uint32(len(record.Key)))
	binary.BigEndian.PutUint64(fixed[14:22], uint64(len(record.Value)))
	if _, err := writer.Write(fixed[:]); err != nil {
		return 0, err
	}
	if _, err := writer.Write(record.Key); err != nil {
		return 0, err
	}
	if _, err := writer.Write(record.Value); err != nil {
		return 0, err
	}
	return int64(1 + len(fixed) + len(record.Key) + len(record.Value)), nil
}

func (e *NativeExecutor) writeRedisArchive(ctx context.Context, binding redisBinding, facts redisServerFacts, aclDigest, path string, progress func(string, int64, *int64) error) (redisArchiveTrailer, int64, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".partial-")
	if err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	partial := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(partial)
		return redisArchiveTrailer{}, 0, err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(partial)
		}
	}()
	written, err := file.Write([]byte(redisArchiveMagic))
	if err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	totalWritten := int64(written)
	summary, err := e.scanRedisRecords(ctx, binding, func(record redisKeyRecord) error {
		count, writeErr := writeRedisRecord(file, record)
		if writeErr != nil {
			return writeErr
		}
		totalWritten += count
		if totalWritten > maximumRedisArchiveBytes {
			return errors.New("Redis archive exceeds the V1 byte limit")
		}
		return progress("redis_snapshot", totalWritten, nil)
	})
	if err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	manifestDigest, err := redisManifestDigest(facts, binding, aclDigest, summary)
	if err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	archiveSummary := summary
	excludedCacheKeys := int64(0)
	if binding.StateMode == "cache" {
		excludedCacheKeys = summary.KeyCount
		empty := sha256.Sum256(nil)
		archiveSummary = redisScanSummary{
			AllRecordDigest:        "sha256:" + hex.EncodeToString(empty[:]),
			PersistentRecordDigest: "sha256:" + hex.EncodeToString(empty[:]),
		}
	}
	trailer := redisArchiveTrailer{
		SchemaVersion: redisArchiveSchema, Engine: facts.Engine, SourceVersionSeries: facts.VersionSeries,
		StateMode: binding.StateMode, PersistenceMode: facts.PersistenceMode,
		DatabaseIndexes: append([]int(nil), binding.DatabaseIndexes...), ACLPolicyDigest: aclDigest,
		RecordCount: archiveSummary.KeyCount, ExcludedCacheKeyCount: excludedCacheKeys,
		PersistentRecordCount: archiveSummary.PersistentKeyCount,
		VolatileRecordCount:   archiveSummary.VolatileKeyCount, AllRecordDigest: archiveSummary.AllRecordDigest,
		PersistentRecordDigest: archiveSummary.PersistentRecordDigest, ManifestDigest: manifestDigest,
	}
	encoded, err := json.Marshal(trailer)
	if err != nil || len(encoded) > maximumRedisTrailerBytes {
		return redisArchiveTrailer{}, 0, errors.New("Redis archive trailer is invalid")
	}
	if _, err := file.Write([]byte{255}); err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err := file.Write(length[:]); err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	if _, err := file.Write(encoded); err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	totalWritten += int64(5 + len(encoded))
	if err := file.Sync(); err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	if err := file.Close(); err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	if err := os.Rename(partial, path); err != nil {
		return redisArchiveTrailer{}, 0, err
	}
	remove = false
	return trailer, totalWritten, nil
}

func readRedisArchive(path string, binding redisBinding, expectedACLDigest string, visit func(redisKeyRecord) error) (redisArchiveTrailer, error) {
	file, info, err := openRegularNoFollow(path)
	if err != nil || info.Size() < int64(len(redisArchiveMagic)+5) || info.Size() > maximumRedisArchiveBytes {
		return redisArchiveTrailer{}, errors.New("Redis archive is unsafe or outside its size limit")
	}
	defer file.Close()
	magic := make([]byte, len(redisArchiveMagic))
	if _, err := io.ReadFull(file, magic); err != nil || string(magic) != redisArchiveMagic {
		return redisArchiveTrailer{}, errors.New("Redis archive header is invalid")
	}
	allHash := sha256.New()
	persistentHash := sha256.New()
	var count, persistent, volatile, databaseBytes, keyIndexBytes int64
	previousDatabase := -1
	previousKey := []byte(nil)
	allowedDatabases := map[int]struct{}{}
	for _, database := range binding.DatabaseIndexes {
		allowedDatabases[database] = struct{}{}
	}
	for {
		var tag [1]byte
		if _, err := io.ReadFull(file, tag[:]); err != nil {
			return redisArchiveTrailer{}, errors.New("Redis archive is truncated")
		}
		if tag[0] == 255 {
			break
		}
		if tag[0] != 1 || binding.StateMode == "cache" {
			return redisArchiveTrailer{}, errors.New("Redis archive contains an unexpected record")
		}
		var fixed [22]byte
		if _, err := io.ReadFull(file, fixed[:]); err != nil {
			return redisArchiveTrailer{}, errors.New("Redis archive record is truncated")
		}
		database := int(binary.BigEndian.Uint16(fixed[0:2]))
		expiry := int64(binary.BigEndian.Uint64(fixed[2:10]))
		keyLength := int(binary.BigEndian.Uint32(fixed[10:14]))
		valueLength := int64(binary.BigEndian.Uint64(fixed[14:22]))
		if _, ok := allowedDatabases[database]; !ok || keyLength < 1 || keyLength > maximumRedisKeyBytes || valueLength < 1 || valueLength > maximumRedisValueBytes || expiry < -1 {
			return redisArchiveTrailer{}, errors.New("Redis archive record contract is invalid")
		}
		keyIndexBytes += int64(keyLength)
		databaseBytes += int64(keyLength) + valueLength
		if keyIndexBytes > maximumRedisKeyIndexBytes || databaseBytes > maximumRedisBytes {
			return redisArchiveTrailer{}, errors.New("Redis archive payload exceeds its V1 memory or byte limit")
		}
		key := make([]byte, keyLength)
		value := make([]byte, int(valueLength))
		if _, err := io.ReadFull(file, key); err != nil {
			return redisArchiveTrailer{}, errors.New("Redis archive key is truncated")
		}
		if _, err := io.ReadFull(file, value); err != nil {
			return redisArchiveTrailer{}, errors.New("Redis archive value is truncated")
		}
		if database < previousDatabase || (database == previousDatabase && bytes.Compare(key, previousKey) <= 0) {
			return redisArchiveTrailer{}, errors.New("Redis archive records are not canonical")
		}
		previousDatabase = database
		previousKey = append(previousKey[:0], key...)
		record := redisKeyRecord{DatabaseIndex: database, ExpiryUnixMS: expiry, Key: key, Value: value}
		updateRedisRecordDigest(allHash, record)
		if expiry == -1 {
			updateRedisRecordDigest(persistentHash, record)
			persistent++
		} else {
			volatile++
		}
		count++
		if count > maximumRedisKeys {
			return redisArchiveTrailer{}, errors.New("Redis archive exceeds the V1 key limit")
		}
		if visit != nil {
			if err := visit(record); err != nil {
				return redisArchiveTrailer{}, err
			}
		}
	}
	var length [4]byte
	if _, err := io.ReadFull(file, length[:]); err != nil {
		return redisArchiveTrailer{}, errors.New("Redis archive trailer is truncated")
	}
	trailerLength := int(binary.BigEndian.Uint32(length[:]))
	if trailerLength < 2 || trailerLength > maximumRedisTrailerBytes {
		return redisArchiveTrailer{}, errors.New("Redis archive trailer length is invalid")
	}
	encoded := make([]byte, trailerLength)
	if _, err := io.ReadFull(file, encoded); err != nil {
		return redisArchiveTrailer{}, errors.New("Redis archive trailer is truncated")
	}
	var extra [1]byte
	if read, err := file.Read(extra[:]); err != io.EOF || read != 0 {
		return redisArchiveTrailer{}, errors.New("Redis archive contains trailing data")
	}
	var trailer redisArchiveTrailer
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&trailer); err != nil {
		return redisArchiveTrailer{}, errors.New("Redis archive trailer is invalid")
	}
	_, supportedSeries := redisSupportedSeries[trailer.Engine][trailer.SourceVersionSeries]
	if trailer.SchemaVersion != redisArchiveSchema || trailer.Engine != binding.Engine || !supportedSeries ||
		trailer.StateMode != binding.StateMode || (trailer.PersistenceMode != "rdb" && trailer.PersistenceMode != "aof") ||
		trailer.ACLPolicyDigest != expectedACLDigest || MustDigest(trailer.DatabaseIndexes) != MustDigest(binding.DatabaseIndexes) ||
		trailer.RecordCount != count || trailer.PersistentRecordCount != persistent || trailer.VolatileRecordCount != volatile ||
		trailer.AllRecordDigest != redisDigestString(allHash) || trailer.PersistentRecordDigest != redisDigestString(persistentHash) ||
		trailer.RecordCount != trailer.PersistentRecordCount+trailer.VolatileRecordCount ||
		(binding.StateMode == "cache" && (trailer.RecordCount != 0 || trailer.ExcludedCacheKeyCount < 0)) ||
		(binding.StateMode == "durable" && trailer.ExcludedCacheKeyCount != 0) {
		return redisArchiveTrailer{}, errors.New("Redis archive trailer contract is invalid")
	}
	facts := redisServerFacts{Engine: trailer.Engine, VersionSeries: trailer.SourceVersionSeries, PersistenceMode: trailer.PersistenceMode}
	summary := redisScanSummary{KeyCount: count, PersistentKeyCount: persistent, VolatileKeyCount: volatile, AllRecordDigest: trailer.AllRecordDigest, PersistentRecordDigest: trailer.PersistentRecordDigest}
	manifestDigest, err := redisManifestDigest(facts, binding, expectedACLDigest, summary)
	if err != nil || manifestDigest != trailer.ManifestDigest {
		return redisArchiveTrailer{}, errors.New("Redis archive manifest verification failed")
	}
	return trailer, nil
}

func redisArchiveCapacityBytes(binding redisBinding, inspection redisInspection) (int64, error) {
	required := int64(len(redisArchiveMagic) + 5 + maximumRedisTrailerBytes)
	if binding.StateMode == "cache" {
		return required, nil
	}
	if inspection.KeyCount < 0 || inspection.KeyCount > maximumRedisKeys || inspection.DatabaseBytes < 0 || inspection.DatabaseBytes > maximumRedisBytes {
		return 0, errors.New("Redis migration payload is outside the V1 archive limit")
	}
	required += inspection.DatabaseBytes + inspection.KeyCount*23
	if required > maximumRedisArchiveBytes {
		return 0, errors.New("Redis migration archive is outside the V1 capacity limit")
	}
	return required, nil
}

func (e *NativeExecutor) redisDump(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolveRedisBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "source" {
		return nil, errors.New("Redis snapshot requires a source binding")
	}
	inspection, err := e.inspectRedis(ctx, bindingID, binding)
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
	requiredCapacity, err := redisArchiveCapacityBytes(binding, inspection)
	if err != nil {
		return nil, err
	}
	if err := e.ensureCapacity(stagingRoot, requiredCapacity); err != nil {
		return nil, err
	}
	relative, directory, err := mysqlArtifactLocation(e, task, stagingHandle, "redis", inspection.ManifestDigest)
	if err != nil {
		return nil, err
	}
	facts := redisServerFacts{Engine: inspection.Engine, Version: inspection.ServerVersion, VersionSeries: inspection.ServerSeries, PersistenceMode: inspection.PersistenceMode}
	artifactPath := filepath.Join(directory, redisArchiveHandle)
	trailer, archiveSize, err := e.writeRedisArchive(ctx, binding, facts, inspection.ACLPolicyDigest, artifactPath, progress)
	if err != nil {
		return nil, err
	}
	digest, actualSize, err := fileSHA256(artifactPath)
	if err != nil || actualSize != archiveSize {
		return nil, errors.New("Redis archive digest generation failed")
	}
	transferManifest, err := buildFileManifest(ctx, directory, nil)
	if err != nil {
		return nil, err
	}
	if err := progress("redis_snapshot_complete", archiveSize, &archiveSize); err != nil {
		return nil, err
	}
	return map[string]any{
		"dump_artifact_handle": redisArchiveHandle, "dump_staging_relative_handle": relative,
		"dump_artifact_digest": digest, "dump_transfer_manifest_digest": transferManifest.Digest,
		"dump_size_bytes": transferManifest.TotalBytes, "dump_archive_size_bytes": archiveSize,
		"database_manifest_digest": trailer.ManifestDigest, "engine": trailer.Engine,
		"server_series": trailer.SourceVersionSeries, "state_mode": trailer.StateMode,
		"persistence_mode": trailer.PersistenceMode, "key_count": trailer.RecordCount,
		"excluded_cache_key_count": trailer.ExcludedCacheKeyCount,
		"persistent_key_count":     trailer.PersistentRecordCount, "volatile_key_count": trailer.VolatileRecordCount,
	}, nil
}

type redisResetMarker struct {
	SchemaVersion      string `json:"schema_version"`
	MigrationID        string `json:"migration_id"`
	BindingID          string `json:"binding_id"`
	InstanceIdentity   string `json:"instance_identity"`
	InitialEmptyDigest string `json:"initial_empty_digest"`
	Generation         int    `json:"generation"`
	UpdatedAt          string `json:"updated_at"`
}

func (e *NativeExecutor) redisMarkerPath(bindingID string) string {
	digest := sha256.Sum256([]byte(bindingID))
	return filepath.Join(e.stateDir, "redis-reset-markers", hex.EncodeToString(digest[:16])+".json")
}

func (e *NativeExecutor) loadRedisMarker(bindingID string) (redisResetMarker, error) {
	data, err := os.ReadFile(e.redisMarkerPath(bindingID))
	if err != nil {
		return redisResetMarker{}, err
	}
	var marker redisResetMarker
	if json.Unmarshal(data, &marker) != nil || marker.SchemaVersion != "operations.migration.redis-reset-marker.v1" {
		return redisResetMarker{}, errors.New("target Redis ownership marker is invalid")
	}
	return marker, nil
}

func (e *NativeExecutor) saveRedisMarker(bindingID string, marker redisResetMarker) error {
	path := e.redisMarkerPath(bindingID)
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

func redisInstanceIdentity(binding redisBinding) string {
	return MustDigest(map[string]any{"host": binding.Host, "port": binding.Port, "engine": binding.Engine, "databases": binding.DatabaseIndexes})
}

func flushRedisDatabases(ctx context.Context, binding redisBinding) error {
	for _, database := range binding.DatabaseIndexes {
		client, err := binding.client(database)
		if err != nil {
			return err
		}
		flushErr := client.FlushDB(ctx).Err()
		_ = client.Close()
		if flushErr != nil {
			return errors.New("target Redis database reset failed safely")
		}
	}
	return nil
}

func (e *NativeExecutor) redisReset(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveRedisBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" || !binding.ResetAllowed {
		return nil, errors.New("target Redis reset is not explicitly constrained")
	}
	expectedDigest, err := stringInput(inputs, "expected_empty_target_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedDigest) {
		return nil, errors.New("expected empty target digest is invalid")
	}
	inspection, err := e.inspectRedis(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	marker, markerErr := e.loadRedisMarker(bindingID)
	identity := redisInstanceIdentity(binding)
	ownedByRun := markerErr == nil && marker.MigrationID == task.MigrationID && marker.BindingID == bindingID &&
		marker.InstanceIdentity == identity && marker.InitialEmptyDigest == expectedDigest
	if (!inspection.Empty || inspection.EmptyTargetDigest != expectedDigest) && !ownedByRun {
		return nil, errors.New("target Redis databases are not the approved empty target and are not owned by this migration")
	}
	if err := flushRedisDatabases(ctx, binding); err != nil {
		return nil, err
	}
	generation := 1
	initialDigest := expectedDigest
	if ownedByRun {
		generation = marker.Generation + 1
		initialDigest = marker.InitialEmptyDigest
	}
	marker = redisResetMarker{SchemaVersion: "operations.migration.redis-reset-marker.v1", MigrationID: task.MigrationID,
		BindingID: bindingID, InstanceIdentity: identity, InitialEmptyDigest: initialDigest,
		Generation: generation, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := e.saveRedisMarker(bindingID, marker); err != nil {
		return nil, err
	}
	return map[string]any{"instance_identity_digest": identity, "reset_generation": generation, "empty": true}, nil
}

func redisArchiveInputPath(e *NativeExecutor, inputs map[string]any) (string, string, int64, error) {
	stagingHandle, err := stringInput(inputs, "staging_root_handle")
	if err != nil {
		return "", "", 0, err
	}
	stagingRelative, err := stringInput(inputs, "dump_staging_relative_handle")
	if err != nil || strings.Contains(stagingRelative, "/") || !fileNamePattern.MatchString(stagingRelative) {
		return "", "", 0, errors.New("Redis dump staging relative handle is invalid")
	}
	artifactHandle, err := stringInput(inputs, "dump_artifact_handle")
	if err != nil || artifactHandle != redisArchiveHandle {
		return "", "", 0, errors.New("Redis dump artifact handle is invalid")
	}
	artifactPath, err := e.resolver.Resolve(stagingHandle, filepath.Join(stagingRelative, artifactHandle), false)
	if err != nil {
		return "", "", 0, err
	}
	expectedDigest, err := stringInput(inputs, "dump_artifact_digest")
	if err != nil || !fileDigestPattern.MatchString(expectedDigest) {
		return "", "", 0, errors.New("Redis dump artifact digest is invalid")
	}
	actualDigest, size, err := fileSHA256(artifactPath)
	if err != nil || actualDigest != expectedDigest {
		return "", "", 0, errors.New("Redis archive digest verification failed")
	}
	return artifactPath, actualDigest, size, nil
}

func redisClients(binding redisBinding) (map[int]*redis.Client, error) {
	clients := map[int]*redis.Client{}
	for _, database := range binding.DatabaseIndexes {
		client, err := binding.client(database)
		if err != nil {
			for _, created := range clients {
				_ = created.Close()
			}
			return nil, err
		}
		clients[database] = client
	}
	return clients, nil
}

func closeRedisClients(clients map[int]*redis.Client) {
	for _, client := range clients {
		_ = client.Close()
	}
}

func verifyRedisArchiveTarget(ctx context.Context, binding redisBinding, path string, trailer redisArchiveTrailer) (int64, error) {
	clients, err := redisClients(binding)
	if err != nil {
		return 0, err
	}
	defer closeRedisClients(clients)
	expected := map[int]map[string]int64{}
	for _, database := range binding.DatabaseIndexes {
		expected[database] = map[string]int64{}
	}
	now := time.Now().UnixMilli()
	_, err = readRedisArchive(path, binding, trailer.ACLPolicyDigest, func(record redisKeyRecord) error {
		if record.ExpiryUnixMS != -1 && record.ExpiryUnixMS <= now {
			return nil
		}
		client := clients[record.DatabaseIndex]
		actual, valueErr := client.Dump(ctx, string(record.Key)).Result()
		if valueErr != nil || !bytes.Equal([]byte(actual), record.Value) {
			return errors.New("restored Redis value does not match the source archive")
		}
		expiry, expiryErr := client.Do(ctx, "PEXPIRETIME", string(record.Key)).Int64()
		if expiryErr != nil || (record.ExpiryUnixMS == -1 && expiry != -1) ||
			(record.ExpiryUnixMS != -1 && (expiry < record.ExpiryUnixMS-redisExpiryTolerance || expiry > record.ExpiryUnixMS+redisExpiryTolerance)) {
			return errors.New("restored Redis expiration does not match the source archive")
		}
		expected[record.DatabaseIndex][string(record.Key)] = record.ExpiryUnixMS
		return nil
	})
	if err != nil {
		return 0, err
	}
	verified := int64(0)
	for database, client := range clients {
		var cursor uint64
		for {
			keys, next, scanErr := client.Scan(ctx, cursor, "*", 1_000).Result()
			if scanErr != nil {
				return 0, errors.New("restored Redis keyspace verification failed")
			}
			for _, key := range keys {
				if _, exists := expected[database][key]; !exists {
					return 0, errors.New("restored Redis keyspace contains an undeclared key")
				}
				delete(expected[database], key)
				verified++
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		for key, expiry := range expected[database] {
			if expiry == -1 || expiry > time.Now().UnixMilli() {
				if exists, existsErr := client.Exists(ctx, key).Result(); existsErr != nil || exists != 1 {
					return 0, errors.New("restored Redis keyspace is missing a source key")
				}
			}
		}
	}
	return verified, nil
}

func (e *NativeExecutor) redisRestore(ctx context.Context, task TaskEnvelope, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	bindingID, binding, err := e.resolveRedisBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" || !binding.ResetAllowed {
		return nil, errors.New("Redis restore requires a target binding")
	}
	marker, err := e.loadRedisMarker(bindingID)
	if err != nil || marker.MigrationID != task.MigrationID || marker.BindingID != bindingID || marker.Generation < 1 ||
		marker.InstanceIdentity != redisInstanceIdentity(binding) {
		return nil, errors.New("target Redis reset ownership is unproven")
	}
	artifactPath, artifactDigest, size, err := redisArchiveInputPath(e, inputs)
	if err != nil {
		return nil, err
	}
	aclDigest, err := redisACLPolicyDigest(ctx, binding)
	if err != nil {
		return nil, err
	}
	ttlCutoff := time.Now().Add(redisMinimumRestoreTTL).UnixMilli()
	trailer, err := readRedisArchive(artifactPath, binding, aclDigest, func(record redisKeyRecord) error {
		if record.ExpiryUnixMS != -1 && record.ExpiryUnixMS <= ttlCutoff {
			return errors.New("Redis archive contains a volatile key too near expiry; create a fresh source snapshot")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	expectedManifest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil || expectedManifest != trailer.ManifestDigest {
		return nil, errors.New("expected Redis manifest digest is invalid")
	}
	before, err := e.inspectRedis(ctx, bindingID, binding)
	if err != nil {
		return nil, err
	}
	if before.Engine != trailer.Engine || before.ServerSeries != trailer.SourceVersionSeries || before.PersistenceMode != trailer.PersistenceMode {
		return nil, errors.New("target Redis or Valkey runtime drifted from the reviewed source compatibility contract")
	}
	retryResetApplied := false
	if !before.Empty {
		if err := flushRedisDatabases(ctx, binding); err != nil {
			return nil, err
		}
		retryResetApplied = true
		afterReset, inspectErr := e.inspectRedis(ctx, bindingID, binding)
		if inspectErr != nil || !afterReset.Empty || afterReset.EmptyTargetDigest != marker.InitialEmptyDigest {
			return nil, errors.New("target Redis retry reset did not reproduce the approved empty target")
		}
	}
	clients, err := redisClients(binding)
	if err != nil {
		return nil, err
	}
	defer closeRedisClients(clients)
	restored := int64(0)
	_, err = readRedisArchive(artifactPath, binding, aclDigest, func(record redisKeyRecord) error {
		arguments := []any{"RESTORE", record.Key, int64(0), record.Value}
		if record.ExpiryUnixMS != -1 {
			if record.ExpiryUnixMS <= time.Now().UnixMilli() {
				return errors.New("Redis archive key expired during restore; create a fresh source snapshot")
			}
			arguments[2] = record.ExpiryUnixMS
			arguments = append(arguments, "ABSTTL")
		}
		if err := clients[record.DatabaseIndex].Do(ctx, arguments...).Err(); err != nil {
			return errors.New("Redis value restore failed safely")
		}
		restored++
		return progress("redis_restore", restored, &trailer.RecordCount)
	})
	if err != nil {
		return nil, err
	}
	verified, err := verifyRedisArchiveTarget(ctx, binding, artifactPath, trailer)
	if err != nil {
		return nil, err
	}
	after, err := e.inspectRedis(ctx, bindingID, binding)
	if err != nil || after.ManifestDigest != trailer.ManifestDigest {
		return nil, errors.New("restored Redis stable manifest does not match the source")
	}
	if err := progress("redis_restore_verified", size, &size); err != nil {
		return nil, err
	}
	return map[string]any{
		"database_manifest_digest": after.ManifestDigest, "dump_artifact_digest": artifactDigest,
		"restored_size_bytes": size, "restored_key_count": restored, "verified_key_count": verified,
		"persistent_key_count": trailer.PersistentRecordCount, "volatile_key_count": trailer.VolatileRecordCount,
		"retry_reset_applied": retryResetApplied, "ttl_safety_window_seconds": int64(redisMinimumRestoreTTL / time.Second),
	}, nil
}

func (e *NativeExecutor) redisVerify(ctx context.Context, task TaskEnvelope, inputs map[string]any) (map[string]any, error) {
	bindingID, binding, err := e.resolveRedisBinding(ctx, task, inputs)
	if err != nil {
		return nil, err
	}
	defer binding.clear()
	if binding.Mode != "target" {
		return nil, errors.New("Redis verification requires a target binding")
	}
	artifactPath, _, _, err := redisArchiveInputPath(e, inputs)
	if err != nil {
		return nil, err
	}
	aclDigest, err := redisACLPolicyDigest(ctx, binding)
	if err != nil {
		return nil, err
	}
	trailer, err := readRedisArchive(artifactPath, binding, aclDigest, nil)
	if err != nil {
		return nil, err
	}
	expectedManifest, err := stringInput(inputs, "expected_manifest_digest")
	if err != nil || expectedManifest != trailer.ManifestDigest {
		return nil, errors.New("expected Redis verification manifest is invalid")
	}
	verified, err := verifyRedisArchiveTarget(ctx, binding, artifactPath, trailer)
	if err != nil {
		return nil, err
	}
	inspection, err := e.inspectRedis(ctx, bindingID, binding)
	if err != nil || inspection.ManifestDigest != expectedManifest {
		return nil, errors.New("Redis stable manifest verification failed")
	}
	return map[string]any{
		"verified": true, "database_manifest_digest": inspection.ManifestDigest,
		"key_count": inspection.KeyCount, "verified_archive_keys": verified,
		"persistent_key_count": inspection.PersistentKeyCount, "volatile_key_count": inspection.VolatileKeyCount,
	}, nil
}
