package migration

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type ObservationFact struct {
	Key        string         `json:"key"`
	Kind       string         `json:"kind"`
	Value      map[string]any `json:"value"`
	Provenance []string       `json:"provenance"`
	Confidence float64        `json:"confidence"`
}

type Observation struct {
	SchemaVersion string            `json:"schema_version"`
	Collector     map[string]any    `json:"collector"`
	EndpointRole  string            `json:"endpoint_role"`
	ObservedAt    string            `json:"observed_at"`
	Completeness  string            `json:"completeness"`
	Facts         []ObservationFact `json:"facts"`
	Redactions    map[string]any    `json:"redactions"`
}

func safeCommandVersion(ctx context.Context, paths []string, args ...string) (string, bool) {
	for _, path := range paths {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			continue
		}
		command := exec.CommandContext(ctx, path, args...)
		command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
		output, err := command.CombinedOutput()
		if err != nil {
			return "", false
		}
		text := strings.TrimSpace(string(output))
		if len(text) > 512 {
			text = text[:512]
		}
		return text, true
	}
	return "", false
}

func dockerClientVersion(ctx context.Context, paths []string) (string, bool) {
	// `docker version` contacts the daemon even when formatting only the client
	// field. Discovery runs as the unprivileged agent user, so use the static
	// client probe and leave daemon access to the typed migration broker.
	return safeCommandVersion(ctx, paths, "--version")
}

func parseOSRelease() map[string]any {
	result := map[string]any{}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || (key != "ID" && key != "VERSION_ID") {
			continue
		}
		result[strings.ToLower(key)] = strings.Trim(strings.TrimSpace(value), `"'`)
	}
	return result
}

func memoryTotalBytes() int64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			return value * 1024
		}
	}
	return 0
}

func kernelVersion() string {
	if version, ok := safeCommandVersion(context.Background(), []string{"/usr/bin/uname", "/bin/uname"}, "-r"); ok {
		return version
	}
	return "unknown"
}

func rootCapacity(path string) map[string]any {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return map[string]any{"exists": false}
	}
	entries, _ := os.ReadDir(path)
	return map[string]any{
		"exists":         true,
		"empty":          len(entries) == 0,
		"capacity_bytes": int64(stat.Blocks) * int64(stat.Bsize),
		"free_bytes":     int64(stat.Bavail) * int64(stat.Bsize),
	}
}

func stableKey(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + "." + hex.EncodeToString(digest[:8])
}

func listSystemdServices(ctx context.Context) []string {
	binary, err := fixedExecutable("/usr/bin/systemctl", "/bin/systemctl")
	if err != nil {
		return nil
	}
	command := exec.CommandContext(ctx, binary, "list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	output, err := command.Output()
	if err != nil {
		return nil
	}
	services := []string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !serviceNamePattern.MatchString(fields[0]) {
			continue
		}
		services = append(services, fields[0])
		if len(services) == 256 {
			break
		}
	}
	sort.Strings(services)
	return services
}

func selectedDatabaseClientFact(ctx context.Context, engine string) (ObservationFact, error) {
	if engine == "mongodb" {
		value := map[string]any{"engine": engine, "client_available": true}
		provenanceValues := []string{}
		for _, name := range []string{"mongodump", "mongorestore", "mongosh"} {
			version, ok := safeCommandVersion(ctx, []string{filepath.Join("/usr/bin", name), filepath.Join("/usr/local/bin", name)}, "--version")
			if !ok {
				value["client_available"] = false
				provenanceValues = []string{"observed:fixed-binary-probe"}
				break
			}
			value[name+"_version"] = version
			provenanceValues = append(provenanceValues, "observed:"+name+"-version")
		}
		return ObservationFact{
			Key: "database.mongodb", Kind: "database", Value: value,
			Provenance: provenanceValues, Confidence: 1,
		}, nil
	}
	var paths []string
	var arguments []string
	var provenance string
	switch engine {
	case "postgresql":
		paths = []string{"/usr/bin/psql", "/usr/local/bin/psql"}
		arguments = []string{"--version"}
		provenance = "observed:psql-version"
	case "mysql":
		paths = []string{"/usr/bin/mysql", "/usr/local/bin/mysql"}
		arguments = []string{"--version"}
		provenance = "observed:mysql-client-version"
	case "mariadb":
		paths = []string{"/usr/bin/mariadb", "/usr/local/bin/mariadb"}
		arguments = []string{"--version"}
		provenance = "observed:mariadb-client-version"
	default:
		return ObservationFact{}, errors.New("discovery database engine is unsupported")
	}
	value := map[string]any{"engine": engine, "client_available": false}
	provenanceValues := []string{"observed:fixed-binary-probe"}
	if version, ok := safeCommandVersion(ctx, paths, arguments...); ok {
		value["version"] = version
		value["client_available"] = true
		provenanceValues = []string{provenance}
	}
	return ObservationFact{
		Key: "database." + engine, Kind: "database", Value: value,
		Provenance: provenanceValues, Confidence: 1,
	}, nil
}

func CollectObservation(ctx context.Context, task TaskEnvelope, rootHandles map[string]string) (Observation, error) {
	role, _ := task.Inputs["endpoint_role"].(string)
	manifestDigest, _ := task.Inputs["collector_manifest_digest"].(string)
	databaseEngine, _ := task.Inputs["database_engine"].(string)
	if (role != "source" && role != "target") || !strings.HasPrefix(manifestDigest, "sha256:") {
		return Observation{}, errors.New("discovery assignment is invalid")
	}
	collectorContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	facts := []ObservationFact{{
		Key: "platform.host", Kind: "platform", Provenance: []string{"observed:/etc/os-release", "observed:uname"}, Confidence: 1,
		Value: map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "kernel": kernelVersion(), "cpu_count": runtime.NumCPU(), "memory_bytes": memoryTotalBytes(), "release": parseOSRelease()},
	}}
	if version, ok := dockerClientVersion(collectorContext, []string{"/usr/bin/docker", "/usr/local/bin/docker"}); ok {
		facts = append(facts, ObservationFact{Key: "runtime.docker", Kind: "runtime", Value: map[string]any{"version": version, "available": true}, Provenance: []string{"observed:docker-client-version"}, Confidence: 1})
	} else {
		facts = append(facts, ObservationFact{Key: "runtime.docker", Kind: "runtime", Value: map[string]any{"available": false}, Provenance: []string{"observed:fixed-binary-probe"}, Confidence: 1})
	}
	if version, ok := safeCommandVersion(collectorContext, []string{"/usr/bin/docker", "/usr/local/bin/docker"}, "compose", "version", "--short"); ok {
		facts = append(facts, ObservationFact{Key: "compose.engine", Kind: "compose", Value: map[string]any{"version": version, "available": true}, Provenance: []string{"observed:docker-compose-version"}, Confidence: 1})
	} else {
		facts = append(facts, ObservationFact{Key: "compose.engine", Kind: "compose", Value: map[string]any{"available": false}, Provenance: []string{"observed:fixed-binary-probe"}, Confidence: 1})
	}
	databaseFact, err := selectedDatabaseClientFact(collectorContext, databaseEngine)
	if err != nil {
		return Observation{}, err
	}
	facts = append(facts, databaseFact)
	handles := make([]string, 0, len(rootHandles))
	for handle := range rootHandles {
		handles = append(handles, handle)
	}
	sort.Strings(handles)
	for _, handle := range handles {
		facts = append(facts, ObservationFact{Key: "file_root." + handle, Kind: "file_root", Value: rootCapacity(rootHandles[handle]), Provenance: []string{"observed:statfs", "declared:root-handle:" + handle}, Confidence: 1})
	}
	for _, service := range listSystemdServices(collectorContext) {
		facts = append(facts, ObservationFact{Key: stableKey("service", service), Kind: "service", Value: map[string]any{"unit": service}, Provenance: []string{"observed:systemd-unit-files"}, Confidence: 1})
	}
	return Observation{
		SchemaVersion: "operations.migration.observation.v1",
		Collector:     map[string]any{"id": "askio-linux-host", "version": "1.1.0", "manifest_digest": manifestDigest},
		EndpointRole:  role, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Completeness: "complete", Facts: facts,
		Redactions: map[string]any{"rules_version": "1.0.0", "values_removed": 0, "canary_hits": 0},
	}, nil
}
