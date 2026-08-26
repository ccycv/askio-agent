package migration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var supportedPrimitives = map[string]struct{}{
	"migration.discovery.collect.v1": {}, "migration.host.preflight.v1": {},
	"migration.host.fence-writers.v1": {}, "migration.host.unfence-writers.v1": {},
	"migration.source.estimate.v1": {}, "migration.source.verify-quiescence.v1": {},
	"migration.files.manifest.v1": {}, "migration.files.sync.v1": {},
	"migration.postgres.inspect.v1": {}, "migration.postgres.dump.v1": {},
	"migration.postgres.reset-empty-target.v1": {}, "migration.postgres.restore.v1": {},
	"migration.postgres.verify.v1": {}, "migration.compose.inspect.v1": {},
	"migration.mysql.inspect.v1": {}, "migration.mysql.dump.v1": {},
	"migration.mysql.reset-empty-target.v1": {}, "migration.mysql.restore.v1": {},
	"migration.mysql.verify.v1":    {},
	"migration.mongodb.inspect.v1": {}, "migration.mongodb.dump.v1": {},
	"migration.mongodb.reset-empty-target.v1": {}, "migration.mongodb.restore.v1": {},
	"migration.mongodb.verify.v1":           {},
	"migration.compose.preflight-target.v1": {},
	"migration.compose.render.v1":           {}, "migration.compose.start-isolated.v1": {},
	"migration.compose.stop.v1":     {},
	"migration.http.validate.v1":    {},
	"migration.evidence.capture.v1": {}, "migration.cleanup.staging.v1": {},
}

type NativeExecutor struct {
	rootHandles   map[string]string
	resolver      *ScopeResolver
	broker        *BrokerClient
	bindings      BindingResolver
	tickets       TicketResolver
	stateDir      string
	agentID       string
	identity      *Identity
	backendKeyID  string
	backendPublic ed25519.PublicKey
	capacityCheck func(string, int64) error
	logger        *slog.Logger
}

func (e *NativeExecutor) ensureCapacity(path string, requiredBytes int64) error {
	if e.capacityCheck != nil {
		return e.capacityCheck(path, requiredBytes)
	}
	return ensureFileSystemCapacity(path, requiredBytes)
}

func NewNativeExecutor(rootHandles map[string]string, brokerSocket, stateDir string) (*NativeExecutor, error) {
	resolver, err := NewScopeResolver(rootHandles)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("migration executor state directory must be absolute")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	return &NativeExecutor{rootHandles: rootHandles, resolver: resolver, broker: NewBrokerClient(brokerSocket), stateDir: stateDir}, nil
}

func (e *NativeExecutor) SetBindingResolver(resolver BindingResolver) {
	e.bindings = resolver
}

func (e *NativeExecutor) SetTicketResolver(resolver TicketResolver) {
	e.tickets = resolver
}

func (e *NativeExecutor) SetLogger(logger *slog.Logger) {
	e.logger = logger
}

func (e *NativeExecutor) ConfigureDataPlaneIdentity(agentID, backendKeyID, backendPublicKeyBase64 string, identity *Identity) error {
	if agentID == "" || backendKeyID == "" || identity == nil {
		return errors.New("migration data-plane identity is incomplete")
	}
	backendPublic, err := parseBackendSigningKey(backendPublicKeyBase64)
	if err != nil {
		return err
	}
	e.agentID = agentID
	e.backendKeyID = backendKeyID
	e.backendPublic = backendPublic
	e.identity = identity
	return nil
}

func (e *NativeExecutor) resolveBinding(ctx context.Context, task TaskEnvelope, bindingID string) ([]byte, error) {
	if e.bindings == nil {
		return nil, errors.New("attempt-scoped binding resolver is unavailable")
	}
	return e.bindings(ctx, task, bindingID)
}

func (e *NativeExecutor) Supports(primitive PrimitiveRef) bool {
	if primitive.Version != "1.0.0" {
		return false
	}
	_, ok := supportedPrimitives[primitive.ID]
	return ok
}

func fail(code, message string, retryable bool) PrimitiveResult {
	return PrimitiveResult{State: "failed", Outputs: map[string]any{}, EvidenceDigests: []string{}, Error: &SafeError{Code: code, SafeMessage: message, Retryable: retryable}}
}

func taskInputs(task TaskEnvelope) map[string]any {
	if nested, ok := task.Inputs["inputs"].(map[string]any); ok {
		return nested
	}
	return task.Inputs
}

func (e *NativeExecutor) preflight(inputs map[string]any) (map[string]any, error) {
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	root, ok := e.rootHandles[handle]
	if !ok {
		return nil, errors.New("root handle is not configured")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("preconfigured migration root is unavailable")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil {
		return nil, err
	}
	empty := directoryEmpty(root)
	if requireEmpty, ok := inputs["require_empty"].(bool); ok && requireEmpty && !empty {
		return nil, errors.New("preconfigured migration root is not empty")
	}
	return map[string]any{"root_handle": handle, "free_bytes": int64(stat.Bavail) * int64(stat.Bsize), "architecture": runtime.GOARCH, "empty": empty}, nil
}

func directoryEmpty(path string) bool {
	directory, err := os.Open(path)
	if err != nil {
		return false
	}
	defer directory.Close()
	_, err = directory.Readdirnames(1)
	return errors.Is(err, io.EOF)
}

func (e *NativeExecutor) manifest(ctx context.Context, inputs map[string]any, progress func(string, int64, *int64) error) (map[string]any, error) {
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	relative := "."
	if value, ok := inputs["relative_handle"].(string); ok && value != "" {
		relative = value
	}
	root, err := e.resolver.Resolve(handle, relative, false)
	if err != nil {
		return nil, err
	}
	summary, err := buildFileManifest(ctx, root, func(completed int64) error {
		return progress("file_manifest", completed, nil)
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"root_handle": handle, "entry_count": len(summary.Manifest.Entries), "file_count": summary.FileCount,
		"directory_count": summary.DirectoryCount, "total_bytes": summary.TotalBytes, "manifest_digest": summary.Digest,
	}, nil
}

func deniedAddress(address net.IP, explicitlyAllowed map[string]struct{}) bool {
	if _, ok := explicitlyAllowed[address.String()]; ok {
		return false
	}
	if address.Equal(net.ParseIP("100.100.100.200")) || address.Equal(net.ParseIP("192.0.0.192")) {
		return true
	}
	return address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() || address.IsPrivate()
}

func validationURLPort(parsed *url.URL) (string, error) {
	if parsed == nil {
		return "", errors.New("validation URL is invalid")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", errors.New("validation URL port is invalid")
		}
		return strconv.Itoa(value), nil
	}
	switch parsed.Scheme {
	case "http":
		return "80", nil
	case "https":
		return "443", nil
	default:
		return "", errors.New("validation URL scheme is invalid")
	}
}

func validateHTTP(ctx context.Context, inputs map[string]any) (map[string]any, error) {
	rawURL, err := stringInput(inputs, "url")
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, errors.New("validation URL is invalid")
	}
	allowedPort, err := validationURLPort(parsed)
	if err != nil {
		return nil, err
	}
	allowedScheme := parsed.Scheme
	allowedHosts, err := stringListInput(inputs, "allowed_hosts", 16)
	if err != nil {
		return nil, err
	}
	allowedHostSet := map[string]struct{}{}
	for _, host := range allowedHosts {
		normalized := strings.ToLower(host)
		if normalized != strings.TrimSpace(normalized) || strings.ContainsAny(normalized, "/?#@%") {
			return nil, errors.New("validation host scope is invalid")
		}
		allowedHostSet[normalized] = struct{}{}
	}
	if _, ok := allowedHostSet[strings.ToLower(parsed.Hostname())]; !ok {
		return nil, errors.New("validation host is outside the task scope")
	}
	explicitIPs := map[string]struct{}{}
	if _, provided := inputs["allowed_ips"]; provided {
		allowedIPs, listErr := stringListInput(inputs, "allowed_ips", 16)
		if listErr != nil {
			return nil, errors.New("validation IP scope is invalid")
		}
		for _, value := range allowedIPs {
			parsedIP := net.ParseIP(value)
			if parsedIP == nil {
				return nil, errors.New("validation IP scope is invalid")
			}
			explicitIPs[parsedIP.String()] = struct{}{}
		}
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(dialContext context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, ok := allowedHostSet[strings.ToLower(host)]; !ok {
			return nil, errors.New("redirect or dial host is outside the task scope")
		}
		if port != allowedPort {
			return nil, errors.New("redirect or dial port is outside the task scope")
		}
		resolved, err := net.DefaultResolver.LookupIP(dialContext, "ip", host)
		if err != nil || len(resolved) == 0 {
			return nil, errors.New("validation host resolution failed")
		}
		for _, candidate := range resolved {
			if deniedAddress(candidate, explicitIPs) {
				return nil, errors.New("validation resolved to a denied address")
			}
		}
		return dialer.DialContext(dialContext, network, net.JoinHostPort(resolved[0].String(), port))
	}}
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	redirects := 0
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		redirects++
		if redirects > 3 || request.URL.User != nil {
			return errors.New("validation redirect limit exceeded")
		}
		redirectPort, portErr := validationURLPort(request.URL)
		if _, ok := allowedHostSet[strings.ToLower(request.URL.Hostname())]; !ok || portErr != nil || request.URL.Scheme != allowedScheme || redirectPort != allowedPort {
			return errors.New("validation redirect left the task scope")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "askio-migration-validator/1.0")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return nil, fmt.Errorf("validation returned status %d", response.StatusCode)
	}
	return map[string]any{"status_code": response.StatusCode, "latency_ms": time.Since(started).Milliseconds(), "redirects": redirects}, nil
}

func (e *NativeExecutor) brokerExecute(ctx context.Context, task TaskEnvelope, inputs map[string]any) PrimitiveResult {
	response, err := e.broker.Execute(ctx, BrokerRequest{SchemaVersion: brokerSchemaVersion, RequestID: task.Nonce, Task: task})
	if err != nil {
		return fail("MIGRATION_BROKER_UNAVAILABLE", "The typed privilege broker is unavailable.", true)
	}
	if !response.OK {
		if response.Error != nil {
			return PrimitiveResult{State: "failed", Outputs: map[string]any{}, EvidenceDigests: []string{}, Error: response.Error}
		}
		return fail("MIGRATION_BROKER_REJECTED", "The typed privilege broker rejected the operation.", false)
	}
	return PrimitiveResult{State: "succeeded", Outputs: response.Outputs, EvidenceDigests: []string{}}
}

func (e *NativeExecutor) Execute(ctx context.Context, task TaskEnvelope, progress func(string, int64, *int64) error) PrimitiveResult {
	inputs := taskInputs(task)
	if err := progress("validating_scope", 0, nil); err != nil {
		return PrimitiveResult{State: "paused_at_checkpoint", Outputs: map[string]any{}, EvidenceDigests: []string{}, Checkpoint: map[string]any{"phase": "validating_scope"}}
	}
	var outputs map[string]any
	var err error
	switch task.Primitive.ID {
	case "migration.discovery.collect.v1":
		var observation Observation
		observation, err = CollectObservation(ctx, task, e.rootHandles)
		outputs = map[string]any{"observation": observation}
	case "migration.host.preflight.v1":
		outputs, err = e.preflight(inputs)
	case "migration.source.estimate.v1":
		outputs, err = e.sourceEstimate(ctx, task, inputs, progress)
	case "migration.source.verify-quiescence.v1":
		outputs, err = e.sourceQuiescence(ctx, task, inputs, progress)
	case "migration.files.manifest.v1":
		outputs, err = e.manifest(ctx, inputs, progress)
	case "migration.http.validate.v1":
		outputs, err = validateHTTP(ctx, inputs)
	case "migration.evidence.capture.v1":
		material := map[string]any{"migration_id": task.MigrationID, "attempt_id": task.AttemptID, "primitive": task.Primitive, "captured_at": time.Now().UTC().Format(time.RFC3339Nano)}
		digest, digestErr := Digest(material)
		if digestErr != nil {
			err = digestErr
		} else {
			outputs = map[string]any{"evidence_digest": digest, "metadata": material}
		}
	case "migration.compose.inspect.v1":
		version, ok := safeCommandVersion(ctx, []string{"/usr/bin/docker", "/usr/local/bin/docker"}, "compose", "version", "--short")
		if !ok {
			err = errors.New("Docker Compose is unavailable")
		} else {
			outputs = map[string]any{"version": version}
		}
	case "migration.compose.render.v1":
		outputs, err = e.composeRender(inputs)
	case "migration.compose.start-isolated.v1":
		outputs, err = e.composeStartWithRuntimeSecrets(ctx, task, inputs)
	case "migration.postgres.inspect.v1":
		outputs, err = e.postgresInspect(ctx, task, inputs)
	case "migration.postgres.dump.v1":
		outputs, err = e.postgresDump(ctx, task, inputs, progress)
	case "migration.postgres.reset-empty-target.v1":
		outputs, err = e.postgresReset(ctx, task, inputs)
	case "migration.postgres.restore.v1":
		outputs, err = e.postgresRestore(ctx, task, inputs, progress)
	case "migration.postgres.verify.v1":
		outputs, err = e.postgresVerify(ctx, task, inputs)
	case "migration.mysql.inspect.v1":
		outputs, err = e.mysqlInspect(ctx, task, inputs)
	case "migration.mysql.dump.v1":
		outputs, err = e.mysqlDump(ctx, task, inputs, progress)
	case "migration.mysql.reset-empty-target.v1":
		outputs, err = e.mysqlReset(ctx, task, inputs)
	case "migration.mysql.restore.v1":
		outputs, err = e.mysqlRestore(ctx, task, inputs, progress)
	case "migration.mysql.verify.v1":
		outputs, err = e.mysqlVerify(ctx, task, inputs)
	case "migration.mongodb.inspect.v1":
		outputs, err = e.mongodbInspect(ctx, task, inputs)
	case "migration.mongodb.dump.v1":
		outputs, err = e.mongodbDump(ctx, task, inputs, progress)
	case "migration.mongodb.reset-empty-target.v1":
		outputs, err = e.mongodbReset(ctx, task, inputs)
	case "migration.mongodb.restore.v1":
		outputs, err = e.mongodbRestore(ctx, task, inputs, progress)
	case "migration.mongodb.verify.v1":
		outputs, err = e.mongodbVerify(ctx, task, inputs)
	case "migration.files.sync.v1":
		outputs, err = e.filesSync(ctx, task, inputs, progress)
	default:
		return e.brokerExecute(ctx, task, inputs)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, errTaskPauseRequested) {
			return PrimitiveResult{State: "paused_at_checkpoint", Outputs: map[string]any{}, EvidenceDigests: []string{}, Checkpoint: map[string]any{"phase": "interrupted"}}
		}
		if errors.Is(err, errTaskCancelRequested) {
			return PrimitiveResult{State: "cancelled", Outputs: map[string]any{}, EvidenceDigests: []string{}, Checkpoint: map[string]any{"phase": "interrupted"}}
		}
		if errors.Is(err, errMigrationDiskCapacity) {
			return fail("MIGRATION_DISK_CAPACITY_INSUFFICIENT", "Migration storage does not have enough free capacity to preserve the safety reserve.", false)
		}
		// Primitive errors may contain local filesystem or socket details from
		// operating-system calls. Keep task/result records path-free; detailed
		// diagnostics remain local to the host runtime.
		if e.logger != nil {
			e.logger.Error("migration primitive failed safely",
				"migration_id", task.MigrationID,
				"attempt_id", task.AttemptID,
				"primitive", task.Primitive.ID,
				"err", err,
			)
		}
		return fail("MIGRATION_PRIMITIVE_FAILED_SAFE", "The migration primitive failed safely. Review the host-local diagnostics before retrying.", false)
	}
	if outputs == nil {
		outputs = map[string]any{}
	}
	return PrimitiveResult{State: "succeeded", Outputs: outputs, EvidenceDigests: []string{}}
}
