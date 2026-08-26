package migration

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	brokerSchemaVersion    = "operations.migration.broker.v1"
	DefaultBrokerStatePath = "/var/lib/askio-migration-broker/broker-state.json"
)

var (
	serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9@_.-]+\.service$`)
	fileNamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

type BrokerRequest struct {
	SchemaVersion string       `json:"schema_version"`
	RequestID     string       `json:"request_id"`
	Task          TaskEnvelope `json:"task"`
}

type BrokerResponse struct {
	OK      bool           `json:"ok"`
	Outputs map[string]any `json:"outputs,omitempty"`
	Error   *SafeError     `json:"error,omitempty"`
}

type composeStartFailure struct {
	message                string
	preserveRuntimeSecrets bool
}

func (failure *composeStartFailure) Error() string { return failure.message }

type BrokerConfig struct {
	SocketPath             string
	StatePath              string
	AgentUser              string
	AgentID                string
	BackendKeyID           string
	BackendPublicKeyBase64 string
	RootHandles            map[string]string
	AllowedServices        []string
}

type brokerPersistentState struct {
	SchemaVersion     string                      `json:"schema_version"`
	Fences            map[string]int64            `json:"fences"`
	WriterFences      map[string]writerFenceState `json:"writer_fences,omitempty"`
	SeenNonces        []string                    `json:"seen_nonces,omitempty"`
	SeenNonceExpiries map[string]string           `json:"seen_nonce_expiries,omitempty"`
}

type writerFenceState struct {
	MigrationID      string   `json:"migration_id"`
	RunID            string   `json:"run_id"`
	Services         []string `json:"services"`
	PreviouslyActive []string `json:"previously_active_services,omitempty"`
	Active           bool     `json:"active"`
	Phase            string   `json:"phase,omitempty"`
	FencingToken     int64    `json:"fencing_token"`
	ActivatedAt      string   `json:"activated_at"`
	LastVerifiedAt   string   `json:"last_verified_at"`
	ViolationCount   int64    `json:"violation_count"`
	LastViolation    string   `json:"last_violation_at,omitempty"`
}

const (
	writerFenceActivating = "activating"
	writerFenceActive     = "active"
	writerFenceReleasing  = "releasing"
	writerFenceReleased   = "released"
)

type serviceController interface {
	Operate(context.Context, string, string) error
	IsActive(context.Context, string) (bool, error)
}

type systemdServiceController struct {
	binary string
}

func (controller systemdServiceController) Operate(ctx context.Context, action, service string) error {
	_, err := runFixed(ctx, controller.binary, action, service)
	return err
}

func (controller systemdServiceController) IsActive(ctx context.Context, service string) (bool, error) {
	_, exitCode, err := runFixedCapture(ctx, controller.binary, "is-active", "--quiet", service)
	if err != nil {
		return false, err
	}
	switch exitCode {
	case 0:
		return true, nil
	case 3:
		return false, nil
	default:
		return false, errors.New("writer service state is not provable")
	}
}

type Broker struct {
	config          BrokerConfig
	resolver        *ScopeResolver
	allowedUID      uint32
	allowedGID      uint32
	allowedServices map[string]struct{}
	backendPublic   ed25519.PublicKey
	mu              sync.Mutex
	writerFenceMu   sync.Mutex
	serviceControl  serviceController
	state           brokerPersistentState
}

func parseUserIDs(account *user.User) (uint32, uint32, error) {
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse user ID: %w", err)
	}
	gid, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse primary group ID: %w", err)
	}
	return uint32(uid), uint32(gid), nil
}

func resolveUserIDs(name string) (uint32, uint32, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	return parseUserIDs(account)
}

func NewBroker(config BrokerConfig) (*Broker, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("migration broker must run as root")
	}
	if !filepath.IsAbs(config.SocketPath) || !filepath.IsAbs(config.StatePath) {
		return nil, errors.New("broker socket and state paths must be absolute")
	}
	resolver, err := NewScopeResolver(config.RootHandles)
	if err != nil {
		return nil, err
	}
	uid, gid, err := resolveUserIDs(config.AgentUser)
	if err != nil {
		return nil, fmt.Errorf("resolve migration agent user: %w", err)
	}
	if config.AgentID == "" || config.BackendKeyID == "" {
		return nil, errors.New("broker task audience configuration is required")
	}
	backendPublic, err := parseBackendSigningKey(config.BackendPublicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("parse broker backend signing key: %w", err)
	}
	allowed := map[string]struct{}{}
	for _, service := range config.AllowedServices {
		if !serviceNamePattern.MatchString(service) {
			return nil, fmt.Errorf("invalid allowed service handle %q", service)
		}
		allowed[service] = struct{}{}
	}
	broker := &Broker{
		config: config, resolver: resolver, allowedUID: uid, allowedGID: gid, allowedServices: allowed, backendPublic: backendPublic,
		state: brokerPersistentState{
			SchemaVersion: "operations.migration.broker-state.v1", Fences: map[string]int64{},
			WriterFences: map[string]writerFenceState{}, SeenNonces: []string{}, SeenNonceExpiries: map[string]string{},
		},
	}
	if err := broker.loadFences(); err != nil {
		return nil, err
	}
	return broker, nil
}

func (b *Broker) loadFences() error {
	data, err := os.ReadFile(b.config.StatePath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &b.state); err != nil {
		return fmt.Errorf("decode broker fences: %w", err)
	}
	if b.state.SchemaVersion != "operations.migration.broker-state.v1" || b.state.Fences == nil {
		return errors.New("unsupported migration broker state schema")
	}
	if b.state.WriterFences == nil {
		b.state.WriterFences = map[string]writerFenceState{}
	}
	if b.state.SeenNonceExpiries == nil {
		b.state.SeenNonceExpiries = map[string]string{}
	}
	for migrationID, fence := range b.state.WriterFences {
		if fence.Phase == "" {
			if fence.Active {
				fence.Phase = writerFenceActive
				// Broker state written before phase-aware fencing restarted every
				// scoped service. Preserve that recovery contract on upgrade.
				if fence.PreviouslyActive == nil {
					fence.PreviouslyActive = append([]string{}, fence.Services...)
				}
			} else {
				fence.Phase = writerFenceReleased
			}
			b.state.WriterFences[migrationID] = fence
		}
	}
	return nil
}

func (b *Broker) socketOwnership() (int, int) {
	return 0, int(b.allowedGID)
}

func (b *Broker) persistFences() error {
	if err := os.MkdirAll(filepath.Dir(b.config.StatePath), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(b.state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(b.config.StatePath), ".fences-*")
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
	if err := os.Rename(name, b.config.StatePath); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(b.config.StatePath))
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func (b *Broker) acceptFence(request BrokerRequest) error {
	task := request.Task
	key := task.MigrationID + ":" + brokerFenceDomain(task.Primitive.ID)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UTC()
	if b.state.SeenNonceExpiries == nil {
		b.state.SeenNonceExpiries = map[string]string{}
	}
	for _, nonce := range b.state.SeenNonces {
		if nonce == task.Nonce {
			return errors.New("broker task envelope was already consumed")
		}
	}
	for nonce, expiry := range b.state.SeenNonceExpiries {
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, expiry)
		if parseErr == nil && !expiresAt.After(now) {
			delete(b.state.SeenNonceExpiries, nonce)
		}
	}
	if _, consumed := b.state.SeenNonceExpiries[task.Nonce]; consumed {
		return errors.New("broker task envelope was already consumed")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, task.ExpiresAt)
	if err != nil || !expiresAt.After(now) {
		return errors.New("broker task envelope expiry is invalid")
	}
	if prior := b.state.Fences[key]; prior > task.FencingToken {
		return errors.New("stale broker fencing token")
	}
	if b.state.Fences[key] < task.FencingToken {
		b.state.Fences[key] = task.FencingToken
	}
	b.state.SeenNonceExpiries[task.Nonce] = expiresAt.Format(time.RFC3339Nano)
	if err := b.persistFences(); err != nil {
		return err
	}
	return nil
}

func brokerTaskRunID(task TaskEnvelope) (string, error) {
	if task.RunID == nil || *task.RunID == "" || task.RunStepID == nil || *task.RunStepID == "" {
		return "", errors.New("privileged task run scope is required")
	}
	return *task.RunID, nil
}

func brokerFenceDomain(primitiveID string) string {
	switch primitiveID {
	case "migration.host.fence-writers.v1", "migration.host.unfence-writers.v1", "migration.source.verify-quiescence.v1":
		return "host-writers"
	case "migration.compose.preflight-target.v1", "migration.compose.start-isolated.v1", "migration.compose.stop.v1":
		return "compose-runtime"
	case "migration.cleanup.staging.v1":
		return "staging-cleanup"
	default:
		return primitiveID
	}
}

func stringInput(inputs map[string]any, key string) (string, error) {
	value, ok := inputs[key].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func stringListInput(inputs map[string]any, key string, maximum int) ([]string, error) {
	raw, ok := inputs[key].([]any)
	if !ok || len(raw) == 0 || len(raw) > maximum {
		return nil, fmt.Errorf("%s must contain 1-%d items", key, maximum)
	}
	values := make([]string, 0, len(raw))
	for _, item := range raw {
		value, ok := item.(string)
		if !ok || value == "" {
			return nil, fmt.Errorf("%s contains an invalid item", key)
		}
		values = append(values, value)
	}
	return values, nil
}

func fixedExecutable(candidates ...string) (string, error) {
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", errors.New("required fixed executable is unavailable")
}

func runFixed(ctx context.Context, binary string, args ...string) (map[string]any, error) {
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	output, err := command.CombinedOutput()
	if len(output) > 32*1024 {
		output = output[:32*1024]
	}
	result := map[string]any{"output": string(output), "exit_code": 0}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			result["exit_code"] = exitError.ExitCode()
		}
		return result, errors.New("typed broker operation failed")
	}
	return result, nil
}

func runFixedCapture(ctx context.Context, binary string, args ...string) (string, int, error) {
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "HOME=/nonexistent"}
	var output cappedBuffer
	output.limit = 32 * 1024
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if err == nil {
		return output.buffer.String(), 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return output.buffer.String(), exitError.ExitCode(), nil
	}
	if ctx.Err() != nil {
		return "", -1, ctx.Err()
	}
	return "", -1, errors.New("typed broker executable failed")
}

func (b *Broker) serviceController() (serviceController, error) {
	if b.serviceControl != nil {
		return b.serviceControl, nil
	}
	systemctl, err := fixedExecutable("/usr/bin/systemctl", "/bin/systemctl")
	if err != nil {
		return nil, err
	}
	return systemdServiceController{binary: systemctl}, nil
}

func (b *Broker) serviceOperation(ctx context.Context, request BrokerRequest, action string) (map[string]any, error) {
	services, err := stringListInput(taskInputs(request.Task), "service_handles", 32)
	if err != nil {
		return nil, err
	}
	for _, service := range services {
		if !serviceNamePattern.MatchString(service) {
			return nil, errors.New("service handle format is invalid")
		}
		if _, allowed := b.allowedServices[service]; !allowed {
			return nil, errors.New("service handle is not preconfigured")
		}
	}
	sort.Strings(services)
	controller, err := b.serviceController()
	if err != nil {
		return nil, err
	}
	b.writerFenceMu.Lock()
	defer b.writerFenceMu.Unlock()
	switch action {
	case "stop":
		return b.activateWriterFence(ctx, controller, request, services)
	case "start":
		return b.releaseWriterFence(ctx, controller, request, services)
	default:
		return nil, errors.New("unsupported service operation")
	}
}

func (b *Broker) activateWriterFence(ctx context.Context, controller serviceController, request BrokerRequest, services []string) (map[string]any, error) {
	runID, err := brokerTaskRunID(request.Task)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	prior, found := b.state.WriterFences[request.Task.MigrationID]
	b.mu.Unlock()
	if found && prior.Active && (prior.RunID != runID || !equalStrings(prior.Services, services)) {
		return nil, errors.New("writer fence ownership or service scope is unproven")
	}

	previouslyActive := append([]string{}, prior.PreviouslyActive...)
	if !found || !prior.Active {
		previouslyActive = previouslyActiveServices(ctx, controller, services)
		if previouslyActive == nil {
			return nil, errors.New("writer service state is not provable")
		}
	}
	intent := prior
	intent.MigrationID = request.Task.MigrationID
	intent.RunID = runID
	intent.Services = append([]string{}, services...)
	intent.PreviouslyActive = previouslyActive
	intent.Active = true
	intent.Phase = writerFenceActivating
	intent.FencingToken = request.Task.FencingToken

	// Persist the fail-closed intent before stopping the first service. The
	// watchdog can therefore finish a partially applied fence after a crash.
	b.mu.Lock()
	b.state.WriterFences[request.Task.MigrationID] = intent
	if err := b.persistFences(); err != nil {
		if found {
			b.state.WriterFences[request.Task.MigrationID] = prior
		} else {
			delete(b.state.WriterFences, request.Task.MigrationID)
		}
		b.mu.Unlock()
		return nil, err
	}
	b.mu.Unlock()

	operationFailed := false
	for _, service := range services {
		if err := controller.Operate(ctx, "stop", service); err != nil {
			operationFailed = true
		}
	}
	if operationFailed {
		return nil, errors.New("writer fence activation is incomplete")
	}
	if err := verifyServicesInactive(ctx, controller, services); err != nil {
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	intent.Phase = writerFenceActive
	if intent.ActivatedAt == "" {
		intent.ActivatedAt = now
	}
	intent.LastVerifiedAt = now
	b.mu.Lock()
	b.state.WriterFences[request.Task.MigrationID] = intent
	if err := b.persistFences(); err != nil {
		b.state.WriterFences[request.Task.MigrationID] = writerFenceState{
			MigrationID: intent.MigrationID, Services: intent.Services, PreviouslyActive: intent.PreviouslyActive,
			Active: true, Phase: writerFenceActivating, FencingToken: intent.FencingToken,
			ActivatedAt: intent.ActivatedAt, LastVerifiedAt: intent.LastVerifiedAt,
			ViolationCount: intent.ViolationCount, LastViolation: intent.LastViolation,
		}
		b.mu.Unlock()
		return nil, err
	}
	b.mu.Unlock()
	return map[string]any{
		"services": services, "action": "stop", "writer_fence_active": true,
		"fencing_token": intent.FencingToken, "verified_at": now,
		"violation_count": intent.ViolationCount, "previously_active_services": previouslyActive,
	}, nil
}

func (b *Broker) releaseWriterFence(ctx context.Context, controller serviceController, request BrokerRequest, services []string) (map[string]any, error) {
	runID, err := brokerTaskRunID(request.Task)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	fence, found := b.state.WriterFences[request.Task.MigrationID]
	b.mu.Unlock()
	verifiedAt := time.Now().UTC().Format(time.RFC3339Nano)
	if !found {
		// A reviewed recovery may have restored the source outside the agent after
		// preserving the broker state for incident analysis. Missing ownership is
		// safe to reconcile only when every scoped writer is already active: this
		// path records the observed release and never starts an unknown service.
		if err := verifyExpectedServiceStates(ctx, controller, services, services); err != nil {
			return nil, errors.New("writer fence ownership or recovered service state is unproven")
		}
		released := writerFenceState{
			MigrationID: request.Task.MigrationID, RunID: runID, Services: append([]string{}, services...),
			PreviouslyActive: append([]string{}, services...), Active: false, Phase: writerFenceReleased,
			FencingToken: request.Task.FencingToken, LastVerifiedAt: verifiedAt,
		}
		b.mu.Lock()
		b.state.WriterFences[request.Task.MigrationID] = released
		if err := b.persistFences(); err != nil {
			delete(b.state.WriterFences, request.Task.MigrationID)
			b.mu.Unlock()
			return nil, err
		}
		b.mu.Unlock()
		return map[string]any{
			"services": services, "action": "start", "writer_fence_active": false,
			"violation_count": int64(0), "verified_at": verifiedAt,
			"restarted_services": []string{}, "observed_active_services": append([]string{}, services...),
			"already_released": true, "recovered_without_fence_record": true,
		}, nil
	}
	if fence.RunID != runID || !equalStrings(fence.Services, services) || fence.Phase == writerFenceReleasing {
		return nil, errors.New("writer fence ownership or service scope is unproven")
	}
	if !fence.Active {
		if fence.Phase != writerFenceReleased || verifyExpectedServiceStates(ctx, controller, services, fence.PreviouslyActive) != nil {
			return nil, errors.New("released writer fence service state is unproven")
		}
		prior := fence
		fence.FencingToken = request.Task.FencingToken
		fence.LastVerifiedAt = verifiedAt
		b.mu.Lock()
		b.state.WriterFences[request.Task.MigrationID] = fence
		if err := b.persistFences(); err != nil {
			b.state.WriterFences[request.Task.MigrationID] = prior
			b.mu.Unlock()
			return nil, err
		}
		b.mu.Unlock()
		return map[string]any{
			"services": services, "action": "start", "writer_fence_active": false,
			"violation_count": fence.ViolationCount, "verified_at": fence.LastVerifiedAt,
			"restarted_services": []string{}, "expected_active_services": append([]string{}, fence.PreviouslyActive...),
			"already_released": true,
		}, nil
	}
	if err := verifyServicesInactive(ctx, controller, services); err != nil {
		return nil, errors.New("writer fence cannot be released while a scoped service is active")
	}

	releasing := fence
	releasing.Phase = writerFenceReleasing
	releasing.FencingToken = request.Task.FencingToken
	releasing.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b.mu.Lock()
	b.state.WriterFences[request.Task.MigrationID] = releasing
	if err := b.persistFences(); err != nil {
		b.state.WriterFences[request.Task.MigrationID] = fence
		b.mu.Unlock()
		return nil, err
	}
	b.mu.Unlock()

	releaseFailed := false
	for _, service := range releasing.PreviouslyActive {
		if err := controller.Operate(ctx, "start", service); err != nil {
			releaseFailed = true
			break
		}
	}
	if !releaseFailed {
		releaseFailed = verifyExpectedServiceStates(ctx, controller, services, releasing.PreviouslyActive) != nil
	}
	if releaseFailed {
		b.restoreActiveWriterFence(ctx, controller, releasing)
		return nil, errors.New("writer fence release failed and was rolled back")
	}

	released := releasing
	released.Active = false
	released.Phase = writerFenceReleased
	released.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b.mu.Lock()
	b.state.WriterFences[request.Task.MigrationID] = released
	if err := b.persistFences(); err != nil {
		b.state.WriterFences[request.Task.MigrationID] = releasing
		b.mu.Unlock()
		b.restoreActiveWriterFence(ctx, controller, releasing)
		return nil, err
	}
	b.mu.Unlock()
	return map[string]any{
		"services": services, "action": "start", "writer_fence_active": false,
		"violation_count": released.ViolationCount, "verified_at": released.LastVerifiedAt,
		"restarted_services": append([]string{}, released.PreviouslyActive...),
	}, nil
}

func (b *Broker) restoreActiveWriterFence(ctx context.Context, controller serviceController, fence writerFenceState) {
	for _, service := range fence.Services {
		_ = controller.Operate(ctx, "stop", service)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	fence.Active = true
	fence.Phase = writerFenceActive
	if verifyServicesInactive(ctx, controller, fence.Services) == nil {
		fence.LastVerifiedAt = now
	}
	b.mu.Lock()
	b.state.WriterFences[fence.MigrationID] = fence
	_ = b.persistFences()
	b.mu.Unlock()
}

func previouslyActiveServices(ctx context.Context, controller serviceController, services []string) []string {
	active := make([]string, 0, len(services))
	for _, service := range services {
		isActive, err := controller.IsActive(ctx, service)
		if err != nil {
			return nil
		}
		if isActive {
			active = append(active, service)
		}
	}
	return active
}

func verifyExpectedServiceStates(ctx context.Context, controller serviceController, services, expectedActive []string) error {
	expected := make(map[string]struct{}, len(expectedActive))
	for _, service := range expectedActive {
		expected[service] = struct{}{}
	}
	for _, service := range services {
		active, err := controller.IsActive(ctx, service)
		if err != nil {
			return err
		}
		_, shouldBeActive := expected[service]
		if active != shouldBeActive {
			return errors.New("writer service recovery state is not provable")
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func verifyServicesInactive(ctx context.Context, controller serviceController, services []string) error {
	for _, service := range services {
		active, err := controller.IsActive(ctx, service)
		if err != nil {
			return err
		}
		if active {
			return errors.New("writer service is not provably inactive")
		}
	}
	return nil
}

func (b *Broker) verifyWriterFence(ctx context.Context, request BrokerRequest) (map[string]any, error) {
	runID, err := brokerTaskRunID(request.Task)
	if err != nil {
		return nil, err
	}
	services, err := stringListInput(taskInputs(request.Task), "service_handles", 32)
	if err != nil {
		return nil, err
	}
	for _, service := range services {
		if !serviceNamePattern.MatchString(service) {
			return nil, errors.New("service handle format is invalid")
		}
		if _, allowed := b.allowedServices[service]; !allowed {
			return nil, errors.New("service handle is not preconfigured")
		}
	}
	sort.Strings(services)
	controller, err := b.serviceController()
	if err != nil {
		return nil, err
	}
	interval, err := boundedIntegerInput(taskInputs(request.Task), "interval_seconds", 5, 60)
	if err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	deadline := started.Add(time.Duration(interval) * time.Second)
	b.writerFenceMu.Lock()
	defer b.writerFenceMu.Unlock()
	for {
		if err := verifyServicesInactive(ctx, controller, services); err != nil {
			return nil, err
		}
		if !time.Now().Before(deadline) {
			break
		}
		wait := time.Until(deadline)
		if wait > time.Second {
			wait = time.Second
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	fence, found := b.state.WriterFences[request.Task.MigrationID]
	if !found || fence.RunID != runID || !fence.Active || fence.Phase == writerFenceReleasing || !equalStrings(fence.Services, services) {
		return nil, errors.New("active writer fence scope is unproven")
	}
	if fence.Phase == writerFenceActivating {
		fence.Phase = writerFenceActive
		if fence.ActivatedAt == "" {
			fence.ActivatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	fence.LastVerifiedAt = time.Now().UTC().Format(time.RFC3339Nano)
	b.state.WriterFences[request.Task.MigrationID] = fence
	if err := b.persistFences(); err != nil {
		return nil, err
	}
	return map[string]any{
		"services": services, "writer_fence_active": true, "fence_fencing_token": fence.FencingToken,
		"violation_count": fence.ViolationCount, "activated_at": fence.ActivatedAt,
		"verified_at": fence.LastVerifiedAt, "verification_started_at": started.Format(time.RFC3339Nano),
		"interval_seconds": interval,
	}, nil
}

func boundedIntegerInput(inputs map[string]any, key string, minimum, maximum int64) (int64, error) {
	var value int64
	switch raw := inputs[key].(type) {
	case float64:
		value = int64(raw)
		if float64(value) != raw {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
	case json.Number:
		parsed, err := raw.Int64()
		if err != nil {
			return 0, fmt.Errorf("%s must be an integer", key)
		}
		value = parsed
	case int:
		value = int64(raw)
	case int64:
		value = raw
	default:
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("%s must be between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

// monitorWriterFences makes a stopped-service fence durable rather than a
// one-shot systemctl call. Any unexpected restart is immediately stopped and
// permanently recorded; a later quiescence proof fails when violations exist.
func (b *Broker) monitorWriterFences(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_ = b.reconcileWriterFences(ctx)
	}
}

func (b *Broker) reconcileWriterFences(ctx context.Context) error {
	controller, err := b.serviceController()
	if err != nil {
		return err
	}
	b.writerFenceMu.Lock()
	defer b.writerFenceMu.Unlock()
	b.mu.Lock()
	active := make([]writerFenceState, 0, len(b.state.WriterFences))
	for _, fence := range b.state.WriterFences {
		if fence.Active {
			active = append(active, fence)
		}
	}
	b.mu.Unlock()
	for _, fence := range active {
		violated := false
		recoveredRelease := fence.Phase == writerFenceReleasing
		countViolations := fence.Phase == writerFenceActive
		for _, service := range fence.Services {
			isActive, commandErr := controller.IsActive(ctx, service)
			if commandErr != nil || isActive || recoveredRelease {
				if countViolations {
					violated = true
				}
				_ = controller.Operate(ctx, "stop", service)
			}
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		b.mu.Lock()
		current, found := b.state.WriterFences[fence.MigrationID]
		if found && current.Active && equalStrings(current.Services, fence.Services) {
			if verifyServicesInactive(ctx, controller, current.Services) == nil {
				current.LastVerifiedAt = now
				if current.Phase == writerFenceActivating || current.Phase == writerFenceReleasing {
					current.Phase = writerFenceActive
					if current.ActivatedAt == "" {
						current.ActivatedAt = now
					}
				}
			}
			if violated {
				current.ViolationCount++
				current.LastViolation = now
			}
			b.state.WriterFences[fence.MigrationID] = current
			_ = b.persistFences()
		}
		b.mu.Unlock()
	}
	return nil
}

func (b *Broker) cleanup(request BrokerRequest) (map[string]any, error) {
	inputs := taskInputs(request.Task)
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	relative, err := stringInput(inputs, "staging_handle")
	if err != nil || relative == "." || strings.Contains(relative, "/") || !fileNamePattern.MatchString(relative) {
		return nil, errors.New("staging handle is invalid")
	}
	target, err := b.resolver.Resolve(handle, relative, true)
	if err != nil {
		return nil, err
	}
	if err := os.RemoveAll(target); err != nil {
		return nil, err
	}
	return map[string]any{"staging_handle": relative, "removed": true}, nil
}

func validateComposeSecretScope(project string, policy composePolicyResult, requireFiles bool) error {
	directory := filepath.Join(composeRuntimeSecretsRoot, project)
	for name, path := range policy.SecretFiles {
		if path != filepath.Join(directory, name) {
			return errors.New("Compose runtime secret path does not match the project scope")
		}
		if !requireFiles {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o444 || info.Size() < 1 || info.Size() > 16*1024 {
			return errors.New("Compose runtime secret file is missing or unsafe")
		}
	}
	return nil
}

func (b *Broker) readComposePolicy(request BrokerRequest, requireSecretFiles bool) (string, string, string, composePolicyResult, error) {
	inputs := taskInputs(request.Task)
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	fileName, err := composeFileInput(inputs)
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	project, err := composeProjectInput(inputs)
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	expectedDigest, err := stringInput(inputs, "compose_digest")
	if err != nil || !strings.HasPrefix(expectedDigest, "sha256:") {
		return "", "", "", composePolicyResult{}, errors.New("Compose policy digest is invalid")
	}
	root, err := b.resolver.Resolve(handle, ".", false)
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	filePath, err := b.resolver.Resolve(handle, fileName, false)
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	info, err := os.Lstat(filePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 256*1024 {
		return "", "", "", composePolicyResult{}, errors.New("Compose policy file is missing or invalid")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	policy, err := parseComposePolicy(data)
	if err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	if policy.Digest != expectedDigest {
		return "", "", "", composePolicyResult{}, errors.New("Compose policy digest changed")
	}
	if err := validateComposeSecretScope(project, policy, requireSecretFiles); err != nil {
		return "", "", "", composePolicyResult{}, err
	}
	for _, relative := range policy.BindMountRoots {
		if _, err := b.resolver.Resolve(handle, relative, false); err != nil {
			return "", "", "", composePolicyResult{}, errors.New("Compose bind mount is outside the configured migration root")
		}
	}
	return root, filePath, project, policy, nil
}

func ensureDockerObjectAbsent(ctx context.Context, docker, objectType, name string) error {
	_, exitCode, err := runFixedCapture(ctx, docker, objectType, "inspect", name)
	if err != nil {
		return err
	}
	if exitCode == 0 {
		return errors.New("Compose target object collision")
	}
	if exitCode != 1 {
		return errors.New("Compose target collision probe failed")
	}
	return nil
}

func ensureComposeTargetAbsent(ctx context.Context, docker, project string, policy composePolicyResult) error {
	containers, exitCode, err := runFixedCapture(ctx, docker, "ps", "-aq", "--filter", "label=com.docker.compose.project="+project)
	if err != nil || exitCode != 0 {
		return errors.New("Compose container collision probe failed")
	}
	if strings.TrimSpace(containers) != "" {
		return errors.New("Compose project container collision")
	}
	for _, volume := range policy.NamedVolumes {
		if err := ensureDockerObjectAbsent(ctx, docker, "volume", project+"_"+volume); err != nil {
			return err
		}
	}
	for _, network := range policy.NetworkNames {
		if err := ensureDockerObjectAbsent(ctx, docker, "network", project+"_"+network); err != nil {
			return err
		}
	}
	return ensurePortsAvailable(policy.PublishedPorts)
}

func (b *Broker) composePreflight(ctx context.Context, request BrokerRequest) (map[string]any, error) {
	inputs := taskInputs(request.Task)
	handle, err := stringInput(inputs, "root_handle")
	if err != nil {
		return nil, err
	}
	root, err := b.resolver.Resolve(handle, ".", false)
	if err != nil {
		return nil, err
	}
	fileName, err := composeFileInput(inputs)
	if err != nil {
		return nil, err
	}
	filePath, err := b.resolver.Resolve(handle, fileName, true)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filePath); err == nil {
		return nil, errors.New("Compose file collision")
	} else if !os.IsNotExist(err) {
		return nil, errors.New("Compose file collision probe failed")
	}
	project, err := composeProjectInput(inputs)
	if err != nil {
		return nil, err
	}
	raw, ok := inputs["rendered_compose"]
	if !ok || raw == nil {
		return nil, errors.New("rendered Compose document is required")
	}
	jsonCompatible, err := CanonicalJSON(raw)
	if err != nil || len(jsonCompatible) > 256*1024 {
		return nil, errors.New("rendered Compose document is invalid")
	}
	var normalized any
	if err := json.Unmarshal(jsonCompatible, &normalized); err != nil {
		return nil, errors.New("rendered Compose document is invalid")
	}
	yamlData, err := yaml.Marshal(normalized)
	if err != nil {
		return nil, errors.New("rendered Compose document is invalid")
	}
	policy, err := parseComposePolicy(yamlData)
	if err != nil {
		return nil, err
	}
	if err := validateComposeSecretScope(project, policy, false); err != nil {
		return nil, err
	}
	docker, err := fixedExecutable("/usr/bin/docker", "/usr/local/bin/docker")
	if err != nil {
		return nil, err
	}
	if _, exitCode, err := runFixedCapture(ctx, docker, "compose", "version", "--short"); err != nil || exitCode != 0 {
		return nil, errors.New("Docker Compose target preflight failed")
	}
	if err := ensureComposeTargetAbsent(ctx, docker, project, policy); err != nil {
		return nil, err
	}
	return map[string]any{
		"root_handle": handle, "root_identity_digest": MustDigest(map[string]any{"root": root}),
		"project_name": project, "compose_digest": policy.Digest, "collision_free": true,
		"published_port_count": len(policy.PublishedPorts), "named_volume_count": len(policy.NamedVolumes), "network_count": len(policy.NetworkNames),
	}, nil
}

func (b *Broker) composeStart(ctx context.Context, request BrokerRequest) (map[string]any, error) {
	root, filePath, project, policy, err := b.readComposePolicy(request, true)
	if err != nil {
		return nil, err
	}
	docker, err := fixedExecutable("/usr/bin/docker", "/usr/local/bin/docker")
	if err != nil {
		return nil, err
	}
	if err := ensureComposeTargetAbsent(ctx, docker, project, policy); err != nil {
		return nil, err
	}
	baseArgs := []string{"compose", "--project-directory", root, "--file", filePath, "--project-name", project}
	if _, err := runFixed(ctx, docker, append(baseArgs, "config", "--quiet")...); err != nil {
		return nil, errors.New("Compose engine rejected the policy document")
	}
	if _, err := runFixed(ctx, docker, append(baseArgs, "up", "--detach", "--wait", "--wait-timeout", "120", "--remove-orphans")...); err != nil {
		downArgs := append(baseArgs, "down", "--remove-orphans", "--timeout", "30", "--volumes")
		if _, cleanupErr := runFixed(ctx, docker, downArgs...); cleanupErr != nil {
			return nil, &composeStartFailure{
				message:                "isolated Compose start failed and project cleanup could not be proven",
				preserveRuntimeSecrets: true,
			}
		}
		if cleanupErr := ensureComposeTargetAbsent(ctx, docker, project, policy); cleanupErr != nil {
			return nil, &composeStartFailure{
				message:                "isolated Compose start failed and residual project state remains",
				preserveRuntimeSecrets: true,
			}
		}
		return nil, errors.New("isolated Compose start failed")
	}
	return map[string]any{
		"project_name": project, "compose_digest": policy.Digest, "service_count": len(policy.Document.Services),
		"started": true, "isolated": true,
	}, nil
}

func (b *Broker) composeStop(ctx context.Context, request BrokerRequest) (map[string]any, error) {
	root, filePath, project, policy, err := b.readComposePolicy(request, false)
	if err != nil {
		return nil, err
	}
	docker, err := fixedExecutable("/usr/bin/docker", "/usr/local/bin/docker")
	if err != nil {
		return nil, err
	}
	baseArgs := []string{"compose", "--project-directory", root, "--file", filePath, "--project-name", project}
	downArgs := append(baseArgs, "down", "--remove-orphans", "--timeout", "30")
	removeVolumes, _ := taskInputs(request.Task)["remove_volumes"].(bool)
	if removeVolumes {
		downArgs = append(downArgs, "--volumes")
	}
	if _, err := runFixed(ctx, docker, downArgs...); err != nil {
		return nil, errors.New("isolated Compose stop failed")
	}
	for _, path := range policy.SecretFiles {
		if err := wipeAndRemoveComposeSecret(path); err != nil {
			return nil, errors.New("Compose runtime secret cleanup failed")
		}
	}
	if err := os.Remove(filepath.Join(composeRuntimeSecretsRoot, project)); err != nil && !os.IsNotExist(err) {
		return nil, errors.New("Compose runtime secret directory cleanup failed")
	}
	return map[string]any{"project_name": project, "compose_digest": policy.Digest, "stopped": true, "volumes_preserved": !removeVolumes}, nil
}

func (b *Broker) execute(ctx context.Context, request BrokerRequest) BrokerResponse {
	task := request.Task
	if request.SchemaVersion != brokerSchemaVersion || request.RequestID == "" || request.RequestID != task.Nonce || task.Primitive.Version != "1.0.0" {
		return BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_REQUEST_INVALID", SafeMessage: "The typed broker request is invalid."}}
	}
	if _, err := verifySignedTaskEnvelope(task, b.config.BackendKeyID, b.config.AgentID, b.backendPublic); err != nil {
		return BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_TASK_UNAUTHORIZED", SafeMessage: "The backend-signed task envelope is invalid or expired."}}
	}
	if _, err := brokerTaskRunID(task); err != nil {
		return BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_TASK_UNAUTHORIZED", SafeMessage: "The backend-signed task envelope is missing its privileged run scope."}}
	}
	if err := b.acceptFence(request); err != nil {
		return BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_FENCED", SafeMessage: "The privileged operation was rejected by its fencing token."}}
	}
	var outputs map[string]any
	var err error
	switch task.Primitive.ID {
	case "migration.host.fence-writers.v1":
		outputs, err = b.serviceOperation(ctx, request, "stop")
	case "migration.host.unfence-writers.v1":
		outputs, err = b.serviceOperation(ctx, request, "start")
	case "migration.source.verify-quiescence.v1":
		outputs, err = b.verifyWriterFence(ctx, request)
	case "migration.cleanup.staging.v1":
		outputs, err = b.cleanup(request)
	case "migration.compose.preflight-target.v1":
		outputs, err = b.composePreflight(ctx, request)
	case "migration.compose.start-isolated.v1":
		outputs, err = b.composeStart(ctx, request)
	case "migration.compose.stop.v1":
		outputs, err = b.composeStop(ctx, request)
	default:
		err = errors.New("primitive is not implemented by the typed broker")
	}
	if err != nil {
		response := BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_OPERATION_REJECTED", SafeMessage: "The typed broker operation failed safely. Review the host-local diagnostics before retrying.", Retryable: false}}
		var startFailure *composeStartFailure
		if errors.As(err, &startFailure) && startFailure.preserveRuntimeSecrets {
			response.Error.Code = "MIGRATION_COMPOSE_START_PARTIAL"
			response.Error.SafeMessage = "The isolated Compose start was only partially applied. Preserve the runtime-secret staging area for reviewed recovery."
			response.Outputs = map[string]any{"preserve_runtime_secrets": true}
		}
		return response
	}
	return BrokerResponse{OK: true, Outputs: outputs}
}

func (b *Broker) handleConnection(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	uid, err := peerUID(connection)
	if err != nil || uid != b.allowedUID {
		_ = json.NewEncoder(connection).Encode(BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_PEER_DENIED", SafeMessage: "Broker peer identity is not authorized."}})
		return
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Minute))
	reader := io.LimitReader(connection, 2*1024*1024)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var request BrokerRequest
	if err := decoder.Decode(&request); err != nil {
		_ = json.NewEncoder(connection).Encode(BrokerResponse{OK: false, Error: &SafeError{Code: "MIGRATION_BROKER_REQUEST_INVALID", SafeMessage: "Broker request decoding failed."}})
		return
	}
	requestContext, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	_ = json.NewEncoder(connection).Encode(b.execute(requestContext, request))
}

func (b *Broker) Serve(ctx context.Context) error {
	socketDirectory := filepath.Dir(b.config.SocketPath)
	ownerID, groupID := b.socketOwnership()
	if err := os.MkdirAll(socketDirectory, 0o750); err != nil {
		return err
	}
	if err := os.Chown(socketDirectory, ownerID, groupID); err != nil {
		return err
	}
	if err := os.Chmod(socketDirectory, 0o750); err != nil {
		return err
	}
	if info, err := os.Lstat(b.config.SocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("broker socket path already exists and is not a socket")
		}
		if err := os.Remove(b.config.SocketPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: b.config.SocketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(b.config.SocketPath)
	if err := os.Chmod(b.config.SocketPath, 0o660); err != nil {
		return err
	}
	if err := os.Chown(b.config.SocketPath, ownerID, groupID); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	go b.monitorWriterFences(ctx)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go b.handleConnection(ctx, connection)
	}
}

type BrokerClient struct {
	socketPath string
}

func NewBrokerClient(socketPath string) *BrokerClient {
	return &BrokerClient{socketPath: socketPath}
}

func (c *BrokerClient) Execute(ctx context.Context, request BrokerRequest) (BrokerResponse, error) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return BrokerResponse{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	writer := bufio.NewWriter(connection)
	if err := json.NewEncoder(writer).Encode(request); err != nil {
		return BrokerResponse{}, err
	}
	if err := writer.Flush(); err != nil {
		return BrokerResponse{}, err
	}
	var response BrokerResponse
	decoder := json.NewDecoder(io.LimitReader(connection, 128*1024))
	if err := decoder.Decode(&response); err != nil {
		return BrokerResponse{}, err
	}
	return response, nil
}
