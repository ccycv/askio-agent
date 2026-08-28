package migration

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeServiceController struct {
	mu       sync.Mutex
	active   map[string]bool
	failures map[string]error
	unknown  map[string]error
}

func (controller *fakeServiceController) Operate(_ context.Context, action, service string) error {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if err := controller.failures[action+":"+service]; err != nil {
		return err
	}
	switch action {
	case "start":
		controller.active[service] = true
	case "stop":
		controller.active[service] = false
	default:
		return errors.New("unsupported fake service action")
	}
	return nil
}

func (controller *fakeServiceController) IsActive(_ context.Context, service string) (bool, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if err := controller.unknown[service]; err != nil {
		return false, err
	}
	return controller.active[service], nil
}

func writerFenceBroker(t *testing.T, controller serviceController) *Broker {
	t.Helper()
	return &Broker{
		config: BrokerConfig{StatePath: filepath.Join(t.TempDir(), "broker-state.json")},
		allowedServices: map[string]struct{}{
			"api.service":    {},
			"worker.service": {},
		},
		serviceControl: controller,
		state: brokerPersistentState{
			SchemaVersion:     "operations.migration.broker-state.v1",
			Fences:            map[string]int64{},
			WriterFences:      map[string]writerFenceState{},
			SeenNonces:        []string{},
			SeenNonceExpiries: map[string]string{},
		},
	}
}

func writerFenceRequest(token int64) BrokerRequest {
	runID := "run-writer-fence-test"
	runStepID := "step-writer-fence-test"
	return BrokerRequest{Task: TaskEnvelope{
		MigrationID:  "migration-writer-fence-test",
		RunID:        &runID,
		RunStepID:    &runStepID,
		FencingToken: token,
		Inputs: map[string]any{
			"service_handles": []any{"worker.service", "api.service"},
		},
	}}
}

func TestWriterFenceCannotBeReleasedByAnotherRun(t *testing.T) {
	controller := &fakeServiceController{
		active: map[string]bool{"api.service": true, "worker.service": true}, failures: map[string]error{}, unknown: map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	if _, err := broker.serviceOperation(context.Background(), writerFenceRequest(50), "stop"); err != nil {
		t.Fatal(err)
	}
	other := writerFenceRequest(51)
	otherRunID := "run-attacker-or-stale"
	other.Task.RunID = &otherRunID
	if _, err := broker.serviceOperation(context.Background(), other, "start"); err == nil {
		t.Fatal("a different run released the active writer fence")
	}
	if controller.active["api.service"] || controller.active["worker.service"] {
		t.Fatal("cross-run release changed a fenced service")
	}
}

func TestWriterFencePersistsIntentBeforePartialStopFailure(t *testing.T) {
	controller := &fakeServiceController{
		active: map[string]bool{"api.service": true, "worker.service": true},
		failures: map[string]error{
			"stop:worker.service": errors.New("injected stop failure"),
		},
		unknown: map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	request := writerFenceRequest(7)

	if _, err := broker.serviceOperation(context.Background(), request, "stop"); err == nil {
		t.Fatal("partial stop failure was not reported")
	}
	fence := broker.state.WriterFences[request.Task.MigrationID]
	if !fence.Active || fence.Phase != writerFenceActivating {
		t.Fatalf("partial fence did not remain fail-closed: %#v", fence)
	}
	if !equalStrings(fence.PreviouslyActive, []string{"api.service", "worker.service"}) {
		t.Fatalf("original service state was not retained: %#v", fence.PreviouslyActive)
	}

	persisted := brokerPersistentState{}
	reloaded := &Broker{config: broker.config, state: persisted}
	if err := reloaded.loadFences(); err != nil {
		t.Fatal(err)
	}
	if stored := reloaded.state.WriterFences[request.Task.MigrationID]; !stored.Active || stored.Phase != writerFenceActivating {
		t.Fatalf("persisted partial fence was not recoverable: %#v", stored)
	}

	delete(controller.failures, "stop:worker.service")
	outputs, err := broker.serviceOperation(context.Background(), writerFenceRequest(8), "stop")
	if err != nil {
		t.Fatal(err)
	}
	if outputs["writer_fence_active"] != true || broker.state.WriterFences[request.Task.MigrationID].Phase != writerFenceActive {
		t.Fatalf("retry did not complete the durable fence: %#v", outputs)
	}
}

func TestWriterFenceReleaseRestartsOnlyPreviouslyActiveServices(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": true, "worker.service": false},
		failures: map[string]error{},
		unknown:  map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	request := writerFenceRequest(11)
	if _, err := broker.serviceOperation(context.Background(), request, "stop"); err != nil {
		t.Fatal(err)
	}

	controller.failures["start:api.service"] = errors.New("injected start failure")
	if _, err := broker.serviceOperation(context.Background(), writerFenceRequest(12), "start"); err == nil {
		t.Fatal("partial release failure was not reported")
	}
	if fence := broker.state.WriterFences[request.Task.MigrationID]; !fence.Active || fence.Phase != writerFenceActive {
		t.Fatalf("failed release did not restore the active fence: %#v", fence)
	}
	if controller.active["api.service"] || controller.active["worker.service"] {
		t.Fatal("failed release left a scoped writer running")
	}

	delete(controller.failures, "start:api.service")
	outputs, err := broker.serviceOperation(context.Background(), writerFenceRequest(13), "start")
	if err != nil {
		t.Fatal(err)
	}
	if outputs["writer_fence_active"] != false || !controller.active["api.service"] || controller.active["worker.service"] {
		t.Fatalf("release did not restore the original service state: outputs=%#v active=%#v", outputs, controller.active)
	}
	if fence := broker.state.WriterFences[request.Task.MigrationID]; fence.Active || fence.Phase != writerFenceReleased {
		t.Fatalf("released fence state was not durable: %#v", fence)
	}

	retry, err := broker.serviceOperation(context.Background(), writerFenceRequest(14), "start")
	if err != nil {
		t.Fatal(err)
	}
	if retry["already_released"] != true || retry["writer_fence_active"] != false || !controller.active["api.service"] || controller.active["worker.service"] {
		t.Fatalf("released fence retry was not idempotent: outputs=%#v active=%#v", retry, controller.active)
	}
}

func TestWriterFenceReleaseReconcilesReviewedExternalRecovery(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": true, "worker.service": true},
		failures: map[string]error{},
		unknown:  map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	outputs, err := broker.serviceOperation(context.Background(), writerFenceRequest(40), "start")
	if err != nil {
		t.Fatal(err)
	}
	if outputs["already_released"] != true || outputs["recovered_without_fence_record"] != true || outputs["writer_fence_active"] != false {
		t.Fatalf("external recovery was not reconciled: %#v", outputs)
	}
	fence := broker.state.WriterFences["migration-writer-fence-test"]
	if fence.Active || fence.Phase != writerFenceReleased || fence.FencingToken != 40 || !equalStrings(fence.PreviouslyActive, []string{"api.service", "worker.service"}) {
		t.Fatalf("external recovery was not persisted as released: %#v", fence)
	}
}

func TestWriterFenceReleaseRejectsAmbiguousMissingFenceState(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": true, "worker.service": false},
		failures: map[string]error{},
		unknown:  map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	if _, err := broker.serviceOperation(context.Background(), writerFenceRequest(41), "start"); err == nil {
		t.Fatal("ambiguous external recovery was accepted")
	}
	if len(broker.state.WriterFences) != 0 || !controller.active["api.service"] || controller.active["worker.service"] {
		t.Fatalf("ambiguous recovery mutated broker or service state: fences=%#v active=%#v", broker.state.WriterFences, controller.active)
	}
}

func TestWriterFenceWatchdogRollsBackCrashDuringRelease(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": true, "worker.service": false},
		failures: map[string]error{},
		unknown:  map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	broker.state.WriterFences["migration-writer-fence-test"] = writerFenceState{
		MigrationID: "migration-writer-fence-test", RunID: "run-writer-fence-test", Services: []string{"api.service", "worker.service"},
		PreviouslyActive: []string{"api.service"}, Active: true, Phase: writerFenceReleasing, FencingToken: 20,
	}

	if err := broker.reconcileWriterFences(context.Background()); err != nil {
		t.Fatal(err)
	}
	if controller.active["api.service"] || controller.active["worker.service"] {
		t.Fatal("watchdog did not fail closed after a release crash")
	}
	if fence := broker.state.WriterFences["migration-writer-fence-test"]; !fence.Active || fence.Phase != writerFenceActive {
		t.Fatalf("watchdog did not restore the active fence state: %#v", fence)
	}
}

func TestWriterFenceWatchdogCompletesActivationWithoutInventingViolation(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": false, "worker.service": true},
		failures: map[string]error{},
		unknown:  map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	broker.state.WriterFences["migration-writer-fence-test"] = writerFenceState{
		MigrationID: "migration-writer-fence-test", RunID: "run-writer-fence-test", Services: []string{"api.service", "worker.service"},
		PreviouslyActive: []string{"api.service", "worker.service"}, Active: true, Phase: writerFenceActivating, FencingToken: 21,
	}

	if err := broker.reconcileWriterFences(context.Background()); err != nil {
		t.Fatal(err)
	}
	fence := broker.state.WriterFences["migration-writer-fence-test"]
	if fence.Phase != writerFenceActive || fence.ViolationCount != 0 || controller.active["worker.service"] {
		t.Fatalf("watchdog did not complete activation cleanly: fence=%#v active=%#v", fence, controller.active)
	}
}

func TestWriterFenceWatchdogPersistsUnknownServiceStateAsBlockingEvidence(t *testing.T) {
	controller := &fakeServiceController{
		active: map[string]bool{"api.service": false, "worker.service": false}, failures: map[string]error{},
		unknown: map[string]error{"api.service": errors.New("injected query failure")},
	}
	broker := writerFenceBroker(t, controller)
	broker.state.WriterFences["migration-writer-fence-test"] = writerFenceState{
		MigrationID: "migration-writer-fence-test", RunID: "run-writer-fence-test", Services: []string{"api.service", "worker.service"},
		PreviouslyActive: []string{"api.service", "worker.service"}, Active: true, Phase: writerFenceActive, FencingToken: 22,
	}

	if err := broker.reconcileWriterFences(context.Background()); err == nil {
		t.Fatal("watchdog enforcement failure was not reported")
	}
	fence := broker.state.WriterFences["migration-writer-fence-test"]
	if fence.WatchdogErrorCount < 1 || fence.ViolationCount < 1 || fence.LastWatchdogError == "" || fence.LastViolation == "" {
		t.Fatalf("watchdog enforcement failure was not retained: %#v", fence)
	}
	persisted := brokerPersistentState{}
	reloaded := &Broker{config: broker.config, state: persisted}
	if err := reloaded.loadFences(); err != nil {
		t.Fatal(err)
	}
	if reloaded.state.WriterFences["migration-writer-fence-test"].WatchdogErrorCount < 1 {
		t.Fatal("watchdog failure evidence did not survive reload")
	}
}

func TestWriterFenceRejectsUnknownServiceStateBeforeMutation(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": true, "worker.service": true},
		failures: map[string]error{},
		unknown:  map[string]error{"api.service": errors.New("injected unknown state")},
	}
	broker := writerFenceBroker(t, controller)
	if _, err := broker.serviceOperation(context.Background(), writerFenceRequest(30), "stop"); err == nil {
		t.Fatal("unknown service state was accepted")
	}
	if len(broker.state.WriterFences) != 0 || !controller.active["api.service"] || !controller.active["worker.service"] {
		t.Fatal("unknown service state caused a mutation")
	}
}

func TestWriterFenceAttestationReconcilesAndReportsLiveFence(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": false, "worker.service": false},
		failures: map[string]error{},
		unknown:  map[string]error{},
	}
	broker := writerFenceBroker(t, controller)
	broker.state.WriterFences["migration-writer-fence-test"] = writerFenceState{
		MigrationID: "migration-writer-fence-test", RunID: "run-writer-fence-test", Services: []string{"api.service", "worker.service"},
		PreviouslyActive: []string{"api.service", "worker.service"}, Active: true, Phase: writerFenceActive, FencingToken: 55,
		ActivatedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
	}

	outputs, err := broker.attestWriterFences(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fences, ok := outputs["fences"].([]WriterFenceAttestation)
	if !ok || len(fences) != 1 {
		t.Fatalf("live fence attestation was not emitted: %#v", outputs)
	}
	attestation := fences[0]
	if !attestation.Active || attestation.Phase != writerFenceActive || attestation.FencingToken != 55 ||
		attestation.LastVerifiedAt == "" || attestation.AttestedAt == "" || attestation.ViolationCount != 0 || attestation.WatchdogErrorCount != 0 {
		t.Fatalf("live fence attestation was incomplete: %#v", attestation)
	}
}

func TestWriterFenceAttestationFailsClosedOnWatchdogError(t *testing.T) {
	controller := &fakeServiceController{
		active:   map[string]bool{"api.service": false, "worker.service": false},
		failures: map[string]error{},
		unknown:  map[string]error{"api.service": errors.New("injected query failure")},
	}
	broker := writerFenceBroker(t, controller)
	broker.state.WriterFences["migration-writer-fence-test"] = writerFenceState{
		MigrationID: "migration-writer-fence-test", RunID: "run-writer-fence-test", Services: []string{"api.service", "worker.service"},
		PreviouslyActive: []string{"api.service", "worker.service"}, Active: true, Phase: writerFenceActive, FencingToken: 56,
		ActivatedAt: time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
	}

	outputs, err := broker.attestWriterFences(context.Background())
	if err == nil {
		t.Fatal("watchdog failure was presented as a valid heartbeat attestation")
	}
	fences, ok := outputs["fences"].([]WriterFenceAttestation)
	if !ok || len(fences) != 1 || fences[0].ViolationCount < 1 || fences[0].WatchdogErrorCount < 1 {
		t.Fatalf("blocking watchdog evidence was not retained: %#v", outputs)
	}
}
