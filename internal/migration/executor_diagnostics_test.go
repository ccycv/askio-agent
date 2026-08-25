package migration

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeExecutorKeepsPrimitiveDiagnosticsHostLocal(t *testing.T) {
	executor, err := NewNativeExecutor(
		map[string]string{"workspace": t.TempDir()},
		filepath.Join(t.TempDir(), "broker.sock"),
		filepath.Join(t.TempDir(), "state"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	executor.SetLogger(slog.New(slog.NewTextHandler(&logs, nil)))
	result := executor.Execute(context.Background(), TaskEnvelope{
		MigrationID: "migration-diagnostic-fixture",
		AttemptID:   "attempt-diagnostic-fixture",
		Primitive:   PrimitiveRef{ID: "migration.host.preflight.v1", Version: "1.0.0"},
		Inputs:      map[string]any{"inputs": map[string]any{"root_handle": "missing"}},
	}, func(string, int64, *int64) error { return nil })
	if result.Error == nil || result.Error.Code != "MIGRATION_PRIMITIVE_FAILED_SAFE" || strings.Contains(result.Error.SafeMessage, "missing") {
		t.Fatalf("control-plane error was not safely redacted: %#v", result.Error)
	}
	local := logs.String()
	for _, expected := range []string{"migration primitive failed safely", "migration-diagnostic-fixture", "attempt-diagnostic-fixture", "root handle is not configured"} {
		if !strings.Contains(local, expected) {
			t.Fatalf("host-local diagnostic is missing %q: %s", expected, local)
		}
	}
}
