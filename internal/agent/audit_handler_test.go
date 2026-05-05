package agent

import (
	"testing"
	"time"
)

func TestAuditJobGuard_PreventsDuplicateWhileInFlightAndAfterHandled(t *testing.T) {
	d := &Daemon{
		auditInFlight: map[string]struct{}{},
		auditRecent:   map[string]time.Time{},
	}

	if !d.beginAuditJob("run-1") {
		t.Fatal("expected first audit job start to be allowed")
	}
	if d.beginAuditJob("run-1") {
		t.Fatal("expected duplicate in-flight audit job to be rejected")
	}

	d.endAuditJob("run-1", true)
	if d.beginAuditJob("run-1") {
		t.Fatal("expected recently handled audit job to be rejected")
	}
}

func TestAuditJobGuard_AllowsRetryWhenUploadNotHandled(t *testing.T) {
	d := &Daemon{
		auditInFlight: map[string]struct{}{},
		auditRecent:   map[string]time.Time{},
	}

	if !d.beginAuditJob("run-1") {
		t.Fatal("expected first audit job start to be allowed")
	}
	d.endAuditJob("run-1", false)
	if !d.beginAuditJob("run-1") {
		t.Fatal("expected audit job retry after failed upload")
	}
}
