package agent

import "testing"

func TestMigrationCapabilitiesMatchFreshRuntimeProfile(t *testing.T) {
	capabilities := migrationCapabilities()
	seen := map[string]bool{}
	for _, capability := range capabilities {
		if seen[capability] {
			t.Fatalf("duplicate migration capability %q", capability)
		}
		seen[capability] = true
	}
	for _, required := range []string{"migration.postgres_logical.v1", "migration.redis_offline.v1"} {
		if !seen[required] {
			t.Fatalf("fresh enrollment omitted runtime capability %q", required)
		}
	}
}

func TestMigrationInstallHeartbeatKeepsFenceAttestationFresh(t *testing.T) {
	if got := installHeartbeatIntervalSeconds(true); got != 10 {
		t.Fatalf("migration heartbeat interval = %d, want 10", got)
	}
	if got := installHeartbeatIntervalSeconds(false); got != 30 {
		t.Fatalf("ordinary monitoring heartbeat interval = %d, want 30", got)
	}
}
