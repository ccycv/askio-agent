package migration

import (
	"encoding/json"
	"strings"
	"testing"
)

func mongodbBindingJSON(overrides map[string]any) []byte {
	value := map[string]any{
		"schema_version": mongodbBindingSchema,
		"mode":           "source",
		"host":           "127.0.0.1",
		"port":           27017,
		"database":       "fixture",
		"auth_database":  "admin",
		"username":       "fixture_user",
		"password":       "bounded-test-value",
		"ssl_mode":       "disable",
	}
	for key, entry := range overrides {
		value[key] = entry
	}
	encoded, _ := json.Marshal(value)
	return encoded
}

func TestMongoDBBindingAcceptsConstrainedTarget(t *testing.T) {
	source, err := parseMongoDBBinding(mongodbBindingJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	source.clear()
	target, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"mode": "target", "database": "askio_mig_fixture", "reset_allowed": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	target.clear()
}

func TestMongoDBBindingRejectsSystemDatabaseRemotePlaintextAndUnknownFields(t *testing.T) {
	if _, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{"database": "admin"})); err == nil {
		t.Fatal("expected MongoDB system database to be rejected")
	}
	if _, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{"host": "db.example.test"})); err == nil {
		t.Fatal("expected remote plaintext MongoDB binding to be rejected")
	}
	if _, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{"javascript": "db.dropDatabase()"})); err == nil {
		t.Fatal("expected unknown MongoDB binding field to be rejected")
	}
}

func TestMongoDBURIEncodesCredentialsAndBindsAuthenticationDatabase(t *testing.T) {
	binding, err := parseMongoDBBinding(mongodbBindingJSON(map[string]any{
		"username": "user@example.test", "password": "colon:slash/value?and#fragment",
	}))
	if err != nil {
		t.Fatal(err)
	}
	uri := mongodbURI(binding, "")
	binding.clear()
	if strings.Contains(uri, "colon:slash/value?and#fragment") || !strings.Contains(uri, "authSource=admin") || !strings.Contains(uri, "directConnection=true") {
		t.Fatalf("MongoDB URI did not safely encode and scope the credential: %q", uri)
	}
}
