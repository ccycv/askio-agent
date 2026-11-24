package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestInventoryDefaultOffAndExplicitTLSHostOnly(t *testing.T) {
	base := Config{APIURL: "https://api.example.invalid/functions/v1", ServerID: "synthetic", AgentToken: "synthetic"}
	c, e := base.Normalized()
	if e != nil || c.Inventory != nil || c.InventoryLocal() != InventoryLocalAbsent {
		t.Fatalf("default enabled: %v", e)
	}
	base.Inventory = &InventoryConfig{Enabled: boolPtr(true)}
	if _, e = base.Normalized(); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*Config){func(c *Config) { c.TLSSkipVerify = true }, func(c *Config) { c.APIURL = "http://api.example.invalid" }, func(c *Config) { c.APIURL = "https://user:pass@api.example.invalid" }, func(c *Config) { c.Mode = "gateway" }} {
		copy := base
		change(&copy)
		if _, e = copy.Normalized(); e == nil {
			t.Fatal("unsafe inventory composition enabled")
		}
	}
	// An explicit false or an absent key never fails loading, whatever the
	// composition: neither is an opt-in.
	for _, inv := range []*InventoryConfig{{Enabled: boolPtr(false)}, {}} {
		copy := base
		copy.Inventory = inv
		copy.TLSSkipVerify = true
		copy.APIURL = "http://api.example.invalid"
		if _, e = copy.Normalized(); e != nil {
			t.Fatalf("non-opt-in rejected: %v", e)
		}
	}
}

// The YAML key is tri-state: absent, explicit false and explicit true are
// distinct, and a save round-trip preserves each.
func TestInventoryLocalIsTriStateInYAML(t *testing.T) {
	cases := []struct {
		name   string
		stanza string
		want   InventoryLocalSetting
	}{
		{"no-stanza", "", InventoryLocalAbsent},
		{"null-stanza", "inventory:\n", InventoryLocalAbsent},
		{"empty-stanza", "inventory: {}\n", InventoryLocalAbsent},
		{"false", "inventory:\n  enabled: false\n", InventoryLocalOff},
		{"true", "inventory:\n  enabled: true\n", InventoryLocalOn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "monitor.conf")
			body := "api_url: https://api.example.invalid/functions/v1\nserver_id: synthetic\nagent_token: synthetic\ndata_dir: " + dir + "\n" + tc.stanza
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := c.InventoryLocal(); got != tc.want {
				t.Fatalf("InventoryLocal = %v, want %v", got, tc.want)
			}
			if err := Save(path, c); err != nil {
				t.Fatal(err)
			}
			raw, _ := os.ReadFile(path)
			if tc.want == InventoryLocalAbsent && strings.Contains(string(raw), "enabled") {
				t.Fatalf("absent setting serialized an enabled key:\n%s", raw)
			}
			again, err := Load(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := again.InventoryLocal(); got != tc.want {
				t.Fatalf("after round-trip InventoryLocal = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInventoryRemoteRefusalReasons(t *testing.T) {
	safe := Config{Mode: "host", APIURL: "https://api.example.invalid/functions/v1"}
	if r := safe.InventoryRemoteRefusal(); r != "" {
		t.Fatalf("safe composition refused: %s", r)
	}
	unset := safe
	unset.Mode = ""
	if r := unset.InventoryRemoteRefusal(); r != "" {
		t.Fatalf("default host mode refused: %s", r)
	}
	cases := []struct {
		name   string
		change func(*Config)
		want   string
	}{
		{"gateway-mode", func(c *Config) { c.Mode = "gateway" }, InventoryRefusedNotHostMode},
		{"gateway-stanza", func(c *Config) { c.Gateway = &GatewayConfig{} }, InventoryRefusedGateway},
		{"http", func(c *Config) { c.APIURL = "http://api.example.invalid/functions/v1" }, InventoryRefusedAPIURL},
		{"credentials", func(c *Config) { c.APIURL = "https://user:pass@api.example.invalid" }, InventoryRefusedAPIURL},
		{"query", func(c *Config) { c.APIURL = "https://api.example.invalid/functions/v1?x=1" }, InventoryRefusedAPIURL},
		{"fragment", func(c *Config) { c.APIURL = "https://api.example.invalid/functions/v1#x" }, InventoryRefusedAPIURL},
		{"no-host", func(c *Config) { c.APIURL = "https:///functions/v1" }, InventoryRefusedAPIURL},
		{"empty", func(c *Config) { c.APIURL = "" }, InventoryRefusedAPIURL},
		{"tls-skip-verify", func(c *Config) { c.TLSSkipVerify = true }, InventoryRefusedTLSSkipVerify},
	}
	for _, tc := range cases {
		c := safe
		tc.change(&c)
		if got := c.InventoryRemoteRefusal(); got != tc.want {
			t.Fatalf("%s: refusal %q, want %q", tc.name, got, tc.want)
		}
	}
}
