package config

import "testing"

func TestInventoryDefaultOffAndExplicitTLSHostOnly(t *testing.T) {
	base := Config{APIURL: "https://api.example.invalid/functions/v1", ServerID: "synthetic", AgentToken: "synthetic"}
	c, e := base.Normalized()
	if e != nil || c.Inventory != nil {
		t.Fatalf("default enabled: %v", e)
	}
	base.Inventory = &InventoryConfig{Enabled: true}
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
}
