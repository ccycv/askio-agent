package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/askio-cloud/askio-monitor/internal/vulnerability"
)

func TestInventoryDedicatedBoundedProtocol(t *testing.T) {
	paths := []string{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("missing authentication")
		}
		fmt.Fprint(w, `{"status":"waiting","request":null,"nextPollAt":"2026-10-25T12:00:00Z"}`)
	}))
	defer s.Close()
	c, e := New(Options{BaseURL: s.URL + "/functions/v1", Token: "synthetic"})
	if e != nil {
		t.Fatal(e)
	}
	response, e := c.ClaimInventory(context.Background(), vulnerability.ClaimCapabilities())
	if e != nil || response.Status != "waiting" {
		t.Fatalf("%+v %v", response, e)
	}
	if len(paths) != 1 || paths[0] != "/functions/v1/monitor-agent-inventory-claim" {
		t.Fatal(paths)
	}
}
func TestInventoryRefusesRedirectUnknownOversizeAndRawErrors(t *testing.T) {
	for _, mode := range []string{"redirect", "unknown", "oversize", "status", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			followed := false
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
			defer target.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, target.URL, 307)
				case "unknown":
					fmt.Fprint(w, `{"status":"waiting","request":null,"nextPollAt":"2026-10-25T12:00:00Z","command":"bad"}`)
				case "oversize":
					fmt.Fprint(w, strings.Repeat("x", vulnerability.MaxPageBytes+1))
				case "status":
					w.WriteHeader(403)
					fmt.Fprint(w, "private-upstream-body")
				case "trailing":
					fmt.Fprint(w, `{"status":"waiting","request":null,"nextPollAt":"2026-10-25T12:00:00Z"}{}`)
				}
			}))
			defer server.Close()
			c, e := New(Options{BaseURL: server.URL, Token: "synthetic"})
			if e != nil {
				t.Fatal(e)
			}
			_, e = c.ClaimInventory(context.Background(), vulnerability.ClaimCapabilities())
			if e == nil || strings.Contains(e.Error(), "private-upstream-body") || followed {
				t.Fatalf("unsafe response: %v followed=%v", e, followed)
			}
		})
	}
}
