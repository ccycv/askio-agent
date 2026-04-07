package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestGatewayProxy_ForwardsWithForwardedServerID(t *testing.T) {
	// Fake cloud endpoint.
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Server-Id") != "srv" {
			t.Fatalf("missing/incorrect X-Forwarded-Server-Id: %q", r.Header.Get("X-Forwarded-Server-Id"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer cloud.Close()

	key := []byte("secret")
	tok := makeToken("srv", time.Now().Add(10*time.Minute), key)

	// Use httptest TLS server with handlerProxy.
	gatewaySrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// minimal injected server fields
		gs := &Server{
			cloudBase:  mustParseURL(t, cloud.URL),
			cloudToken: "cloudtok",
			key:        key,
			httpClient: &http.Client{Timeout: 5 * time.Second},
		}
		gs.handleProxy(w, r)
	}))
	defer gatewaySrv.Close()

	client := gatewaySrv.Client()
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, gatewaySrv.URL+"/monitor-agent-heartbeat", mustJSONReader(map[string]any{"server_id": "srv"}))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func mustParseURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustJSONReader(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}
