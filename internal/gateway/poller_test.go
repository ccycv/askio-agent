package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

func TestPollOnce_GenerateHostToken_PostsResult(t *testing.T) {
	var posted model.GatewayHostTokenResult

	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/monitor-agent-config":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"fetched_at": time.Now().UTC().Format(time.RFC3339),
				"monitors":   []any{},
				"pending_command": map[string]any{
					"type":               "generate_host_token",
					"command_id":          "cmd1",
					"server_id":           "host1",
					"expires_in_seconds":  3600,
				},
			})
		case "/gateway-host-token-result":
			b, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(b, &posted); err != nil {
				t.Fatalf("failed to decode posted body: %v body=%s", err, string(b))
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer cloud.Close()

	u, _ := url.Parse(cloud.URL)
	key := []byte("secret")
	s := &Server{
		cloudBase:  u,
		cloudToken: "cloudtok",
		key:        key,
		httpClient: &http.Client{Timeout: 2 * time.Second},
	}

	if err := s.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce failed: %v", err)
	}
	if posted.CommandID != "cmd1" || posted.ServerID != "host1" || posted.Token == "" {
		t.Fatalf("unexpected posted payload: %+v", posted)
	}

	// Validate token signature
	b, err := base64.RawURLEncoding.DecodeString(posted.Token)
	if err != nil {
		t.Fatalf("token not base64url: %v", err)
	}
	parts := strings.Split(string(b), ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token format: %q", string(b))
	}
	sid := parts[0]
	expStr := parts[1]
	sig := parts[2]
	if sid != "host1" {
		t.Fatalf("sid mismatch: %s", sid)
	}
	msg := fmt.Sprintf("%s.%s", sid, expStr)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(msg))
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if expected != sig {
		t.Fatalf("sig mismatch")
	}
}
