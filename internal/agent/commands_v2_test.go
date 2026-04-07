package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/api"
	"github.com/askio-cloud/askio-monitor/internal/config"
	"github.com/askio-cloud/askio-monitor/internal/model"
)

func TestGenerateHostToken_PostsResult(t *testing.T) {
	var got model.GatewayHostTokenResult

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gateway-host-token-result" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client, err := api.New(api.Options{BaseURL: srv.URL, Token: "cloudtok"})
	if err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		cfg: config.Config{
			Mode: "gateway",
			Gateway: &config.GatewayConfig{
				TokenHMACKey: "secret",
			},
		},
		api: client,
	}

	cmd := &model.PendingCommand{
		Type:             "generate_host_token",
		CommandID:        "cmd1",
		ServerID:         "srv1",
		ExpiresInSeconds: 3600,
	}
	res := model.CommandResult{CommandID: cmd.CommandID, CommandType: cmd.Type, Status: "failed", StartedAt: time.Now().UTC()}
	d.handleGenerateHostToken(context.Background(), cmd, &res)

	if got.CommandID != "cmd1" || got.ServerID != "srv1" || got.Token == "" {
		t.Fatalf("unexpected result posted: %+v", got)
	}
	// Validate token structure (must match gateway auth validator)
	b, err := base64.RawURLEncoding.DecodeString(got.Token)
	if err != nil {
		t.Fatalf("token not base64url: %v", err)
	}
	// verify HMAC
	parts := strings.Split(string(b), ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token decoded format: %q", string(b))
	}
	sid, expStr, sig := parts[0], parts[1], parts[2]
	if sid != "srv1" {
		t.Fatalf("sid mismatch: %s", sid)
	}
	msg := sid + "." + expStr
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(msg))
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if expected != sig {
		t.Fatalf("sig mismatch")
	}
}
