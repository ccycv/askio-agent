package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"crypto/tls"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/model"
	"github.com/askio-cloud/askio-monitor/internal/version"
)

type Server struct {
	listenAddr string
	cloudBase  *url.URL
	cloudToken string
	tlsConfig  *tls.Config
	key        []byte
	gatewayServerID string

	httpClient *http.Client
	server     *http.Server

	lastCommandID string
}

type Config struct {
	ListenAddr      string
	TLSCertPath     string
	TLSKeyPath      string
	TokenHMACKey    []byte
	CloudAPIURL     string
	CloudAgentToken string
	GatewayServerID string
}

func NewServer(cfg Config) (*Server, error) {
	u, err := url.Parse(cfg.CloudAPIURL)
	if err != nil {
		return nil, fmt.Errorf("parse cloud_api_url: %w", err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8443"
	}
	if len(cfg.TokenHMACKey) == 0 {
		return nil, fmt.Errorf("token_hmac_key is required")
	}
	if cfg.CloudAgentToken == "" {
		return nil, fmt.Errorf("cloud_agent_token is required")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load tls cert/key: %w", err)
	}

	s := &Server{
		listenAddr: cfg.ListenAddr,
		cloudBase:  u,
		cloudToken: cfg.CloudAgentToken,
		tlsConfig:  &tls.Config{Certificates: []tls.Certificate{cert}},
		key:        cfg.TokenHMACKey,
		gatewayServerID: cfg.GatewayServerID,
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Transparent proxy endpoints.
	paths := []string{
		"/monitor-agent-heartbeat",
		"/monitor-agent-config",
		"/monitor-agent-results",
		"/monitor-agent-remediation-log",
		"/monitor-agent-discovered-services",
		"/operations-agent-result",
		"/monitor-agent-command-result",
	}
	for _, p := range paths {
		mux.HandleFunc(p, s.handleProxy)
	}

	s.server = &http.Server{
		Addr:      s.listenAddr,
		Handler:   mux,
		TLSConfig: s.tlsConfig,
	}

	go s.commandPollLoop(ctx, 30*time.Second)
	go s.heartbeatLoop(ctx, 30*time.Second)

	go func() {
		<-ctx.Done()
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(ctx2)
	}()

	err := s.server.ListenAndServeTLS("", "")
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) heartbeatLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	// initial delay so networking settles
	select {
	case <-ctx.Done():
		return
	case <-time.After(3 * time.Second):
	}

	for {
		_ = s.postGatewayHeartbeat(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) postGatewayHeartbeat(ctx context.Context) error {
	// POST /monitor-agent-heartbeat
	ep := *s.cloudBase
	ep.Path = strings.TrimRight(ep.Path, "/") + "/monitor-agent-heartbeat"

	host, _ := os.Hostname()
	serverID := strings.TrimSpace(s.gatewayServerID)
	if serverID == "" {
		serverID = "gateway"
	}

	payload := map[string]any{
		"server_id":     serverID,
		"agent_version": version.Version,
		"go_version":    runtime.Version(),
		"hostname":      host,
		"pid":           os.Getpid(),
		"timestamp":     time.Now().UTC(),
		"agent_mode":    "gateway",
		"gateway": map[string]any{
			"listen_addr": s.listenAddr,
		},
	}
	b, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cloudToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "askio-monitor-gateway/"+version.Version)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("gateway heartbeat failed: status=%d", resp.StatusCode)
	}
	return nil
}

func (s *Server) commandPollLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()

	// small initial jitter
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	for {
		_ = s.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) pollOnce(ctx context.Context) error {
	// GET /monitor-agent-config
	ep := *s.cloudBase
	ep.Path = strings.TrimRight(ep.Path, "/") + "/monitor-agent-config"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.cloudToken)
	req.Header.Set("User-Agent", "askio-monitor-gateway")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("poll config failed: status=%d", resp.StatusCode)
	}

	var rc model.RemoteConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rc); err != nil {
		return err
	}
	cmd := rc.PendingCommand.V2
	if cmd == nil || cmd.CommandID == "" {
		return nil
	}
	if cmd.CommandID == s.lastCommandID {
		return nil
	}
	if cmd.Type != "generate_host_token" {
		// v1: ignore other command types in gateway poller
		s.lastCommandID = cmd.CommandID
		return nil
	}
	if strings.TrimSpace(cmd.ServerID) == "" {
		s.lastCommandID = cmd.CommandID
		return nil
	}

	// Generate token
	exp := time.Now().UTC().Add(365 * 24 * time.Hour)
	if cmd.ExpiresInSeconds > 0 {
		exp = time.Now().UTC().Add(time.Duration(cmd.ExpiresInSeconds) * time.Second)
	}
	expUnix := exp.Unix()
	msg := fmt.Sprintf("%s.%d", cmd.ServerID, expUnix)
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(msg))
	sig := fmt.Sprintf("%x", mac.Sum(nil))
	plain := fmt.Sprintf("%s.%d.%s", cmd.ServerID, expUnix, sig)
	token := base64.RawURLEncoding.EncodeToString([]byte(plain))

	// POST /gateway-host-token-result
	resPayload := model.GatewayHostTokenResult{CommandID: cmd.CommandID, ServerID: cmd.ServerID, Token: token, ExpiresAt: exp}
	b, _ := json.Marshal(resPayload)
	ep2 := *s.cloudBase
	ep2.Path = strings.TrimRight(ep2.Path, "/") + "/gateway-host-token-result"

	req2, err := http.NewRequestWithContext(ctx, http.MethodPost, ep2.String(), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req2.Header.Set("Authorization", "Bearer "+s.cloudToken)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := s.httpClient.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()
	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		_, _ = io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
		return fmt.Errorf("post token result failed: status=%d", resp2.StatusCode)
	}

	s.lastCommandID = cmd.CommandID
	return nil
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract server_id
	serverID := r.URL.Query().Get("server_id")

	// Read body (if any) so we can extract server_id and forward.
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 4<<20))
	}
	_ = r.Body.Close()

	if serverID == "" && len(bodyBytes) > 0 {
		var m map[string]any
		if err := json.Unmarshal(bodyBytes, &m); err == nil {
			if v, ok := m["server_id"].(string); ok {
				serverID = v
			}
		}
	}
	if serverID == "" {
		http.Error(w, "missing server_id", http.StatusBadRequest)
		return
	}

	// Authenticate host token
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	hostToken := strings.TrimSpace(auth[len("Bearer "):])
	if err := ValidateHostToken(hostToken, s.key, serverID, time.Now().UTC()); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Forward to cloud
	ep := *s.cloudBase
	ep.Path = strings.TrimRight(ep.Path, "/") + r.URL.Path
	ep.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(ctx, r.Method, ep.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// forward content-type
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Authorization", "Bearer "+s.cloudToken)
	req.Header.Set("X-Forwarded-Server-Id", serverID)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Pass-through status + body (headers kept minimal)
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}
