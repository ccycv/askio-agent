package migration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	dataPlaneTicketSchema = "operations.migration.data-plane-ticket.v1"
	transferBindingSchema = "operations.migration.transfer-binding.v1"
	dataPlaneAudience     = "askio-migration-data-plane"
)

type DataPlaneTicket struct {
	SchemaVersion          string `json:"schema_version"`
	KeyID                  string `json:"key_id"`
	Algorithm              string `json:"algorithm"`
	Audience               string `json:"audience"`
	MigrationID            string `json:"migration_id"`
	RunID                  string `json:"run_id"`
	AttemptID              string `json:"attempt_id"`
	FencingToken           int64  `json:"fencing_token"`
	BindingID              string `json:"binding_id"`
	SourceAgentID          string `json:"source_agent_id"`
	TargetAgentID          string `json:"target_agent_id"`
	SourceSigningKeyID     string `json:"source_signing_key_id"`
	SourceSigningPublicPEM string `json:"source_signing_public_key_pem"`
	TargetSigningKeyID     string `json:"target_signing_key_id"`
	TargetSigningPublicPEM string `json:"target_signing_public_key_pem"`
	SourceRootHandle       string `json:"source_root_handle"`
	SourceRelativeHandle   string `json:"source_relative_handle"`
	ManifestDigest         string `json:"manifest_digest"`
	ChunkSizeBytes         int64  `json:"chunk_size_bytes"`
	MaximumBytes           int64  `json:"maximum_bytes"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	Nonce                  string `json:"nonce"`
	Signature              string `json:"signature"`
}

func dataPlaneTicketUnsigned(ticket DataPlaneTicket) map[string]any {
	return map[string]any{
		"schema_version": ticket.SchemaVersion, "key_id": ticket.KeyID, "algorithm": ticket.Algorithm,
		"audience": ticket.Audience, "migration_id": ticket.MigrationID, "run_id": ticket.RunID,
		"attempt_id": ticket.AttemptID, "fencing_token": ticket.FencingToken, "binding_id": ticket.BindingID,
		"source_agent_id": ticket.SourceAgentID, "target_agent_id": ticket.TargetAgentID,
		"source_signing_key_id": ticket.SourceSigningKeyID, "source_signing_public_key_pem": ticket.SourceSigningPublicPEM,
		"target_signing_key_id": ticket.TargetSigningKeyID, "target_signing_public_key_pem": ticket.TargetSigningPublicPEM,
		"source_root_handle": ticket.SourceRootHandle, "source_relative_handle": ticket.SourceRelativeHandle,
		"manifest_digest": ticket.ManifestDigest, "chunk_size_bytes": ticket.ChunkSizeBytes,
		"maximum_bytes": ticket.MaximumBytes, "issued_at": ticket.IssuedAt, "expires_at": ticket.ExpiresAt,
		"nonce": ticket.Nonce,
	}
}

func parseEd25519PublicKey(pemText string) (ed25519.PublicKey, error) {
	if len(pemText) > 4096 {
		return nil, errors.New("data-plane public key is invalid")
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("data-plane public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("data-plane public key is invalid")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("data-plane public key is not Ed25519")
	}
	return key, nil
}

func validateDataPlaneTicket(ticket DataPlaneTicket, backendKeyID string, backendPublic ed25519.PublicKey) error {
	issuedAt, issuedErr := time.Parse(time.RFC3339Nano, ticket.IssuedAt)
	expiresAt, expiresErr := time.Parse(time.RFC3339Nano, ticket.ExpiresAt)
	now := time.Now().UTC()
	if ticket.SchemaVersion != dataPlaneTicketSchema || ticket.KeyID != backendKeyID || ticket.Algorithm != "ed25519-v1" || ticket.Audience != dataPlaneAudience {
		return errors.New("data-plane ticket contract is unsupported")
	}
	if issuedErr != nil || expiresErr != nil || expiresAt.Before(now) || issuedAt.After(now.Add(30*time.Second)) || expiresAt.Sub(issuedAt) > 10*time.Minute {
		return errors.New("data-plane ticket validity window is invalid")
	}
	if ticket.MigrationID == "" || ticket.RunID == "" || ticket.AttemptID == "" || ticket.FencingToken < 1 ||
		!opaqueBindingPattern.MatchString(ticket.BindingID) || ticket.SourceAgentID == "" || ticket.TargetAgentID == "" || ticket.SourceAgentID == ticket.TargetAgentID ||
		ticket.SourceSigningKeyID == "" || ticket.TargetSigningKeyID == "" || ticket.ChunkSizeBytes != transferChunkSize ||
		ticket.MaximumBytes < 0 || ticket.MaximumBytes > maximumManifestBytes || !strings.HasPrefix(ticket.ManifestDigest, "sha256:") ||
		len(ticket.Nonce) < 22 || len(ticket.Nonce) > 128 {
		return errors.New("data-plane ticket scope is invalid")
	}
	if _, err := cleanRelative(ticket.SourceRelativeHandle); err != nil {
		return errors.New("data-plane source scope is invalid")
	}
	if _, err := parseEd25519PublicKey(ticket.SourceSigningPublicPEM); err != nil {
		return err
	}
	if _, err := parseEd25519PublicKey(ticket.TargetSigningPublicPEM); err != nil {
		return err
	}
	canonical, err := CanonicalJSON(dataPlaneTicketUnsigned(ticket))
	if err != nil {
		return errors.New("data-plane ticket canonicalization failed")
	}
	signature, err := base64.RawURLEncoding.DecodeString(ticket.Signature)
	if err != nil || !ed25519.Verify(backendPublic, canonical, signature) {
		return errors.New("data-plane ticket signature is invalid")
	}
	return nil
}

func tlsCertificateForIdentity(identity *Identity) (tls.Certificate, error) {
	if identity == nil || len(identity.SigningPrivateKey) != ed25519.PrivateKeySize {
		return tls.Certificate{}, errors.New("data-plane signing identity is unavailable")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "askio-migration-agent"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, identity.SigningPrivateKey.Public(), identity.SigningPrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: identity.SigningPrivateKey, Leaf: template}, nil
}

func peerMatchesPublicKey(connectionState *tls.ConnectionState, expected ed25519.PublicKey) bool {
	if connectionState == nil || len(connectionState.PeerCertificates) != 1 {
		return false
	}
	actual, ok := connectionState.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	return ok && bytes.Equal(actual, expected)
}

type dataPlaneRequest struct {
	Ticket     DataPlaneTicket `json:"ticket"`
	Relative   string          `json:"relative,omitempty"`
	ChunkIndex int64           `json:"chunk_index,omitempty"`
}

type DataPlaneServer struct {
	agentID       string
	identity      *Identity
	backendKeyID  string
	backendPublic ed25519.PublicKey
	resolver      *ScopeResolver
	listener      net.Listener
	httpServer    *http.Server
}

func NewDataPlaneServer(listenAddress, agentID, backendKeyID, backendPublicKeyBase64 string, identity *Identity, roots map[string]string) (*DataPlaneServer, error) {
	if agentID == "" || listenAddress == "" {
		return nil, errors.New("data-plane listener identity and address are required")
	}
	resolver, err := NewScopeResolver(roots)
	if err != nil {
		return nil, err
	}
	backendPublic, err := parseBackendSigningKey(backendPublicKeyBase64)
	if err != nil {
		return nil, err
	}
	certificate, err := tlsCertificateForIdentity(identity)
	if err != nil {
		return nil, err
	}
	baseListener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAnyClientCert,
	}
	server := &DataPlaneServer{agentID: agentID, identity: identity, backendKeyID: backendKeyID, backendPublic: backendPublic, resolver: resolver}
	server.listener = tls.NewListener(baseListener, tlsConfig)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/manifest", server.handleManifest)
	mux.HandleFunc("/v1/chunk", server.handleChunk)
	server.httpServer = &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	return server, nil
}

func (s *DataPlaneServer) Address() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *DataPlaneServer) Serve(ctx context.Context) error {
	if s == nil || s.httpServer == nil || s.listener == nil {
		return errors.New("data-plane server is unavailable")
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.httpServer.Shutdown(shutdownContext)
		case <-done:
		}
	}()
	err := s.httpServer.Serve(s.listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *DataPlaneServer) authorize(request *http.Request) (dataPlaneRequest, string, FileManifestSummary, error) {
	if request.Method != http.MethodPost || request.TLS == nil {
		return dataPlaneRequest{}, "", FileManifestSummary{}, errors.New("data-plane request method or TLS state is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 256*1024))
	decoder.DisallowUnknownFields()
	var body dataPlaneRequest
	if err := decoder.Decode(&body); err != nil {
		return dataPlaneRequest{}, "", FileManifestSummary{}, errors.New("data-plane request is invalid")
	}
	if err := validateDataPlaneTicket(body.Ticket, s.backendKeyID, s.backendPublic); err != nil {
		return dataPlaneRequest{}, "", FileManifestSummary{}, err
	}
	if body.Ticket.SourceAgentID != s.agentID || body.Ticket.SourceSigningKeyID != s.identity.SigningKeyID {
		return dataPlaneRequest{}, "", FileManifestSummary{}, errors.New("data-plane ticket source audience mismatch")
	}
	localPublic, err := parseEd25519PublicKey(s.identity.SigningPublicKeyPEM)
	if err != nil || !bytes.Equal(localPublic, mustParseEd25519(body.Ticket.SourceSigningPublicPEM)) {
		return dataPlaneRequest{}, "", FileManifestSummary{}, errors.New("data-plane ticket source key mismatch")
	}
	targetPublic, err := parseEd25519PublicKey(body.Ticket.TargetSigningPublicPEM)
	if err != nil || !peerMatchesPublicKey(request.TLS, targetPublic) {
		return dataPlaneRequest{}, "", FileManifestSummary{}, errors.New("data-plane mutual TLS peer mismatch")
	}
	base, err := s.resolver.Resolve(body.Ticket.SourceRootHandle, body.Ticket.SourceRelativeHandle, false)
	if err != nil {
		return dataPlaneRequest{}, "", FileManifestSummary{}, err
	}
	summary, err := buildFileManifest(request.Context(), base, nil)
	if err != nil {
		return dataPlaneRequest{}, "", FileManifestSummary{}, err
	}
	if summary.Digest != body.Ticket.ManifestDigest || summary.TotalBytes > body.Ticket.MaximumBytes {
		return dataPlaneRequest{}, "", FileManifestSummary{}, errors.New("data-plane source manifest drifted or exceeds its ticket")
	}
	return body, base, summary, nil
}

func mustParseEd25519(value string) ed25519.PublicKey {
	key, _ := parseEd25519PublicKey(value)
	return key
}

func dataPlaneError(writer http.ResponseWriter, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write([]byte(`{"error":"data-plane request rejected"}`))
}

func (s *DataPlaneServer) handleManifest(writer http.ResponseWriter, request *http.Request) {
	body, _, summary, err := s.authorize(request)
	if err != nil || body.Relative != "" || body.ChunkIndex != 0 {
		dataPlaneError(writer, http.StatusForbidden)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Askio-Manifest-Digest", summary.Digest)
	_ = json.NewEncoder(writer).Encode(summary.Manifest)
}

func findManifestEntry(entries []FileManifestEntry, relative string) (FileManifestEntry, bool) {
	index := sort.Search(len(entries), func(index int) bool { return entries[index].Relative >= relative })
	if index < len(entries) && entries[index].Relative == relative {
		return entries[index], true
	}
	return FileManifestEntry{}, false
}

func (s *DataPlaneServer) handleChunk(writer http.ResponseWriter, request *http.Request) {
	body, base, summary, err := s.authorize(request)
	if err != nil || body.ChunkIndex < 0 {
		dataPlaneError(writer, http.StatusForbidden)
		return
	}
	clean, err := cleanRelative(body.Relative)
	if err != nil || clean == "." {
		dataPlaneError(writer, http.StatusBadRequest)
		return
	}
	relative := filepath.ToSlash(clean)
	entry, found := findManifestEntry(summary.Manifest.Entries, relative)
	if !found || entry.Type != "file" || body.ChunkIndex*transferChunkSize >= entry.SizeBytes {
		dataPlaneError(writer, http.StatusNotFound)
		return
	}
	path := filepath.Join(base, filepath.FromSlash(relative))
	file, info, err := openRegularNoFollow(path)
	if err != nil || info.Size() != entry.SizeBytes {
		if file != nil {
			file.Close()
		}
		dataPlaneError(writer, http.StatusConflict)
		return
	}
	defer file.Close()
	offset := body.ChunkIndex * transferChunkSize
	length := transferChunkSize
	if remaining := entry.SizeBytes - offset; remaining < length {
		length = remaining
	}
	buffer := make([]byte, length)
	read, err := file.ReadAt(buffer, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		zeroBytes(buffer)
		dataPlaneError(writer, http.StatusConflict)
		return
	}
	buffer = buffer[:read]
	digest := sha256.Sum256(buffer)
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Askio-Chunk-Digest", "sha256:"+hex.EncodeToString(digest[:]))
	writer.Header().Set("X-Askio-File-Digest", entry.SHA256)
	writer.Header().Set("Content-Length", strconv.Itoa(len(buffer)))
	_, _ = writer.Write(buffer)
	zeroBytes(buffer)
}

type transferBinding struct {
	SchemaVersion string `json:"schema_version"`
	SourceAddress string `json:"source_address"`
}

func parseTransferBinding(raw []byte) (transferBinding, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var binding transferBinding
	if err := decoder.Decode(&binding); err != nil || binding.SchemaVersion != transferBindingSchema {
		return transferBinding{}, errors.New("transfer binding contract is invalid")
	}
	host, port, err := net.SplitHostPort(binding.SourceAddress)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "\x00\r\n\t") {
		return transferBinding{}, errors.New("transfer binding source address is invalid")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return transferBinding{}, errors.New("transfer binding source port is invalid")
	}
	if address := net.ParseIP(host); address != nil && (address.IsUnspecified() || address.IsMulticast()) {
		return transferBinding{}, errors.New("transfer binding source address is denied")
	}
	return binding, nil
}

type dataPlaneClient struct {
	httpClient *http.Client
	address    string
	ticket     DataPlaneTicket
	refresh    func(context.Context, DataPlaneTicket) (DataPlaneTicket, error)
}

func newDataPlaneClient(
	address string,
	identity *Identity,
	ticket DataPlaneTicket,
	refresh ...func(context.Context, DataPlaneTicket) (DataPlaneTicket, error),
) (*dataPlaneClient, error) {
	certificate, err := tlsCertificateForIdentity(identity)
	if err != nil {
		return nil, err
	}
	expectedServer, err := parseEd25519PublicKey(ticket.SourceSigningPublicPEM)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if !peerMatchesPublicKey(&state, expectedServer) {
				return errors.New("data-plane server identity mismatch")
			}
			return nil
		},
	}
	dialer := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 15 * time.Second}
	transport := &http.Transport{
		Proxy: nil, TLSClientConfig: tlsConfig, DisableCompression: true, ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
	client := &dataPlaneClient{httpClient: &http.Client{Transport: transport, Timeout: 2 * time.Minute}, address: address, ticket: ticket}
	if len(refresh) > 0 {
		client.refresh = refresh[0]
	}
	return client, nil
}

func sameDataPlaneScope(left, right DataPlaneTicket) bool {
	return left.SchemaVersion == right.SchemaVersion && left.KeyID == right.KeyID && left.Algorithm == right.Algorithm &&
		left.Audience == right.Audience && left.MigrationID == right.MigrationID && left.RunID == right.RunID &&
		left.AttemptID == right.AttemptID && left.FencingToken == right.FencingToken && left.BindingID == right.BindingID &&
		left.SourceAgentID == right.SourceAgentID && left.TargetAgentID == right.TargetAgentID &&
		left.SourceSigningKeyID == right.SourceSigningKeyID && left.SourceSigningPublicPEM == right.SourceSigningPublicPEM &&
		left.TargetSigningKeyID == right.TargetSigningKeyID && left.TargetSigningPublicPEM == right.TargetSigningPublicPEM &&
		left.SourceRootHandle == right.SourceRootHandle && left.SourceRelativeHandle == right.SourceRelativeHandle &&
		left.ManifestDigest == right.ManifestDigest && left.ChunkSizeBytes == right.ChunkSizeBytes &&
		left.MaximumBytes == right.MaximumBytes
}

func (c *dataPlaneClient) ensureTicket(ctx context.Context) error {
	expiresAt, err := time.Parse(time.RFC3339Nano, c.ticket.ExpiresAt)
	if err != nil {
		return errors.New("direct-transfer ticket expiry is invalid")
	}
	if time.Until(expiresAt) > 75*time.Second {
		return nil
	}
	if c.refresh == nil {
		return errors.New("direct-transfer ticket expired without a refresh path")
	}
	refreshed, err := c.refresh(ctx, c.ticket)
	if err != nil {
		return err
	}
	if !sameDataPlaneScope(c.ticket, refreshed) {
		return errors.New("refreshed direct-transfer ticket changed immutable scope")
	}
	c.ticket = refreshed
	return nil
}

func (c *dataPlaneClient) post(ctx context.Context, path string, request dataPlaneRequest) (*http.Response, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://askio-data-plane"+path, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("User-Agent", "askio-migration-data-plane/1.0")
	return c.httpClient.Do(httpRequest)
}

func (c *dataPlaneClient) manifest(ctx context.Context) (FileManifest, error) {
	if err := c.ensureTicket(ctx); err != nil {
		return FileManifest{}, err
	}
	response, err := c.post(ctx, "/v1/manifest", dataPlaneRequest{Ticket: c.ticket})
	if err != nil {
		return FileManifest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Askio-Manifest-Digest") != c.ticket.ManifestDigest {
		return FileManifest{}, errors.New("direct source manifest request failed")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024*1024))
	decoder.DisallowUnknownFields()
	var manifest FileManifest
	if err := decoder.Decode(&manifest); err != nil || manifest.SchemaVersion != fileManifestSchema || len(manifest.Entries) > maximumManifestEntries {
		return FileManifest{}, errors.New("direct source manifest response is invalid")
	}
	digest, err := Digest(manifest)
	if err != nil || digest != c.ticket.ManifestDigest {
		return FileManifest{}, errors.New("direct source manifest digest mismatch")
	}
	return manifest, nil
}

func (c *dataPlaneClient) chunk(ctx context.Context, relative string, index int64, expectedFileDigest string) ([]byte, string, error) {
	if err := c.ensureTicket(ctx); err != nil {
		return nil, "", err
	}
	response, err := c.post(ctx, "/v1/chunk", dataPlaneRequest{Ticket: c.ticket, Relative: relative, ChunkIndex: index})
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("X-Askio-File-Digest") != expectedFileDigest {
		return nil, "", errors.New("direct source chunk request failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, transferChunkSize+1))
	if err != nil || int64(len(data)) > transferChunkSize {
		zeroBytes(data)
		return nil, "", errors.New("direct source chunk response exceeded its bound")
	}
	digest := sha256.Sum256(data)
	actualDigest := "sha256:" + hex.EncodeToString(digest[:])
	if actualDigest != response.Header.Get("X-Askio-Chunk-Digest") {
		zeroBytes(data)
		return nil, "", errors.New("direct source chunk digest mismatch")
	}
	return data, actualDigest, nil
}
