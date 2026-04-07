package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestClient_CACertPath_AllowsSelfSignedServer(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()

	certDER := s.TLS.Certificates[0].Certificate[0]
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.crt")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without CA: New() succeeds, request should fail.
	c0, err := New(Options{BaseURL: s.URL, Token: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c0.doJSON(context.Background(), http.MethodGet, c0.endpoint(""), nil, nil); err == nil {
		t.Fatalf("expected TLS verification error without ca_cert_path")
	}

	// With CA should succeed to perform request.
	c, err := New(Options{BaseURL: s.URL, Token: "x", CACertPath: caPath})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.doJSON(context.Background(), http.MethodGet, c.endpoint(""), nil, nil); err != nil {
		// Note: endpoint(" ") will be base URL path joined; this is fine for httptest server root.
		t.Fatalf("expected success, got %v", err)
	}
}

func TestClient_TLSSkipVerify_AllowsSelfSignedServer(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer s.Close()

	c, err := New(Options{BaseURL: s.URL, Token: "x", TLSSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.doJSON(context.Background(), http.MethodGet, c.endpoint(""), nil, nil); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}
