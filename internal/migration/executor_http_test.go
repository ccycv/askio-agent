package migration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func validationInputs(t *testing.T, rawURL string) map[string]any {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"url":           rawURL,
		"allowed_hosts": []any{parsed.Hostname()},
		"allowed_ips":   []any{"127.0.0.1"},
	}
}

func TestHTTPValidationPinsSchemeHostPortAndIgnoresProxyEnvironment(t *testing.T) {
	otherRequests := 0
	other := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		otherRequests++
		response.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()

	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/same-origin", func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, "/ok", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/other-port", func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, other.URL, http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/other-scheme", func(response http.ResponseWriter, request *http.Request) {
		location := "https://" + request.Host + "/ok"
		http.Redirect(response, request, location, http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/other-host", func(response http.ResponseWriter, request *http.Request) {
		_, port, _ := net.SplitHostPort(request.Host)
		http.Redirect(response, request, fmt.Sprintf("http://localhost:%s/ok", port), http.StatusTemporaryRedirect)
	})
	server = httptest.NewServer(mux)
	defer server.Close()

	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	outputs, err := validateHTTP(context.Background(), validationInputs(t, server.URL+"/same-origin"))
	if err != nil {
		t.Fatal(err)
	}
	if outputs["status_code"] != http.StatusNoContent || outputs["redirects"] != 1 {
		t.Fatalf("unexpected bounded validation output: %#v", outputs)
	}

	for _, path := range []string{"/other-port", "/other-scheme", "/other-host"} {
		if _, err := validateHTTP(context.Background(), validationInputs(t, server.URL+path)); err == nil {
			t.Fatalf("expected redirect scope rejection for %s", path)
		}
	}
	if otherRequests != 0 {
		t.Fatal("the validator followed a redirect to an unapproved port")
	}
}

func TestHTTPValidationRejectsMalformedIPScopeAndMetadataAddresses(t *testing.T) {
	inputs := map[string]any{
		"url":           "http://127.0.0.1:8080/health",
		"allowed_hosts": []any{"127.0.0.1"},
		"allowed_ips":   []any{"999.999.999.999"},
	}
	if _, err := validateHTTP(context.Background(), inputs); err == nil {
		t.Fatal("expected malformed validation IP scope to be rejected")
	}

	for _, value := range []string{
		"127.0.0.1", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "192.0.0.192",
		"10.0.0.1", "172.16.0.1", "192.168.0.1", "fd00:ec2::254", "::", "224.0.0.1",
	} {
		address := net.ParseIP(value)
		if address == nil || !deniedAddress(address, map[string]struct{}{}) {
			t.Fatalf("expected denied validation address %s", value)
		}
	}
	allowed := map[string]struct{}{net.ParseIP("10.0.0.1").String(): {}}
	if deniedAddress(net.ParseIP("10.0.0.1"), allowed) {
		t.Fatal("explicitly scoped private endpoint was rejected")
	}
}
