package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"crypto/x509"
	"os"
	"time"

	"github.com/askio-cloud/askio-monitor/internal/version"
)

type Client struct {
	baseURL   *url.URL
	token     string
	http      *http.Client
	userAgent string
}

type Options struct {
	BaseURL   string
	Token     string
	Timeout   time.Duration
	UserAgent string
	TLSSkipVerify bool
	CACertPath string
}

func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "askio-monitor/" + version.Version
	}

	tr := &http.Transport{}
	if u.Scheme == "https" {
		tlsCfg := &tls.Config{}
		if opts.CACertPath != "" {
			b, err := os.ReadFile(opts.CACertPath)
			if err != nil {
				return nil, fmt.Errorf("read ca_cert_path: %w", err)
			}
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if ok := pool.AppendCertsFromPEM(b); !ok {
				return nil, fmt.Errorf("ca_cert_path does not contain any valid PEM certificates")
			}
			tlsCfg.RootCAs = pool
		} else if opts.TLSSkipVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		tr.TLSClientConfig = tlsCfg
	}
	return &Client{
		baseURL:   u,
		token:     opts.Token,
		http:      &http.Client{Timeout: opts.Timeout, Transport: tr},
		userAgent: ua,
	}, nil
}

func (c *Client) endpoint(p string) string {
	u := *c.baseURL
	u.Path = path.Join(u.Path, p)
	return u.String()
}

func (c *Client) doJSON(ctx context.Context, method, endpoint string, in any, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api %s %s failed: status=%d body=%s", method, endpoint, resp.StatusCode, string(rb))
	}
	if out == nil {
		return nil
	}
	if len(rb) == 0 {
		return nil
	}
	return json.Unmarshal(rb, out)
}

func (c *Client) GetConfig(ctx context.Context, serverID string, out any) error {
	ep := c.endpoint("monitor-agent-config")
	if serverID != "" {
		ep = ep + "?server_id=" + url.QueryEscape(serverID)
	}
	return c.doJSON(ctx, http.MethodGet, ep, nil, out)
}

func (c *Client) PostHeartbeat(ctx context.Context, payload any) error {
	ep := c.endpoint("monitor-agent-heartbeat")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}

func (c *Client) PostResults(ctx context.Context, payload any) error {
	ep := c.endpoint("monitor-agent-results")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}

func (c *Client) PostRemediationLog(ctx context.Context, payload any) error {
	ep := c.endpoint("monitor-agent-remediation-log")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}

func (c *Client) PostDiscoveredServices(ctx context.Context, payload any) error {
	ep := c.endpoint("monitor-agent-discovered-services")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}

func (c *Client) PostOperationsResult(ctx context.Context, payload any) error {
	ep := c.endpoint("operations-agent-result")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}
