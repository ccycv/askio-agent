package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/askio-cloud/askio-monitor/internal/vulnerability"
)

// Inventory has its own bounded, strict protocol. It never exposes arbitrary
// routes, raw commands or response bodies in errors/logs.
func (c *Client) inventoryJSON(ctx context.Context, route string, input any, output any) error {
	encoded, e := json.Marshal(input)
	limit := vulnerability.MaxPageBytes
	if completion, ok := input.(vulnerability.Completion); ok && route == "monitor-agent-inventory-complete" && completion.Capture.Collector.Version == vulnerability.ProvenanceCollectorVersion {
		limit = vulnerability.MaxProvenanceCompletionBytes
	}
	if e != nil || len(encoded) > limit {
		return errors.New("inventory request budget exceeded")
	}
	endpoint := c.endpoint(route)
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if e != nil {
		return errors.New("invalid inventory request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", c.userAgent)
	// Copy the configured transport and TLS policy, but refuse redirects so a
	// response cannot move the authenticated inventory request to another URL.
	client := *c.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, e := client.Do(req)
	if e != nil {
		return errors.New("inventory transport failed")
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, vulnerability.MaxPageBytes+1))
	if e != nil || len(data) > vulnerability.MaxPageBytes {
		return errors.New("inventory response budget exceeded")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("inventory request refused")
	}
	if output == nil {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(output); e != nil {
		return errors.New("invalid inventory response")
	}
	if e = decoder.Decode(new(any)); e != io.EOF {
		return errors.New("invalid inventory response trailing data")
	}
	return nil
}
func (c *Client) ClaimInventory(ctx context.Context, in vulnerability.Claim) (vulnerability.Assignment, error) {
	var out vulnerability.Assignment
	e := c.inventoryJSON(ctx, "monitor-agent-inventory-claim", in, &out)
	return out, e
}
func (c *Client) UploadInventoryPage(ctx context.Context, in vulnerability.Page) error {
	return c.inventoryJSON(ctx, "monitor-agent-inventory-page", in, nil)
}
func (c *Client) CompleteInventory(ctx context.Context, in vulnerability.Completion) error {
	return c.inventoryJSON(ctx, "monitor-agent-inventory-complete", in, nil)
}
