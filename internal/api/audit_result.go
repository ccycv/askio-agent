package api

import (
	"context"
	"net/http"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

func (c *Client) PostAuditResult(ctx context.Context, payload model.AuditAgentResult) error {
	ep := c.endpoint("audit-agent-result")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}
