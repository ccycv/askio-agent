package api

import (
	"context"
	"net/http"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

func (c *Client) PostCommandResult(ctx context.Context, payload model.CommandResult) error {
	ep := c.endpoint("monitor-agent-command-result")
	return c.doJSON(ctx, http.MethodPost, ep, payload, nil)
}
