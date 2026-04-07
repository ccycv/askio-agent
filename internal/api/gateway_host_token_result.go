package api

import (
	"context"

	"github.com/askio-cloud/askio-monitor/internal/model"
)

func (c *Client) PostGatewayHostTokenResult(ctx context.Context, payload model.GatewayHostTokenResult) error {
	ep := c.endpoint("gateway-host-token-result")
	return c.doJSON(ctx, "POST", ep, payload, nil)
}

