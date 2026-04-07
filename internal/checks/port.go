package checks

import (
	"context"
	"fmt"
	"net"
	"time"
)

func PortOpen(ctx context.Context, host string, port int, timeout time.Duration) (bool, int64, error) {
	if port <= 0 || port > 65535 {
		return false, 0, fmt.Errorf("invalid port: %d", port)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, port))
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return false, lat, nil
	}
	_ = conn.Close()
	return true, lat, nil
}
