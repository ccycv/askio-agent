package checks

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

type HTTPResult struct {
	StatusCode int
	LatencyMS  int64
	BodyPrefix string
}

func HTTPGet(ctx context.Context, url string, timeout time.Duration) (HTTPResult, error) {
	if url == "" {
		return HTTPResult{}, fmt.Errorf("http url empty")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HTTPResult{}, err
	}
	resp, err := client.Do(req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return HTTPResult{LatencyMS: lat}, nil
	}
	defer resp.Body.Close()

	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)

	return HTTPResult{
		StatusCode: resp.StatusCode,
		LatencyMS:  lat,
		BodyPrefix: string(buf[:n]),
	}, nil
}
