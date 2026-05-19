package doctor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func probeHealth(ctx context.Context, client *http.Client, baseURL string) error {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	url := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, res.StatusCode)
	}
	return nil
}
