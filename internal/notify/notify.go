// Package notify posts a plain-text digest to ntfy. The body is already
// redacted and truncated by the caller; ntfy is unauthenticated on the LAN.
package notify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Ntfy posts to one topic.
type Ntfy struct {
	URL      string // http://ntfy.monitoring.svc
	Topic    string
	ClickURL string // optional: where tapping the push goes
	HTTP     *http.Client
}

// Send posts title + body. A no-op when URL is empty.
func (n Ntfy) Send(ctx context.Context, title, body, priority string) error {
	if n.URL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(n.URL, "/")+"/"+n.Topic, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", title)
	req.Header.Set("Tags", "mag")
	if priority != "" {
		req.Header.Set("Priority", priority)
	}
	if n.ClickURL != "" {
		req.Header.Set("Click", n.ClickURL)
	}
	hc := n.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("ntfy: HTTP %d", resp.StatusCode)
	}
	return nil
}
