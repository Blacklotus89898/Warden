// Package kuma reads Uptime Kuma's public status page: every monitor on it,
// its group, current state, 24h uptime and response time. These are the two
// unauthenticated JSON endpoints that page's own UI uses, so Warden needs no
// Kuma credentials and can't reach anything a browser on the LAN couldn't.
// Only monitors placed on the status page are visible.
package kuma

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Blacklotus89898/Warden/internal/redact"
)

// Client reads one status page.
type Client struct {
	Base string // http://uptime-kuma.monitoring.svc:3001
	Slug string // homelab
	HTTP *http.Client
}

// Paths returns the only two URLs the client ever requests (pinned by the
// boundary test).
func (c *Client) Paths() []string {
	s := url.PathEscape(c.Slug)
	return []string{"/api/status-page/" + s, "/api/status-page/heartbeat/" + s}
}

// Monitor is one status-page monitor, as of its latest heartbeat.
type Monitor struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	Group    string   `json:"group"`
	Type     string   `json:"type"`
	State    string   `json:"state"`              // up | down | pending | maintenance | unknown
	Uptime24 *float64 `json:"uptime24,omitempty"` // 0..1
	PingMs   *int     `json:"pingMs,omitempty"`   // latest
	AvgMs    *int     `json:"avgMs,omitempty"`    // over the beats returned
	Last     string   `json:"last,omitempty"`     // latest heartbeat time (Kuma's clock, UTC)
	Msg      string   `json:"msg,omitempty"`      // latest message when not up (redacted)
	Recent   []string `json:"recent,omitempty"`   // last beats, oldest first: up | down | pending | maintenance
	CertDays *int     `json:"certDays,omitempty"`
}

// RecentBeats is how many heartbeats Monitor.Recent keeps.
const RecentBeats = 30

func state(code int) string {
	switch code {
	case 0:
		return "down"
	case 1:
		return "up"
	case 2:
		return "pending"
	case 3:
		return "maintenance"
	}
	return "unknown"
}

// Fetch reads the page and its heartbeats.
func (c *Client) Fetch(ctx context.Context) ([]Monitor, error) {
	p := c.Paths()
	var page struct {
		PublicGroupList []struct {
			Name        string `json:"name"`
			MonitorList []struct {
				ID       int    `json:"id"`
				Name     string `json:"name"`
				Type     string `json:"type"`
				CertDays any    `json:"certExpiryDaysRemaining"`
			} `json:"monitorList"`
		} `json:"publicGroupList"`
	}
	if err := c.get(ctx, p[0], &page); err != nil {
		return nil, err
	}
	var hb struct {
		HeartbeatList map[string][]struct {
			Status int    `json:"status"`
			Time   string `json:"time"`
			Msg    string `json:"msg"`
			Ping   *int   `json:"ping"`
		} `json:"heartbeatList"`
		UptimeList map[string]float64 `json:"uptimeList"`
	}
	if err := c.get(ctx, p[1], &hb); err != nil {
		return nil, err
	}
	var out []Monitor
	for _, g := range page.PublicGroupList {
		for _, m := range g.MonitorList {
			mon := Monitor{ID: m.ID, Name: m.Name, Group: g.Name, Type: m.Type, State: "unknown"}
			if n, ok := certDays(m.CertDays); ok {
				mon.CertDays = &n
			}
			key := strconv.Itoa(m.ID)
			if u, ok := hb.UptimeList[key+"_24"]; ok {
				mon.Uptime24 = &u
			}
			beats := hb.HeartbeatList[key]
			if len(beats) > 0 {
				last := beats[len(beats)-1]
				mon.State, mon.Last, mon.PingMs = state(last.Status), last.Time, last.Ping
				if last.Status != 1 && last.Msg != "" {
					mon.Msg = redact.Truncate(redact.String(last.Msg), 200)
				}
				sum, n := 0, 0
				for _, b := range beats {
					if b.Ping != nil {
						sum, n = sum+*b.Ping, n+1
					}
				}
				if n > 0 {
					avg := sum / n
					mon.AvgMs = &avg
				}
				from := max(0, len(beats)-RecentBeats)
				for _, b := range beats[from:] {
					mon.Recent = append(mon.Recent, state(b.Status))
				}
			}
			out = append(out, mon)
		}
	}
	return out, nil
}

// certDays: Kuma sends a number, or "" when the monitor has no certificate.
func certDays(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	}
	return 0, false
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Base, "/")+path, nil)
	if err != nil {
		return err
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("kuma: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kuma: %s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("kuma: %s: decode: %w", path, err)
	}
	return nil
}
