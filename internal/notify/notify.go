// Package notify posts a plain-text digest to ntfy. The body is already
// redacted and truncated by the caller; ntfy is unauthenticated on the LAN.
//
// Pushes use ntfy's JSON publishing (POST to the server root) so action
// buttons can carry URLs with '?', '=' and '#' without the header format's
// quoting rules.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MaxActions is ntfy's limit on buttons per notification.
const MaxActions = 3

// Action is a "view" button: tapping it opens URL.
type Action struct {
	Label string
	URL   string
}

// Push is one notification.
type Push struct {
	Title    string
	Body     string
	Priority string   // min, low, default, high, max ("" = default)
	Click    string   // where tapping the notification goes ("" = Ntfy.ClickURL)
	Tags     []string // emoji shortcodes; nil = "mag"
	Actions  []Action // at most MaxActions; extras are dropped
}

// Ntfy posts to one topic.
type Ntfy struct {
	URL      string // http://ntfy.monitoring.svc
	Topic    string
	ClickURL string // optional default for where tapping the push goes
	HTTP     *http.Client
}

var priorities = map[string]int{"min": 1, "low": 2, "default": 3, "high": 4, "max": 5, "urgent": 5}

type message struct {
	Topic    string   `json:"topic"`
	Title    string   `json:"title,omitempty"`
	Message  string   `json:"message"`
	Priority int      `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Click    string   `json:"click,omitempty"`
	Actions  []action `json:"actions,omitempty"`
}

type action struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	URL    string `json:"url"`
}

// Send posts p. A no-op when URL is empty.
func (n Ntfy) Send(ctx context.Context, p Push) error {
	if n.URL == "" {
		return nil
	}
	m := message{Topic: n.Topic, Title: p.Title, Message: p.Body, Priority: priorities[p.Priority], Tags: p.Tags, Click: p.Click}
	if m.Tags == nil {
		m.Tags = []string{"mag"}
	}
	if m.Click == "" {
		m.Click = n.ClickURL
	}
	for _, a := range p.Actions {
		if a.Label == "" || a.URL == "" {
			continue
		}
		if len(m.Actions) == MaxActions {
			break
		}
		m.Actions = append(m.Actions, action{Action: "view", Label: a.Label, URL: a.URL})
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(n.URL, "/")+"/", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
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
