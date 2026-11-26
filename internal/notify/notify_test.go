package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendPublishesJSONWithButtons(t *testing.T) {
	var got map[string]any
	var path, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ctype = r.URL.Path, r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer srv.Close()

	n := Ntfy{URL: srv.URL + "/", Topic: "warden", ClickURL: "https://warden.lab.home/console"}
	err := n.Send(context.Background(), Push{
		Title: "t", Body: "b", Priority: "high",
		Actions: []Action{
			{Label: "Investigation", URL: "https://warden.lab.home/console#/inv/inv_1"},
			{Label: "No URL", URL: ""}, // dropped
			{Label: "What changed", URL: "https://warden.lab.home/console#/ns/a?x=1,2"},
			{Label: "Grafana", URL: "https://grafana.lab.home/d/service-health"},
			{Label: "Fourth", URL: "https://example.invalid/"}, // over MaxActions
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/" || ctype != "application/json" {
		t.Fatalf("posted to %q as %q, want / as application/json", path, ctype)
	}
	if got["topic"] != "warden" || got["priority"] != float64(4) || got["click"] != "https://warden.lab.home/console" {
		t.Fatalf("message = %v", got)
	}
	acts, _ := got["actions"].([]any)
	if len(acts) != MaxActions {
		t.Fatalf("actions = %v, want %d", acts, MaxActions)
	}
	second := acts[1].(map[string]any)
	if second["action"] != "view" || second["url"] != "https://warden.lab.home/console#/ns/a?x=1,2" {
		t.Fatalf("second action = %v (URL must survive verbatim)", second)
	}
	if tags, _ := got["tags"].([]any); len(tags) != 1 || tags[0] != "mag" {
		t.Fatalf("tags = %v, want default [mag]", got["tags"])
	}
}

func TestSendWithoutURLIsNoop(t *testing.T) {
	if err := (Ntfy{}).Send(context.Background(), Push{Title: "x"}); err != nil {
		t.Fatal(err)
	}
}

func TestSendReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	if err := (Ntfy{URL: srv.URL, Topic: "w"}).Send(context.Background(), Push{}); err == nil {
		t.Fatal("want an error for HTTP 429")
	}
}
