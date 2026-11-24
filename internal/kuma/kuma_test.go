package kuma

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Trimmed from a real /api/status-page/homelab + heartbeat response (2026-11-24).
const pageJSON = `{"config":{"slug":"homelab"},"incidents":[],"publicGroupList":[
 {"id":7,"name":"Apps","monitorList":[{"id":22,"name":"Kavita","type":"http"},{"id":23,"name":"Linkding","type":"http"}]},
 {"id":9,"name":"Front door (Istio gateway)","monitorList":[{"id":30,"name":"kavita.lab.home","type":"http","certExpiryDaysRemaining":3600,"validCert":true}]},
 {"id":10,"name":"Home network","monitorList":[{"id":41,"name":"Proxmox","type":"http","certExpiryDaysRemaining":""}]}]}`

const beatsJSON = `{"heartbeatList":{
 "22":[{"status":1,"time":"2026-11-24 01:46:11.391","msg":"","ping":6},{"status":1,"time":"2026-11-24 01:47:11.391","msg":"","ping":8}],
 "30":[{"status":1,"time":"2026-11-24 01:47:00.000","msg":"","ping":20}],
 "41":[{"status":1,"time":"2026-11-24 01:46:00.000","msg":"","ping":3},{"status":0,"time":"2026-11-24 01:47:00.000","msg":"connect ECONNREFUSED 192.168.0.10:8006 token=abc123","ping":null}]},
 "uptimeList":{"22_24":1,"30_24":0.9993,"41_24":0.5}}`

func TestFetch(t *testing.T) {
	var got []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("non-GET %s", r.Method)
		}
		got = append(got, r.URL.Path)
		switch r.URL.Path {
		case "/api/status-page/homelab":
			_, _ = w.Write([]byte(pageJSON))
		case "/api/status-page/heartbeat/homelab":
			_, _ = w.Write([]byte(beatsJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := &Client{Base: ts.URL, Slug: "homelab"}
	ms, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != c.Paths()[0] || got[1] != c.Paths()[1] {
		t.Fatalf("requested %v, want exactly %v", got, c.Paths())
	}
	if len(ms) != 4 {
		t.Fatalf("got %d monitors", len(ms))
	}
	by := map[string]Monitor{}
	for _, m := range ms {
		by[m.Name] = m
	}

	k := by["Kavita"]
	if k.State != "up" || k.Group != "Apps" || *k.Uptime24 != 1 || *k.PingMs != 8 || *k.AvgMs != 7 || len(k.Recent) != 2 {
		t.Errorf("Kavita = %+v", k)
	}
	if l := by["Linkding"]; l.State != "unknown" || l.Uptime24 != nil {
		t.Errorf("a monitor with no beats is unknown, got %+v", l)
	}
	if d := by["kavita.lab.home"].CertDays; d == nil || *d != 3600 {
		t.Errorf("cert days = %v", d)
	}
	p := by["Proxmox"]
	if p.State != "down" || p.CertDays != nil || p.PingMs != nil {
		t.Errorf("Proxmox = %+v", p)
	}
	if p.Msg == "" || strings.Contains(p.Msg, "abc123") {
		t.Errorf("down message must be kept and redacted, got %q", p.Msg)
	}
}

func TestFetchHTTPError(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	if _, err := (&Client{Base: ts.URL, Slug: "nope"}).Fetch(context.Background()); err == nil {
		t.Fatal("want an error for a missing status page")
	}
}
