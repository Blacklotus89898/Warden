package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

func TestParseSummaryAt(t *testing.T) {
	if s, err := ParseSummaryAt("", "America/Toronto"); err != nil || s.enabled() {
		t.Fatalf("empty = off, got %+v %v", s, err)
	}
	for _, bad := range []string{"8", "24:00", "08:60", "ab:cd"} {
		if _, err := ParseSummaryAt(bad, ""); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
	if _, err := ParseSummaryAt("08:00", "Mars/Olympus"); err == nil {
		t.Error("unknown zone: want an error")
	}
	s, err := ParseSummaryAt("08:05", "America/Toronto")
	if err != nil || !s.enabled() || s.Hour != 8 || s.Minute != 5 {
		t.Fatalf("got %+v %v", s, err)
	}
}

func TestSummaryNext(t *testing.T) {
	s, _ := ParseSummaryAt("08:00", "America/Toronto")
	loc := s.Loc
	cases := []struct{ now, want time.Time }{
		{time.Date(2026, 11, 25, 7, 59, 0, 0, loc), time.Date(2026, 11, 25, 8, 0, 0, 0, loc)},
		{time.Date(2026, 11, 25, 8, 0, 0, 0, loc), time.Date(2026, 11, 26, 8, 0, 0, 0, loc)}, // strictly after
		{time.Date(2026, 11, 25, 23, 0, 0, 0, loc), time.Date(2026, 11, 26, 8, 0, 0, 0, loc)},
		// DST ends 2026-11-01 in Toronto: still 08:00 local, not 07:00.
		{time.Date(2026, 10, 31, 9, 0, 0, 0, loc), time.Date(2026, 11, 1, 8, 0, 0, 0, loc)},
	}
	for _, c := range cases {
		if got := s.next(c.now.UTC()); !got.Equal(c.want) {
			t.Errorf("next(%v) = %v, want %v", c.now, got, c.want)
		}
	}
}

type fakeDisk struct{ samples []vm.Sample }

func (f fakeDisk) Query(context.Context, string, int) ([]vm.Sample, error) { return f.samples, nil }

func TestBuildSummary(t *testing.T) {
	s, _, n := setup(t, true, 40)
	s.PublicURL = "https://warden.lab.home"
	s.Summary.Disk = fakeDisk{[]vm.Sample{
		{Labels: map[string]string{"nodename": "k3s-worker-01"}, Value: "82.4"},
		{Labels: map[string]string{"nodename": "debian"}, Value: "60"},
	}}
	ctx := context.Background()
	s.Accept(ctx, alert.Payload{Alerts: []alert.Alert{firing("ContainerOOMKilled", "fp1", time.Now())}})
	waitFor(t, func() bool { return n.count() == 1 })

	p := s.BuildSummary(ctx)
	for _, want := range []string{
		"Last 24h: 1 alert investigations, 0 by you",
		"Not yet diagnosed (7d): 1",
		"Pushes: 1 sent, 0 grouped, 0 skipped",
		"Disk: debian 60%, k3s-worker-01 82% ⚠",
	} {
		if !strings.Contains(p.Body, want) {
			t.Errorf("body lacks %q:\n%s", want, p.Body)
		}
	}
	if p.Title != "Warden daily: all green" || p.Priority != "low" {
		t.Errorf("title/priority = %q/%q", p.Title, p.Priority)
	}
	if p.Click != "https://warden.lab.home/services" || len(p.Actions) != 3 || p.Actions[0].URL != "https://warden.lab.home/map" {
		t.Errorf("click/actions = %q %+v", p.Click, p.Actions)
	}

	s.SendSummary(ctx)
	if got, _ := s.J.CountSince(ctx, KindSummary, time.Now().Add(-time.Minute)); got != 1 {
		t.Errorf("summary journaled %d times, want 1", got)
	}
	if n.last() != p.Title {
		t.Errorf("last push = %q, want the summary", n.last())
	}
}

func TestDigestHasButtons(t *testing.T) {
	s, _, n := setup(t, true, 40)
	s.PublicURL = "https://warden.lab.home"
	s.GrafanaURL = "https://grafana.lab.home/d/service-health"
	s.Accept(context.Background(), alert.Payload{Alerts: []alert.Alert{firing("ContainerOOMKilled", "fp1", time.Now())}})
	waitFor(t, func() bool { return n.count() == 1 })

	n.mu.Lock()
	p := n.pushes[0]
	n.mu.Unlock()
	if !strings.HasPrefix(p.Click, "https://warden.lab.home/console#/inv/inv_") {
		t.Fatalf("click = %q", p.Click)
	}
	var labels []string
	for _, a := range p.Actions {
		labels = append(labels, a.Label+"="+a.URL)
	}
	want := []string{
		"Investigation=" + p.Click,
		"What changed=https://warden.lab.home/console#/ns/petal",
		"Grafana=https://grafana.lab.home/d/service-health",
	}
	if strings.Join(labels, " ") != strings.Join(want, " ") {
		t.Fatalf("actions = %v, want %v", labels, want)
	}
}
