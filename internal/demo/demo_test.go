package demo

import (
	"context"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/console"
	"github.com/Blacklotus89898/Warden/internal/services"
	"github.com/Blacklotus89898/Warden/internal/statusmap"
)

// The demo must keep answering every read the pages make, without errors,
// and still tell its story; this fails when a page starts reading something
// the fixture doesn't serve.
func TestDemoServesEveryPage(t *testing.T) {
	ctx := context.Background()
	src := New(time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC))

	m, err := (&statusmap.Builder{Kube: src, Metrics: src}).Build(ctx)
	if err != nil || len(m.Errors) != 0 {
		t.Fatalf("map: %v %v", err, m.Errors)
	}

	sb := &services.Builder{Kube: src, Metrics: src, Kuma: src, MonitorNS: MonitorNS, Now: func() time.Time { return src.Now }}
	v, err := sb.Build(ctx)
	if err != nil || len(v.Errors) != 0 {
		t.Fatalf("services: %v %v", err, v.Errors)
	}
	red := map[string]bool{}
	for _, s := range v.Services {
		red[s.Namespace] = s.Status == "red"
		if s.Signals.Memory == nil {
			t.Errorf("%s: no memory signal", s.Namespace)
		}
	}
	if !red["linkding"] || !red["tulip"] || red["kavita"] {
		t.Errorf("story: want linkding and tulip red, kavita not: %v", red)
	}
	for _, rng := range []string{"6h", "24h", "7d", "30d"} {
		h, err := sb.History(ctx, rng)
		if err != nil || len(h.Errors) != 0 || h.Series["kavita"]["latency"] == nil {
			t.Fatalf("history %s: %v %v", rng, err, h)
		}
	}

	c := &console.Console{Kube: src, Metrics: src, Now: func() time.Time { return src.Now }}
	tl, err := c.Timeline(ctx, "linkding", src.Now.Add(-24*time.Hour))
	if err != nil || len(tl.Errors) != 0 || len(tl.Entries) < 5 {
		t.Fatalf("timeline: %v %+v", err, tl)
	}
	for rng := range console.Ranges {
		tr, err := c.Traffic(ctx, "linkding", rng)
		if err != nil || len(tr.Errors) != 0 || len(tr.Series["requests"]) == 0 {
			t.Fatalf("traffic %s: %v %+v", rng, err, tr)
		}
	}
	b, err := c.Blast(ctx, "linkding")
	if err != nil || len(b.Errors) != 0 || len(b.Callers) == 0 {
		t.Fatalf("blast: %v %+v", err, b)
	}
}
