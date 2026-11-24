package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/vm"
)

type fakeRange struct {
	fakeVM
	mu    sync.Mutex
	exprs []string
	steps []time.Duration
}

func (f *fakeRange) QueryRange(_ context.Context, expr string, start, end time.Time, step time.Duration, _ int) ([]vm.Series, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.exprs = append(f.exprs, expr)
	f.steps = append(f.steps, step)
	if strings.Contains(expr, "histogram_quantile") {
		return nil, errors.New("boom")
	}
	lbl := "destination_service_namespace"
	if strings.Contains(expr, "container_") {
		lbl = "namespace"
	}
	return []vm.Series{{Labels: map[string]string{lbl: "kavita"}, Points: [][2]float64{
		{float64(start.Unix()), 1}, {float64(start.Unix()) + 600, 1}, {float64(start.Unix()) + 1200, 9}, {float64(end.Unix()), 2},
	}}}, nil
}

func TestHistory(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 3, 0, 0, time.UTC)
	f := &fakeRange{}
	b := &Builder{Metrics: f, Now: func() time.Time { return now }}
	if _, err := b.History(context.Background(), "1y"); err == nil {
		t.Error("unknown range must be refused")
	}
	h, err := b.History(context.Background(), "24h")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.exprs) != 5 || len(h.Errors) != 1 || !strings.HasPrefix(h.Errors[0], "latency") {
		t.Fatalf("exprs %d errors %v", len(f.exprs), h.Errors)
	}
	for i, e := range f.exprs {
		if f.steps[i] != 10*time.Minute || !strings.Contains(e, "[600s]") {
			t.Errorf("24h: every point must cover its 10m step: %s", e)
		}
	}
	tr := h.Series["kavita"]["traffic"]
	if tr == nil || tr.Min != 1 || tr.Max != 9 || tr.Last != 2 || tr.Median != 1.5 || tr.Spread == nil || *tr.Spread != 6 {
		t.Errorf("trend = %+v", tr)
	}
	if h.Series["kavita"]["memory"] == nil || h.Series["kavita"]["latency"] != nil {
		t.Errorf("series = %+v", h.Series["kavita"])
	}

	f.exprs = nil
	if _, err := b.History(context.Background(), "6h"); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.exprs {
		if strings.Contains(e, "[120s]") {
			t.Errorf("rate window must stay at least 5m: %s", e)
		}
	}
	if _, err := (&Builder{Metrics: fakeVM{}}).History(context.Background(), "6h"); err == nil {
		t.Error("an instant-only source must be refused, not return empty graphs")
	}
}

func TestErrorShareIsZeroWithoutAny5xx(t *testing.T) {
	e := QueriesFor("5m")["errors"].Expr
	if !strings.Contains(e, " or (") || !strings.Contains(e, "* 0") {
		t.Errorf("a namespace that never served a 5xx must read 0, not no data: %s", e)
	}
}
