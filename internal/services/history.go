package services

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Blacklotus89898/Warden/internal/vm"
)

// RangeMetrics runs range queries (vm.Client implements it).
type RangeMetrics interface {
	QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration, max int) ([]vm.Series, error)
}

// Span is one selectable history range. Each point covers Step (the rate
// window is the step, at least 5m), so nothing between two points is skipped:
// a short burst still moves the point it falls in.
type Span struct {
	Range time.Duration
	Step  time.Duration
}

// Spans are the ranges /services/history.json accepts (vmsingle keeps 30d).
var Spans = map[string]Span{
	"6h":  {6 * time.Hour, 2 * time.Minute},
	"24h": {24 * time.Hour, 10 * time.Minute},
	"7d":  {7 * 24 * time.Hour, time.Hour},
	"30d": {30 * 24 * time.Hour, 4 * time.Hour},
}

// Trend is one signal of one namespace over the range, with the numbers that
// show how much it moved. Spread is max/median (1 = flat); nil when the
// median is 0.
type Trend struct {
	Points [][2]float64 `json:"points"` // [unix seconds, value]
	Min    float64      `json:"min"`
	Median float64      `json:"median"`
	Max    float64      `json:"max"`
	MaxAt  float64      `json:"maxAt"`
	Last   float64      `json:"last"`
	Spread *float64     `json:"spread,omitempty"`
}

// History is every namespace's signals over one range.
type History struct {
	Range  string                       `json:"range"`
	Step   string                       `json:"step"`
	Start  time.Time                    `json:"start"`
	End    time.Time                    `json:"end"`
	Series map[string]map[string]*Trend `json:"series"` // namespace → signal → trend
	Errors []string                     `json:"errors,omitempty"`
}

// MaxPoints bounds one series (the longest span has 180).
const MaxPoints = 400

// History reads the golden signals over rng. A failing query is listed in
// Errors; History only fails on an unknown range or no range-capable source.
func (b *Builder) History(ctx context.Context, rng string) (*History, error) {
	sp, ok := Spans[rng]
	if !ok {
		return nil, fmt.Errorf("services: unknown range %q", rng)
	}
	rm, ok := b.Metrics.(RangeMetrics)
	if !ok {
		return nil, fmt.Errorf("services: metrics source has no range queries")
	}
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	end := now().UTC().Truncate(sp.Step)
	start := end.Add(-sp.Range)
	w := sp.Step
	if w < 5*time.Minute {
		w = 5 * time.Minute
	}
	h := &History{Range: rng, Step: sp.Step.String(), Start: start, End: end, Series: map[string]map[string]*Trend{}}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for sig, q := range QueriesFor(strconv.Itoa(int(w.Seconds())) + "s") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			series, err := rm.QueryRange(ctx, q.Expr, start, end, sp.Step, 0)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				h.Errors = append(h.Errors, sig+": "+err.Error())
				return
			}
			for _, s := range series {
				ns := s.Labels[q.Label]
				if ns == "" || len(s.Points) == 0 {
					continue
				}
				if h.Series[ns] == nil {
					h.Series[ns] = map[string]*Trend{}
				}
				h.Series[ns][sig] = trend(s.Points)
			}
		}()
	}
	wg.Wait()
	sort.Strings(h.Errors)
	return h, nil
}

func trend(pts [][2]float64) *Trend {
	if len(pts) > MaxPoints {
		pts = pts[len(pts)-MaxPoints:]
	}
	t := &Trend{Points: pts, Min: pts[0][1], Max: pts[0][1], MaxAt: pts[0][0], Last: pts[len(pts)-1][1]}
	vals := make([]float64, len(pts))
	for i, p := range pts {
		vals[i] = p[1]
		if p[1] < t.Min {
			t.Min = p[1]
		}
		if p[1] > t.Max {
			t.Max, t.MaxAt = p[1], p[0]
		}
	}
	sort.Float64s(vals)
	if n := len(vals); n%2 == 1 {
		t.Median = vals[n/2]
	} else {
		t.Median = (vals[n/2-1] + vals[n/2]) / 2
	}
	if t.Median > 0 {
		s := t.Max / t.Median
		t.Spread = &s
	}
	return t
}
