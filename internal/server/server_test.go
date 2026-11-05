package server

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/journal"
)

type fakeRunner struct {
	mu  sync.Mutex
	ran []string
}

func (f *fakeRunner) Run(_ context.Context, id string, a alert.Alert) *investigate.Bundle {
	f.mu.Lock()
	f.ran = append(f.ran, a.Name())
	f.mu.Unlock()
	return &investigate.Bundle{ID: id, Alert: a, Namespace: a.Namespace(), Duration: "1ms"}
}

type fakeNotify struct {
	mu     sync.Mutex
	titles []string
}

func (f *fakeNotify) Send(_ context.Context, title, _, _ string) error {
	f.mu.Lock()
	f.titles = append(f.titles, title)
	f.mu.Unlock()
	return nil
}

func (f *fakeNotify) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.titles)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func (f *fakeNotify) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.titles) == 0 {
		return ""
	}
	return f.titles[len(f.titles)-1]
}

// setupClock is setup with a controllable clock (enabled).
func setupClock(t *testing.T, cap int) (*Server, *fakeRunner, *fakeNotify, *clock) {
	t.Helper()
	clk := &clock{t: time.Now()}
	s, r, n := setupWith(t, true, cap, clk.now)
	return s, r, n, clk
}

func setup(t *testing.T, enabled bool, cap int) (*Server, *fakeRunner, *fakeNotify) {
	return setupWith(t, enabled, cap, nil)
}

func setupWith(t *testing.T, enabled bool, cap int, now func() time.Time) (*Server, *fakeRunner, *fakeNotify) {
	t.Helper()
	j, err := journal.Open(context.Background(), filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	r, n := &fakeRunner{}, &fakeNotify{}
	s := &Server{J: j, Runner: r, Notify: n, Enabled: enabled, DailyCap: cap, Now: now}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.Start(ctx)
	return s, r, n
}

func firing(name, fp string, at time.Time) alert.Alert {
	return alert.Alert{Status: "firing", Fingerprint: fp, StartsAt: at,
		Labels: map[string]string{"alertname": name, "namespace": "petal", "severity": "warning"}}
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func kindCount(t *testing.T, s *Server, kind string) int {
	evs, err := s.J.List(context.Background(), kind, 500)
	if err != nil {
		t.Fatal(err)
	}
	return len(evs)
}

func TestEachFiringIsInvestigatedOnce(t *testing.T) {
	ctx := context.Background()
	s, r, n, clk := setupClock(t, 40)
	t0 := time.Now().Add(-time.Hour)
	p := alert.Payload{Alerts: []alert.Alert{firing("KubePodCrashLooping", "fp1", t0),
		{Status: "resolved", Fingerprint: "fp2", Labels: map[string]string{"alertname": "Done"}}}}

	if q := s.Accept(ctx, p); q != 1 {
		t.Fatalf("queued %d, want 1 (resolved alerts are not investigated)", q)
	}
	waitFor(t, func() bool { return n.count() == 1 })
	// alertmanager re-sends every group_interval / repeat_interval: no repeat.
	if q := s.Accept(ctx, p); q != 0 {
		t.Fatalf("re-send queued %d", q)
	}
	// A NEW firing of the same alert is a new incident, once the group window
	// has passed (inside it, see TestSameNamespaceIsGrouped).
	clk.add(GroupWindow + time.Minute)
	if q := s.Accept(ctx, alert.Payload{Alerts: []alert.Alert{firing("KubePodCrashLooping", "fp1", t0.Add(30*time.Minute))}}); q != 1 {
		t.Fatalf("new firing queued %d", q)
	}
	waitFor(t, func() bool { return n.count() == 2 })
	if len(r.ran) != 2 || kindCount(t, s, KindInvestigated) != 2 || kindCount(t, s, KindNotified) != 2 {
		t.Errorf("ran %v, journal investigated %d notified %d", r.ran, kindCount(t, s, KindInvestigated), kindCount(t, s, KindNotified))
	}
}

func TestDisabledJournalsAndDoesNothing(t *testing.T) {
	s, r, n := setup(t, false, 40)
	if q := s.Accept(context.Background(), alert.Payload{Alerts: []alert.Alert{firing("X", "fp", time.Now())}}); q != 0 {
		t.Fatalf("queued %d", q)
	}
	time.Sleep(50 * time.Millisecond)
	if len(r.ran) != 0 || n.count() != 0 || kindCount(t, s, KindSkipped) != 1 {
		t.Errorf("disabled must only journal a skip")
	}
}

// The cap bounds phone pushes; intake is bounded at 4x so a storm of
// grouped alerts (reads, no push) cannot blind Warden for the day.
func TestDailyCap(t *testing.T) {
	s, r, n, _ := setupClock(t, 2)
	var as []alert.Alert
	for i := 0; i < 10; i++ {
		a := firing("A", string(rune('a'+i)), time.Now())
		a.Labels["namespace"] = "ns-" + string(rune('a'+i)) // distinct: nothing groups
		as = append(as, a)
	}
	if q := s.Accept(context.Background(), alert.Payload{Alerts: as}); q != 8 {
		t.Fatalf("queued %d, want the intake bound (4 x 2)", q)
	}
	waitFor(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.ran) == 8 })
	waitFor(t, func() bool { return kindCount(t, s, KindSkipped) == 2+6 })
	if n.count() != 2 {
		t.Errorf("pushed %d, want the cap (2)", n.count())
	}
}

// 2026-11-05: ArgoCD's door went down, then burned its SLO 2 min later.
// Same namespace within GroupWindow = one push, two journaled bundles.
func TestSameNamespaceIsGrouped(t *testing.T) {
	ctx := context.Background()
	s, r, n, clk := setupClock(t, 40)
	s.Accept(ctx, alert.Payload{Alerts: []alert.Alert{firing("SloFrontDoorDown", "d1", time.Now())}})
	waitFor(t, func() bool { return n.count() == 1 })
	clk.add(2 * time.Minute)
	s.Accept(ctx, alert.Payload{Alerts: []alert.Alert{firing("SloFrontDoorFastBurn", "b1", time.Now())}})
	waitFor(t, func() bool { return kindCount(t, s, KindGrouped) == 1 })
	if n.count() != 1 || len(r.ran) != 2 || kindCount(t, s, KindInvestigated) != 2 {
		t.Errorf("pushed %d ran %d: grouped alerts are investigated but not pushed", n.count(), len(r.ran))
	}
}

// Many namespaces at once is one incident: StormAfter digests, then one
// storm notice, then silence for StormWindow — every bundle still journaled.
func TestStormIsOneNotice(t *testing.T) {
	ctx := context.Background()
	s, r, n, clk := setupClock(t, 40)
	var as []alert.Alert
	for i := 0; i < 10; i++ {
		a := firing("SloFrontDoorDown", "s"+string(rune('a'+i)), time.Now())
		a.Labels["namespace"] = "ns-" + string(rune('a'+i))
		as = append(as, a)
	}
	s.Accept(ctx, alert.Payload{Alerts: as})
	waitFor(t, func() bool { r.mu.Lock(); defer r.mu.Unlock(); return len(r.ran) == 10 })
	waitFor(t, func() bool { return kindCount(t, s, KindGrouped) == 10-StormAfter-1 }) // the 5th opens the storm
	if n.count() != StormAfter+1 || kindCount(t, s, KindStorm) != 1 {
		t.Fatalf("pushed %d storms %d, want %d digests + 1 storm notice", n.count(), kindCount(t, s, KindStorm), StormAfter)
	}
	if last := n.last(); !strings.Contains(last, "alert storm") {
		t.Errorf("last push %q must be the storm notice", last)
	}
	// After the window, a new namespace pages again.
	clk.add(StormWindow + time.Minute)
	a := firing("KubePodCrashLooping", "later", time.Now())
	a.Labels["namespace"] = "later"
	s.Accept(ctx, alert.Payload{Alerts: []alert.Alert{a}})
	waitFor(t, func() bool { return n.count() == StormAfter+2 })
}
