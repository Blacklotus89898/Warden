package server

import (
	"context"
	"path/filepath"
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

func setup(t *testing.T, enabled bool, cap int) (*Server, *fakeRunner, *fakeNotify) {
	t.Helper()
	j, err := journal.Open(context.Background(), filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	r, n := &fakeRunner{}, &fakeNotify{}
	s := &Server{J: j, Runner: r, Notify: n, Enabled: enabled, DailyCap: cap}
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
	s, r, n := setup(t, true, 40)
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
	// A NEW firing of the same alert is a new incident.
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

func TestDailyCap(t *testing.T) {
	s, _, n := setup(t, true, 2)
	var as []alert.Alert
	for i := 0; i < 4; i++ {
		as = append(as, firing("A", string(rune('a'+i)), time.Now()))
	}
	if q := s.Accept(context.Background(), alert.Payload{Alerts: as}); q != 2 {
		t.Fatalf("queued %d, want the cap (2)", q)
	}
	waitFor(t, func() bool { return n.count() == 2 })
	if kindCount(t, s, KindSkipped) != 2 {
		t.Errorf("over-cap alerts must be journaled as skipped")
	}
}
