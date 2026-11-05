// Package server is Warden's HTTP surface and its single investigation
// worker (Homelab ADR 0011 §4–5): alertmanager posts alerts, each firing is
// investigated once, one at a time, within a daily cap. Every decision —
// including every skip — is journaled.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/journal"
	"github.com/Blacklotus89898/Warden/internal/redact"
	"github.com/Blacklotus89898/Warden/internal/statusmap"
)

// Journal kinds.
const (
	KindReceived     = "alert.received"
	KindSkipped      = "alert.skipped"
	KindInvestigated = "investigation.finished"
	KindNotified     = "notify.sent"
	KindNotifyError  = "notify.error"
	KindGrouped      = "alert.grouped" // investigated, digest folded into an earlier one
	KindStorm        = "storm.started"
)

// Grouping (the 2026-11-05 recovery sent 23 digests in 8 minutes for one
// outage). Every alert is still investigated and journaled — reads are cheap
// and the bundles are the eval set — but only the first digest per
// namespace (or per alertname when there is none) within GroupWindow goes to
// the phone, and once StormAfter digests went out within StormWindow, the
// rest are held behind a single storm notice carrying the cluster-wide view.
const (
	GroupWindow = 15 * time.Minute
	StormWindow = 10 * time.Minute
	StormAfter  = 4
)

// Notifier sends the digest (notify.Ntfy implements it).
type Notifier interface {
	Send(ctx context.Context, title, body, priority string) error
}

// Runner investigates one alert (investigate.Investigator implements it).
type Runner interface {
	Run(ctx context.Context, id string, a alert.Alert) *investigate.Bundle
}

// Server wires intake, the worker and the read API.
type Server struct {
	J        *journal.Journal
	Runner   Runner
	Notify   Notifier
	Enabled  bool
	DailyCap int // digests (phone pushes) per UTC day (default 40); intake is bounded at 4x
	Now      func() time.Time
	Log      *slog.Logger
	Version  string
	Map      *statusmap.Builder // nil = no /map

	queue chan job

	// Worker-only state (one goroutine): no lock. Lost on restart, which at
	// worst sends one extra digest.
	groups  map[string]sent // group key → the digest it folds into
	digests []time.Time     // digests sent within StormWindow
	storm   sent            // the open storm notice, if any

	mapMu   sync.Mutex
	mapAt   time.Time
	mapLast []byte
}

// MapTTL bounds how often the map re-reads the cluster (~30 GETs a build),
// however many browsers have it open.
const MapTTL = 15 * time.Second

type sent struct {
	id string
	at time.Time
}

type job struct {
	id string
	a  alert.Alert
}

// QueueSize bounds the backlog: an outage fans out; the rest is journaled.
const QueueSize = 16

// Start runs the worker until ctx ends.
func (s *Server) Start(ctx context.Context) {
	s.queue = make(chan job, QueueSize)
	s.groups = map[string]sent{}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case jb := <-s.queue:
				s.investigate(ctx, jb)
			}
		}
	}()
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "inv_" + hex.EncodeToString(b)
}

func (s *Server) cap() int {
	if s.DailyCap > 0 {
		return s.DailyCap
	}
	return 40
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) skip(ctx context.Context, a alert.Alert, reason string) {
	_, _ = s.J.Append(ctx, KindSkipped, "", map[string]string{
		"alertname": a.Name(), "namespace": a.Namespace(), "key": a.Key(), "reason": reason})
}

// Accept decides, for each alert of a payload, whether to investigate it.
// Returns how many were queued.
func (s *Server) Accept(ctx context.Context, p alert.Payload) int {
	n := 0
	for _, a := range p.Alerts {
		if a.Status != "firing" {
			continue // resolved: nothing to investigate (alertmanager already told the phone)
		}
		if !s.Enabled {
			s.skip(ctx, a, "disabled")
			continue
		}
		if err := s.J.Claim(ctx, a.Key()); errors.Is(err, journal.ErrSeen) {
			continue // a re-send of a firing already handled: silent by design
		} else if err != nil {
			s.skip(ctx, a, "dedup store: "+err.Error())
			continue
		}
		// Intake bound: grouped alerts cost reads, not pushes, so intake
		// allows 4x the digest cap before refusing to investigate at all.
		day := s.now().UTC().Truncate(24 * time.Hour)
		if used, err := s.J.CountSince(ctx, KindReceived, day); err != nil || used >= 4*s.cap() {
			s.skip(ctx, a, fmt.Sprintf("daily intake %d reached", 4*s.cap()))
			continue
		}
		id := newID()
		select {
		case s.queue <- job{id: id, a: a}:
			_, _ = s.J.Append(ctx, KindReceived, id, a)
			n++
		default:
			s.skip(ctx, a, "queue full")
		}
	}
	return n
}

func (s *Server) investigate(ctx context.Context, jb job) {
	b := s.Runner.Run(ctx, jb.id, jb.a)
	if _, err := s.J.Append(ctx, KindInvestigated, jb.id, b); err != nil && s.Log != nil {
		s.Log.Error("journal bundle", "id", jb.id, "err", err)
	}
	if s.hold(ctx, jb, b) {
		return
	}
	title, body := b.Digest()
	prio := "default"
	if jb.a.Labels["severity"] == "critical" {
		prio = "high"
	}
	if !s.send(ctx, jb.id, title, body, prio) {
		return
	}
	s.groups[groupKey(b)] = sent{id: jb.id, at: s.now()}
	if s.Log != nil {
		s.Log.Info("investigated", "id", jb.id, "alert", jb.a.Name(), "ns", jb.a.Namespace(), "took", b.Duration)
	}
}

// groupKey: alerts about the same namespace are one incident; with no
// namespace (resolved or labelled), the alertname is the best we have.
func groupKey(b *investigate.Bundle) string {
	if b.Namespace != "" {
		return "ns:" + b.Namespace
	}
	return "alert:" + b.Alert.Name()
}

// hold decides whether b's digest is folded into an earlier push instead of
// sent. It journals why, and opens a storm notice when one is due.
func (s *Server) hold(ctx context.Context, jb job, b *investigate.Bundle) bool {
	now := s.now()
	key := groupKey(b)
	fold := func(into sent, reason string) bool {
		_, _ = s.J.Append(ctx, KindGrouped, jb.id, map[string]string{
			"into": into.id, "key": key, "alertname": jb.a.Name(), "reason": reason})
		return true
	}
	if g, ok := s.groups[key]; ok && now.Sub(g.at) < GroupWindow {
		return fold(g, "same "+key+" within "+GroupWindow.String())
	}
	if s.storm.id != "" && now.Sub(s.storm.at) < StormWindow {
		s.groups[key] = s.storm
		return fold(s.storm, "alert storm")
	}
	recent := s.digests[:0]
	for _, t := range s.digests {
		if now.Sub(t) < StormWindow {
			recent = append(recent, t)
		}
	}
	s.digests = recent
	if len(s.digests) < StormAfter {
		return false
	}
	// Storm: one notice with the cluster-wide picture, then hold the rest.
	title := fmt.Sprintf("Warden: alert storm — %d+ alerts in %s", len(s.digests)+1, StormWindow)
	var w strings.Builder
	fmt.Fprintf(&w, "Further digests are held for %s and every alert is still investigated (GET /investigations).\n", StormWindow)
	fmt.Fprintf(&w, "Latest: %s (%s)\n", jb.a.Name(), strings.TrimPrefix(strings.TrimPrefix(key, "ns:"), "alert:"))
	if s.Map != nil {
		mctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		m, err := s.Map.Build(mctx)
		cancel()
		switch {
		case err != nil:
			fmt.Fprintf(&w, "\nStatus map unavailable: %v\n", err)
		case len(m.Causes) == 0:
			fmt.Fprintf(&w, "\nStatus map: no red component right now (transient?)\n")
		default:
			fmt.Fprintf(&w, "\nLikely causes (status map):\n")
			for i, c := range m.Causes {
				if i == 8 {
					fmt.Fprintf(&w, "… %d more on /map\n", len(m.Causes)-8)
					break
				}
				fmt.Fprintf(&w, "• %s\n", c)
			}
		}
	}
	s.storm = sent{id: jb.id, at: now}
	_, _ = s.J.Append(ctx, KindStorm, jb.id, map[string]any{"digests_in_window": len(s.digests), "window": StormWindow.String()})
	s.send(ctx, jb.id, title, redact.Truncate(redact.String(w.String()), investigate.DigestLimit), "high")
	s.groups[key] = s.storm
	return true
}

// send pushes one notification within the daily digest cap and journals it.
func (s *Server) send(ctx context.Context, id, title, body, prio string) bool {
	day := s.now().UTC().Truncate(24 * time.Hour)
	if used, err := s.J.CountSince(ctx, KindNotified, day); err != nil || used >= s.cap() {
		_, _ = s.J.Append(ctx, KindSkipped, id, map[string]string{"reason": fmt.Sprintf("daily digest cap %d reached", s.cap())})
		return false
	}
	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.Notify.Send(nctx, title, body, prio); err != nil {
		_, _ = s.J.Append(ctx, KindNotifyError, id, map[string]string{"error": err.Error()})
		return false
	}
	_, _ = s.J.Append(ctx, KindNotified, id, map[string]string{"title": title})
	s.digests = append(s.digests, s.now())
	return true
}

// Routes registers the HTTP API.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "version": s.Version, "enabled": s.Enabled})
	})
	// Alertmanager webhook (receiver "warden"). In-cluster ClusterIP only.
	mux.HandleFunc("POST /alerts", func(w http.ResponseWriter, r *http.Request) {
		var p alert.Payload
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&p); err != nil {
			http.Error(w, "bad payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		n := s.Accept(r.Context(), p)
		writeJSON(w, map[string]int{"queued": n})
	})
	// Read-only: recent investigations, and one bundle with its trail.
	mux.HandleFunc("GET /investigations", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		evs, err := s.J.List(r.Context(), KindInvestigated, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		type row struct {
			ID, TS, Alert, Namespace, Duration string
			Problems                           int
		}
		out := []row{}
		for _, e := range evs {
			var b investigate.Bundle
			if json.Unmarshal(e.Payload, &b) != nil {
				continue
			}
			p := 0
			for _, pod := range b.Pods {
				p += len(pod.Problems)
			}
			out = append(out, row{ID: b.ID, TS: e.TS, Alert: b.Alert.Name(), Namespace: b.Namespace, Duration: b.Duration, Problems: p})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /investigations/{id}", func(w http.ResponseWriter, r *http.Request) {
		evs, err := s.J.ByRef(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(evs) == 0 {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, evs)
	})
	// Status map (read-only): the page, and the JSON it polls. Exposed on
	// the gateway by path prefix /map only — /investigations stays in-cluster.
	mux.HandleFunc("GET /map", func(w http.ResponseWriter, r *http.Request) {
		if s.Map == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
		_, _ = w.Write(statusmap.Page)
	})
	mux.HandleFunc("GET /map.json", func(w http.ResponseWriter, r *http.Request) {
		if s.Map == nil {
			http.NotFound(w, r)
			return
		}
		b, err := s.mapJSON(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		counts, err := s.J.Counts(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		kinds := make([]string, 0, len(counts))
		for k := range counts {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		var b strings.Builder
		b.WriteString("# HELP warden_journal_events_total Journal events by kind.\n# TYPE warden_journal_events_total counter\n")
		for _, k := range kinds {
			fmt.Fprintf(&b, "warden_journal_events_total{kind=%q} %d\n", k, counts[k])
		}
		enabled := 0
		if s.Enabled {
			enabled = 1
		}
		fmt.Fprintf(&b, "# HELP warden_enabled 1 when Warden investigates alerts.\n# TYPE warden_enabled gauge\nwarden_enabled %d\n", enabled)
		fmt.Fprintf(&b, "# HELP warden_build_info Running build.\n# TYPE warden_build_info gauge\nwarden_build_info{version=%q} 1\n", s.Version)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(b.String()))
	})
}

// mapJSON builds (or reuses, within MapTTL) the encoded status map with each
// namespace's latest investigation attached.
func (s *Server) mapJSON(ctx context.Context) ([]byte, error) {
	s.mapMu.Lock()
	defer s.mapMu.Unlock()
	if s.mapLast != nil && time.Since(s.mapAt) < MapTTL {
		return s.mapLast, nil
	}
	bctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	m, err := s.Map.Build(bctx)
	if err != nil {
		return nil, err
	}
	if evs, err := s.J.List(ctx, KindInvestigated, 100); err == nil {
		seen := make([]statusmap.Seen, 0, len(evs))
		for _, e := range evs {
			var b investigate.Bundle
			if json.Unmarshal(e.Payload, &b) != nil {
				continue
			}
			seen = append(seen, statusmap.Seen{
				Investigation: statusmap.Investigation{ID: b.ID, Alert: b.Alert.Name(), TS: e.TS},
				Namespace:     b.Namespace,
			})
		}
		m.Attach(seen)
	}
	out, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	s.mapLast, s.mapAt = out, time.Now()
	return out, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
