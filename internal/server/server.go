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
	"time"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/journal"
)

// Journal kinds.
const (
	KindReceived     = "alert.received"
	KindSkipped      = "alert.skipped"
	KindInvestigated = "investigation.finished"
	KindNotified     = "notify.sent"
	KindNotifyError  = "notify.error"
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
	DailyCap int // investigations per UTC day (default 40)
	Log      *slog.Logger
	Version  string

	queue chan job
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
		day := time.Now().UTC().Truncate(24 * time.Hour)
		if used, err := s.J.CountSince(ctx, KindReceived, day); err != nil || used >= s.cap() {
			s.skip(ctx, a, fmt.Sprintf("daily cap %d reached", s.cap()))
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
	title, body := b.Digest()
	prio := "default"
	if jb.a.Labels["severity"] == "critical" {
		prio = "high"
	}
	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.Notify.Send(nctx, title, body, prio); err != nil {
		_, _ = s.J.Append(ctx, KindNotifyError, jb.id, map[string]string{"error": err.Error()})
		return
	}
	_, _ = s.J.Append(ctx, KindNotified, jb.id, map[string]string{"title": title})
	if s.Log != nil {
		s.Log.Info("investigated", "id", jb.id, "alert", jb.a.Name(), "ns", jb.a.Namespace(), "took", b.Duration)
	}
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

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
