package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/console"
	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/redact"
	"github.com/Blacklotus89898/Warden/internal/services"
)

// Console journal kinds (shared with internal/console's timeline).
const (
	KindRequested = console.KindRequested
	KindDiagnosis = console.KindDiagnosis
)

// Operator-request limits: one at a time, a minimum gap, and a daily bound
// equal to the alert intake bound, so the console can't turn Warden into a
// load generator against the API server.
const (
	OperatorGap      = 10 * time.Second
	OperatorTimeout  = 60 * time.Second
	MaxDiagnosisText = 4000
)

// RequestHeader must be present on console writes. A browser can't add a
// custom header to a cross-site form post, so this closes CSRF while the
// session cookie belongs to the auth proxy.
const RequestHeader = "X-Warden-Request"

// consoleRoutes registers /console (page + JSON API). The gateway puts
// /console behind authentik (Homelab ADR 0011 amendment 2026-11-24).
func (s *Server) consoleRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /console", func(w http.ResponseWriter, r *http.Request) {
		if s.Console == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write(console.Page)
	})
	api := func(pattern string, h func(w http.ResponseWriter, r *http.Request)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if s.Console == nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			// Fail closed: if the gateway's auth policy were ever missing,
			// reads stop here instead of serving logs to the LAN.
			if s.signInRequired() && s.user(r) == "" {
				http.Error(w, "not signed in (no valid authentik session)", http.StatusUnauthorized)
				return
			}
			h(w, r)
		})
	}

	api("GET /console/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"user": s.user(r), "enabled": s.Enabled, "version": s.Version})
	})
	api("GET /console/api/investigations", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		rows, err := s.investigationRows(r.Context(), limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)
	})
	api("GET /console/api/investigations/{id}", func(w http.ResponseWriter, r *http.Request) {
		evs, err := s.J.ByRef(r.Context(), r.PathValue("id"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(evs) == 0 {
			http.NotFound(w, r)
			return
		}
		out := map[string]any{"trail": []any{}}
		var trail, diag []any
		for _, e := range evs {
			switch e.Kind {
			case KindInvestigated:
				out["bundle"] = e.Payload
				out["ts"] = e.TS
			case KindDiagnosis:
				var d console.Diagnosis
				if json.Unmarshal(e.Payload, &d) == nil {
					diag = append(diag, map[string]any{"ts": e.TS, "by": d.By, "text": d.Text})
				}
			default:
				trail = append(trail, map[string]any{"ts": e.TS, "kind": e.Kind, "payload": e.Payload})
			}
		}
		out["trail"], out["diagnoses"] = trail, diag
		writeJSON(w, out)
	})
	api("POST /console/api/investigate", s.handleInvestigate)
	api("POST /console/api/investigations/{id}/diagnosis", s.handleDiagnosis)

	api("GET /console/api/namespaces/{ns}/timeline", func(w http.ResponseWriter, r *http.Request) {
		hours, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		if hours <= 0 || hours > 24*7 {
			hours = 24
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		t, err := s.Console.Timeline(ctx, r.PathValue("ns"), s.now().Add(-time.Duration(hours)*time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, t)
	})
	api("GET /console/api/namespaces/{ns}/traffic", func(w http.ResponseWriter, r *http.Request) {
		rng := r.URL.Query().Get("range")
		if rng == "" {
			rng = "24h"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		t, err := s.Console.Traffic(ctx, r.PathValue("ns"), rng)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, t)
	})
	api("GET /console/api/namespaces/{ns}/blast", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		b, err := s.Console.Blast(ctx, r.PathValue("ns"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Colour each related namespace with its status from /services.
		if s.Services != nil {
			if raw, err := s.servicesJSON(ctx); err == nil {
				var v services.View
				if json.Unmarshal(raw, &v) == nil {
					st := map[string]string{}
					for _, sv := range v.Services {
						st[sv.Namespace] = string(sv.Status)
					}
					for i := range b.Callers {
						b.Callers[i].Status = st[b.Callers[i].Namespace]
					}
					for i := range b.Callees {
						b.Callees[i].Status = st[b.Callees[i].Namespace]
					}
				}
			}
		}
		writeJSON(w, b)
	})
}

// JWTHeader is where authentik's proxy outpost forwards the signed token.
const JWTHeader = "X-Authentik-Jwt"

// user is the signed-in operator, "" if none. With a verifier, only a valid
// authentik JWT counts: a username header alone is ignored, so neither a LAN
// client nor a pod calling the Service directly can claim to be someone.
func (s *Server) user(r *http.Request) string {
	if s.Auth != nil {
		tok := strings.TrimSpace(r.Header.Get(JWTHeader))
		if tok == "" {
			return ""
		}
		c, err := s.Auth.Verify(r.Context(), tok)
		if err != nil {
			if s.Log != nil {
				s.Log.Warn("console: rejected token", "err", err)
			}
			return ""
		}
		return trimUser(c.Username)
	}
	if s.UserHeader == "" {
		return ""
	}
	return trimUser(r.Header.Get(s.UserHeader))
}

// signInRequired: is a signed-in user needed for console API calls?
func (s *Server) signInRequired() bool { return s.Auth != nil || s.UserHeader != "" }

func trimUser(u string) string {
	u = strings.TrimSpace(u)
	if len(u) > 64 {
		u = u[:64]
	}
	return u
}

// writeGuard rejects console writes that lack the CSRF header or, when a
// user header is configured, a signed-in user. Returns the user.
func (s *Server) writeGuard(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Header.Get(RequestHeader) != "1" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "console writes need Content-Type: application/json and "+RequestHeader+": 1", http.StatusForbidden)
		return "", false
	}
	u := s.user(r)
	if s.signInRequired() && u == "" {
		http.Error(w, "not signed in (no valid authentik session)", http.StatusUnauthorized)
		return "", false
	}
	if u == "" {
		u = "operator"
	}
	return u, true
}

type invRow struct {
	ID        string `json:"id"`
	TS        string `json:"ts"`
	Alert     string `json:"alert"`
	Severity  string `json:"severity,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Source    string `json:"source"` // alert | operator
	Problems  int    `json:"problems"`
	Errors    int    `json:"errors"`
	Duration  string `json:"duration"`
	Diagnosed bool   `json:"diagnosed"`
}

func (s *Server) investigationRows(ctx context.Context, limit int) ([]invRow, error) {
	evs, err := s.J.List(ctx, KindInvestigated, limit)
	if err != nil {
		return nil, err
	}
	diagnosed := map[string]bool{}
	if ds, err := s.J.List(ctx, KindDiagnosis, 1000); err == nil {
		for _, d := range ds {
			diagnosed[d.Ref] = true
		}
	}
	rows := []invRow{}
	for _, e := range evs {
		var b investigate.Bundle
		if json.Unmarshal(e.Payload, &b) != nil {
			continue
		}
		p := 0
		for _, pod := range b.Pods {
			p += len(pod.Problems)
		}
		src := "alert"
		if b.Alert.Name() == console.OperatorAlert {
			src = "operator"
		}
		rows = append(rows, invRow{ID: b.ID, TS: e.TS, Alert: b.Alert.Name(), Severity: b.Alert.Labels["severity"],
			Namespace: b.Namespace, Pod: b.Alert.Labels["pod"], Source: src, Problems: p, Errors: len(b.Errors),
			Duration: b.Duration, Diagnosed: diagnosed[b.ID]})
	}
	return rows, nil
}

// ErrBusy means another operator investigation is running or ran too recently.
var ErrBusy = errors.New("another investigation ran less than 10s ago; wait and retry")

// handleInvestigate runs the collectors on a namespace (optionally one pod or
// node) the operator chose, with no alert. Synchronous, journaled like an
// alert investigation, never pushed to ntfy: the operator is looking at it.
func (s *Server) handleInvestigate(w http.ResponseWriter, r *http.Request) {
	who, ok := s.writeGuard(w, r)
	if !ok {
		return
	}
	if !s.Enabled {
		http.Error(w, "WARDEN_ENABLED=false: journal only", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		Node      string `json:"node"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, v := range []string{req.Namespace, req.Pod, req.Node} {
		if v != "" && !validName(v) {
			http.Error(w, fmt.Sprintf("%q is not a Kubernetes name", v), http.StatusBadRequest)
			return
		}
	}
	if req.Namespace == "" && req.Node == "" {
		http.Error(w, "give a namespace (optionally a pod) or a node", http.StatusBadRequest)
		return
	}

	if !s.opMu.TryLock() {
		http.Error(w, ErrBusy.Error(), http.StatusTooManyRequests)
		return
	}
	defer s.opMu.Unlock()
	if !s.opLast.IsZero() && s.now().Sub(s.opLast) < OperatorGap {
		http.Error(w, ErrBusy.Error(), http.StatusTooManyRequests)
		return
	}
	day := s.now().UTC().Truncate(24 * time.Hour)
	if used, err := s.J.CountSince(r.Context(), KindRequested, day); err != nil || used >= 4*s.cap() {
		http.Error(w, fmt.Sprintf("daily operator bound %d reached", 4*s.cap()), http.StatusTooManyRequests)
		return
	}
	s.opLast = s.now()

	id := newID()
	labels := map[string]string{"alertname": console.OperatorAlert, "severity": "info"}
	for k, v := range map[string]string{"namespace": req.Namespace, "pod": req.Pod, "node": req.Node} {
		if v != "" {
			labels[k] = v
		}
	}
	a := alert.Alert{Status: "firing", Labels: labels, StartsAt: s.now().UTC(), Fingerprint: "operator-" + id,
		Annotations: map[string]string{"summary": "Investigation requested by " + who}}
	_, _ = s.J.Append(r.Context(), KindRequested, id, map[string]string{
		"by": who, "namespace": req.Namespace, "pod": req.Pod, "node": req.Node})

	ctx, cancel := context.WithTimeout(r.Context(), OperatorTimeout)
	defer cancel()
	b := s.Runner.Run(ctx, id, a)
	if _, err := s.J.Append(context.WithoutCancel(r.Context()), KindInvestigated, id, b); err != nil {
		http.Error(w, "journal: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"id": id})
}

// handleDiagnosis records the operator's conclusion on an investigation.
// Append-only like everything else: a later diagnosis adds, never replaces.
func (s *Server) handleDiagnosis(w http.ResponseWriter, r *http.Request) {
	who, ok := s.writeGuard(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	evs, err := s.J.ByRef(r.Context(), id)
	if err != nil || len(evs) == 0 {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	text := strings.TrimSpace(req.Text)
	if text == "" || utf8.RuneCountInString(text) > MaxDiagnosisText {
		http.Error(w, fmt.Sprintf("diagnosis must be 1–%d characters", MaxDiagnosisText), http.StatusBadRequest)
		return
	}
	// Operators paste log lines: scrub secrets before they enter the journal.
	d := console.Diagnosis{By: who, Text: redact.String(text)}
	if _, err := s.J.Append(r.Context(), KindDiagnosis, id, d); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, d)
}

func validName(s string) bool {
	if len(s) > 253 {
		return false
	}
	for i, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || (c == '-' || c == '.') && i > 0 && i < len(s)-1
		if !ok {
			return false
		}
	}
	return s != ""
}
