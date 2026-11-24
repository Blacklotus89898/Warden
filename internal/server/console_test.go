package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/console"
)

func consoleServer(t *testing.T) (*Server, *fakeRunner, *http.ServeMux, *clock) {
	t.Helper()
	s, r, _, clk := setupClock(t, 40)
	s.Console = &console.Console{Kube: nil, Metrics: nil, J: s.J}
	s.UserHeader = "X-Authentik-Username"
	mux := http.NewServeMux()
	s.Routes(mux)
	return s, r, mux, clk
}

func post(mux *http.ServeMux, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

var signedIn = map[string]string{"Content-Type": "application/json", RequestHeader: "1", "X-Authentik-Username": "steve"}

func TestConsoleWritesNeedCSRFHeaderAndUser(t *testing.T) {
	_, r, mux, _ := consoleServer(t)
	body := `{"namespace":"linkding"}`
	cases := []struct {
		name string
		hdr  map[string]string
		code int
	}{
		{"plain form post (CSRF)", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "X-Authentik-Username": "steve"}, 403},
		{"json without the request header", map[string]string{"Content-Type": "application/json", "X-Authentik-Username": "steve"}, 403},
		{"not signed in", map[string]string{"Content-Type": "application/json", RequestHeader: "1"}, 401},
	}
	for _, c := range cases {
		if w := post(mux, "/console/api/investigate", body, c.hdr); w.Code != c.code {
			t.Errorf("%s: got %d %s, want %d", c.name, w.Code, w.Body, c.code)
		}
	}
	if len(r.ran) != 0 {
		t.Fatal("a refused request must not run collectors")
	}
}

func TestOperatorInvestigation(t *testing.T) {
	s, r, mux, clk := consoleServer(t)
	w := post(mux, "/console/api/investigate", `{"namespace":"linkding","pod":"linkding-1"}`, signedIn)
	if w.Code != 200 {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	var out struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.ID == "" || len(r.ran) != 1 || r.ran[0] != console.OperatorAlert {
		t.Fatalf("id %q ran %v", out.ID, r.ran)
	}
	if kindCount(t, s, KindRequested) != 1 || kindCount(t, s, KindInvestigated) != 1 {
		t.Error("request and bundle must both be journaled")
	}
	if kindCount(t, s, KindNotified) != 0 {
		t.Error("operator investigations are never pushed")
	}
	// The trail names who asked.
	evs, _ := s.J.ByRef(context.Background(), out.ID)
	if !strings.Contains(string(evs[0].Payload), `"by":"steve"`) {
		t.Errorf("request must record the operator: %s", evs[0].Payload)
	}

	if w := post(mux, "/console/api/investigate", `{"namespace":"linkding"}`, signedIn); w.Code != http.StatusTooManyRequests {
		t.Errorf("second request within %s: got %d", OperatorGap, w.Code)
	}
	clk.add(OperatorGap + time.Second)
	if w := post(mux, "/console/api/investigate", `{"namespace":"linkding"}`, signedIn); w.Code != 200 {
		t.Errorf("after the gap: got %d %s", w.Code, w.Body)
	}
	for _, bad := range []string{`{}`, `{"namespace":"Linkding"}`, `{"namespace":"a/../b"}`, `{"namespace":"x","pod":"p;rm"}`} {
		clk.add(OperatorGap + time.Second)
		if w := post(mux, "/console/api/investigate", bad, signedIn); w.Code != 400 {
			t.Errorf("%s: got %d", bad, w.Code)
		}
	}
}

func TestOperatorInvestigationRespectsOffSwitch(t *testing.T) {
	s, r, mux, _ := consoleServer(t)
	s.Enabled = false
	if w := post(mux, "/console/api/investigate", `{"namespace":"linkding"}`, signedIn); w.Code != http.StatusServiceUnavailable || len(r.ran) != 0 {
		t.Errorf("WARDEN_ENABLED=false must stay journal-only: %d", w.Code)
	}
}

func TestDiagnosis(t *testing.T) {
	s, _, mux, _ := consoleServer(t)
	w := post(mux, "/console/api/investigate", `{"namespace":"linkding"}`, signedIn)
	var out struct{ ID string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	if w := post(mux, "/console/api/investigations/nope/diagnosis", `{"text":"x"}`, signedIn); w.Code != 404 {
		t.Errorf("unknown investigation: got %d", w.Code)
	}
	if w := post(mux, "/console/api/investigations/"+out.ID+"/diagnosis", `{"text":"  "}`, signedIn); w.Code != 400 {
		t.Errorf("empty diagnosis: got %d", w.Code)
	}
	w = post(mux, "/console/api/investigations/"+out.ID+"/diagnosis",
		`{"text":"OOM after deploy; log showed token=abc123secretvalue"}`, signedIn)
	if w.Code != 200 {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "abc123secretvalue") {
		t.Error("diagnoses must be redacted before they are journaled")
	}

	req := httptest.NewRequest(http.MethodGet, "/console/api/investigations/"+out.ID, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("reads without a signed-in user must fail closed, got %d", rec.Code)
	}
	req.Header.Set("X-Authentik-Username", "steve")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var page struct {
		Bundle    json.RawMessage
		Diagnoses []map[string]string
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &page)
	if len(page.Bundle) == 0 || len(page.Diagnoses) != 1 || page.Diagnoses[0]["by"] != "steve" {
		t.Errorf("investigation page = %s", rec.Body)
	}

	req = httptest.NewRequest(http.MethodGet, "/console/api/investigations", nil)
	req.Header.Set("X-Authentik-Username", "steve")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var rows []invRow
	_ = json.Unmarshal(rec.Body.Bytes(), &rows)
	if len(rows) != 1 || !rows[0].Diagnosed || rows[0].Source != "operator" {
		t.Errorf("rows = %+v", rows)
	}
	_ = s
}

func TestPushLinksToTheConsole(t *testing.T) {
	s, _, _ := setup(t, true, 40)
	if s.InvestigationURL("inv_1") != "" {
		t.Error("no PublicURL, no link")
	}
	s.PublicURL = "https://warden.lab.home/"
	if got := s.InvestigationURL("inv_1"); got != "https://warden.lab.home/console#/inv/inv_1" {
		t.Errorf("got %q", got)
	}
}

func TestConsoleOffWithoutBuilder(t *testing.T) {
	s, _, _ := setup(t, true, 40)
	mux := http.NewServeMux()
	s.Routes(mux)
	for _, p := range []string{"/console", "/console/api/investigations"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != 404 {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}
