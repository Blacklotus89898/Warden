// Package console is the operator's side of Warden: the reads behind the
// /console pages. For one namespace it answers "what changed" (a merged
// timeline), "what is its traffic doing" (range queries) and "what else is
// affected if it breaks" (blast radius from observed mesh traffic).
//
// Everything here is read-only and deterministic: it lays evidence out for
// the person investigating and draws no conclusions. It reads only what the
// collectors already read (pods, events, ArgoCD Applications, vmsingle) and
// Warden's own journal.
package console

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Blacklotus89898/Warden/internal/journal"
	"github.com/Blacklotus89898/Warden/internal/kube"
	"github.com/Blacklotus89898/Warden/internal/redact"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

// Page is the console UI; it calls /console/api next to itself.
//
//go:embed console.html
var Page []byte

// Kube is the read path (kube.Client implements it).
type Kube interface {
	GetJSON(ctx context.Context, path string, q url.Values, out any) error
}

// Metrics runs instant and range queries (vm.Client implements it).
type Metrics interface {
	Query(ctx context.Context, expr string, max int) ([]vm.Sample, error)
	QueryRange(ctx context.Context, expr string, start, end time.Time, step time.Duration, max int) ([]vm.Series, error)
}

// Journal is what the timeline reads from Warden's own record.
type Journal interface {
	List(ctx context.Context, kind string, limit int) ([]journal.Event, error)
}

// Journal kinds the timeline understands (the server writes them).
const (
	KindReceived     = "alert.received"
	KindInvestigated = "investigation.finished"
	KindRequested    = "operator.requested"
	KindDiagnosis    = "operator.diagnosis"
)

// Console holds the read-only sources.
type Console struct {
	Kube    Kube
	Metrics Metrics
	J       Journal
	Now     func() time.Time
}

func (c *Console) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

var nsRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// ValidNamespace reports whether ns is a Kubernetes namespace name. Every
// namespace reaching a PromQL string or an API path goes through it.
func ValidNamespace(ns string) bool { return len(ns) <= 63 && nsRe.MatchString(ns) }

// ---------------------------------------------------------------- timeline

// Entry is one thing that happened to a namespace.
type Entry struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`  // deploy | sync | restart | event | alert | investigation | request | diagnosis
	Level  string    `json:"level"` // info | warn | bad
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
	Ref    string    `json:"ref,omitempty"` // investigation id
}

// Timeline is "what changed" for a namespace, newest first.
type Timeline struct {
	Namespace string    `json:"namespace"`
	Since     time.Time `json:"since"`
	Entries   []Entry   `json:"entries"`
	Errors    []string  `json:"errors,omitempty"`
	Notes     []string  `json:"notes,omitempty"`
}

// MaxEntries bounds one timeline.
const MaxEntries = 300

func short(rev string) string {
	if len(rev) > 7 {
		return rev[:7]
	}
	return rev
}

func clean(s string, n int) string { return redact.Truncate(redact.String(s), n) }

// Timeline merges ArgoCD syncs, container restarts, Kubernetes events and
// Warden's journal (alerts, investigations, the operator's requests and
// diagnoses) for ns since the given time. Each source fails on its own.
func (c *Console) Timeline(ctx context.Context, ns string, since time.Time) (*Timeline, error) {
	if !ValidNamespace(ns) {
		return nil, fmt.Errorf("console: %q is not a namespace name", ns)
	}
	t := &Timeline{Namespace: ns, Since: since.UTC(),
		Notes: []string{"Kubernetes keeps events for about an hour, so older restarts show without their events."}}
	var mu sync.Mutex
	add := func(e Entry) {
		if e.At.Before(since) || e.At.IsZero() {
			return
		}
		mu.Lock()
		t.Entries = append(t.Entries, e)
		mu.Unlock()
	}
	fail := func(what string, err error) {
		mu.Lock()
		t.Errors = append(t.Errors, what+": "+clean(err.Error(), 300))
		mu.Unlock()
	}
	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }

	run(func() { // ArgoCD: deploys and the latest operation
		var apps kube.List[kube.Application]
		if err := c.Kube.GetJSON(ctx, "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications", nil, &apps); err != nil {
			fail("argocd", err)
			return
		}
		for _, a := range apps.Items {
			if a.Spec.Destination.Namespace != ns {
				continue
			}
			name := a.Metadata.Name
			for _, h := range a.Status.History {
				add(Entry{At: h.DeployedAt, Kind: "deploy", Level: "info",
					Title: "ArgoCD deployed " + name + " @ " + short(h.Revision)})
			}
			if op := a.Status.OperationState; op != nil && op.Phase != "" && op.Phase != "Succeeded" {
				at := op.FinishedAt
				if at.IsZero() {
					at = op.StartedAt
				}
				lvl := "bad"
				if op.Phase == "Running" {
					lvl = "warn"
				}
				add(Entry{At: at, Kind: "sync", Level: lvl, Title: "ArgoCD sync of " + name + ": " + op.Phase,
					Detail: clean(op.Message, 400)})
			}
		}
	})
	run(func() { // restarts, current waits and new pods
		var pods kube.List[kube.Pod]
		if err := c.Kube.GetJSON(ctx, "/api/v1/namespaces/"+ns+"/pods", nil, &pods); err != nil {
			fail("pods", err)
			return
		}
		now := c.now()
		for _, p := range pods.Items {
			add(Entry{At: p.Metadata.CreationTimestamp, Kind: "pod", Level: "info",
				Title: "Pod created: " + p.Metadata.Name, Detail: "node " + p.Spec.NodeName})
			for _, cs := range p.Status.ContainerStatuses {
				if lt := cs.LastState.Terminated; lt != nil {
					lvl := "warn"
					if lt.Reason == "OOMKilled" || lt.Reason == "Error" {
						lvl = "bad"
					}
					add(Entry{At: lt.FinishedAt, Kind: "restart", Level: lvl,
						Title:  fmt.Sprintf("%s/%s restarted: %s (exit %d)", p.Metadata.Name, cs.Name, lt.Reason, lt.ExitCode),
						Detail: fmt.Sprintf("%d restarts in total", cs.RestartCount)})
				}
				if w := cs.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" {
					add(Entry{At: now, Kind: "restart", Level: "bad",
						Title: fmt.Sprintf("%s/%s is waiting now: %s", p.Metadata.Name, cs.Name, w.Reason), Detail: clean(w.Message, 300)})
				}
			}
		}
	})
	run(func() { // events: warnings, plus the Normal reasons that mark a change
		var evs kube.List[kube.Event]
		if err := c.Kube.GetJSON(ctx, "/api/v1/namespaces/"+ns+"/events", nil, &evs); err != nil {
			fail("events", err)
			return
		}
		changes := map[string]bool{"ScalingReplicaSet": true, "Killing": true, "Preempted": true, "Evicted": true, "SuccessfulRescale": true}
		for _, e := range evs.Items {
			if e.Type != "Warning" && !changes[e.Reason] {
				continue
			}
			at := e.LastTimestamp
			if at.IsZero() {
				at = e.EventTime
			}
			lvl := "info"
			if e.Type == "Warning" {
				lvl = "warn"
			}
			title := e.Reason + ": " + e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name
			if e.Count > 1 {
				title += fmt.Sprintf(" (×%d)", e.Count)
			}
			add(Entry{At: at, Kind: "event", Level: lvl, Title: title, Detail: clean(e.Message, 400)})
		}
	})
	run(func() { c.journalEntries(ctx, ns, add, fail) })
	wg.Wait()

	sort.SliceStable(t.Entries, func(i, j int) bool { return t.Entries[i].At.After(t.Entries[j].At) })
	if len(t.Entries) > MaxEntries {
		t.Entries = t.Entries[:MaxEntries]
	}
	sort.Strings(t.Errors)
	return t, nil
}

// journalEntries adds Warden's own record for ns: alerts it received, its
// investigations, the operator's requests and diagnoses.
func (c *Console) journalEntries(ctx context.Context, ns string, add func(Entry), fail func(string, error)) {
	if c.J == nil {
		return
	}
	at := func(ts string) time.Time { t, _ := time.Parse(time.RFC3339Nano, ts); return t }
	invNS := map[string]string{} // investigation id → namespace
	if evs, err := c.J.List(ctx, KindInvestigated, 500); err != nil {
		fail("journal", err)
	} else {
		for _, e := range evs {
			var b struct {
				ID        string `json:"id"`
				Namespace string `json:"namespace"`
				Alert     struct {
					Labels map[string]string `json:"labels"`
				} `json:"alert"`
			}
			if json.Unmarshal(e.Payload, &b) != nil {
				continue
			}
			invNS[b.ID] = b.Namespace
			if b.Namespace != ns {
				continue
			}
			name := b.Alert.Labels["alertname"]
			kind, title := "investigation", "Warden investigated "+name
			if name == OperatorAlert {
				kind, title = "request", "You investigated "+ns
				if p := b.Alert.Labels["pod"]; p != "" {
					title += " (pod " + p + ")"
				}
			} else {
				add(Entry{At: at(e.TS), Kind: "alert", Level: levelFor(b.Alert.Labels["severity"]), Title: "Alert fired: " + name, Ref: b.ID})
			}
			add(Entry{At: at(e.TS), Kind: kind, Level: "info", Title: title, Ref: b.ID})
		}
	}
	if evs, err := c.J.List(ctx, KindDiagnosis, 500); err == nil {
		for _, e := range evs {
			if invNS[e.Ref] != ns {
				continue
			}
			var d Diagnosis
			if json.Unmarshal(e.Payload, &d) != nil {
				continue
			}
			add(Entry{At: at(e.TS), Kind: "diagnosis", Level: "info", Title: "Diagnosis by " + d.By, Detail: clean(d.Text, 400), Ref: e.Ref})
		}
	}
}

func levelFor(sev string) string {
	if sev == "critical" {
		return "bad"
	}
	return "warn"
}

// OperatorAlert is the alertname of an investigation the operator started.
const OperatorAlert = "OperatorRequest"

// Diagnosis is the operator's conclusion on one investigation.
type Diagnosis struct {
	By   string `json:"by"`
	Text string `json:"text"`
}

// ---------------------------------------------------------------- traffic

// Range is one selectable traffic window.
type Range struct {
	Span time.Duration
	Step time.Duration
}

// Ranges are the windows the console offers.
var Ranges = map[string]Range{
	"1h":  {time.Hour, time.Minute},
	"6h":  {6 * time.Hour, 5 * time.Minute},
	"24h": {24 * time.Hour, 10 * time.Minute},
	"7d":  {7 * 24 * time.Hour, time.Hour},
}

// Traffic is one namespace's signals over a window.
type Traffic struct {
	Namespace string                 `json:"namespace"`
	Range     string                 `json:"range"`
	Step      string                 `json:"step"`
	Series    map[string][]vm.Series `json:"series"`
	Errors    []string               `json:"errors,omitempty"`
}

// TrafficQueries returns the range expressions for ns, keyed by panel.
// Rates use a window of at least 5m so a 1-minute step still has samples.
func TrafficQueries(ns string, r Range) map[string]string {
	w := r.Step
	if w < 5*time.Minute {
		w = 5 * time.Minute
	}
	win := fmt.Sprintf("%ds", int(w.Seconds()))
	gw := `reporter="source",destination_service_namespace="` + ns + `"`
	return map[string]string{
		// requests/s by status class (2xx, 3xx, 4xx, 5xx)
		"requests": `sum by (class) (label_replace(rate(istio_requests_total{` + gw + `}[` + win + `]), "class", "${1}xx", "response_code", "([0-9]).."))`,
		"errors": `sum(rate(istio_requests_total{` + gw + `,response_code=~"5.."}[` + win + `]))` +
			` / sum(rate(istio_requests_total{` + gw + `}[` + win + `]))`,
		"latencyP95": `histogram_quantile(0.95, sum by (le) (rate(istio_request_duration_milliseconds_bucket{` + gw + `}[` + win + `])))`,
		"cpu": `max(max by (container) (rate(container_cpu_usage_seconds_total{namespace="` + ns + `",container!="",container!="POD"}[` + win + `]))` +
			` / max by (container) (kube_pod_container_resource_limits{namespace="` + ns + `",resource="cpu"}))`,
		"memory": `max(max by (container) (container_memory_working_set_bytes{namespace="` + ns + `",container!="",container!="POD"})` +
			` / max by (container) (kube_pod_container_resource_limits{namespace="` + ns + `",resource="memory"}))`,
		"restarts": `sum(increase(kube_pod_container_status_restarts_total{namespace="` + ns + `"}[` + win + `]))`,
	}
}

// Traffic runs the range queries for ns over the named window.
func (c *Console) Traffic(ctx context.Context, ns, rng string) (*Traffic, error) {
	if !ValidNamespace(ns) {
		return nil, fmt.Errorf("console: %q is not a namespace name", ns)
	}
	r, ok := Ranges[rng]
	if !ok {
		return nil, fmt.Errorf("console: range must be one of 1h, 6h, 24h, 7d")
	}
	end := c.now()
	t := &Traffic{Namespace: ns, Range: rng, Step: r.Step.String(), Series: map[string][]vm.Series{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, expr := range TrafficQueries(ns, r) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.Metrics.QueryRange(ctx, expr, end.Add(-r.Span), end, r.Step, 10)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errors = append(t.Errors, name+": "+clean(err.Error(), 300))
				return
			}
			t.Series[name] = s
		}()
	}
	wg.Wait()
	sort.Strings(t.Errors)
	return t, nil
}

// ---------------------------------------------------------------- blast radius

// Link is one observed dependency between namespaces over the window.
type Link struct {
	Namespace string  `json:"namespace"`
	Requests  float64 `json:"requests,omitempty"`    // HTTP requests (gateway/waypoint-reported)
	Conns     float64 `json:"connections,omitempty"` // TCP connections (ztunnel-reported)
	Status    string  `json:"status,omitempty"`      // filled by the caller from the services view
}

// Blast is who depends on a namespace and what it depends on, as observed.
type Blast struct {
	Namespace string   `json:"namespace"`
	Window    string   `json:"window"`
	Callers   []Link   `json:"callers"` // break ns → these feel it
	Callees   []Link   `json:"callees"` // these break → ns feels it
	Nodes     []string `json:"nodes,omitempty"`
	Gateway   bool     `json:"gateway"` // reached through the *.lab.home front door
	Errors    []string `json:"errors,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// BlastWindow is how far back observed traffic counts as a dependency.
const BlastWindow = "24h"

// BlastQueries returns the four dependency queries for ns: HTTP and TCP,
// callers (ns as destination) and callees (ns as source). Reporter is
// collapsed with max so a connection both ends report counts once.
func BlastQueries(ns string) map[string]string {
	q := func(metric, match, by string) string {
		return `max by (` + by + `) (sum by (` + by + `, reporter) (increase(` + metric + `{` + match + `}[` + BlastWindow + `]))) > 0`
	}
	return map[string]string{
		"callers/http": q("istio_requests_total", `destination_service_namespace="`+ns+`"`, "source_workload_namespace"),
		"callers/tcp":  q("istio_tcp_connections_opened_total", `destination_service_namespace="`+ns+`"`, "source_workload_namespace"),
		"callees/http": q("istio_requests_total", `source_workload_namespace="`+ns+`"`, "destination_service_namespace"),
		"callees/tcp":  q("istio_tcp_connections_opened_total", `source_workload_namespace="`+ns+`"`, "destination_service_namespace"),
	}
}

// Blast reads observed mesh traffic and where ns's pods run.
func (c *Console) Blast(ctx context.Context, ns string) (*Blast, error) {
	if !ValidNamespace(ns) {
		return nil, fmt.Errorf("console: %q is not a namespace name", ns)
	}
	b := &Blast{Namespace: ns, Window: BlastWindow, Notes: []string{
		"Observed, not declared: a dependency shows up only if traffic crossed the mesh in the last " + BlastWindow + ".",
		"Namespaces outside the ambient mesh, and calls to things outside the cluster, are invisible here.",
	}}
	callers, callees := map[string]*Link{}, map[string]*Link{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for key, expr := range BlastQueries(ns) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			samples, err := c.Metrics.Query(ctx, expr, 0)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				b.Errors = append(b.Errors, key+": "+clean(err.Error(), 300))
				return
			}
			dir, proto, _ := strings.Cut(key, "/")
			set, label := callers, "source_workload_namespace"
			if dir == "callees" {
				set, label = callees, "destination_service_namespace"
			}
			for _, s := range samples {
				other := s.Labels[label]
				if other == "" || other == "unknown" || other == ns {
					continue
				}
				var v float64
				fmt.Sscan(s.Value, &v)
				l := set[other]
				if l == nil {
					l = &Link{Namespace: other}
					set[other] = l
				}
				if proto == "http" {
					l.Requests += v
				} else {
					l.Conns += v
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var pods kube.List[kube.Pod]
		if err := c.Kube.GetJSON(ctx, "/api/v1/namespaces/"+ns+"/pods", nil, &pods); err != nil {
			mu.Lock()
			b.Errors = append(b.Errors, "pods: "+clean(err.Error(), 300))
			mu.Unlock()
			return
		}
		seen := map[string]bool{}
		for _, p := range pods.Items {
			if n := p.Spec.NodeName; n != "" && !seen[n] {
				seen[n] = true
				mu.Lock()
				b.Nodes = append(b.Nodes, n)
				mu.Unlock()
			}
		}
	}()
	wg.Wait()

	flatten := func(m map[string]*Link) []Link {
		out := make([]Link, 0, len(m))
		for _, l := range m {
			out = append(out, *l)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Requests+out[i].Conns != out[j].Requests+out[j].Conns {
				return out[i].Requests+out[i].Conns > out[j].Requests+out[j].Conns
			}
			return out[i].Namespace < out[j].Namespace
		})
		return out
	}
	if _, ok := callers["istio-system"]; ok {
		b.Gateway = true
	}
	b.Callers, b.Callees = flatten(callers), flatten(callees)
	sort.Strings(b.Nodes)
	sort.Strings(b.Errors)
	return b, nil
}
