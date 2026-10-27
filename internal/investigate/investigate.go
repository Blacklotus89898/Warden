// Package investigate turns one alert into an evidence bundle (Homelab ADR
// 0011, phase 1a): deterministic collection, no model. Each collector is
// read-only, bounded and independent — one failing is recorded in the bundle
// and the rest still run. The bundle is journaled whole (the eval set); only
// the digest, redacted and truncated, goes to ntfy.
package investigate

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/kb"
	"github.com/Blacklotus89898/Warden/internal/kube"
	"github.com/Blacklotus89898/Warden/internal/redact"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

// Kube is what the collectors need from the API (kube.Client implements it).
type Kube interface {
	GetJSON(ctx context.Context, path string, q url.Values, out any) error
	Get(ctx context.Context, path string, q url.Values) ([]byte, error)
}

// Metrics runs instant queries (vm.Client implements it).
type Metrics interface {
	Query(ctx context.Context, expr string, max int) ([]vm.Sample, error)
}

// KB searches the knowledge base (kb.Index implements it).
type KB interface {
	Search(terms []string, n int) []kb.Hit
}

// Investigator holds the read-only sources.
type Investigator struct {
	Kube    Kube
	Metrics Metrics
	KB      KB
	Now     func() time.Time
}

// Collectors is the fixed catalogue of evidence, in order (pinned by a test).
var Collectors = []string{"pods", "logs", "events", "argocd", "nodes", "metric", "kb"}

// PodState summarises one pod.
type PodState struct {
	Name     string              `json:"name"`
	Node     string              `json:"node,omitempty"`
	Phase    string              `json:"phase"`
	Ready    bool                `json:"ready"`
	Restarts int                 `json:"restarts"`
	Problems []string            `json:"problems,omitempty"` // e.g. "app: CrashLoopBackOff", "app last: OOMKilled (137)"
	Logs     map[string][]string `json:"logs,omitempty"`     // container → last lines (redacted)
}

// EventLine is one warning event.
type EventLine struct {
	Object  string    `json:"object"`
	Reason  string    `json:"reason"`
	Message string    `json:"message"`
	Count   int       `json:"count"`
	Last    time.Time `json:"last"`
}

// AppState is one ArgoCD Application.
type AppState struct {
	Name       string   `json:"name"`
	Sync       string   `json:"sync"`
	Health     string   `json:"health"`
	Message    string   `json:"message,omitempty"`
	Conditions []string `json:"conditions,omitempty"`
}

// NodeState is one node's notable state.
type NodeState struct {
	Name     string   `json:"name"`
	Ready    bool     `json:"ready"`
	Cordoned bool     `json:"cordoned,omitempty"`
	Pressure []string `json:"pressure,omitempty"`
}

// Bundle is the full evidence for one alert.
type Bundle struct {
	ID        string            `json:"id"`
	Alert     alert.Alert       `json:"alert"`
	Started   time.Time         `json:"started"`
	Duration  string            `json:"duration"`
	Namespace string            `json:"namespace,omitempty"`
	Pods      []PodState        `json:"pods,omitempty"`
	Events    []EventLine       `json:"events,omitempty"`
	Apps      []AppState        `json:"apps,omitempty"`
	Nodes     []NodeState       `json:"nodes,omitempty"`
	Expr      string            `json:"expr,omitempty"`
	Metric    []vm.Sample       `json:"metric,omitempty"`
	Runbook   string            `json:"runbook,omitempty"`
	KB        []kb.Hit          `json:"kb,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"` // collector → error
}

func (iv *Investigator) now() time.Time {
	if iv.Now != nil {
		return iv.Now()
	}
	return time.Now()
}

const (
	maxPods       = 5
	maxLogPods    = 2
	logLines      = 30
	maxEvents     = 12
	eventsWindow  = 2 * time.Hour
	maxSeries     = 8
	collectorTime = 20 * time.Second
)

// Run collects the bundle for a. It never fails: collector errors are kept.
func (iv *Investigator) Run(ctx context.Context, id string, a alert.Alert) *Bundle {
	start := iv.now()
	b := &Bundle{ID: id, Alert: a, Started: start.UTC(), Namespace: a.Namespace(),
		Runbook: a.Annotations["runbook_url"], Errors: map[string]string{}}
	step := func(name string, f func(context.Context) error) {
		cctx, cancel := context.WithTimeout(ctx, collectorTime)
		defer cancel()
		if err := f(cctx); err != nil {
			b.Errors[name] = redact.Truncate(redact.String(err.Error()), 300)
		}
	}
	var pods []kube.Pod
	if b.Namespace != "" {
		step("pods", func(c context.Context) error {
			var err error
			pods, err = iv.pods(c, b, a)
			return err
		})
		step("logs", func(c context.Context) error { return iv.logs(c, b, pods) })
		step("events", func(c context.Context) error { return iv.events(c, b) })
	}
	step("argocd", func(c context.Context) error { return iv.argocd(c, b) })
	step("nodes", func(c context.Context) error { return iv.nodes(c, b, a) })
	step("metric", func(c context.Context) error { return iv.metric(c, b, a) })
	step("kb", func(context.Context) error { iv.kb(b, a); return nil })
	if len(b.Errors) == 0 {
		b.Errors = nil
	}
	b.Duration = iv.now().Sub(start).Round(time.Millisecond).String()
	return b
}

// pods: the alert's pod if it names one, else the unhealthy pods of the
// namespace (not Running/Succeeded, not ready, or restarted).
func (iv *Investigator) pods(ctx context.Context, b *Bundle, a alert.Alert) ([]kube.Pod, error) {
	var list kube.List[kube.Pod]
	if err := iv.Kube.GetJSON(ctx, "/api/v1/namespaces/"+b.Namespace+"/pods", nil, &list); err != nil {
		return nil, err
	}
	want := a.Labels["pod"]
	var picked []kube.Pod
	for _, p := range list.Items {
		st := podState(p)
		if want != "" {
			if p.Metadata.Name != want {
				continue
			}
		} else if st.Ready && st.Restarts == 0 && (p.Status.Phase == "Running" || p.Status.Phase == "Succeeded") {
			continue
		}
		picked = append(picked, p)
		b.Pods = append(b.Pods, st)
	}
	// Most troubled first, then cap.
	order := make([]int, len(b.Pods))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		x, y := b.Pods[order[i]], b.Pods[order[j]]
		if len(x.Problems) != len(y.Problems) {
			return len(x.Problems) > len(y.Problems)
		}
		return x.Restarts > y.Restarts
	})
	var ps []PodState
	var pp []kube.Pod
	for _, i := range order {
		if len(ps) == maxPods {
			break
		}
		ps, pp = append(ps, b.Pods[i]), append(pp, picked[i])
	}
	b.Pods = ps
	return pp, nil
}

func podState(p kube.Pod) PodState {
	st := PodState{Name: p.Metadata.Name, Node: p.Spec.NodeName, Phase: p.Status.Phase, Ready: true}
	if p.Status.Reason != "" {
		st.Problems = append(st.Problems, "pod: "+p.Status.Reason)
	}
	for _, c := range p.Status.ContainerStatuses {
		st.Restarts += c.RestartCount
		if !c.Ready {
			st.Ready = false
		}
		if w := c.State.Waiting; w != nil && w.Reason != "" && w.Reason != "ContainerCreating" {
			st.Problems = append(st.Problems, c.Name+": "+w.Reason)
		}
		if t := c.State.Terminated; t != nil && t.Reason != "Completed" {
			st.Problems = append(st.Problems, fmt.Sprintf("%s: terminated %s (%d)", c.Name, t.Reason, t.ExitCode))
		}
		if t := c.LastState.Terminated; t != nil && c.RestartCount > 0 {
			st.Problems = append(st.Problems, fmt.Sprintf("%s last: %s (exit %d, %s)", c.Name, t.Reason, t.ExitCode, t.FinishedAt.UTC().Format("01-02 15:04Z")))
		}
	}
	if len(p.Status.ContainerStatuses) == 0 {
		st.Ready = p.Status.Phase == "Succeeded"
	}
	return st
}

// logs: last lines of the troubled containers — the previous instance when a
// container restarted (the crash is there), else the current one.
func (iv *Investigator) logs(ctx context.Context, b *Bundle, pods []kube.Pod) error {
	var errs []string
	for i, p := range pods {
		if i == maxLogPods {
			break
		}
		for _, c := range p.Status.ContainerStatuses {
			if c.Ready && c.RestartCount == 0 && len(pods) > 1 {
				continue
			}
			q := url.Values{"container": {c.Name}, "tailLines": {strconv.Itoa(logLines)}, "limitBytes": {"65536"}}
			if c.RestartCount > 0 && c.LastState.Terminated != nil {
				q.Set("previous", "true")
			}
			raw, err := iv.Kube.Get(ctx, "/api/v1/namespaces/"+b.Namespace+"/pods/"+p.Metadata.Name+"/log", q)
			if err != nil {
				errs = append(errs, p.Metadata.Name+"/"+c.Name+": "+err.Error())
				continue
			}
			if len(raw) == 0 {
				continue
			}
			for j := range b.Pods {
				if b.Pods[j].Name == p.Metadata.Name {
					if b.Pods[j].Logs == nil {
						b.Pods[j].Logs = map[string][]string{}
					}
					key := c.Name
					if q.Get("previous") == "true" {
						key += " (previous)"
					}
					b.Pods[j].Logs[key] = redact.Lines(string(raw), logLines)
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (iv *Investigator) events(ctx context.Context, b *Bundle) error {
	var list kube.List[kube.Event]
	if err := iv.Kube.GetJSON(ctx, "/api/v1/namespaces/"+b.Namespace+"/events", nil, &list); err != nil {
		return err
	}
	cut := iv.now().Add(-eventsWindow)
	seen := map[string]int{}
	for _, e := range list.Items {
		last := e.LastTimestamp
		if last.IsZero() {
			last = e.EventTime
		}
		if e.Type != "Warning" || last.Before(cut) {
			continue
		}
		obj := e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name
		k := obj + "|" + e.Reason
		if i, ok := seen[k]; ok {
			if last.After(b.Events[i].Last) {
				b.Events[i].Last, b.Events[i].Message = last, redact.Truncate(redact.String(e.Message), 240)
			}
			b.Events[i].Count += max(e.Count, 1)
			continue
		}
		seen[k] = len(b.Events)
		b.Events = append(b.Events, EventLine{Object: obj, Reason: e.Reason,
			Message: redact.Truncate(redact.String(e.Message), 240), Count: max(e.Count, 1), Last: last.UTC()})
	}
	sort.Slice(b.Events, func(i, j int) bool { return b.Events[i].Last.After(b.Events[j].Last) })
	if len(b.Events) > maxEvents {
		b.Events = b.Events[:maxEvents]
	}
	return nil
}

// argocd: the apps deploying into the namespace; for a cluster-wide alert,
// every app that isn't Synced+Healthy.
func (iv *Investigator) argocd(ctx context.Context, b *Bundle) error {
	var list kube.List[kube.Application]
	if err := iv.Kube.GetJSON(ctx, "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications", nil, &list); err != nil {
		return err
	}
	for _, a := range list.Items {
		ok := a.Status.Sync.Status == "Synced" && a.Status.Health.Status == "Healthy"
		if b.Namespace != "" {
			if a.Spec.Destination.Namespace != b.Namespace {
				continue
			}
		} else if ok {
			continue
		}
		s := AppState{Name: a.Metadata.Name, Sync: a.Status.Sync.Status, Health: a.Status.Health.Status,
			Message: redact.Truncate(redact.String(a.Status.Health.Message), 200)}
		if op := a.Status.OperationState; op != nil && op.Phase != "Succeeded" && op.Phase != "" {
			s.Conditions = append(s.Conditions, "operation "+op.Phase+": "+redact.Truncate(redact.String(op.Message), 200))
		}
		for _, c := range a.Status.Conditions {
			s.Conditions = append(s.Conditions, c.Type+": "+redact.Truncate(redact.String(c.Message), 200))
		}
		b.Apps = append(b.Apps, s)
	}
	return nil
}

// nodes: the alert's node, plus any node that is NotReady, cordoned or
// under pressure.
func (iv *Investigator) nodes(ctx context.Context, b *Bundle, a alert.Alert) error {
	var list kube.List[kube.Node]
	if err := iv.Kube.GetJSON(ctx, "/api/v1/nodes", nil, &list); err != nil {
		return err
	}
	named := a.Node()
	for _, n := range list.Items {
		st := NodeState{Name: n.Metadata.Name, Cordoned: n.Spec.Unschedulable}
		for _, c := range n.Status.Conditions {
			switch {
			case c.Type == "Ready":
				st.Ready = c.Status == "True"
			case c.Status == "True":
				st.Pressure = append(st.Pressure, c.Type)
			}
		}
		// The control plane is cordoned by design (SchedulingDisabled):
		// only report it when it is the alert's node or otherwise unwell.
		if n.Metadata.Name == named || !st.Ready || len(st.Pressure) > 0 || (st.Cordoned && !strings.Contains(n.Metadata.Name, "debian")) {
			b.Nodes = append(b.Nodes, st)
		}
	}
	return nil
}

func (iv *Investigator) metric(ctx context.Context, b *Bundle, a alert.Alert) error {
	b.Expr = a.Expr()
	if b.Expr == "" || iv.Metrics == nil {
		return nil
	}
	s, err := iv.Metrics.Query(ctx, b.Expr, maxSeries)
	b.Metric = s
	return err
}

// kb: search by the alert name, its namespace and the problem reasons found.
func (iv *Investigator) kb(b *Bundle, a alert.Alert) {
	if iv.KB == nil {
		return
	}
	terms := []string{a.Name(), b.Namespace}
	for _, p := range b.Pods {
		for _, pr := range p.Problems {
			terms = append(terms, pr)
		}
	}
	for _, e := range b.Events {
		terms = append(terms, e.Reason)
	}
	b.KB = iv.KB.Search(terms, 3)
}
