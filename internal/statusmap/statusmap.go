// Package statusmap builds the platform status map: every node, namespace
// and front door with one status each, plus the dependency edges between
// them, so "what is down and why" is one look.
//
// It reads through the same read-only kube catalogue the collectors use
// (nodes, ArgoCD Applications, per-namespace pods) and one instant query
// (probe_success). No new API paths: the ADR 0011 boundary is unchanged.
package statusmap

import (
	"context"
	_ "embed"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Blacklotus89898/Warden/internal/kube"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

// Kube is the read path (kube.Client implements it).
type Kube interface {
	GetJSON(ctx context.Context, path string, q url.Values, out any) error
}

// Metrics runs instant queries (vm.Client implements it).
type Metrics interface {
	Query(ctx context.Context, expr string, max int) ([]vm.Sample, error)
}

// Status of one component, worst first.
type Status string

const (
	Red     Status = "red"     // down / failing
	Amber   Status = "amber"   // degraded, starting, drifting
	Green   Status = "green"   // fine
	Grey    Status = "grey"    // intentionally off (Suspended) or not observable
	Unknown Status = "unknown" // a collector failed
)

func rank(s Status) int {
	switch s {
	case Red:
		return 4
	case Amber:
		return 3
	case Unknown:
		return 2
	case Green:
		return 1
	}
	return 0
}

func worst(a, b Status) Status {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// App is one ArgoCD Application in a namespace.
type App struct {
	Name   string `json:"name"`
	Sync   string `json:"sync"`
	Health string `json:"health"`
}

// Investigation is Warden's latest look at a component.
type Investigation struct {
	ID    string `json:"id"`
	Alert string `json:"alert"`
	TS    string `json:"ts"`
}

// Component is one box on the map.
type Component struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Kind    string         `json:"kind"` // host | node | namespace | frontdoor
	Status  Status         `json:"status"`
	Reasons []string       `json:"reasons,omitempty"`
	Notes   []string       `json:"notes,omitempty"`
	Apps    []App          `json:"apps,omitempty"`
	Pods    *PodCount      `json:"pods,omitempty"`
	PodList []PodDot       `json:"podList,omitempty"` // namespace: each live pod
	Nodes   []string       `json:"nodes,omitempty"`   // namespace: where its pods run
	Target  string         `json:"target,omitempty"`
	Last    *Investigation `json:"last,omitempty"`
}

// PodDot is one live pod: where it runs and how it is doing.
type PodDot struct {
	Name   string `json:"name"`
	Node   string `json:"node,omitempty"`
	Status Status `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// PodCount summarises a namespace's live pods.
type PodCount struct {
	Total int `json:"total"`
	Ready int `json:"ready"`
}

// Tier is one row of the map, top (host) to bottom (apps).
type Tier struct {
	Name       string       `json:"name"`
	Components []*Component `json:"components"`
}

// Edge is "From depends on / runs on To" — drawn from the dependent upward.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// Map is the whole picture.
type Map struct {
	Generated time.Time       `json:"generated"`
	Summary   map[Status]int  `json:"summary"`
	Causes    []string        `json:"causes"`
	Tiers     []Tier          `json:"tiers"`
	Edges     []Edge          `json:"edges"`
	Errors    []string        `json:"errors,omitempty"`
	Recent    []Investigation `json:"recent,omitempty"`
	byID      map[string]*Component
}

// Builder assembles a Map.
type Builder struct {
	Kube    Kube
	Metrics Metrics
	// Hosts maps a *.lab.home front-door host label to its namespace when the
	// label is not itself a namespace or an app name (e.g. grafana=monitoring).
	Hosts map[string]string
	Now   func() time.Time
}

// Tier membership for the platform layers; everything else is an app.
var (
	platformNS = []string{"kube-system", "istio-system", "argocd", "cert-manager", "sealed-secrets", "argo-rollouts"}
	observeNS  = []string{"monitoring", "openobserve", "warden", "heartbeat"}
)

// PendingGrace is how long a Pending pod is "starting" before it counts as stuck.
const PendingGrace = 5 * time.Minute

var redWaiting = map[string]bool{
	"CrashLoopBackOff": true, "ImagePullBackOff": true, "ErrImagePull": true,
	"CreateContainerConfigError": true, "CreateContainerError": true, "InvalidImageName": true,
}

func (b *Builder) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func in(list []string, s string) bool { return slices.Contains(list, s) }

// Page is the map UI; it fetches map.json next to itself.
//
//go:embed map.html
var Page []byte

// Build reads the cluster and returns the map. Collector failures mark the
// affected boxes Unknown and are listed in Errors; Build itself only fails
// if it cannot even list nodes.
func (b *Builder) Build(ctx context.Context) (*Map, error) {
	m := &Map{Generated: b.now().UTC(), Summary: map[Status]int{}, byID: map[string]*Component{}}

	// ---- nodes ----
	var nodes kube.List[kube.Node]
	if err := b.Kube.GetJSON(ctx, "/api/v1/nodes", nil, &nodes); err != nil {
		return nil, fmt.Errorf("statusmap: nodes: %w", err)
	}
	nodeStatus := map[string]Status{}
	var nodeComps []*Component
	readyNodes := 0
	for _, n := range nodes.Items {
		c := &Component{ID: "node/" + n.Metadata.Name, Name: n.Metadata.Name, Kind: "node", Status: Green}
		ready := false
		for _, cond := range n.Status.Conditions {
			switch {
			case cond.Type == "Ready" && cond.Status == "True":
				ready = true
			case cond.Type == "Ready":
				c.Status = Red
				c.Reasons = append(c.Reasons, "NotReady: "+firstLine(cond.Message, "kubelet stopped posting status"))
			case cond.Status == "True": // MemoryPressure, DiskPressure, PIDPressure…
				c.Status = worst(c.Status, Amber)
				c.Reasons = append(c.Reasons, cond.Type)
			}
		}
		if ready {
			readyNodes++
		}
		if n.Spec.Unschedulable {
			c.Notes = append(c.Notes, "cordoned: takes no new pods")
		}
		nodeStatus[n.Metadata.Name] = c.Status
		nodeComps = append(nodeComps, c)
	}
	sort.Slice(nodeComps, func(i, j int) bool { return nodeComps[i].Name < nodeComps[j].Name })

	host := &Component{ID: "host/proxmox", Name: "Proxmox host", Kind: "host", Status: Grey,
		Notes: []string{"not observed directly — Warden cannot reach Proxmox"}}
	if readyNodes > 0 {
		host.Status = Green
		host.Notes = []string{"inferred: at least one VM node is Ready (Warden cannot reach Proxmox itself)"}
	}
	for _, n := range nodeComps {
		m.Edges = append(m.Edges, Edge{From: n.ID, To: host.ID})
	}

	// ---- ArgoCD applications → namespaces ----
	nsApps := map[string][]App{}
	var apps kube.List[kube.Application]
	appsErr := b.Kube.GetJSON(ctx, "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications", nil, &apps)
	if appsErr != nil {
		m.Errors = append(m.Errors, "argocd applications: "+appsErr.Error())
	}
	appNS := map[string]string{} // app name → destination namespace
	for _, a := range apps.Items {
		ns := a.Spec.Destination.Namespace
		if ns == "" {
			continue
		}
		appNS[a.Metadata.Name] = ns
		nsApps[ns] = append(nsApps[ns], App{Name: a.Metadata.Name, Sync: a.Status.Sync.Status, Health: a.Status.Health.Status})
	}
	namespaces := map[string]bool{"default": true}
	for _, ns := range slices.Concat(platformNS, observeNS) {
		namespaces[ns] = true
	}
	for ns := range nsApps {
		namespaces[ns] = true
	}

	// ---- pods, per namespace (the catalogue has no cluster-wide pod list) ----
	type nsPods struct {
		pods []kube.Pod
		err  error
	}
	results := map[string]nsPods{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for ns := range namespaces {
		wg.Add(1)
		go func(ns string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var l kube.List[kube.Pod]
			err := b.Kube.GetJSON(ctx, "/api/v1/namespaces/"+ns+"/pods", nil, &l)
			mu.Lock()
			results[ns] = nsPods{pods: l.Items, err: err}
			mu.Unlock()
		}(ns)
	}
	wg.Wait()

	// ---- namespace components ----
	now := b.now()
	var platform, observe, appTier []*Component
	for ns := range namespaces {
		r := results[ns]
		c := &Component{ID: "ns/" + ns, Name: ns, Kind: "namespace", Status: Green, Apps: nsApps[ns]}
		sort.Slice(c.Apps, func(i, j int) bool { return c.Apps[i].Name < c.Apps[j].Name })
		if r.err != nil {
			c.Status = Unknown
			c.Reasons = append(c.Reasons, "pods unreadable: "+r.err.Error())
			m.Errors = append(m.Errors, ns+" pods: "+r.err.Error())
		}
		onNode := map[string]bool{}
		pc := &PodCount{}
		for _, p := range r.pods {
			if p.Status.Phase == "Succeeded" || p.Status.Phase == "Failed" {
				continue // finished Job pods are history, not health
			}
			pc.Total++
			pd := PodDot{Name: p.Metadata.Name, Node: p.Spec.NodeName, Status: Green}
			// flag marks the pod and folds it into the namespace; sep joins pod
			// name and reason ("/" for a container, ": " for the pod itself).
			flag := func(s Status, sep, why string) {
				pd.Status = worst(pd.Status, s)
				if pd.Reason == "" || s == Red {
					pd.Reason = why
				}
				c.Status = worst(c.Status, s)
				c.Reasons = appendOnce(c.Reasons, p.Metadata.Name+sep+why)
			}
			if p.Spec.NodeName != "" {
				onNode[p.Spec.NodeName] = true
				if nodeStatus[p.Spec.NodeName] == Red {
					pd.Status, pd.Reason = Red, "node NotReady"
					c.Status = Red
					c.Reasons = appendOnce(c.Reasons, "runs on "+p.Spec.NodeName+", which is NotReady")
				}
			}
			podReady := false
			for _, cond := range p.Status.Conditions {
				if cond.Type == "Ready" && cond.Status == "True" {
					podReady = true
				}
			}
			if podReady {
				pc.Ready++
			}
			for _, cs := range p.Status.ContainerStatuses {
				if w := cs.State.Waiting; w != nil && redWaiting[w.Reason] {
					flag(Red, "/", cs.Name+": "+w.Reason)
				}
			}
			switch {
			case p.Status.Phase == "Pending" && now.Sub(p.Metadata.CreationTimestamp) > PendingGrace:
				flag(Red, ": ", "Pending > 5m")
			case p.Status.Phase == "Pending":
				flag(Amber, ": ", "starting")
			case p.Status.Phase == "Running" && !podReady:
				flag(Amber, ": ", "not ready")
			case p.Status.Phase == "Unknown":
				flag(Red, ": ", "status Unknown (node lost)")
			}
			c.PodList = append(c.PodList, pd)
		}
		sort.Slice(c.PodList, func(i, j int) bool { return c.PodList[i].Name < c.PodList[j].Name })
		if pc.Total > 0 {
			c.Pods = pc
		}
		for n := range onNode {
			c.Nodes = append(c.Nodes, n)
			m.Edges = append(m.Edges, Edge{From: c.ID, To: "node/" + n})
		}
		sort.Strings(c.Nodes)
		allSuspended := len(c.Apps) > 0
		for _, a := range c.Apps {
			switch a.Health {
			case "Degraded", "Missing":
				c.Status = worst(c.Status, Red)
				c.Reasons = appendOnce(c.Reasons, "app "+a.Name+": "+a.Health)
			case "Progressing", "Unknown":
				c.Status = worst(c.Status, Amber)
				c.Reasons = appendOnce(c.Reasons, "app "+a.Name+": "+a.Health)
			}
			if a.Health != "Suspended" {
				allSuspended = false
			}
			if a.Sync == "OutOfSync" || a.Sync == "Unknown" {
				c.Status = worst(c.Status, Amber)
				c.Reasons = appendOnce(c.Reasons, "app "+a.Name+": sync "+a.Sync)
			}
		}
		if allSuspended && pc.Total == 0 && c.Status == Green {
			c.Status = Grey
			c.Notes = append(c.Notes, "suspended on purpose")
		}
		if pc.Total == 0 && len(c.Apps) == 0 && r.err == nil {
			continue // an empty namespace isn't a component
		}
		switch {
		case in(platformNS, ns):
			platform = append(platform, c)
		case in(observeNS, ns):
			observe = append(observe, c)
		default:
			appTier = append(appTier, c)
		}
		m.byID[c.ID] = c
	}

	// ---- front doors (blackbox probes) ----
	var doors []*Component
	if b.Metrics != nil {
		samples, err := b.Metrics.Query(ctx, "probe_success", 200)
		if err != nil {
			m.Errors = append(m.Errors, "probes: "+err.Error())
		}
		for _, s := range samples {
			inst := s.Labels["instance"]
			if inst == "" {
				continue
			}
			c := &Component{ID: "door/" + inst, Name: doorName(inst), Kind: "frontdoor", Target: inst, Status: Green}
			if job := s.Labels["job"]; strings.HasPrefix(job, "staging") {
				c.Notes = append(c.Notes, "staging (no SLO)")
			}
			if s.Value != "1" {
				c.Status = Red
				c.Reasons = append(c.Reasons, "probe failing")
			}
			if ns := b.doorNamespace(inst, namespaces, appNS); ns != "" {
				m.Edges = append(m.Edges, Edge{From: c.ID, To: "ns/" + ns})
				if nc := m.byID["ns/"+ns]; nc != nil && c.Status == Red {
					nc.Status = worst(nc.Status, Red)
					nc.Reasons = appendOnce(nc.Reasons, "front door "+c.Name+" failing")
				}
			}
			doors = append(doors, c)
			m.byID[c.ID] = c
		}
	}

	for _, t := range [][]*Component{platform, observe, appTier, doors} {
		sort.Slice(t, func(i, j int) bool { return t[i].Name < t[j].Name })
	}
	m.Tiers = []Tier{
		{Name: "Host", Components: []*Component{host}},
		{Name: "Nodes", Components: nodeComps},
		{Name: "Platform", Components: platform},
		{Name: "Observability", Components: observe},
		{Name: "Apps", Components: appTier},
		{Name: "Front doors", Components: doors},
	}
	m.byID[host.ID] = host
	for _, n := range nodeComps {
		m.byID[n.ID] = n
	}
	for _, t := range m.Tiers {
		for _, c := range t.Components {
			m.Summary[c.Status]++
		}
	}
	m.causes()
	sort.Strings(m.Errors)
	return m, nil
}

// causes names the likely roots: red nodes first (everything on them is
// downstream), then red components whose own dependencies are healthy.
func (m *Map) causes() {
	affected := map[string]int{}
	for _, e := range m.Edges {
		if strings.HasPrefix(e.To, "node/") && strings.HasPrefix(e.From, "ns/") {
			if n := m.byID[e.To]; n != nil && n.Status == Red {
				affected[e.To]++
			}
		}
	}
	for _, t := range m.Tiers {
		for _, c := range t.Components {
			if c.Kind == "node" && c.Status == Red {
				m.Causes = append(m.Causes, fmt.Sprintf("Node %s is down — %d namespaces run on it", c.Name, affected[c.ID]))
			}
		}
	}
	for _, t := range m.Tiers {
		for _, c := range t.Components {
			if c.Kind != "namespace" || c.Status != Red {
				continue
			}
			downstream := false
			for _, r := range c.Reasons {
				if strings.Contains(r, "which is NotReady") {
					downstream = true
				}
			}
			if !downstream {
				m.Causes = append(m.Causes, fmt.Sprintf("%s: %s", c.Name, c.Reasons[0]))
			}
		}
	}
}

// Seen is a journaled investigation and the namespace it looked at.
type Seen struct {
	Investigation
	Namespace string
}

// Attach puts each namespace's latest investigation on its box and keeps the
// newest cluster-wide ones as Recent. invs must be newest first.
func (m *Map) Attach(invs []Seen) {
	for _, iv := range invs {
		if iv.Namespace == "" {
			if len(m.Recent) < 5 {
				m.Recent = append(m.Recent, iv.Investigation)
			}
			continue
		}
		if c := m.byID["ns/"+iv.Namespace]; c != nil && c.Last == nil {
			x := iv.Investigation
			c.Last = &x
		}
	}
}

// doorNamespace maps a probe target to the namespace that serves it.
func (b *Builder) doorNamespace(inst string, namespaces map[string]bool, appNS map[string]string) string {
	u, err := url.Parse(inst)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	h := u.Hostname()
	if strings.HasSuffix(h, ".svc.cluster.local") || strings.HasSuffix(h, ".svc") {
		parts := strings.Split(h, ".")
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	label, _, _ := strings.Cut(h, ".")
	if ns, ok := b.Hosts[label]; ok {
		return ns
	}
	if namespaces[label] {
		return label
	}
	if ns, ok := appNS[label]; ok {
		return ns
	}
	for app, ns := range appNS { // uptime → uptime-kuma, auth → authentik
		if strings.HasPrefix(app, label) {
			return ns
		}
	}
	return ""
}

func doorName(inst string) string {
	u, err := url.Parse(inst)
	if err != nil || u.Hostname() == "" {
		return inst
	}
	h := u.Hostname()
	if strings.HasSuffix(h, ".svc.cluster.local") {
		parts := strings.Split(h, ".")
		return parts[0] + "." + parts[1] + " (in-cluster)"
	}
	return h
}

func firstLine(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func appendOnce(list []string, s string) []string {
	if len(list) >= 6 || in(list, s) {
		return list
	}
	return append(list, s)
}
