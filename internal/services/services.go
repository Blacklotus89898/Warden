// Package services builds the per-service health view: the four golden
// signals for every namespace ArgoCD deploys (traffic, errors and latency as
// the Istio gateway sees them, saturation as CPU and memory against limits),
// joined with each service's Uptime Kuma monitors. Monitors that map to no
// namespace (the Proxmox host, LXCs, the router) are listed on their own.
//
// It only presents evidence: thresholds colour a cell, nothing is concluded
// or acted on. Sources are the ones Warden already reads (ArgoCD
// Applications, vmsingle instant queries) plus Kuma's public status page.
package services

import (
	"context"
	_ "embed"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Blacklotus89898/Warden/internal/door"
	"github.com/Blacklotus89898/Warden/internal/kube"
	"github.com/Blacklotus89898/Warden/internal/kuma"
	"github.com/Blacklotus89898/Warden/internal/statusmap"
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

// Kuma reads the status page (kuma.Client implements it).
type Kuma interface {
	Fetch(ctx context.Context) ([]kuma.Monitor, error)
}

// Page is the services UI; it fetches services.json next to itself.
//
//go:embed services.html
var Page []byte

// Window is the rate window behind every "now" number.
const Window = "5m"

// Thresholds that colour a cell. They match the paging rules in Homelab
// infrastructure/victoria-metrics/golden-signals-rules.yaml, so amber here
// means "the alert would be getting close".
const (
	ErrorAmber      = 0.10 // ServiceErrorRateHigh: 5xx share above 10%
	LatencyAmberMs  = 3000 // ServiceLatencyHigh: p95 above 3s
	SaturationAmber = 0.90 // ContainerMemoryNearLimit: 90% of the limit
)

// Query is one golden-signal expression and the label naming its namespace.
type Query struct {
	Expr  string
	Label string
}

// Queries is the fixed set of golden-signal expressions, one series per
// namespace. Traffic, errors and latency come from the Istio gateway
// (reporter="source"), the same series as the Grafana "Service health"
// dashboard, grouped by namespace instead of service name.
var Queries = map[string]Query{
	"traffic": {`sum by (destination_service_namespace) (rate(istio_requests_total{reporter="source"}[` + Window + `]))`, "destination_service_namespace"},
	"errors": {`sum by (destination_service_namespace) (rate(istio_requests_total{reporter="source",response_code=~"5.."}[` + Window + `]))` +
		` / sum by (destination_service_namespace) (rate(istio_requests_total{reporter="source"}[` + Window + `]))`, "destination_service_namespace"},
	"latency": {`histogram_quantile(0.95, sum by (le, destination_service_namespace) (rate(istio_request_duration_milliseconds_bucket{reporter="source"}[` + Window + `])))`, "destination_service_namespace"},
	"cpu": {`max by (namespace) (max by (namespace, container) (rate(container_cpu_usage_seconds_total{container!="",container!="POD"}[` + Window + `]))` +
		` / max by (namespace, container) (kube_pod_container_resource_limits{resource="cpu"}))`, "namespace"},
	"memory": {`max by (namespace) (max by (namespace, container) (container_memory_working_set_bytes{container!="",container!="POD"})` +
		` / max by (namespace, container) (kube_pod_container_resource_limits{resource="memory"}))`, "namespace"},
}

// Signals are one service's golden signals now. Nil means no data: a
// service with no gateway route has no traffic/errors/latency series.
type Signals struct {
	TrafficRPS *float64 `json:"trafficRps,omitempty"`
	ErrorShare *float64 `json:"errorShare,omitempty"` // 0..1
	LatencyP95 *float64 `json:"latencyP95Ms,omitempty"`
	CPU        *float64 `json:"cpuOfLimit,omitempty"`    // busiest container, 0..1
	Memory     *float64 `json:"memoryOfLimit,omitempty"` // fullest container, 0..1
}

// Service is one namespace with its apps, signals and monitors.
type Service struct {
	Namespace string           `json:"namespace"`
	Apps      []string         `json:"apps,omitempty"`
	Status    statusmap.Status `json:"status"`
	Flags     []string         `json:"flags,omitempty"` // why it isn't green
	Signals   Signals          `json:"signals"`
	Monitors  []kuma.Monitor   `json:"monitors,omitempty"`
}

// View is the whole page.
type View struct {
	Generated time.Time      `json:"generated"`
	Window    string         `json:"window"`
	Services  []*Service     `json:"services"`
	Outside   []kuma.Monitor `json:"outside,omitempty"` // monitors with no namespace
	Errors    []string       `json:"errors,omitempty"`
}

// Builder assembles a View.
type Builder struct {
	Kube    Kube
	Metrics Metrics
	Kuma    Kuma // nil: no monitors
	// Hosts is the front-door label override shared with the status map.
	Hosts map[string]string
	// MonitorNS maps a Kuma monitor name to its namespace when the name
	// resolves to none on its own (WARDEN_KUMA_MAP).
	MonitorNS map[string]string
	Now       func() time.Time
}

var paren = regexp.MustCompile(`\s*\(.*?\)`)

// monitorNamespace resolves a Kuma monitor to a namespace, "" if none:
// the explicit map, then the monitor name as a front-door host
// (kavita.lab.home) or as a name (Sealed Secrets → sealed-secrets).
func monitorNamespace(r *door.Resolver, explicit map[string]string, name string) string {
	if ns, ok := explicit[name]; ok {
		return ns
	}
	if strings.Contains(name, ".") && !strings.Contains(name, " ") {
		return r.Namespace("https://" + name)
	}
	slug := strings.ToLower(strings.TrimSpace(paren.ReplaceAllString(name, "")))
	slug = strings.ReplaceAll(slug, " ", "-")
	if slug == "" {
		return ""
	}
	return r.Namespace("https://" + slug)
}

// Build reads ArgoCD, vmsingle and Kuma. A failing source is listed in
// Errors and leaves its cells empty; Build only fails if it cannot list the
// ArgoCD Applications that define what a service is.
func (b *Builder) Build(ctx context.Context) (*View, error) {
	now := time.Now
	if b.Now != nil {
		now = b.Now
	}
	v := &View{Generated: now().UTC(), Window: Window}

	var apps kube.List[kube.Application]
	if err := b.Kube.GetJSON(ctx, "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications", nil, &apps); err != nil {
		return nil, fmt.Errorf("services: applications: %w", err)
	}
	byNS := map[string]*Service{}
	appNS := map[string]string{}
	for _, a := range apps.Items {
		ns := a.Spec.Destination.Namespace
		if ns == "" {
			continue
		}
		appNS[a.Metadata.Name] = ns
		s := byNS[ns]
		if s == nil {
			s = &Service{Namespace: ns, Status: statusmap.Green}
			byNS[ns] = s
		}
		s.Apps = append(s.Apps, a.Metadata.Name)
	}

	// Signals and monitors are independent reads: run them together.
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = map[string]map[string]float64{}
		mons    []kuma.Monitor
	)
	fail := func(what string, err error) {
		mu.Lock()
		v.Errors = append(v.Errors, what+": "+err.Error())
		mu.Unlock()
	}
	for sig, q := range Queries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			samples, err := b.Metrics.Query(ctx, q.Expr, 0)
			if err != nil {
				fail(sig, err)
				return
			}
			m := map[string]float64{}
			for _, s := range samples {
				f, err := strconv.ParseFloat(s.Value, 64)
				if ns := s.Labels[q.Label]; ns != "" && err == nil && !isNaN(f) {
					m[ns] = f
				}
			}
			mu.Lock()
			results[sig] = m
			mu.Unlock()
		}()
	}
	if b.Kuma != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ms, err := b.Kuma.Fetch(ctx)
			if err != nil {
				fail("uptime-kuma", err)
				return
			}
			mons = ms
		}()
	}
	wg.Wait()

	pick := func(sig, ns string) *float64 {
		if f, ok := results[sig][ns]; ok {
			return &f
		}
		return nil
	}
	for ns, s := range byNS {
		s.Signals = Signals{
			TrafficRPS: pick("traffic", ns),
			ErrorShare: pick("errors", ns),
			LatencyP95: pick("latency", ns),
			CPU:        pick("cpu", ns),
			Memory:     pick("memory", ns),
		}
	}

	r := door.NewResolver(b.Hosts, appNS)
	for _, m := range mons {
		ns := monitorNamespace(r, b.MonitorNS, m.Name)
		if s := byNS[ns]; s != nil {
			s.Monitors = append(s.Monitors, m)
		} else {
			v.Outside = append(v.Outside, m)
		}
	}

	for _, s := range byNS {
		grade(s)
		sort.Strings(s.Apps)
		v.Services = append(v.Services, s)
	}
	sort.Slice(v.Services, func(i, j int) bool {
		ri, rj := rank(v.Services[i].Status), rank(v.Services[j].Status)
		if ri != rj {
			return ri > rj
		}
		return v.Services[i].Namespace < v.Services[j].Namespace
	})
	sort.SliceStable(v.Outside, func(i, j int) bool {
		ri, rj := monRank(v.Outside[i].State), monRank(v.Outside[j].State)
		if ri != rj {
			return ri > rj
		}
		return v.Outside[i].Group < v.Outside[j].Group
	})
	sort.Strings(v.Errors)
	return v, nil
}

// grade colours a service from what is measured; it never guesses a cause.
func grade(s *Service) {
	flag := func(st statusmap.Status, why string) {
		if rank(st) > rank(s.Status) {
			s.Status = st
		}
		s.Flags = append(s.Flags, why)
	}
	for _, m := range s.Monitors {
		switch m.State {
		case "down":
			flag(statusmap.Red, "Kuma: "+m.Name+" down")
		case "pending":
			flag(statusmap.Amber, "Kuma: "+m.Name+" pending")
		}
	}
	sg := s.Signals
	if sg.ErrorShare != nil && *sg.ErrorShare > ErrorAmber && sg.TrafficRPS != nil && *sg.TrafficRPS > 0 {
		flag(statusmap.Amber, fmt.Sprintf("5xx at %.0f%%", *sg.ErrorShare*100))
	}
	if sg.LatencyP95 != nil && *sg.LatencyP95 > LatencyAmberMs {
		flag(statusmap.Amber, fmt.Sprintf("p95 %.1fs", *sg.LatencyP95/1000))
	}
	if sg.Memory != nil && *sg.Memory > SaturationAmber {
		flag(statusmap.Amber, fmt.Sprintf("memory at %.0f%% of limit", *sg.Memory*100))
	}
	if sg.CPU != nil && *sg.CPU > SaturationAmber {
		flag(statusmap.Amber, fmt.Sprintf("CPU at %.0f%% of limit", *sg.CPU*100))
	}
}

func rank(s statusmap.Status) int {
	switch s {
	case statusmap.Red:
		return 4
	case statusmap.Amber:
		return 3
	case statusmap.Unknown:
		return 2
	case statusmap.Green:
		return 1
	}
	return 0
}

func monRank(state string) int {
	switch state {
	case "down":
		return 3
	case "pending":
		return 2
	case "up":
		return 0
	}
	return 1
}

func isNaN(f float64) bool { return f != f }
