// Package demo is a made-up homelab for `go run ./cmd/warden-demo`: fake
// Kubernetes, VictoriaMetrics and Uptime Kuma sources that answer every read
// Warden's pages make, so the UI can be seen and screenshotted without a
// cluster. Nothing here is used by the real binary.
//
// The story: linkding got a new revision three hours ago, its memory climbed
// and it is now OOM-killed in a crash loop (an alert fired and was
// investigated); kavita had a latency spike yesterday afternoon; the tulip
// front door is failing. Everything else is healthy.
package demo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Blacklotus89898/Warden/internal/kuma"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

// App is one ArgoCD application in the fixture.
type App struct {
	Name, Namespace string
	Pods            int
	Traffic         float64 // requests/s at the gateway, 0 = no front door
	LatencyMs       float64
	CPU, Memory     float64 // share of limit
}

// Apps is the fixture's platform. Tiers follow the status map's grouping.
var Apps = []App{
	{"argocd", "argocd", 3, 0.04, 12, 0.03, 0.18},
	{"istio", "istio-system", 2, 0, 0, 0.01, 0.38},
	{"cluster-dns", "kube-system", 1, 0, 0, 0.01, 0.22},
	{"sealed-secrets", "sealed-secrets", 1, 0, 0, 0.002, 0.11},
	{"victoria-metrics", "monitoring", 4, 0.24, 35, 0.14, 0.62},
	{"uptime-kuma", "monitoring", 1, 0, 0, 0.02, 0.4},
	{"linkding", "linkding", 1, 0.14, 48, 0.05, 0.97},
	{"kavita", "kavita", 1, 0.05, 30, 0.01, 0.16},
	{"petal", "petal", 1, 0.04, 22, 0.01, 0.24},
	{"tulip", "tulip", 1, 0.03, 18, 0.004, 0.06},
	{"warden", "warden", 1, 0.05, 40, 0.004, 0.22},
}

// MonitorNS joins Kuma monitors whose names resolve to no namespace
// (WARDEN_KUMA_MAP in a real deployment).
var MonitorNS = map[string]string{"Istio gateway": "istio-system", "VictoriaMetrics": "monitoring"}

// Nodes are the fixture's two k3s nodes.
var Nodes = []string{"cp-1", "worker-1"}

// Source is the fake cluster: Kubernetes reads, VictoriaMetrics queries and
// the Kuma status page, all anchored at Now.
type Source struct {
	Now time.Time
}

// New anchors the fixture at now.
func New(now time.Time) *Source { return &Source{Now: now.UTC().Truncate(time.Minute)} }

func (s *Source) ago(d time.Duration) time.Time { return s.Now.Add(-d) }

func nodeFor(ns string, i int) string {
	switch ns {
	case "kube-system", "argocd", "sealed-secrets":
		return "cp-1"
	case "istio-system":
		return Nodes[i%2]
	}
	return "worker-1"
}

// ---------------------------------------------------------------- Kubernetes

// GetJSON answers the catalogue paths the pages read.
func (s *Source) GetJSON(_ context.Context, path string, _ url.Values, out any) error {
	v, err := s.object(path)
	if err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// Get answers pod logs.
func (s *Source) Get(_ context.Context, path string, q url.Values) ([]byte, error) {
	if strings.HasPrefix(path, "/api/v1/namespaces/linkding/pods/") && strings.HasSuffix(path, "/log") {
		lines := []string{
			"[2026-11-24 11:02:10] INFO  Booting worker with pid: 7",
			"[2026-11-24 11:02:11] INFO  Background task runner started",
			"[2026-11-24 11:04:37] INFO  Importing bookmarks: 18,240 rows",
			"[2026-11-24 11:05:02] WARN  Import batch held in memory (no streaming): 912 MiB",
			"[2026-11-24 11:05:09] INFO  Building search index",
		}
		return []byte(strings.Join(lines, "\n") + "\n"), nil
	}
	return []byte("ready\n"), nil
}

var podsPath = regexp.MustCompile(`^/api/v1/namespaces/([a-z0-9-]+)/(pods|events)$`)

func (s *Source) object(path string) (any, error) {
	switch path {
	case "/api/v1/nodes":
		var items []any
		for _, n := range Nodes {
			items = append(items, map[string]any{
				"metadata": map[string]any{"name": n},
				"status": map[string]any{"conditions": []any{
					map[string]any{"type": "Ready", "status": "True"},
					map[string]any{"type": "MemoryPressure", "status": "False"},
					map[string]any{"type": "DiskPressure", "status": "False"},
				}},
			})
		}
		return map[string]any{"items": items}, nil
	case "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications":
		var items []any
		for _, a := range Apps {
			health, sync := "Healthy", "Synced"
			hist := []any{
				map[string]any{"id": 1, "revision": "3f1c2a9e7b4d", "deployedAt": s.ago(9 * 24 * time.Hour)},
				map[string]any{"id": 2, "revision": "8d2e44b1c0aa", "deployedAt": s.ago(2*24*time.Hour + 3*time.Hour)},
			}
			if a.Name == "linkding" {
				health = "Degraded"
				hist = append(hist, map[string]any{"id": 3, "revision": "c41f9e02d7b3", "deployedAt": s.ago(3 * time.Hour)})
			}
			items = append(items, map[string]any{
				"metadata": map[string]any{"name": a.Name},
				"spec":     map[string]any{"destination": map[string]any{"namespace": a.Namespace}},
				"status": map[string]any{
					"sync":    map[string]any{"status": sync, "revision": "c41f9e02d7b3"},
					"health":  map[string]any{"status": health},
					"history": hist,
					"operationState": map[string]any{"phase": "Succeeded", "message": "successfully synced (all tasks run)",
						"startedAt": s.ago(3 * time.Hour), "finishedAt": s.ago(3*time.Hour - 40*time.Second)},
				},
			})
		}
		return map[string]any{"items": items}, nil
	}
	m := podsPath.FindStringSubmatch(path)
	if m == nil {
		return nil, errors.New("demo: not in the read catalogue: " + path)
	}
	ns := m[1]
	if m[2] == "events" {
		return map[string]any{"items": s.events(ns)}, nil
	}
	var items []any
	for _, a := range Apps {
		if a.Namespace != ns {
			continue
		}
		for i := 0; i < a.Pods; i++ {
			items = append(items, s.pod(a, i))
		}
	}
	return map[string]any{"items": items}, nil
}

func (s *Source) pod(a App, i int) any {
	name := fmt.Sprintf("%s-%x-%d", a.Name, 0x5c9f7+i*977, i)
	created := s.ago(2*24*time.Hour + 3*time.Hour)
	cs := map[string]any{"name": a.Name, "ready": true, "restartCount": 0,
		"state": map[string]any{"running": map[string]any{"startedAt": created}}}
	phase := "Running"
	if a.Name == "linkding" {
		created = s.ago(3 * time.Hour)
		name = "linkding-c41f9e-7xk2p"
		cs = map[string]any{"name": "linkding", "ready": false, "restartCount": 6,
			"state": map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff",
				"message": "back-off 5m0s restarting failed container=linkding"}},
			"lastState": map[string]any{"terminated": map[string]any{"reason": "OOMKilled", "exitCode": 137,
				"finishedAt": s.ago(4 * time.Minute)}}}
	}
	return map[string]any{
		"metadata": map[string]any{"name": name, "namespace": a.Namespace, "creationTimestamp": created,
			"labels": map[string]any{"app": a.Name}},
		"spec": map[string]any{"nodeName": nodeFor(a.Namespace, i)},
		"status": map[string]any{"phase": phase, "containerStatuses": []any{cs},
			"conditions": []any{map[string]any{"type": "Ready", "status": ready(a.Name != "linkding")}}},
	}
}

func ready(ok bool) string {
	if ok {
		return "True"
	}
	return "False"
}

func (s *Source) events(ns string) []any {
	if ns != "linkding" {
		return nil
	}
	ev := func(typ, reason, kind, obj, msg string, count int, first, last time.Duration) any {
		return map[string]any{"type": typ, "reason": reason, "message": msg, "count": count,
			"involvedObject": map[string]any{"kind": kind, "name": obj},
			"firstTimestamp": s.ago(first), "lastTimestamp": s.ago(last)}
	}
	return []any{
		ev("Normal", "ScalingReplicaSet", "Deployment", "linkding", "Scaled up replica set linkding-c41f9e to 1", 1, 3*time.Hour, 3*time.Hour),
		ev("Normal", "Killing", "Pod", "linkding-8d2e44-q9mfz", "Stopping container linkding", 1, 3*time.Hour-time.Minute, 3*time.Hour-time.Minute),
		ev("Warning", "BackOff", "Pod", "linkding-c41f9e-7xk2p", "Back-off restarting failed container linkding in pod linkding-c41f9e-7xk2p", 23, 55*time.Minute, 2*time.Minute),
		ev("Warning", "Unhealthy", "Pod", "linkding-c41f9e-7xk2p", "Readiness probe failed: Get \"http://10.42.1.37:9090/health\": connect: connection refused", 41, 58*time.Minute, 3*time.Minute),
	}
}

// ---------------------------------------------------------------- metrics

var nsLabel = regexp.MustCompile(`(destination_service_namespace|namespace)="([a-z0-9-]+)"`)

func appsIn(ns string) []App {
	var out []App
	for _, a := range Apps {
		if a.Namespace == ns {
			out = append(out, a)
		}
	}
	return out
}

func namespaces() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range Apps {
		if !seen[a.Namespace] {
			seen[a.Namespace] = true
			out = append(out, a.Namespace)
		}
	}
	return out
}

// signal names the golden signal an expression asks for.
func signal(expr string) string {
	switch {
	case strings.Contains(expr, "histogram_quantile"):
		return "latency"
	case strings.Contains(expr, `response_code=~"5.."`):
		return "errors"
	case strings.Contains(expr, "kube_pod_container_status_restarts_total"):
		return "restarts"
	case strings.Contains(expr, "container_cpu_usage_seconds_total"):
		return "cpu"
	case strings.Contains(expr, "container_memory_working_set_bytes"):
		return "memory"
	case strings.Contains(expr, "istio_requests_total"):
		return "traffic"
	}
	return ""
}

// value is ns's signal at t: a daily rhythm plus the story's incidents.
func (s *Source) value(ns, sig string, t time.Time) (float64, bool) {
	var a App
	var traffic, mem, cpu float64
	for _, x := range appsIn(ns) {
		a = x
		traffic += x.Traffic
		mem = math.Max(mem, x.Memory)
		cpu = math.Max(cpu, x.CPU)
	}
	if a.Name == "" {
		return 0, false
	}
	hour := float64(t.Hour()) + float64(t.Minute())/60
	day := 0.75 + 0.35*math.Sin((hour-9)/24*2*math.Pi) // busier in the evening
	wobble := 1 + 0.06*math.Sin(float64(t.Unix())/1700+float64(len(ns)))
	since := s.Now.Sub(t)
	switch sig {
	case "traffic":
		if traffic == 0 {
			return 0, false
		}
		v := traffic * day * wobble
		if ns == "linkding" && since < time.Hour {
			v *= 0.2
		}
		return v, true
	case "errors":
		if traffic == 0 {
			return 0, false
		}
		if ns == "linkding" && since < time.Hour {
			return 0.62, true
		}
		return 0, true
	case "latency":
		if traffic == 0 {
			return 0, false
		}
		v := a.LatencyMs * (0.85 + 0.3*day) * wobble
		if ns == "kavita" && since > 20*time.Hour && since < 20*time.Hour+40*time.Minute {
			v = 4200
		}
		return v, true
	case "cpu":
		return cpu * day * wobble, true
	case "memory":
		if ns == "linkding" {
			switch {
			case since > 3*time.Hour:
				return 0.41 * wobble, true
			case since > time.Hour:
				return 0.41 + 0.56*(1-float64(since-time.Hour)/float64(2*time.Hour)), true
			default:
				return 0.97 - 0.3*math.Abs(math.Sin(float64(t.Unix())/400)), true
			}
		}
		return mem * (0.97 + 0.03*wobble), true
	case "restarts":
		if ns == "linkding" && since < time.Hour {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// Query answers instant queries: golden signals by namespace, blast radius,
// blackbox probes and an alert's expression.
func (s *Source) Query(_ context.Context, expr string, _ int) ([]vm.Sample, error) {
	if expr == "probe_success" {
		var out []vm.Sample
		for _, d := range []string{"argocd", "linkding", "kavita", "petal", "tulip", "warden", "grafana"} {
			v := "1"
			if d == "tulip" {
				v = "0"
			}
			out = append(out, vm.Sample{Labels: map[string]string{"instance": "https://" + d + ".lab.home/", "job": "frontdoor"}, Value: v})
		}
		return out, nil
	}
	if strings.Contains(expr, "last_terminated_reason") { // the story's ContainerOOMKilled rule
		return []vm.Sample{{Labels: map[string]string{"namespace": "linkding", "pod": "linkding-c41f9e-7xk2p", "container": "linkding"}, Value: "1"}}, nil
	}
	if strings.Contains(expr, "increase(") && strings.Contains(expr, "> 0") {
		return s.blast(expr), nil
	}
	sig := signal(expr)
	if sig == "" {
		return []vm.Sample{{Labels: map[string]string{"namespace": "linkding", "container": "linkding"}, Value: "1"}}, nil
	}
	label := "namespace"
	if strings.Contains(expr, "destination_service_namespace)") {
		label = "destination_service_namespace"
	}
	if m := nsLabel.FindStringSubmatch(expr); m != nil {
		v, ok := s.value(m[2], sig, s.Now)
		if !ok {
			return nil, nil
		}
		return []vm.Sample{{Labels: map[string]string{label: m[2]}, Value: fmt.Sprint(v)}}, nil
	}
	var out []vm.Sample
	for _, ns := range namespaces() {
		if v, ok := s.value(ns, sig, s.Now); ok {
			out = append(out, vm.Sample{Labels: map[string]string{label: ns}, Value: fmt.Sprint(v)})
		}
	}
	return out, nil
}

// calls is who calls whom in the fixture (requests over 24h).
var calls = []struct {
	from, to string
	n        float64
}{
	{"istio-system", "linkding", 12100}, {"istio-system", "kavita", 4300}, {"istio-system", "petal", 3600},
	{"istio-system", "tulip", 2800}, {"istio-system", "warden", 4100}, {"istio-system", "argocd", 3500},
	{"monitoring", "linkding", 1440}, {"monitoring", "kavita", 1440}, {"monitoring", "warden", 2880},
	{"warden", "monitoring", 5200}, {"warden", "argocd", 900}, {"petal", "argocd", 300},
	{"linkding", "default", 260},
}

func (s *Source) blast(expr string) []vm.Sample {
	m := nsLabel.FindStringSubmatch(expr)
	if m == nil {
		return nil
	}
	ns := m[2]
	asCaller := strings.Contains(expr, `source_workload_namespace="`)
	tcp := strings.Contains(expr, "istio_tcp_connections_opened_total")
	var out []vm.Sample
	for _, c := range calls {
		n := c.n
		if tcp {
			n = math.Round(n / 40)
		}
		switch {
		case asCaller && c.from == ns:
			out = append(out, vm.Sample{Labels: map[string]string{"destination_service_namespace": c.to}, Value: fmt.Sprint(n)})
		case !asCaller && c.to == ns:
			out = append(out, vm.Sample{Labels: map[string]string{"source_workload_namespace": c.from}, Value: fmt.Sprint(n)})
		}
	}
	return out
}

// QueryRange answers the services history and console traffic panels.
func (s *Source) QueryRange(_ context.Context, expr string, start, end time.Time, step time.Duration, _ int) ([]vm.Series, error) {
	sig := signal(expr)
	if sig == "" {
		return nil, nil
	}
	points := func(ns, sig string, scale float64) [][2]float64 {
		var pts [][2]float64
		for t := start; !t.After(end); t = t.Add(step) {
			if v, ok := s.value(ns, sig, t); ok {
				pts = append(pts, [2]float64{float64(t.Unix()), v * scale})
			}
		}
		return pts
	}
	if m := nsLabel.FindStringSubmatch(expr); m != nil { // console: one namespace
		ns := m[2]
		if strings.Contains(expr, "by (class)") {
			var out []vm.Series
			for class, share := range map[string]float64{"2xx": 0.93, "3xx": 0.05, "4xx": 0.02} {
				out = append(out, vm.Series{Labels: map[string]string{"class": class}, Points: points(ns, "traffic", share)})
			}
			if ns == "linkding" {
				var pts [][2]float64
				for t := start; !t.After(end); t = t.Add(step) {
					v := 0.0
					if s.Now.Sub(t) < time.Hour {
						v = 0.018
					}
					pts = append(pts, [2]float64{float64(t.Unix()), v})
				}
				out = append(out, vm.Series{Labels: map[string]string{"class": "5xx"}, Points: pts})
			}
			return out, nil
		}
		pts := points(ns, sig, 1)
		if len(pts) == 0 {
			return nil, nil
		}
		return []vm.Series{{Labels: map[string]string{}, Points: pts}}, nil
	}
	label := "namespace"
	if strings.Contains(expr, "destination_service_namespace)") {
		label = "destination_service_namespace"
	}
	var out []vm.Series
	for _, ns := range namespaces() {
		if pts := points(ns, sig, 1); len(pts) > 0 {
			out = append(out, vm.Series{Labels: map[string]string{label: ns}, Points: pts})
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- Uptime Kuma

// Fetch is the Kuma status page.
func (s *Source) Fetch(context.Context) ([]kuma.Monitor, error) {
	up := func(group, name string, ping int, cert int) kuma.Monitor {
		m := kuma.Monitor{Group: group, Name: name, Type: "http", State: "up", Uptime24: f(0.9998)}
		if ping > 0 {
			m.PingMs = &ping
		}
		if cert > 0 {
			m.CertDays = &cert
		}
		for i := 0; i < 30; i++ {
			m.Recent = append(m.Recent, "up")
		}
		return m
	}
	ld := up("Apps", "Linkding", 0, 0)
	ld.State, ld.Uptime24, ld.Msg = "down", f(0.962), "connect ECONNREFUSED 10.43.12.9:9090"
	for i := 24; i < 30; i++ {
		ld.Recent[i] = "down"
	}
	ld.Recent[22], ld.Recent[23] = "pending", "down"
	ldDoor := up("Front door (Istio gateway)", "linkding.lab.home", 0, 56)
	ldDoor.State, ldDoor.Msg = "down", "Request failed with status code 503"
	for i := 25; i < 30; i++ {
		ldDoor.Recent[i] = "down"
	}
	tulipDoor := up("Front door (Istio gateway)", "tulip.lab.home", 0, 56)
	tulipDoor.State, tulipDoor.Msg = "down", "Request failed with status code 404"
	for i := 0; i < 30; i++ {
		tulipDoor.Recent[i] = "down"
	}
	nas := up("Home network", "NAS", 3, 0)
	nas.State, nas.Msg = "down", "timeout of 48000ms exceeded"
	for i := 12; i < 30; i++ {
		nas.Recent[i] = "down"
	}
	return []kuma.Monitor{
		up("Cluster platform", "ArgoCD", 8, 0), up("Cluster platform", "Istio gateway", 4, 0),
		up("Cluster platform", "Cluster DNS (CoreDNS)", 1, 0), up("Cluster platform", "Sealed Secrets", 3, 0),
		up("Observability", "VictoriaMetrics", 4, 0), up("Observability", "Uptime Kuma", 2, 0),
		ld, up("Apps", "Kavita", 5, 0), up("Apps", "Petal", 4, 0), up("Apps", "Tulip", 3, 0), up("Apps", "Warden", 4, 0),
		up("Front door (Istio gateway)", "argocd.lab.home", 10, 56), ldDoor, up("Front door (Istio gateway)", "kavita.lab.home", 6, 56),
		tulipDoor, up("Front door (Istio gateway)", "warden.lab.home", 9, 56),
		up("Home network", "Hypervisor", 2, 0), up("Home network", "Router", 3, 0), up("Home network", "DNS", 1, 0), nas,
	}, nil
}

func f(v float64) *float64 { return &v }
