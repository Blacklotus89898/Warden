package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/door"
	"github.com/Blacklotus89898/Warden/internal/kuma"
	"github.com/Blacklotus89898/Warden/internal/statusmap"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

type fakeKube struct{ apps string }

func (f fakeKube) GetJSON(_ context.Context, path string, _ url.Values, out any) error {
	if path != "/apis/argoproj.io/v1alpha1/namespaces/argocd/applications" {
		return errors.New("unexpected path " + path)
	}
	return json.Unmarshal([]byte(f.apps), out)
}

// fakeVM answers by which signal's expression it was given.
type fakeVM struct {
	by   map[string][]vm.Sample
	fail string
}

func (f fakeVM) Query(_ context.Context, expr string, _ int) ([]vm.Sample, error) {
	for sig, q := range Queries {
		if q.Expr == expr {
			if sig == f.fail {
				return nil, errors.New("boom")
			}
			return f.by[sig], nil
		}
	}
	return nil, errors.New("query not in the catalogue")
}

type fakeKuma struct {
	ms  []kuma.Monitor
	err error
}

func (f fakeKuma) Fetch(context.Context) ([]kuma.Monitor, error) { return f.ms, f.err }

const apps = `{"items":[
 {"metadata":{"name":"kavita"},"spec":{"destination":{"namespace":"kavita"}}},
 {"metadata":{"name":"linkding"},"spec":{"destination":{"namespace":"linkding"}}},
 {"metadata":{"name":"sealed-secrets"},"spec":{"destination":{"namespace":"sealed-secrets"}}},
 {"metadata":{"name":"cluster-dns"},"spec":{"destination":{"namespace":"kube-system"}}},
 {"metadata":{"name":"victoria-metrics"},"spec":{"destination":{"namespace":"monitoring"}}},
 {"metadata":{"name":"ntfy"},"spec":{"destination":{"namespace":"monitoring"}}},
 {"metadata":{"name":"no-dest"},"spec":{"destination":{}}}]}`

func s(ns, val string, label string) vm.Sample {
	return vm.Sample{Labels: map[string]string{label: ns}, Value: val}
}

func TestMonitorNamespace(t *testing.T) {
	explicit := map[string]string{"VictoriaMetrics": "monitoring"}
	cases := map[string]string{
		"Kavita":                "kavita",
		"kavita.lab.home":       "kavita",
		"Sealed Secrets":        "sealed-secrets",
		"Cluster DNS (CoreDNS)": "kube-system",
		"ntfy":                  "monitoring",
		"grafana.lab.home":      "monitoring", // Hosts override
		"VictoriaMetrics":       "monitoring", // explicit map
		"Proxmox":               "",
		"k3s worker kubelet":    "",
	}
	appNS := map[string]string{"kavita": "kavita", "linkding": "linkding", "sealed-secrets": "sealed-secrets",
		"cluster-dns": "kube-system", "victoria-metrics": "monitoring", "ntfy": "monitoring"}
	r := door.NewResolver(map[string]string{"grafana": "monitoring"}, appNS)
	for name, want := range cases {
		if got := monitorNamespace(r, explicit, name); got != want {
			t.Errorf("%q → %q, want %q", name, got, want)
		}
	}
}

func TestBuild(t *testing.T) {
	ns, svc := "namespace", "destination_service_namespace"
	b := &Builder{
		Kube: fakeKube{apps},
		Metrics: fakeVM{by: map[string][]vm.Sample{
			"traffic": {s("kavita", "0.5", svc), s("linkding", "0.2", svc)},
			"errors":  {s("kavita", "0", svc), s("linkding", "0.25", svc)},
			"latency": {s("kavita", "120", svc), s("linkding", "NaN", svc)},
			"memory":  {s("kavita", "0.4", ns), s("monitoring", "0.95", ns)},
		}, fail: "cpu"},
		Kuma: fakeKuma{ms: []kuma.Monitor{
			{Name: "Kavita", Group: "Apps", State: "up"},
			{Name: "kavita.lab.home", Group: "Front door", State: "up"},
			{Name: "Linkding", Group: "Apps", State: "up"},
			{Name: "Sealed Secrets", Group: "Cluster platform", State: "down"},
			{Name: "Proxmox", Group: "Home network", State: "up"},
			{Name: "Immich", Group: "Home network", State: "down"},
		}},
		Now: func() time.Time { return time.Date(2026, 11, 24, 3, 0, 0, 0, time.UTC) },
	}
	v, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*Service{}
	for _, s := range v.Services {
		by[s.Namespace] = s
	}
	if len(by) != 5 {
		t.Fatalf("services %v (an app with no destination is skipped)", keys(by))
	}

	k := by["kavita"]
	if k.Status != statusmap.Green || len(k.Monitors) != 2 || *k.Signals.TrafficRPS != 0.5 || *k.Signals.LatencyP95 != 120 || *k.Signals.Memory != 0.4 {
		t.Errorf("kavita = %+v signals %+v", k, k.Signals)
	}
	if k.Signals.CPU != nil {
		t.Error("a failed query leaves its cell empty")
	}
	l := by["linkding"]
	if l.Status != statusmap.Amber || l.Signals.LatencyP95 != nil || !strings.Contains(strings.Join(l.Flags, ";"), "5xx at 25%") {
		t.Errorf("linkding = %+v (NaN latency must be dropped)", l)
	}
	if ss := by["sealed-secrets"]; ss.Status != statusmap.Red {
		t.Errorf("a down monitor makes its service red: %+v", ss)
	}
	if m := by["monitoring"]; m.Status != statusmap.Amber || len(m.Apps) != 2 {
		t.Errorf("monitoring = %+v", m)
	}
	if v.Services[0].Namespace != "sealed-secrets" {
		t.Errorf("worst first, got %s", v.Services[0].Namespace)
	}
	if len(v.Outside) != 2 || v.Outside[0].Name != "Immich" {
		t.Errorf("outside = %+v (down first)", v.Outside)
	}
	if len(v.Errors) != 1 || !strings.HasPrefix(v.Errors[0], "cpu:") {
		t.Errorf("errors = %v", v.Errors)
	}
}

func TestBuildWithoutKuma(t *testing.T) {
	b := &Builder{Kube: fakeKube{apps}, Metrics: fakeVM{}, Kuma: fakeKuma{err: errors.New("down")}}
	v, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Services) != 5 || len(v.Errors) != 1 || !strings.HasPrefix(v.Errors[0], "uptime-kuma:") {
		t.Errorf("Kuma failing must not hide the signals: %+v", v)
	}
}

func TestQueriesCoverTheFourSignals(t *testing.T) {
	for _, sig := range []string{"traffic", "errors", "latency", "cpu", "memory"} {
		q, ok := Queries[sig]
		if !ok || q.Expr == "" || q.Label == "" || !strings.Contains(q.Expr, q.Label) {
			t.Errorf("%s: %+v", sig, q)
		}
	}
}

func keys(m map[string]*Service) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
