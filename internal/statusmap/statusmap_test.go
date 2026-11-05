package statusmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/kube"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

var now = time.Date(2026, 11, 5, 0, 20, 0, 0, time.UTC)

type fakeKube struct {
	resp map[string]string
	got  []string
}

func (f *fakeKube) GetJSON(_ context.Context, path string, _ url.Values, out any) error {
	f.got = append(f.got, path)
	b, ok := f.resp[path]
	if !ok {
		b = `{"items":[]}`
	}
	return json.Unmarshal([]byte(b), out)
}

type fakeVM struct{ s []vm.Sample }

func (f fakeVM) Query(context.Context, string, int) ([]vm.Sample, error) { return f.s, nil }

const nodesJSON = `{"items":[
 {"metadata":{"name":"debian"},"spec":{"unschedulable":true},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"k3s-worker-01"},"status":{"conditions":[{"type":"Ready","status":"%s","message":"Kubelet stopped posting node status."}]}}]}`

func pod(name, node, phase string, ready bool, waiting string, created time.Time) string {
	rs := "False"
	if ready {
		rs = "True"
	}
	w := ""
	if waiting != "" {
		w = fmt.Sprintf(`,"state":{"waiting":{"reason":%q}}`, waiting)
	}
	return fmt.Sprintf(`{"metadata":{"name":%q,"creationTimestamp":%q},"spec":{"nodeName":%q},
	 "status":{"phase":%q,"conditions":[{"type":"Ready","status":%q}],"containerStatuses":[{"name":"c","ready":%v%s}]}}`,
		name, created.Format(time.RFC3339), node, phase, rs, ready, w)
}

func items(p ...string) string { return `{"items":[` + strings.Join(p, ",") + `]}` }

const appsJSON = `{"items":[
 {"metadata":{"name":"kavita"},"spec":{"destination":{"namespace":"kavita"}},"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}},
 {"metadata":{"name":"uptime-kuma"},"spec":{"destination":{"namespace":"monitoring"}},"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}},
 {"metadata":{"name":"audiobookshelf"},"spec":{"destination":{"namespace":"audiobookshelf"}},"status":{"sync":{"status":"Synced"},"health":{"status":"Suspended"}}},
 {"metadata":{"name":"petal"},"spec":{"destination":{"namespace":"petal"}},"status":{"sync":{"status":"OutOfSync"},"health":{"status":"Healthy"}}}]}`

func build(t *testing.T, workerReady string, extra map[string]string, probes []vm.Sample) (*Map, *fakeKube) {
	t.Helper()
	old := now.Add(-time.Hour)
	fk := &fakeKube{resp: map[string]string{
		"/api/v1/nodes": fmt.Sprintf(nodesJSON, workerReady),
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications": appsJSON,
		"/api/v1/namespaces/kavita/pods":                            items(pod("kavita-1", "k3s-worker-01", "Running", true, "", old)),
		"/api/v1/namespaces/monitoring/pods":                        items(pod("uptime-0", "k3s-worker-01", "Running", true, "", old)),
		"/api/v1/namespaces/petal/pods":                             items(pod("petal-1", "k3s-worker-01", "Running", true, "", old)),
		"/api/v1/namespaces/kube-system/pods":                       items(pod("coredns-1", "debian", "Running", true, "", old), pod("job-1", "debian", "Failed", false, "", old)),
	}}
	for k, v := range extra {
		fk.resp[k] = v
	}
	b := &Builder{Kube: fk, Metrics: fakeVM{probes}, Hosts: map[string]string{"grafana": "monitoring"}, Now: func() time.Time { return now }}
	m, err := b.Build(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return m, fk
}

func comp(m *Map, id string) *Component {
	if c := m.byID[id]; c != nil {
		return c
	}
	return &Component{}
}

func TestNodeDownMakesItsNamespacesRedAndIsTheCause(t *testing.T) {
	m, _ := build(t, "Unknown", nil, nil)
	if comp(m, "node/k3s-worker-01").Status != Red {
		t.Fatal("NotReady node must be red")
	}
	for _, ns := range []string{"kavita", "monitoring", "petal"} {
		if c := comp(m, "ns/"+ns); c.Status != Red || !strings.Contains(strings.Join(c.Reasons, ";"), "k3s-worker-01, which is NotReady") {
			t.Errorf("%s = %s %v; want red, downstream of the node", ns, c.Status, c.Reasons)
		}
	}
	if comp(m, "ns/kube-system").Status != Green {
		t.Errorf("kube-system runs on debian only; got %s", comp(m, "ns/kube-system").Status)
	}
	if len(m.Causes) != 1 || !strings.Contains(m.Causes[0], "k3s-worker-01 is down — 3 namespaces") {
		t.Fatalf("causes = %v; want only the node (namespaces on it are downstream)", m.Causes)
	}
}

func TestHealthyClusterHasNoCauses(t *testing.T) {
	m, _ := build(t, "True", nil, nil)
	if len(m.Causes) != 0 || m.Summary[Red] != 0 {
		t.Fatalf("causes %v, summary %v", m.Causes, m.Summary)
	}
	if comp(m, "host/proxmox").Status != Green {
		t.Error("host is inferred green when a node is Ready")
	}
	if n := comp(m, "node/debian"); n.Status != Green || len(n.Notes) == 0 {
		t.Errorf("cordoned is a note, not a fault: %+v", n)
	}
	if comp(m, "ns/audiobookshelf").Status != Grey {
		t.Errorf("suspended app with no pods = grey; got %s", comp(m, "ns/audiobookshelf").Status)
	}
	if comp(m, "ns/petal").Status != Amber {
		t.Errorf("OutOfSync = amber; got %s", comp(m, "ns/petal").Status)
	}
	if pl := comp(m, "ns/kube-system").PodList; len(pl) != 1 || pl[0].Status != Green {
		t.Errorf("one live green pod dot (the finished Job is left out): %+v", pl)
	}
	if p := comp(m, "ns/kube-system").Pods; p == nil || p.Total != 1 {
		t.Errorf("finished Job pods are not counted: %+v", p)
	}
}

func TestCrashLoopIsARootCause(t *testing.T) {
	m, _ := build(t, "True", map[string]string{
		"/api/v1/namespaces/kavita/pods": items(pod("kavita-1", "k3s-worker-01", "Running", false, "CrashLoopBackOff", now.Add(-time.Hour))),
	}, nil)
	if c := comp(m, "ns/kavita"); c.Status != Red {
		t.Fatalf("crashloop = red; got %s %v", c.Status, c.Reasons)
	}
	if len(m.Causes) != 1 || !strings.HasPrefix(m.Causes[0], "kavita: kavita-1/c: CrashLoopBackOff") {
		t.Fatalf("causes = %v", m.Causes)
	}
	pl := comp(m, "ns/kavita").PodList
	if len(pl) != 1 || pl[0].Status != Red || pl[0].Node != "k3s-worker-01" || pl[0].Reason != "c: CrashLoopBackOff" {
		t.Errorf("pod dot = %+v; want red on k3s-worker-01 with its reason", pl)
	}
}

func TestPendingIsStartingThenStuck(t *testing.T) {
	fresh, _ := build(t, "True", map[string]string{
		"/api/v1/namespaces/kavita/pods": items(pod("kavita-1", "", "Pending", false, "", now.Add(-time.Minute))),
	}, nil)
	if s := comp(fresh, "ns/kavita").Status; s != Amber {
		t.Errorf("fresh Pending = amber; got %s", s)
	}
	stuck, _ := build(t, "True", map[string]string{
		"/api/v1/namespaces/kavita/pods": items(pod("kavita-1", "", "Pending", false, "", now.Add(-10*time.Minute))),
	}, nil)
	if s := comp(stuck, "ns/kavita").Status; s != Red {
		t.Errorf("Pending > grace = red; got %s", s)
	}
}

func TestFrontDoorsMapToNamespaces(t *testing.T) {
	m, _ := build(t, "True", nil, []vm.Sample{
		{Labels: map[string]string{"job": "front-doors", "instance": "https://kavita.lab.home/"}, Value: "0"},
		{Labels: map[string]string{"job": "front-doors", "instance": "https://grafana.lab.home/"}, Value: "1"},
		{Labels: map[string]string{"job": "front-doors", "instance": "https://uptime.lab.home/"}, Value: "1"},
		{Labels: map[string]string{"job": "staging-front-doors", "instance": "http://linkding-svc.staging-linkding.svc.cluster.local:9090"}, Value: "1"},
		{Labels: map[string]string{"job": "front-doors", "instance": "https://nowhere.lab.home/"}, Value: "1"},
	})
	want := map[string]string{
		"door/https://kavita.lab.home/":                                    "ns/kavita",     // namespace name
		"door/https://grafana.lab.home/":                                   "ns/monitoring", // WARDEN_MAP_HOSTS override
		"door/https://uptime.lab.home/":                                    "ns/monitoring", // app-name prefix (uptime-kuma)
		"door/http://linkding-svc.staging-linkding.svc.cluster.local:9090": "ns/staging-linkding",
	}
	got := map[string]string{}
	for _, e := range m.Edges {
		if strings.HasPrefix(e.From, "door/") {
			got[e.From] = e.To
		}
	}
	for d, ns := range want {
		if got[d] != ns {
			t.Errorf("%s → %q; want %q", d, got[d], ns)
		}
	}
	if _, ok := got["door/https://nowhere.lab.home/"]; ok {
		t.Error("an unmatched host gets no edge rather than a guessed one")
	}
	if c := comp(m, "ns/kavita"); c.Status != Red {
		t.Errorf("a failing front door turns its namespace red; got %s", c.Status)
	}
}

func TestOnlyCatalogueReads(t *testing.T) {
	_, fk := build(t, "True", nil, nil)
	if len(fk.got) == 0 {
		t.Fatal("no reads recorded")
	}
	for _, p := range fk.got {
		if !kube.Allowed(p) {
			t.Errorf("statusmap read %s, which is outside the ADR 0011 catalogue", p)
		}
	}
}

func TestAttach(t *testing.T) {
	m, _ := build(t, "True", nil, nil)
	m.Attach([]Seen{
		{Investigation{ID: "inv_new", Alert: "KubePodCrashLooping", TS: "2026-11-05T00:10:00Z"}, "kavita"},
		{Investigation{ID: "inv_old", Alert: "KubePodNotReady", TS: "2026-11-04T00:10:00Z"}, "kavita"},
		{Investigation{ID: "inv_c", Alert: "SloFrontDoorDown", TS: "2026-11-05T00:11:00Z"}, ""},
	})
	if l := comp(m, "ns/kavita").Last; l == nil || l.ID != "inv_new" {
		t.Errorf("latest wins: %+v", l)
	}
	if len(m.Recent) != 1 || m.Recent[0].ID != "inv_c" {
		t.Errorf("cluster-wide investigations go to Recent: %+v", m.Recent)
	}
}
