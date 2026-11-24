package console

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/journal"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

var now = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

type fakeKube map[string]string // path → JSON

func (f fakeKube) GetJSON(_ context.Context, path string, _ url.Values, out any) error {
	b, ok := f[path]
	if !ok {
		return errors.New("forbidden: " + path)
	}
	return json.Unmarshal([]byte(b), out)
}

type fakeVM struct {
	mu      sync.Mutex
	instant map[string][]vm.Sample // by query substring
	ranges  []string
	fail    bool
}

func (f *fakeVM) Query(_ context.Context, expr string, _ int) ([]vm.Sample, error) {
	if f.fail {
		return nil, errors.New("vm down")
	}
	for k, v := range f.instant {
		if strings.Contains(expr, k) {
			return v, nil
		}
	}
	return nil, nil
}

func (f *fakeVM) QueryRange(_ context.Context, expr string, start, end time.Time, step time.Duration, _ int) ([]vm.Series, error) {
	f.mu.Lock()
	f.ranges = append(f.ranges, expr)
	f.mu.Unlock()
	return []vm.Series{{Labels: map[string]string{}, Points: [][2]float64{{float64(end.Unix()), 1}}}}, nil
}

type fakeJournal map[string][]journal.Event

func (f fakeJournal) List(_ context.Context, kind string, _ int) ([]journal.Event, error) {
	return f[kind], nil
}

func ts(t time.Time) string { return t.Format(time.RFC3339Nano) }

func TestValidNamespace(t *testing.T) {
	for _, ok := range []string{"kavita", "kube-system", "a"} {
		if !ValidNamespace(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "Kavita", "-x", "x-", `kavita"}) or vector(1) #`, "a/b", "a.b", strings.Repeat("a", 64)} {
		if ValidNamespace(bad) {
			t.Errorf("%q must be rejected before it reaches PromQL or an API path", bad)
		}
	}
	c := &Console{Kube: fakeKube{}, Metrics: &fakeVM{}}
	if _, err := c.Timeline(context.Background(), `x"}`, now); err == nil {
		t.Error("Timeline must refuse a bad namespace")
	}
	if _, err := c.Traffic(context.Background(), `x"}`, "1h"); err == nil {
		t.Error("Traffic must refuse a bad namespace")
	}
	if _, err := c.Blast(context.Background(), `x"}`); err == nil {
		t.Error("Blast must refuse a bad namespace")
	}
}

func TestTimeline(t *testing.T) {
	k := fakeKube{
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications": `{"items":[
		 {"metadata":{"name":"linkding"},"spec":{"destination":{"namespace":"linkding"}},
		  "status":{"history":[{"id":1,"revision":"aaaaaaaaaaaa","deployedAt":"2026-11-20T10:00:00Z"},{"id":2,"revision":"bbbbbbbbbbbb","deployedAt":"2026-11-24T09:00:00Z"}],
		   "operationState":{"phase":"Failed","message":"one or more objects failed to apply password=hunter2","finishedAt":"2026-11-24T09:05:00Z"}}},
		 {"metadata":{"name":"kavita"},"spec":{"destination":{"namespace":"kavita"}},"status":{"history":[{"revision":"cccccccc","deployedAt":"2026-11-24T08:00:00Z"}]}}]}`,
		"/api/v1/namespaces/linkding/pods": `{"items":[{"metadata":{"name":"linkding-1","creationTimestamp":"2026-11-24T09:01:00Z"},"spec":{"nodeName":"k3s-worker-01"},
		 "status":{"containerStatuses":[{"name":"app","restartCount":3,"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137,"finishedAt":"2026-11-24T11:00:00Z"}},
		  "state":{"waiting":{"reason":"CrashLoopBackOff","message":"back-off"}}}]}}]}`,
		"/api/v1/namespaces/linkding/events": `{"items":[
		 {"type":"Warning","reason":"BackOff","message":"Back-off restarting","count":5,"involvedObject":{"kind":"Pod","name":"linkding-1"},"lastTimestamp":"2026-11-24T11:30:00Z"},
		 {"type":"Normal","reason":"Pulled","message":"noise","involvedObject":{"kind":"Pod","name":"linkding-1"},"lastTimestamp":"2026-11-24T11:31:00Z"},
		 {"type":"Normal","reason":"ScalingReplicaSet","message":"Scaled up","involvedObject":{"kind":"Deployment","name":"linkding"},"lastTimestamp":"2026-11-24T09:00:30Z"}]}`,
	}
	bundle := func(id, ns, name string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"id": id, "namespace": ns, "alert": map[string]any{"labels": map[string]string{"alertname": name, "severity": "critical"}}})
		return b
	}
	diag, _ := json.Marshal(Diagnosis{By: "steve", Text: "memory limit too low after the 9:00 deploy"})
	j := fakeJournal{
		KindInvestigated: {
			{TS: ts(now.Add(-50 * time.Minute)), Kind: KindInvestigated, Ref: "inv_1", Payload: bundle("inv_1", "linkding", "ContainerOOMKilled")},
			{TS: ts(now.Add(-10 * time.Minute)), Kind: KindInvestigated, Ref: "inv_2", Payload: bundle("inv_2", "linkding", OperatorAlert)},
			{TS: ts(now.Add(-5 * time.Minute)), Kind: KindInvestigated, Ref: "inv_3", Payload: bundle("inv_3", "kavita", "KubePodCrashLooping")},
		},
		KindDiagnosis: {{TS: ts(now.Add(-2 * time.Minute)), Kind: KindDiagnosis, Ref: "inv_1", Payload: diag}},
	}
	c := &Console{Kube: k, Metrics: &fakeVM{}, J: j, Now: func() time.Time { return now }}
	tl, err := c.Timeline(context.Background(), "linkding", now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	var titles []string
	for _, e := range tl.Entries {
		kinds[e.Kind]++
		titles = append(titles, e.Title)
	}
	all := strings.Join(titles, "\n")
	want := map[string]int{"deploy": 1, "sync": 1, "restart": 2, "event": 2, "pod": 1, "alert": 1, "investigation": 1, "request": 1, "diagnosis": 1}
	for k, n := range want {
		if kinds[k] != n {
			t.Errorf("%s entries = %d, want %d\n%s", k, kinds[k], n, all)
		}
	}
	if strings.Contains(all, "kavita") || strings.Contains(all, "Pulled") || strings.Contains(all, "aaaaaaa") {
		t.Errorf("other namespaces, noise events and out-of-window deploys must be left out:\n%s", all)
	}
	for i := 1; i < len(tl.Entries); i++ {
		if tl.Entries[i].At.After(tl.Entries[i-1].At) {
			t.Fatal("entries must be newest first")
		}
	}
	for _, e := range tl.Entries {
		if strings.Contains(e.Detail, "hunter2") {
			t.Error("details must be redacted")
		}
		if e.Kind == "restart" && strings.Contains(e.Title, "OOMKilled") && e.Level != "bad" {
			t.Error("an OOM kill is bad")
		}
	}
	if len(tl.Errors) != 0 {
		t.Errorf("errors: %v", tl.Errors)
	}
}

func TestTimelineSourceFailsAlone(t *testing.T) {
	c := &Console{Kube: fakeKube{"/api/v1/namespaces/x/events": `{"items":[]}`}, Metrics: &fakeVM{}, Now: func() time.Time { return now }}
	tl, err := c.Timeline(context.Background(), "x", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(tl.Errors) != 2 { // argocd + pods fail, events works, no journal
		t.Errorf("errors = %v", tl.Errors)
	}
}

func TestTraffic(t *testing.T) {
	m := &fakeVM{}
	c := &Console{Kube: fakeKube{}, Metrics: m, Now: func() time.Time { return now }}
	if _, err := c.Traffic(context.Background(), "kavita", "2y"); err == nil {
		t.Error("unknown range must be refused")
	}
	tr, err := c.Traffic(context.Background(), "kavita", "1h")
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Series) != 6 || len(m.ranges) != 6 {
		t.Fatalf("series = %v", tr.Series)
	}
	for _, q := range m.ranges {
		if !strings.Contains(q, `"kavita"`) {
			t.Errorf("query not scoped to the namespace: %s", q)
		}
		if strings.Contains(q, "[60s]") {
			t.Errorf("rate window must be at least 5m: %s", q)
		}
	}
}

func TestBlast(t *testing.T) {
	s := func(label, ns, v string) vm.Sample { return vm.Sample{Labels: map[string]string{label: ns}, Value: v} }
	m := &fakeVM{instant: map[string][]vm.Sample{
		`istio_requests_total{destination_service_namespace="linkding"}`:               {s("source_workload_namespace", "istio-system", "120"), s("source_workload_namespace", "unknown", "5")},
		`istio_tcp_connections_opened_total{destination_service_namespace="linkding"}`: {s("source_workload_namespace", "monitoring", "300"), s("source_workload_namespace", "linkding", "9")},
		`istio_tcp_connections_opened_total{source_workload_namespace="linkding"}`:     {s("destination_service_namespace", "default", "40")},
	}}
	k := fakeKube{"/api/v1/namespaces/linkding/pods": `{"items":[{"metadata":{"name":"a"},"spec":{"nodeName":"k3s-worker-01"}},{"metadata":{"name":"b"},"spec":{"nodeName":"k3s-worker-01"}}]}`}
	c := &Console{Kube: k, Metrics: m}
	b, err := c.Blast(context.Background(), "linkding")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Callers) != 2 || b.Callers[0].Namespace != "monitoring" || b.Callers[1].Requests != 120 {
		t.Errorf("callers = %+v (unknown and self dropped, biggest first)", b.Callers)
	}
	if !b.Gateway {
		t.Error("traffic from istio-system means a front door")
	}
	if len(b.Callees) != 1 || b.Callees[0].Namespace != "default" || b.Callees[0].Conns != 40 {
		t.Errorf("callees = %+v", b.Callees)
	}
	if len(b.Nodes) != 1 {
		t.Errorf("nodes = %v", b.Nodes)
	}

	m.fail = true
	b, err = c.Blast(context.Background(), "linkding")
	if err != nil || len(b.Errors) != 4 || len(b.Nodes) != 1 {
		t.Errorf("metrics failing must keep the node view: %+v %v", b, err)
	}
}
