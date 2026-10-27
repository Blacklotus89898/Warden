package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Blacklotus89898/Warden/internal/alert"
	"github.com/Blacklotus89898/Warden/internal/kb"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

var now = time.Date(2026, 10, 27, 15, 0, 0, 0, time.UTC)

type fakeKube struct {
	resp map[string]string // path → JSON body (or raw log text)
	got  []string
}

func (f *fakeKube) Get(_ context.Context, path string, q url.Values) ([]byte, error) {
	f.got = append(f.got, path+"?"+q.Encode())
	b, ok := f.resp[path]
	if !ok {
		return nil, fmt.Errorf("HTTP 404 %s", path)
	}
	return []byte(b), nil
}

func (f *fakeKube) GetJSON(ctx context.Context, path string, q url.Values, out any) error {
	b, err := f.Get(ctx, path, q)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

type fakeVM struct{}

func (fakeVM) Query(_ context.Context, expr string, _ int) ([]vm.Sample, error) {
	return []vm.Sample{{Labels: map[string]string{"namespace": "petal", "pod": "petal-1"}, Value: "4"}}, nil
}

type fakeKB struct{ terms []string }

func (f *fakeKB) Search(terms []string, _ int) []kb.Hit {
	f.terms = terms
	return []kb.Hit{{Path: "davinci/runbooks/crashloop.md", Heading: "CrashLoopBackOff triage"}}
}

const pods = `{"items":[
 {"metadata":{"name":"petal-1","namespace":"petal"},"spec":{"nodeName":"k3s-worker-01"},
  "status":{"phase":"Running","containerStatuses":[
   {"name":"dind","ready":false,"restartCount":3,
    "state":{"waiting":{"reason":"CrashLoopBackOff"}},
    "lastState":{"terminated":{"reason":"Error","exitCode":1,"finishedAt":"2026-10-27T14:58:00Z"}}},
   {"name":"petal","ready":true,"restartCount":0,"state":{"running":{"startedAt":"2026-10-27T10:00:00Z"}}}]}},
 {"metadata":{"name":"healthy","namespace":"petal"},"spec":{},"status":{"phase":"Running","containerStatuses":[{"name":"x","ready":true,"restartCount":0,"state":{"running":{}}}]}}
]}`

const events = `{"items":[
 {"type":"Warning","reason":"BackOff","message":"Back-off restarting failed container dind","count":5,"involvedObject":{"kind":"Pod","name":"petal-1"},"lastTimestamp":"2026-10-27T14:59:00Z"},
 {"type":"Warning","reason":"BackOff","message":"Back-off restarting failed container dind","count":2,"involvedObject":{"kind":"Pod","name":"petal-1"},"lastTimestamp":"2026-10-27T14:50:00Z"},
 {"type":"Warning","reason":"Old","message":"long ago","count":1,"involvedObject":{"kind":"Pod","name":"x"},"lastTimestamp":"2026-10-26T01:00:00Z"},
 {"type":"Normal","reason":"Pulled","message":"pulled","count":1,"involvedObject":{"kind":"Pod","name":"petal-1"},"lastTimestamp":"2026-10-27T14:59:00Z"}
]}`

const apps = `{"items":[
 {"metadata":{"name":"petal"},"spec":{"destination":{"namespace":"petal"}},"status":{"sync":{"status":"Synced"},"health":{"status":"Degraded","message":"Deployment exceeded its progress deadline"}}},
 {"metadata":{"name":"tulip"},"spec":{"destination":{"namespace":"tulip"}},"status":{"sync":{"status":"Synced"},"health":{"status":"Healthy"}}}
]}`

const nodes = `{"items":[
 {"metadata":{"name":"debian"},"spec":{"unschedulable":true},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
 {"metadata":{"name":"k3s-worker-01"},"spec":{},"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"DiskPressure","status":"True"}]}}
]}`

func harness() (*Investigator, *fakeKube, *fakeKB) {
	k := &fakeKube{resp: map[string]string{
		"/api/v1/namespaces/petal/pods":                             pods,
		"/api/v1/namespaces/petal/events":                           events,
		"/api/v1/nodes":                                             nodes,
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications": apps,
		"/api/v1/namespaces/petal/pods/petal-1/log":                 "starting dockerd\nconnecting with password=hunter2\nAuthorization: Bearer abc.def.ghi\ntimeout waiting for containerd to start\n",
	}}
	f := &fakeKB{}
	return &Investigator{Kube: k, Metrics: fakeVM{}, KB: f, Now: func() time.Time { return now }}, k, f
}

func crashAlert() alert.Alert {
	return alert.Alert{Status: "firing", Fingerprint: "abc",
		Labels:       map[string]string{"alertname": "KubePodCrashLooping", "namespace": "petal", "severity": "warning"},
		Annotations:  map[string]string{"summary": "Pod is crash looping.", "runbook_url": "https://runbooks.prometheus-operator.dev/runbooks/kubernetes/kubepodcrashlooping"},
		GeneratorURL: "http://vmalert/vmalert/alert?group_id=1&alert_id=2&expr=" + url.QueryEscape(`max_over_time(kube_pod_container_status_waiting_reason{reason="CrashLoopBackOff"}[5m]) >= 1`),
		StartsAt:     now.Add(-10 * time.Minute)}
}

func TestBundleFromACrashLoop(t *testing.T) {
	iv, k, f := harness()
	b := iv.Run(context.Background(), "inv_1", crashAlert())

	if len(b.Errors) != 0 {
		t.Fatalf("errors: %v", b.Errors)
	}
	if len(b.Pods) != 1 || b.Pods[0].Name != "petal-1" || b.Pods[0].Restarts != 3 {
		t.Fatalf("pods = %+v (only the troubled one)", b.Pods)
	}
	pr := strings.Join(b.Pods[0].Problems, "|")
	if !strings.Contains(pr, "dind: CrashLoopBackOff") || !strings.Contains(pr, "dind last: Error (exit 1") {
		t.Errorf("problems = %s", pr)
	}
	// The crashed container's PREVIOUS log, redacted.
	logs := b.Pods[0].Logs["dind (previous)"]
	joined := strings.Join(logs, "\n")
	if len(logs) == 0 || !strings.Contains(joined, "timeout waiting for containerd") {
		t.Fatalf("logs = %v", b.Pods[0].Logs)
	}
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "abc.def.ghi") {
		t.Errorf("secrets leaked into the bundle: %s", joined)
	}
	if !strings.Contains(strings.Join(k.got, " "), "previous=true") {
		t.Error("restarted container: must read the previous instance's log")
	}
	// Events: warnings in the window only, merged per object+reason.
	if len(b.Events) != 1 || b.Events[0].Count != 7 || b.Events[0].Reason != "BackOff" {
		t.Errorf("events = %+v", b.Events)
	}
	if len(b.Apps) != 1 || b.Apps[0].Name != "petal" || b.Apps[0].Health != "Degraded" {
		t.Errorf("apps = %+v (the namespace's app only)", b.Apps)
	}
	// The cordoned control plane is by design; the worker's pressure isn't.
	if len(b.Nodes) != 1 || b.Nodes[0].Name != "k3s-worker-01" || b.Nodes[0].Pressure[0] != "DiskPressure" {
		t.Errorf("nodes = %+v", b.Nodes)
	}
	if !strings.Contains(b.Expr, "CrashLoopBackOff") || len(b.Metric) != 1 {
		t.Errorf("metric: expr %q, %v", b.Expr, b.Metric)
	}
	if !strings.Contains(strings.Join(f.terms, " "), "CrashLoopBackOff") {
		t.Errorf("kb terms = %v", f.terms)
	}

	title, body := b.Digest()
	if title != "Warden: KubePodCrashLooping (petal)" {
		t.Errorf("title = %q", title)
	}
	for _, want := range []string{"petal-1", "CrashLoopBackOff", "BackOff ×7", "ArgoCD petal: Synced/Degraded", "DiskPressure", "davinci/runbooks/crashloop.md", "inv_1"} {
		if !strings.Contains(body, want) {
			t.Errorf("digest lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "hunter2") || len(body) > DigestLimit+4 {
		t.Errorf("digest leaks or is too long (%d)", len(body))
	}
}

func TestCollectorFailureIsRecordedNotFatal(t *testing.T) {
	iv, k, _ := harness()
	delete(k.resp, "/api/v1/namespaces/petal/events")
	b := iv.Run(context.Background(), "inv_2", crashAlert())
	if b.Errors["events"] == "" || len(b.Pods) != 1 || len(b.Apps) != 1 {
		t.Fatalf("one failing collector must not stop the rest: %+v", b)
	}
	if _, body := b.Digest(); !strings.Contains(body, "incomplete: events failed") {
		t.Errorf("digest must say it's incomplete:\n%s", body)
	}
}

func TestClusterWideAlertSkipsNamespaceCollectors(t *testing.T) {
	iv, k, _ := harness()
	a := alert.Alert{Status: "firing", Labels: map[string]string{"alertname": "SloFrontDoorDown", "severity": "critical"}, StartsAt: now}
	b := iv.Run(context.Background(), "inv_3", a)
	for _, p := range k.got {
		if strings.Contains(p, "/namespaces/") && !strings.Contains(p, "argocd") {
			t.Errorf("no namespace: must not list %s", p)
		}
	}
	if len(b.Apps) != 1 || b.Apps[0].Name != "petal" {
		t.Errorf("cluster-wide: only unhealthy apps, got %+v", b.Apps)
	}
}
