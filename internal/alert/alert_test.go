package alert

import (
	"testing"
	"time"
)

func TestExprFromGeneratorURLs(t *testing.T) {
	cases := map[string]string{
		// Verbatim shape from this cluster's vmalert (2026-10-27): Grafana explore.
		`http:/explore?left={"datasource":"VictoriaMetrics","queries":[{"expr":%22up%7Bjob%3D%5C%22petal%5C%22%7D+%3D%3D+0%5Cn%22,"refId":"A"}],"range":{"from":"1792928700000","to":"now"}}`: "up{job=\"petal\"} == 0\n",
		"http://prom/graph?g0.expr=up+%3D%3D+0&g0.tab=1":                   "up == 0",
		"http://vmalert/vmalert/alert?group_id=1&expr=rate%28x%5B5m%5D%29": "rate(x[5m])",
		"": "",
	}
	for u, want := range cases {
		if got := (Alert{GeneratorURL: u}).Expr(); got != want {
			t.Errorf("Expr(%q) = %q, want %q", u, got, want)
		}
	}
}

func TestKeyAndLabels(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	a := Alert{Fingerprint: "fp", StartsAt: t0, Labels: map[string]string{"alertname": "X", "exported_namespace": "petal", "instance": "k3s-worker-01:9100"}}
	if a.Key() != "fp@2026-10-27T12:00:00Z" || a.Namespace() != "petal" || a.Node() != "k3s-worker-01" {
		t.Errorf("key %q ns %q node %q", a.Key(), a.Namespace(), a.Node())
	}
}
