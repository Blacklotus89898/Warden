package door

import "testing"

// The ArgoCD apps → destinations of the live cluster (2026-11-05).
var liveApps = map[string]string{
	"argo-rollouts": "argo-rollouts", "argocd": "argocd", "audiobookshelf": "audiobookshelf",
	"authentik": "default", "backstage": "backstage", "backstage-k8s-rbac": "backstage",
	"blackbox-exporter": "monitoring", "cert-manager": "cert-manager", "heartbeat": "heartbeat",
	"istio": "istio-system", "istio-gateway": "istio-system", "kavita": "kavita",
	"linkding": "linkding", "ntfy": "monitoring", "opencost": "monitoring", "openobserve": "openobserve",
	"petal": "petal", "sealed-secrets": "sealed-secrets", "staging-linkding": "staging-linkding",
	"tulip": "tulip", "uptime-kuma": "monitoring", "victoria-metrics": "monitoring",
	"victoria-metrics-infra": "monitoring", "warden": "warden",
}

// Every door that alerted without a namespace on 2026-11-05 (24 of 44
// investigations then ran cluster-wide and found nothing specific).
func TestLiveDoorsResolve(t *testing.T) {
	r := NewResolver(map[string]string{"grafana": "monitoring", "auth": "default"}, liveApps)
	for inst, want := range map[string]string{
		"https://uptime.lab.home/":                                     "monitoring", // uptime → uptime-kuma
		"https://argocd.lab.home/":                                     "argocd",
		"https://ntfy.lab.home/":                                       "monitoring", // ntfy is an app in monitoring, not a namespace
		"https://kavita.lab.home/":                                     "kavita",
		"https://petal.lab.home/":                                      "petal",
		"https://grafana.lab.home/":                                    "monitoring", // Hosts override
		"https://linkding.lab.home/":                                   "linkding",
		"https://auth.lab.home/":                                       "default",
		"http://backstage.backstage.svc.cluster.local:7007":            "backstage",
		"http://victoria-metrics-grafana.monitoring.svc.cluster.local": "monitoring",
		"http://kavita-service.kavita.svc.cluster.local:5000":          "kavita",
		"http://kavita-service.staging-kavita.svc.cluster.local:5000":  "staging-kavita",
		"http://linkding-svc.staging-linkding.svc.cluster.local:9090":  "staging-linkding",
		"https://nothing-here.lab.home/":                               "",
		"192.168.0.108:9100":                                           "", // node exporter, not a door
	} {
		if got := r.Namespace(inst); got != want {
			t.Errorf("%s → %q, want %q", inst, got, want)
		}
	}
}

// Prefix matches must not depend on map order.
func TestPrefixTieIsStable(t *testing.T) {
	r := NewResolver(nil, map[string]string{"victoria-metrics-infra": "infra", "victoria-metrics": "monitoring"})
	for range 50 {
		if got := r.Namespace("https://victoria.lab.home/"); got != "monitoring" {
			t.Fatalf("got %q, want the shortest match (victoria-metrics → monitoring)", got)
		}
	}
}
