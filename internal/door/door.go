// Package door maps a front-door probe target (a blackbox `instance`, e.g.
// https://linkding.lab.home/ or http://kavita-service.kavita.svc.cluster.local:5000)
// to the namespace that serves it. The status map and the investigator share
// it, so "which app is this door" has one answer.
package door

import (
	"net/url"
	"sort"
	"strings"
)

// Tier membership for the platform layers (the status map groups by these;
// the resolver treats them as known namespaces).
var (
	Platform = []string{"kube-system", "istio-system", "argocd", "cert-manager", "sealed-secrets", "argo-rollouts"}
	Observe  = []string{"monitoring", "openobserve", "warden", "heartbeat"}
)

// Resolver answers door → namespace from what the cluster says.
type Resolver struct {
	// Hosts maps a *.lab.home host label to its namespace when the label is
	// neither a namespace nor an app name (grafana=monitoring).
	Hosts map[string]string
	// Namespaces known to exist (platform tiers + ArgoCD destinations).
	Namespaces map[string]bool
	// AppNS maps an ArgoCD Application name to its destination namespace.
	AppNS map[string]string
}

// NewResolver builds a resolver from the ArgoCD app → namespace map; the
// platform tiers and every destination count as known namespaces.
func NewResolver(hosts, appNS map[string]string) *Resolver {
	ns := map[string]bool{"default": true}
	for _, n := range Platform {
		ns[n] = true
	}
	for _, n := range Observe {
		ns[n] = true
	}
	for _, n := range appNS {
		ns[n] = true
	}
	return &Resolver{Hosts: hosts, Namespaces: ns, AppNS: appNS}
}

// IsDoor reports whether an instance label looks like a probe URL.
func IsDoor(inst string) bool {
	u, err := url.Parse(inst)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != ""
}

// Namespace maps a probe target to its namespace, "" if unknown. Order:
// in-cluster service DNS (svc.ns.svc…), the Hosts override, a namespace of
// that name, an app of that name, then the shortest app name the label
// prefixes (uptime → uptime-kuma), alphabetical on ties so it is stable.
func (r *Resolver) Namespace(inst string) string {
	if !IsDoor(inst) {
		return ""
	}
	u, _ := url.Parse(inst)
	h := u.Hostname()
	if strings.HasSuffix(h, ".svc.cluster.local") || strings.HasSuffix(h, ".svc") {
		if parts := strings.Split(h, "."); len(parts) >= 3 {
			return parts[1]
		}
	}
	label, _, _ := strings.Cut(h, ".")
	if ns, ok := r.Hosts[label]; ok {
		return ns
	}
	if r.Namespaces[label] {
		return label
	}
	if ns, ok := r.AppNS[label]; ok {
		return ns
	}
	apps := make([]string, 0, len(r.AppNS))
	for app := range r.AppNS {
		if strings.HasPrefix(app, label) {
			apps = append(apps, app)
		}
	}
	sort.Slice(apps, func(i, j int) bool {
		if len(apps[i]) != len(apps[j]) {
			return len(apps[i]) < len(apps[j])
		}
		return apps[i] < apps[j]
	})
	if len(apps) > 0 {
		return r.AppNS[apps[0]]
	}
	return ""
}

// Name is the short display name of a door: the host, or svc.ns (in-cluster).
func Name(inst string) string {
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
