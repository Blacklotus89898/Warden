// Package alert decodes alertmanager's webhook payload (version 4). Every
// field is untrusted input (Homelab ADR 0011 §3): labels and annotations come
// from rules, but a pod controls its own labels and log lines.
package alert

import (
	"net/url"
	"strings"
	"time"
)

// Payload is one webhook POST (a group of alerts).
type Payload struct {
	Version     string            `json:"version"`
	Status      string            `json:"status"`
	Receiver    string            `json:"receiver"`
	GroupLabels map[string]string `json:"groupLabels"`
	Alerts      []Alert           `json:"alerts"`
}

// Alert is one alert in the group.
type Alert struct {
	Status       string            `json:"status"` // firing | resolved
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

// Key identifies one firing of one alert: re-sends share it, a new firing
// (new startsAt) does not.
func (a Alert) Key() string {
	fp := a.Fingerprint
	if fp == "" {
		fp = a.Name() + "|" + a.Namespace() + "|" + a.Labels["pod"]
	}
	return fp + "@" + a.StartsAt.UTC().Format(time.RFC3339)
}

// Name is the alertname.
func (a Alert) Name() string { return a.Labels["alertname"] }

// Namespace is the alert's namespace label, if any.
func (a Alert) Namespace() string {
	if ns := a.Labels["namespace"]; ns != "" {
		return ns
	}
	return a.Labels["exported_namespace"]
}

// Node is the node the alert names, if any (node, or instance's host part).
func (a Alert) Node() string {
	if n := a.Labels["node"]; n != "" {
		return n
	}
	inst := a.Labels["instance"]
	if h, _, ok := strings.Cut(inst, ":"); ok {
		inst = h
	}
	return inst
}

// Expr extracts the PromQL expression from a vmalert/Prometheus generator URL
// (…?g0.expr=… for Prometheus, …&expr=… for vmalert).
func (a Alert) Expr() string {
	u, err := url.Parse(a.GeneratorURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	if e := q.Get("g0.expr"); e != "" {
		return e
	}
	return q.Get("expr")
}
