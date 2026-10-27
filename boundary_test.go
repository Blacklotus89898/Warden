package main

// The boundary of Homelab ADR 0011 §1–2, pinned. If one of these fails, the
// change needs a new ADR, not an edited test.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/kube"
)

func TestKubeCatalogueIsReadOnlyAndClosed(t *testing.T) {
	allowed := []string{
		"/api/v1/namespaces/petal/pods",
		"/api/v1/namespaces/petal/pods/petal-7d9f-abc12/log",
		"/api/v1/namespaces/tulip/events",
		"/api/v1/nodes",
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications",
	}
	for _, p := range allowed {
		if !kube.Allowed(p) {
			t.Errorf("catalogue must allow %s", p)
		}
	}
	refused := []string{
		"/api/v1/namespaces/tulip/secrets",
		"/api/v1/namespaces/tulip/secrets/tulip-approval",
		"/api/v1/secrets",
		"/api/v1/namespaces/monitoring/configmaps",
		"/api/v1/namespaces/petal/pods/p/exec",
		"/api/v1/namespaces/petal/pods/p/attach",
		"/api/v1/namespaces/petal/pods/p/portforward",
		"/api/v1/namespaces/petal/pods/p/proxy",
		"/api/v1/namespaces/tulip/services/tulip-svc/proxy/approve/x",
		"/api/v1/nodes/k3s-worker-01/proxy",
		"/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/tulip",
		"/apis/bitnami.com/v1alpha1/sealedsecrets",
		"/api/v1/namespaces/../secrets",
		"/api/v1/namespaces/petal/pods/../secrets/x/log",
	}
	for _, p := range refused {
		if kube.Allowed(p) {
			t.Errorf("catalogue must refuse %s", p)
		}
	}
}

func TestKubeClientRefusesBeforeTheNetwork(t *testing.T) {
	hit := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		if r.Method != http.MethodGet {
			t.Errorf("non-GET request: %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer ts.Close()
	c := &kube.Client{Base: ts.URL}
	if _, err := c.Get(context.Background(), "/api/v1/namespaces/tulip/secrets", nil); !errors.Is(err, kube.ErrNotInCatalogue) {
		t.Fatalf("got %v", err)
	}
	if hit {
		t.Fatal("a refused path must never reach the API server")
	}
	if _, err := c.Get(context.Background(), "/api/v1/nodes", nil); err != nil || !hit {
		t.Fatalf("an allowed path must work (err %v)", err)
	}
}

func TestCollectorCatalogueIsPinned(t *testing.T) {
	want := []string{"pods", "logs", "events", "argocd", "nodes", "metric", "kb"}
	if !reflect.DeepEqual(investigate.Collectors, want) {
		t.Fatalf("collectors = %v; adding one changes the ADR 0011 boundary", investigate.Collectors)
	}
}
