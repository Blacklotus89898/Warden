// Command warden-demo serves every Warden page on a made-up homelab
// (internal/demo), so the UI can be tried and screenshotted without a
// cluster:
//
//	go run ./cmd/warden-demo            # http://localhost:8080/map
//
// It wires the real server, journal and collectors to fake read sources,
// seeds one alert investigation, one operator investigation and a diagnosis,
// and signs every console request in as "demo" (the development header path;
// the real deployment verifies authentik's JWT instead). Nothing is pushed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/Blacklotus89898/Warden/internal/console"
	"github.com/Blacklotus89898/Warden/internal/demo"
	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/journal"
	"github.com/Blacklotus89898/Warden/internal/kb"
	"github.com/Blacklotus89898/Warden/internal/notify"
	"github.com/Blacklotus89898/Warden/internal/server"
	"github.com/Blacklotus89898/Warden/internal/services"
	"github.com/Blacklotus89898/Warden/internal/statusmap"
)

func main() {
	addr := flag.String("addr", "localhost:8080", "listen address")
	flag.Parse()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	dir, err := os.MkdirTemp("", "warden-demo-")
	if err != nil {
		fail(err)
	}
	defer os.RemoveAll(dir)
	j, err := journal.Open(ctx, filepath.Join(dir, "journal.db"))
	if err != nil {
		fail(err)
	}
	defer j.Close()

	kbDir, err := demo.WriteKB(dir)
	if err != nil {
		fail(err)
	}
	src := demo.New(time.Now())
	hosts := map[string]string{"grafana": "monitoring"}
	srv := &server.Server{
		J: j, Enabled: true, DailyCap: 40, Log: logger, Version: "demo",
		Runner:     &investigate.Investigator{Kube: src, Metrics: src, KB: &kb.Index{Roots: []kb.Root{{Label: "davinci", Dir: kbDir}}}, Hosts: hosts},
		Map:        &statusmap.Builder{Kube: src, Metrics: src, Hosts: hosts},
		Services:   &services.Builder{Kube: src, Metrics: src, Kuma: src, Hosts: hosts, MonitorNS: demo.MonitorNS},
		Console:    &console.Console{Kube: src, Metrics: src, J: j},
		PublicURL:  "http://" + *addr,
		UserHeader: "X-Authentik-Username",
		Notify:     notify.Ntfy{}, // no URL: pushes are off
	}
	srv.Start(ctx)
	mux := http.NewServeMux()
	srv.Routes(mux)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Authentik-Username", "demo") // dev header path, see package doc
		mux.ServeHTTP(w, r)
	})
	if err := seed(ctx, h, src); err != nil {
		fail(err)
	}

	hs := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = hs.Shutdown(context.Background()) }()
	fmt.Printf("Warden demo on http://%s\n  /map  /services  /console\n", *addr)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fail(err)
	}
}

// seed sends the story's alert, waits for its bundle, then runs an operator
// investigation and writes a diagnosis, all through the public handlers.
func seed(ctx context.Context, h http.Handler, src *demo.Source) error {
	call := func(method, path, body string) (*httptest.ResponseRecorder, error) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(server.RequestHeader, "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code >= 300 {
			return w, fmt.Errorf("seed %s %s: %d %s", method, path, w.Code, w.Body)
		}
		return w, nil
	}
	alert := map[string]any{"status": "firing", "alerts": []any{map[string]any{
		"status": "firing", "fingerprint": "demo-oom",
		"labels": map[string]string{"alertname": "ContainerOOMKilled", "severity": "warning",
			"namespace": "linkding", "pod": "linkding-c41f9e-7xk2p", "container": "linkding"},
		"annotations": map[string]string{"summary": "linkding was OOM-killed 6 times in the last hour",
			"runbook_url": "kb://runbooks/k8s-oomkilled.md"},
		// Homelab's ContainerOOMKilled rule, as vmalert links it.
		"generatorURL": "http://vmalert.monitoring.svc:8080/vmalert/alert?g0.expr=" + url.QueryEscape(oomRule),
		"startsAt":     src.Now.Add(-48 * time.Minute),
	}}}
	b, _ := json.Marshal(alert)
	if _, err := call(http.MethodPost, "/alerts", string(b)); err != nil {
		return err
	}
	var id string
	for i := 0; i < 50 && id == ""; i++ {
		w, err := call(http.MethodGet, "/console/api/investigations", "")
		if err != nil {
			return err
		}
		var rows []struct{ ID string }
		_ = json.Unmarshal(w.Body.Bytes(), &rows)
		if len(rows) > 0 {
			id = rows[0].ID
		}
		time.Sleep(100 * time.Millisecond)
	}
	if id == "" {
		return fmt.Errorf("seed: the alert was not investigated")
	}
	if _, err := call(http.MethodPost, "/console/api/investigations/"+id+"/diagnosis", `{"text":"Revision c41f9e (3h ago) holds the whole bookmark import in memory (912 MiB batch in the last log lines); memory climbs from 41% to the 512Mi limit and the pod is OOM-killed on every import. Fix: stream the import, or raise the limit to 1Gi until it does. Rolled back to 8d2e44 until it lands."}`); err != nil {
		return err
	}
	if _, err := call(http.MethodPost, "/console/api/investigate", `{"namespace":"kavita"}`); err != nil {
		return err
	}
	return nil
}

const oomRule = `(max by (namespace, pod, container) (kube_pod_container_status_last_terminated_reason{reason="OOMKilled"}) == 1)
  and on (namespace, pod, container)
(sum by (namespace, pod, container) (increase(kube_pod_container_status_restarts_total[10m])) > 0)`

func fail(err error) {
	fmt.Fprintln(os.Stderr, "warden-demo:", err)
	os.Exit(1)
}
