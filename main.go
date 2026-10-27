// Command warden investigates platform alerts (Homelab ADR 0011): alertmanager
// posts an alert, Warden collects read-only evidence — pods, logs, events,
// ArgoCD, nodes, the alert's metric, the knowledge base — journals the bundle
// and pushes a digest to ntfy. Phase 1a: no model, no writes, anywhere.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/journal"
	"github.com/Blacklotus89898/Warden/internal/kb"
	"github.com/Blacklotus89898/Warden/internal/kube"
	"github.com/Blacklotus89898/Warden/internal/notify"
	"github.com/Blacklotus89898/Warden/internal/server"
	"github.com/Blacklotus89898/Warden/internal/vm"
)

// version is stamped at build time (-ldflags "-X main.version=<sha>").
var version = "dev"

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "data/warden.db", "journal database path")
	flag.Parse()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		logger.Error("create data dir", "err", err)
		os.Exit(1)
	}
	j, err := journal.Open(ctx, *dbPath)
	if err != nil {
		logger.Error("open journal", "err", err)
		os.Exit(1)
	}
	defer j.Close()

	kc, err := kube.InCluster()
	if err != nil {
		logger.Error("kubernetes client (Warden runs in-cluster)", "err", err)
		os.Exit(1)
	}
	// "label=dir,label=dir": git-synced knowledge roots (ADR 0011 §6).
	var roots []kb.Root
	for _, kv := range strings.Split(envOr("WARDEN_KB_ROOTS", ""), ",") {
		if l, d, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
			roots = append(roots, kb.Root{Label: l, Dir: d})
		}
	}
	enabled := envOr("WARDEN_ENABLED", "true") != "false"
	daily, _ := strconv.Atoi(envOr("WARDEN_DAILY_CAP", "40"))
	srv := &server.Server{
		J: j, Enabled: enabled, DailyCap: daily, Log: logger, Version: version,
		Runner: &investigate.Investigator{
			Kube:    kc,
			Metrics: &vm.Client{Base: envOr("WARDEN_VM_URL", "http://vmsingle-vmstack.monitoring.svc:8428")},
			KB:      &kb.Index{Roots: roots},
		},
		Notify: notify.Ntfy{URL: os.Getenv("WARDEN_NTFY_URL"), Topic: envOr("WARDEN_NTFY_TOPIC", "warden")},
	}
	srv.Start(ctx)
	_, _ = j.Append(ctx, "service.started", "", map[string]any{
		"version": version, "enabled": enabled, "daily_cap": daily, "kb_roots": roots,
		"notify": os.Getenv("WARDEN_NTFY_URL") != "",
	})

	mux := http.NewServeMux()
	srv.Routes(mux)
	hs := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- hs.ListenAndServe() }()
	logger.Info("warden listening", "addr", *addr, "version", version, "enabled", enabled, "kb_roots", len(roots))
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
