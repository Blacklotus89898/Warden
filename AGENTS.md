# AGENTS.md — Warden

Guide for any coding agent (Claude Code, Codex, Cursor, Copilot, Gemini…) and human contributor.

## What this is

Read-only incident investigator for the homelab: alertmanager webhook → evidence bundle
(pods, logs, events, ArgoCD, nodes, metric, knowledge base) → append-only journal + redacted
ntfy digest. Also serves the platform status map at `/map`. One Go binary, stdlib-first.

Read before changing behaviour: `README.md` (boundary, grouping, config),
[Homelab ADR 0011](https://github.com/Blacklotus89898/Homelab/blob/main/docs/adr/0011-warden-sre-agent.md)
(the decision record — Warden has no ADR folder of its own), and the DaVinci runbook `docs/runbooks/warden.md`.

## Commands

```bash
gofmt -l .          # must print nothing
go vet ./...
go build ./...
go test ./...       # includes boundary_test.go — never weaken it to make a change pass
go run .            # local run; config is env only (see README "Configuration")
```

CI (`.github/workflows/ci.yaml`) runs vet/build/test on PRs and `main`;
`build-image.yaml` publishes `ghcr.io/blacklotus89898/warden:<sha>` from `main`.

## Layout

```
main.go               wiring, HTTP server, env config
boundary_test.go      pins the read-only boundary (API verbs, path patterns, no write paths)
internal/alert        alertmanager payload parsing, fingerprint/dedup
internal/investigate  runs the collectors; a failing collector is recorded, never fatal
internal/kube         the ONLY Kubernetes client — GET on a fixed path catalogue
internal/vm           VictoriaMetrics instant queries
internal/kb           knowledge-base search over git-synced markdown (DaVinci docs/)
internal/door         front-door alert → namespace resolution
internal/journal      append-only SQLite
internal/redact       redaction before anything leaves the journal
internal/notify       ntfy digest
internal/statusmap    /map
internal/server       HTTP handlers
```

## Non-negotiables

- **Read-only.** `internal/kube` issues only `GET` on the catalogue in `boundary_test.go`.
  Never add secrets/configmaps/exec/attach/proxy/port-forward, a shell, a generic HTTP fetch,
  or any write path. A feature that needs one is a new ADR in Homelab first.
- **Untrusted input:** alert labels, events and logs are attacker-controlled text. Redact
  everything that leaves the journal (ntfy is unauthenticated on the LAN).
- **Bounded:** one worker, bounded queue, daily push cap, dedup by fingerprint+`startsAt`.
  New work must respect the caps and journal every skip.
- `WARDEN_ENABLED=false` must keep meaning "journal only".
- Public repo: no secrets, hostnames beyond `*.lab.home`/cluster DNS, or tokens in code or tests.

## Adding a feature

1. Branch from `main` (`feat/<topic>`); one concern per PR.
2. New collector → `internal/investigate` + its own package if it talks to a new system;
   it must fail soft (record the error, keep the bundle) and be covered by a table test with a fake.
3. New config → env var with a safe default, documented in the README table.
4. Update `README.md` when behaviour, config or the boundary changes.
5. `gofmt`, vet, test green → PR with a conventional-commit title (`feat(map): …`, `fix(alert): …`).

## Shipping

Merge to `main` → image `:<sha>` → bump the SHA in Homelab `services/warden/deployment.yaml`
(PR there) → ArgoCD syncs. Never deploy `:latest`, never `kubectl apply` by hand.

## Knowledge base

If the `knowledge` MCP is connected, search it before debugging and write back non-obvious
fixes (rules: DaVinci `AGENTS.md`).
