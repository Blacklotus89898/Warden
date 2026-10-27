package investigate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Blacklotus89898/Warden/internal/redact"
)

// DigestLimit keeps a push readable (ntfy's message limit is 4096 bytes).
const DigestLimit = 3500

// Digest is the phone-sized summary of a bundle: findings first, at most a
// few log lines, everything redacted. The full bundle stays in the journal.
func (b *Bundle) Digest() (title, body string) {
	a := b.Alert
	scope := b.Namespace
	if scope == "" {
		scope = "cluster"
	}
	title = fmt.Sprintf("Warden: %s (%s)", a.Name(), scope)
	var w strings.Builder
	line := func(f string, args ...any) { fmt.Fprintf(&w, f+"\n", args...) }

	if s := a.Annotations["summary"]; s != "" {
		line("%s", redact.Truncate(redact.String(s), 200))
	}
	if len(b.Pods) > 0 {
		line("\nPods:")
		for _, p := range b.Pods {
			state := p.Phase
			if !p.Ready {
				state += ", not ready"
			}
			line("• %s — %s, %d restarts%s", p.Name, state, p.Restarts, nodeSuffix(p.Node))
			for _, pr := range p.Problems {
				line("   %s", pr)
			}
		}
	}
	if len(b.Events) > 0 {
		line("\nWarning events (2h):")
		for i, e := range b.Events {
			if i == 4 {
				line("   … %d more", len(b.Events)-4)
				break
			}
			line("• %s %s ×%d: %s", e.Object, e.Reason, e.Count, redact.Truncate(e.Message, 140))
		}
	}
	for _, ap := range b.Apps {
		if ap.Sync == "Synced" && ap.Health == "Healthy" {
			line("\nArgoCD %s: Synced/Healthy", ap.Name)
			continue
		}
		line("\nArgoCD %s: %s/%s %s", ap.Name, ap.Sync, ap.Health, ap.Message)
		for _, c := range ap.Conditions {
			line("   %s", redact.Truncate(c, 160))
		}
	}
	for _, n := range b.Nodes {
		st := "Ready"
		if !n.Ready {
			st = "NotReady"
		}
		if n.Cordoned {
			st += ", cordoned"
		}
		if len(n.Pressure) > 0 {
			st += ", " + strings.Join(n.Pressure, ",")
		}
		line("\nNode %s: %s", n.Name, st)
	}
	if b.Expr != "" {
		if len(b.Metric) == 0 {
			line("\nAlert expr now: no series (condition cleared?)")
		} else {
			line("\nAlert expr now: %d series, e.g. %s = %s", len(b.Metric), labelString(b.Metric[0].Labels), b.Metric[0].Value)
		}
	}
	for _, p := range b.Pods { // a few log lines, troubled pod first
		keys := make([]string, 0, len(p.Logs))
		for k := range p.Logs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			ls := p.Logs[k]
			if len(ls) > 5 {
				ls = ls[len(ls)-5:]
			}
			line("\nLogs %s/%s:", p.Name, k)
			for _, l := range ls {
				line("  %s", redact.Truncate(l, 160))
			}
		}
		break
	}
	if b.Runbook != "" || len(b.KB) > 0 {
		line("\nKnowledge:")
		if b.Runbook != "" {
			line("• runbook: %s", b.Runbook)
		}
		for _, h := range b.KB {
			line("• %s — %s", h.Path, h.Heading)
		}
	}
	if len(b.Errors) > 0 {
		names := make([]string, 0, len(b.Errors))
		for k := range b.Errors {
			names = append(names, k)
		}
		sort.Strings(names)
		line("\n(incomplete: %s failed)", strings.Join(names, ", "))
	}
	line("\nBundle %s (%s)", b.ID, b.Duration)
	return title, redact.Truncate(w.String(), DigestLimit)
}

func nodeSuffix(n string) string {
	if n == "" {
		return ""
	}
	return " on " + n
}

func labelString(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "__name__" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	s := "{" + strings.Join(parts, ",") + "}"
	return redact.Truncate(redact.String(s), 160)
}
