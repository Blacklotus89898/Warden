package server

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Blacklotus89898/Warden/internal/investigate"
	"github.com/Blacklotus89898/Warden/internal/notify"
	"github.com/Blacklotus89898/Warden/internal/redact"
	"github.com/Blacklotus89898/Warden/internal/services"
	"github.com/Blacklotus89898/Warden/internal/statusmap"
)

// KindSummary journals each daily summary push (or why it wasn't sent).
const KindSummary = "summary.sent"

// Summary schedules one push a day: services that are not green, the last
// 24h of investigations and pushes, what is still undiagnosed, and node disk.
// It reads only what Warden already reads (no new endpoints) and does not
// count against the digest cap: it is one push a day, journaled.
type Summary struct {
	Hour, Minute int            // local time of day
	Loc          *time.Location // nil = off
	// Disk reads node root-filesystem use; nil = no disk line.
	Disk services.Metrics
}

func (m Summary) enabled() bool { return m.Loc != nil }

// ParseSummaryAt parses "HH:MM" ("" = off).
func ParseSummaryAt(at, tz string) (Summary, error) {
	if at == "" {
		return Summary{}, nil
	}
	h, m, ok := strings.Cut(at, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return Summary{}, fmt.Errorf("summary time %q: want HH:MM", at)
	}
	loc := time.UTC
	if tz != "" {
		l, err := time.LoadLocation(tz)
		if err != nil {
			return Summary{}, fmt.Errorf("summary timezone %q: %w", tz, err)
		}
		loc = l
	}
	return Summary{Hour: hh, Minute: mm, Loc: loc}, nil
}

// next is the first scheduled time strictly after now.
func (m Summary) next(now time.Time) time.Time {
	l := now.In(m.Loc)
	t := time.Date(l.Year(), l.Month(), l.Day(), m.Hour, m.Minute, 0, 0, m.Loc)
	if !t.After(l) {
		t = time.Date(l.Year(), l.Month(), l.Day()+1, m.Hour, m.Minute, 0, 0, m.Loc)
	}
	return t
}

func (s *Server) summaryLoop(ctx context.Context) {
	for {
		at := s.Summary.next(s.now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(at)):
		}
		// A restart right after the scheduled time must not send twice.
		if n, err := s.J.CountSince(ctx, KindSummary, at.Add(-time.Minute)); err == nil && n > 0 {
			continue
		}
		s.SendSummary(ctx)
	}
}

// SendSummary builds and pushes the summary now, and journals it.
func (s *Server) SendSummary(ctx context.Context) {
	bctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	p := s.BuildSummary(bctx)
	cancel()
	nctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.Notify.Send(nctx, p); err != nil {
		_, _ = s.J.Append(ctx, KindNotifyError, "", map[string]string{"error": err.Error(), "push": "summary"})
		return
	}
	_, _ = s.J.Append(ctx, KindSummary, "", map[string]string{"title": p.Title})
}

// BuildSummary assembles the summary push. Every section fails soft: a
// collector error becomes a line, never a missing push.
func (s *Server) BuildSummary(ctx context.Context) notify.Push {
	now := s.now()
	var w strings.Builder
	prio := "low"
	red, amber := 0, 0

	if s.Services != nil {
		v, err := s.Services.Build(ctx)
		if err != nil {
			fmt.Fprintf(&w, "Services: unavailable (%v)\n", err)
		} else {
			var bad []string
			for _, sv := range v.Services {
				switch sv.Status {
				case statusmap.Red:
					red++
				case statusmap.Amber:
					amber++
				default:
					continue
				}
				line := fmt.Sprintf("• %s %s", sv.Status, sv.Namespace)
				if len(sv.Flags) > 0 {
					line += ": " + strings.Join(sv.Flags, ", ")
				}
				bad = append(bad, line)
			}
			sort.Strings(bad) // "amber" < "red": stable order, reds together
			fmt.Fprintf(&w, "Services: %d green of %d", len(v.Services)-red-amber, len(v.Services))
			if red+amber > 0 {
				fmt.Fprintf(&w, " (%d red, %d amber)\n", red, amber)
				for i, l := range bad {
					if i == 8 {
						fmt.Fprintf(&w, "… %d more on /services\n", len(bad)-8)
						break
					}
					w.WriteString(l + "\n")
				}
			} else {
				w.WriteString("\n")
			}
		}
	}
	if red > 0 {
		prio = "default"
	}

	since := now.Add(-24 * time.Hour)
	if rows, err := s.investigationRows(ctx, 500); err != nil {
		fmt.Fprintf(&w, "\nInvestigations: unavailable (%v)\n", err)
	} else {
		alerts, ops, open := 0, 0, 0
		weekAgo := now.Add(-7 * 24 * time.Hour)
		for _, r := range rows {
			ts, err := time.Parse(time.RFC3339Nano, r.TS)
			if err != nil {
				continue
			}
			if ts.After(since) {
				if r.Source == "operator" {
					ops++
				} else {
					alerts++
				}
			}
			if r.Source == "alert" && !r.Diagnosed && ts.After(weekAgo) {
				open++
			}
		}
		fmt.Fprintf(&w, "\nLast 24h: %d alert investigations, %d by you\n", alerts, ops)
		if open > 0 {
			fmt.Fprintf(&w, "Not yet diagnosed (7d): %d\n", open)
		}
	}
	pushed, _ := s.J.CountSince(ctx, KindNotified, since)
	skipped, _ := s.J.CountSince(ctx, KindSkipped, since)
	grouped, _ := s.J.CountSince(ctx, KindGrouped, since)
	fmt.Fprintf(&w, "Pushes: %d sent, %d grouped, %d skipped\n", pushed, grouped, skipped)

	if s.Summary.Disk != nil {
		w.WriteString(s.diskLine(ctx))
	}

	title := "Warden daily: all green"
	switch {
	case red > 0:
		title = fmt.Sprintf("Warden daily: %d red", red)
	case amber > 0:
		title = fmt.Sprintf("Warden daily: %d amber", amber)
	}
	return notify.Push{
		Title: title, Priority: prio, Tags: []string{"sunrise"},
		Body:    redact.Truncate(redact.String(w.String()), investigate.DigestLimit),
		Click:   s.page("/services"),
		Actions: s.pageActions(),
	}
}

// DiskQuery is root-filesystem use per node, by node name.
const DiskQuery = `max by (nodename) (100 * (1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * on (instance) group_left (nodename) node_uname_info)`

func (s *Server) diskLine(ctx context.Context) string {
	samples, err := s.Summary.Disk.Query(ctx, DiskQuery, 20)
	if err != nil {
		return fmt.Sprintf("Disk: unavailable (%v)\n", err)
	}
	if len(samples) == 0 {
		return ""
	}
	var parts []string
	for _, x := range samples {
		v, err := strconv.ParseFloat(x.Value, 64)
		if err != nil {
			continue
		}
		mark := ""
		if v >= 80 {
			mark = " ⚠"
		}
		parts = append(parts, fmt.Sprintf("%s %.0f%%%s", x.Labels["nodename"], v, mark))
	}
	sort.Strings(parts)
	return "Disk: " + strings.Join(parts, ", ") + "\n"
}
