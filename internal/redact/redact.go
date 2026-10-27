// Package redact scrubs secret-shaped strings before anything leaves the
// journal: ntfy is unauthenticated on the LAN (Homelab ADR 0011 §3), and log
// lines are untrusted. Conservative by design — a false positive costs a
// readable token, a false negative leaks one.
package redact

import (
	"regexp"
	"strings"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization|bearer|token|secret|passw(or)?d|api[_-]?key|access[_-]?key|private[_-]?key|credential|cookie|session)(["'\s:=]+)(?:(?i:bearer|basic|token)\s+)?[^\s"',;]+`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
	regexp.MustCompile(`(gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})`),
	regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),         // user:pass@ in URLs
	regexp.MustCompile(`\b[A-Za-z0-9+/_-]{40,}={0,2}\b`), // long opaque blobs
}

// String returns s with secret-shaped substrings replaced.
func String(s string) string {
	s = patterns[0].ReplaceAllString(s, "$1$3[redacted]")
	s = patterns[1].ReplaceAllString(s, "[redacted private key]")
	for _, re := range patterns[2:4] {
		s = re.ReplaceAllString(s, "[redacted]")
	}
	s = patterns[4].ReplaceAllString(s, "://[redacted]@")
	s = patterns[5].ReplaceAllString(s, "[redacted]")
	return s
}

// Truncate cuts s to at most n bytes on a rune boundary, marking the cut.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return strings.TrimRight(s[:cut], " \n") + " …"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// Lines redacts each line and keeps the last n.
func Lines(s string, n int) []string {
	all := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	out := make([]string, 0, len(all))
	for _, l := range all {
		out = append(out, Truncate(String(l), 300))
	}
	return out
}
