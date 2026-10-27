// Package kb searches the knowledge base read-only (Homelab ADR 0011 §6):
// markdown under git-synced roots (DaVinci docs/, Homelab docs/). Plain term
// scoring is enough to cite the right runbook; semantic search stays in
// DaVinci. Warden never writes the KB.
package kb

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Hit is one matching document.
type Hit struct {
	Path    string  `json:"path"`    // root-label/relative/path.md
	Heading string  `json:"heading"` // first # heading
	Score   float64 `json:"score"`
}

// noise: living documents that mention everything and would top every search.
var noise = map[string]bool{"ROADMAP.MD": true, "CHANGELOG.MD": true}

// Root is a directory to index, shown under Label.
type Root struct{ Label, Dir string }

type doc struct {
	path, heading string
	words         map[string]int
	title         []string // heading + filename tokens: strong signals
}

// titleMatch: a query term hits a title token exactly, or one contains the
// other (≥5 chars) — "crashloop.md" for "CrashLoopBackOff".
func (d doc) titleMatch(w string) bool {
	for _, t := range d.title {
		if t == w || (len(t) >= 5 && len(w) >= 5 && (strings.Contains(w, t) || strings.Contains(t, w))) {
			return true
		}
	}
	return false
}

// Index re-reads its roots at most every TTL (git-sync updates them).
type Index struct {
	Roots []Root
	TTL   time.Duration

	mu   sync.Mutex
	at   time.Time
	docs []doc
}

func tokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_'
	})
}

func (x *Index) load() {
	ttl := x.TTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if x.docs != nil && time.Since(x.at) < ttl {
		return
	}
	var docs []doc
	for _, r := range x.Roots {
		_ = filepath.WalkDir(r.Dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if strings.HasPrefix(d.Name(), ".") && p != r.Dir {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".md") || noise[strings.ToUpper(d.Name())] {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || len(b) > 1<<20 {
				return nil
			}
			rel, _ := filepath.Rel(r.Dir, p)
			dd := doc{path: r.Label + "/" + filepath.ToSlash(rel), words: map[string]int{}}
			for _, line := range strings.Split(string(b), "\n") {
				if dd.heading == "" && strings.HasPrefix(line, "# ") {
					dd.heading = strings.TrimSpace(line[2:])
				}
			}
			for _, t := range tokens(string(b)) {
				dd.words[t]++
			}
			dd.title = append(tokens(dd.heading), tokens(strings.TrimSuffix(filepath.Base(rel), ".md"))...)
			docs = append(docs, dd)
			return nil
		})
	}
	x.docs, x.at = docs, time.Now()
}

// Search scores documents by the query terms (each term counted with a
// diminishing weight, rarer terms worth more) and returns the top n.
func (x *Index) Search(terms []string, n int) []Hit {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.load()
	var q []string
	seen := map[string]bool{}
	for _, t := range terms {
		for _, w := range tokens(t) {
			if len(w) >= 3 && !seen[w] {
				seen[w] = true
				q = append(q, w)
			}
		}
	}
	if len(q) == 0 || len(x.docs) == 0 {
		return nil
	}
	hitsOf := func(d doc, w string) int {
		c := d.words[w]
		if d.titleMatch(w) {
			c += 5
		}
		return c
	}
	df := map[string]int{}
	for _, d := range x.docs {
		for _, w := range q {
			if hitsOf(d, w) > 0 {
				df[w]++
			}
		}
	}
	var hits []Hit
	for _, d := range x.docs {
		s, matched := 0.0, 0
		for _, w := range q {
			c := hitsOf(d, w)
			if c == 0 {
				continue
			}
			matched++
			idf := 1.0 + float64(len(x.docs))/float64(1+df[w])
			s += idf * (1 - 1/float64(1+c))
		}
		if matched > 0 {
			hits = append(hits, Hit{Path: d.path, Heading: d.heading, Score: s * float64(matched) / float64(len(q))})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > n {
		hits = hits[:n]
	}
	return hits
}
