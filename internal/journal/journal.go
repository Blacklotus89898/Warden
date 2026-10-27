// Package journal is Warden's append-only event log (Homelab ADR 0011 §3):
// every alert received, every skip and why, every investigation bundle and
// every notification. Inserted, never updated or deleted — the triggers make
// the database refuse edits. The bundles are phase 2's eval set. SQLite in WAL
// mode with one writer (the Tulip/Petal pattern).
package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Event is one journal entry.
type Event struct {
	ID      int64           `json:"id"`
	TS      string          `json:"ts"`
	Kind    string          `json:"kind"`
	Ref     string          `json:"ref,omitempty"` // investigation id
	Payload json.RawMessage `json:"payload"`
}

// Journal wraps the SQLite event store.
type Journal struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      TEXT NOT NULL,
	kind    TEXT NOT NULL,
	ref     TEXT NOT NULL DEFAULT '',
	payload TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind, id);
CREATE INDEX IF NOT EXISTS idx_events_ref ON events(ref);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'journal is append-only'); END;
-- Dedup (ADR 0011 §4): one investigation per alert firing, however often
-- alertmanager re-sends it. The PRIMARY KEY is the guarantee.
CREATE TABLE IF NOT EXISTS seen (
	key TEXT PRIMARY KEY,
	ts  TEXT NOT NULL
);
`

// Open opens (creating if needed) the journal at path.
func Open(ctx context.Context, path string) (*Journal, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Journal{db: db}, nil
}

// Close closes the database.
func (j *Journal) Close() error { return j.db.Close() }

// Append records an event; payload is JSON-encoded.
func (j *Journal) Append(ctx context.Context, kind, ref string, payload any) (*Event, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("journal: encode %s: %w", kind, err)
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := j.db.ExecContext(ctx, `INSERT INTO events (ts, kind, ref, payload) VALUES (?, ?, ?, ?)`, ts, kind, ref, string(raw))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Event{ID: id, TS: ts, Kind: kind, Ref: ref, Payload: raw}, nil
}

// ErrSeen means the key was already claimed.
var ErrSeen = errors.New("already seen")

// Claim records key once; a second claim returns ErrSeen.
func (j *Journal) Claim(ctx context.Context, key string) error {
	_, err := j.db.ExecContext(ctx, `INSERT INTO seen (key, ts) VALUES (?, ?)`, key, time.Now().UTC().Format(time.RFC3339))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return ErrSeen
	}
	return err
}

// List returns events of a kind (all kinds if empty), newest first.
func (j *Journal) List(ctx context.Context, kind string, limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT id, ts, kind, ref, payload FROM events`
	var args []any
	if kind != "" {
		q += ` WHERE kind = ?`
		args = append(args, kind)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	return j.query(ctx, q, append(args, limit)...)
}

// ByRef returns every event of one investigation, oldest first.
func (j *Journal) ByRef(ctx context.Context, ref string) ([]Event, error) {
	return j.query(ctx, `SELECT id, ts, kind, ref, payload FROM events WHERE ref = ? ORDER BY id`, ref)
}

// CountSince counts events of a kind since t (the daily cap).
func (j *Journal) CountSince(ctx context.Context, kind string, t time.Time) (int, error) {
	var n int
	err := j.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE kind = ? AND ts >= ?`,
		kind, t.UTC().Format(time.RFC3339Nano)).Scan(&n)
	return n, err
}

// Counts returns event totals by kind (for /metrics).
func (j *Journal) Counts(ctx context.Context) (map[string]int64, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT kind, COUNT(*) FROM events GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

func (j *Journal) query(ctx context.Context, q string, args ...any) ([]Event, error) {
	rows, err := j.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var p string
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.Ref, &p); err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(p)
		out = append(out, e)
	}
	return out, rows.Err()
}
