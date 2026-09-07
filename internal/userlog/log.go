// Package userlog implements the user-event append-only log for IDUNA local users.
//
// Architecture mirrors PRRJECT_FATBABY's eventstore package:
//   - Events are appended as NDJSON records to date-partitioned files under rootDir/events/.
//   - Each record has a monotonically increasing sequence number persisted in rootDir/state/latest-seq.
//   - Projectors (SQLite or MySQL) subscribe to the log at startup to replay unapplied events,
//     and are applied inline on each write so the read model stays synchronous.
//
// Write path:  handler → FileEventLog.Append() → NDJSON file → projector.Apply()
// Read path:   handler → UserProjector.GetByUID() / ListUsers() → SQL table
package userlog

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is the canonical user-event envelope.
// Mirrors PRRJECT_FATBABY eventstore.Event so projectors can be ported between stacks.
type Event struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Source      string          `json:"source"`
	OccurredAt  time.Time       `json:"occurred_at"`
	IngestedAt  time.Time       `json:"ingested_at"`
	OperatorUID int             `json:"operator_uid"`
	Data        json.RawMessage `json:"data"`
}

// Record wraps an Event with its assigned sequence number.
type Record struct {
	Sequence   uint64    `json:"sequence"`
	Event      Event     `json:"event"`
	AppendedAt time.Time `json:"appended_at"`
}

// EventLog is the write-side interface for the user event log.
type EventLog interface {
	Append(ctx context.Context, events ...Event) ([]Record, error)
	ReadFrom(ctx context.Context, fromSeq uint64, limit int) ([]Record, error)
	LatestSeq(ctx context.Context) (uint64, error)
	Close() error
}

// FileEventLog is a file-backed EventLog implementation.
// Events are stored as NDJSON in date-partitioned files under rootDir/events/.
// One file per UTC day: YYYY-MM-DD.ndjson
type FileEventLog struct {
	rootDir    string
	eventsDir  string
	stateDir   string
	seqFile    string
	clock      func() time.Time
	mu         sync.Mutex
	latest     uint64
	currentDay string // "YYYY-MM-DD" of the open file
	current    *os.File
}

// NewFileEventLog opens (or creates) a FileEventLog rooted at rootDir.
// Typical path: var/user-events/
func NewFileEventLog(rootDir string) (*FileEventLog, error) {
	l := &FileEventLog{
		rootDir:   rootDir,
		eventsDir: filepath.Join(rootDir, "events"),
		stateDir:  filepath.Join(rootDir, "state"),
		seqFile:   filepath.Join(rootDir, "state", "latest-seq"),
		clock:     func() time.Time { return time.Now().UTC() },
	}
	for _, d := range []string{l.eventsDir, l.stateDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("userlog: create dir %s: %w", d, err)
		}
	}
	seq, err := l.recoverSeq()
	if err != nil {
		return nil, err
	}
	l.latest = seq
	if err := l.persistSeq(seq); err != nil {
		return nil, err
	}
	if err := l.openJournal(l.clock()); err != nil {
		return nil, err
	}
	return l, nil
}

// Append appends one or more events, assigning sequential sequence numbers.
// All events are written atomically (under lock) before returning.
func (l *FileEventLog) Append(_ context.Context, events ...Event) ([]Record, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("userlog: Append requires at least one event")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	if err := l.rotateIfNeeded(now); err != nil {
		return nil, err
	}

	records := make([]Record, len(events))
	for i, ev := range events {
		if ev.ID == "" {
			return nil, fmt.Errorf("userlog: event[%d] missing ID", i)
		}
		if ev.Type == "" {
			return nil, fmt.Errorf("userlog: event[%d] missing Type", i)
		}
		if len(ev.Data) == 0 {
			return nil, fmt.Errorf("userlog: event[%d] missing Data", i)
		}
		if ev.OccurredAt.IsZero() {
			ev.OccurredAt = now
		}
		ev.IngestedAt = now
		if ev.Source == "" {
			ev.Source = "iduna"
		}
		l.latest++
		rec := Record{Sequence: l.latest, Event: ev, AppendedAt: now}
		line, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("userlog: marshal record: %w", err)
		}
		line = append(line, '\n')
		if _, err := l.current.Write(line); err != nil {
			return nil, fmt.Errorf("userlog: write record: %w", err)
		}
		records[i] = rec
	}
	if err := l.current.Sync(); err != nil {
		return nil, fmt.Errorf("userlog: fsync: %w", err)
	}
	if err := l.persistSeq(l.latest); err != nil {
		return nil, err
	}
	return records, nil
}

// ReadFrom returns up to limit records with sequence >= fromSeq.
// Pass limit=0 for no limit.
func (l *FileEventLog) ReadFrom(_ context.Context, fromSeq uint64, limit int) ([]Record, error) {
	l.mu.Lock()
	files, err := l.sortedJournalFiles()
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}

	var out []Record
	for _, name := range files {
		recs, err := l.readFile(filepath.Join(l.eventsDir, name), fromSeq)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// LatestSeq returns the sequence number of the most recently appended record.
func (l *FileEventLog) LatestSeq(_ context.Context) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.latest, nil
}

// Close flushes and closes the current journal file.
func (l *FileEventLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.current != nil {
		if err := l.current.Sync(); err != nil {
			return err
		}
		return l.current.Close()
	}
	return nil
}

// ── internals ──────────────────────────────────────────────────────────────────

func (l *FileEventLog) journalPath(t time.Time) string {
	return filepath.Join(l.eventsDir, t.UTC().Format("2006-01-02")+".ndjson")
}

func (l *FileEventLog) openJournal(t time.Time) error {
	day := t.UTC().Format("2006-01-02")
	if l.current != nil && l.currentDay == day {
		return nil
	}
	if l.current != nil {
		_ = l.current.Sync()
		_ = l.current.Close()
	}
	f, err := os.OpenFile(l.journalPath(t), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("userlog: open journal: %w", err)
	}
	l.current = f
	l.currentDay = day
	return nil
}

func (l *FileEventLog) rotateIfNeeded(t time.Time) error {
	day := t.UTC().Format("2006-01-02")
	if l.currentDay == day {
		return nil
	}
	return l.openJournal(t)
}

func (l *FileEventLog) readFile(path string, fromSeq uint64) ([]Record, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("userlog: open %s: %w", path, err)
	}
	defer f.Close()

	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // skip corrupt lines
		}
		if rec.Sequence >= fromSeq {
			out = append(out, rec)
		}
	}
	return out, sc.Err()
}

func (l *FileEventLog) sortedJournalFiles() ([]string, error) {
	entries, err := os.ReadDir(l.eventsDir)
	if err != nil {
		return nil, fmt.Errorf("userlog: read events dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".ndjson") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// RedactUser implements the real half of GDPR erasure this package's own append-only design
// doesn't get for free: appending a EventUserDeleted record only ever updates the SQL
// PROJECTION (see sqlite_projector.go's own Apply, which just sets status='deleted' -- the
// original email/display_name/password_hash from that user's real local_user.created event, and
// any local_user.updated/password_reset events since, stay in the raw NDJSON files on disk
// FOREVER, because Append() never rewrites a line once it's written. A "GDPR delete" that only
// appends another event and calls it done would be misleading -- the real personal data would
// still be sitting in plain files, replayable by anyone with disk access or by rebuilding the
// projection from scratch.
//
// RedactUser scans every journal file for records whose Event.Data references localUID (every
// event payload type in this package -- created/updated/password_reset/status_changed/
// admin_changed/deleted -- carries a local_uid field), and overwrites the PII-bearing string
// fields in place (Email, DisplayName, PasswordHash) with a fixed redaction marker, while
// leaving the record's own structural fields (Sequence, Type, OccurredAt, the non-PII parts of
// Data like OldStatus/NewStatus/IsAdmin) intact -- the event HAPPENED, and this repo's own
// append-only design depends on sequence/structure staying replayable; only the personal DATA
// inside it is erased, matching how real event-sourced systems handle right-to-erasure
// (redaction-in-place / crypto-shredding) rather than mutating history's shape.
//
// Real, deliberate scope: this rewrites files under the log's own lock, and if the file being
// rewritten is the one currently open for appends, it closes and reopens the handle afterward --
// a concurrent Append during a RedactUser call blocks on the same mutex Append already uses, so
// there is no window where a write could land on a file mid-rewrite.
func (l *FileEventLog) RedactUser(_ context.Context, localUID int) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	files, err := l.sortedJournalFiles()
	if err != nil {
		return 0, err
	}

	needReopenCurrent := false
	total := 0
	for _, name := range files {
		path := filepath.Join(l.eventsDir, name)
		n, changed, err := redactFile(path, localUID)
		if err != nil {
			return total, fmt.Errorf("userlog: redact %s: %w", name, err)
		}
		total += n
		if changed && l.current != nil && filepath.Base(l.journalPath(l.clock())) == name {
			needReopenCurrent = true
		}
	}

	if needReopenCurrent {
		_ = l.current.Close()
		f, err := os.OpenFile(l.journalPath(l.clock()), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return total, fmt.Errorf("userlog: reopen current journal after redaction: %w", err)
		}
		l.current = f
	}
	return total, nil
}

const redactionMarker = "[redacted-gdpr-erasure]"

// eventLocalUID extracts the local_uid field common to every event payload type in this
// package, without needing a type-specific unmarshal first -- every UserXxxData struct
// json-tags this field the same way ("local_uid"), so a generic probe is safe and future-proof
// against new event types that follow the same convention.
func eventLocalUID(data json.RawMessage) (int, bool) {
	var probe struct {
		LocalUID int `json:"local_uid"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0, false
	}
	return probe.LocalUID, probe.LocalUID != 0
}

// redactPII overwrites the known PII-bearing string fields for rec's own event type, returning
// the possibly-modified Data and whether anything actually changed (a record can legitimately
// have nothing to redact -- e.g. UserStatusChangedData/UserAdminChangedData/UserDeletedData
// carry no PII at all, only structural fields, so those pass through byte-for-byte unchanged).
func redactPII(rec *Record) (bool, error) {
	switch rec.Event.Type {
	case EventUserCreated:
		var d UserCreatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return false, err
		}
		if d.Email == redactionMarker && d.DisplayName == redactionMarker && d.PasswordHash == redactionMarker {
			return false, nil // already redacted -- idempotent no-op, not a re-write
		}
		d.Email = redactionMarker
		d.DisplayName = redactionMarker
		d.PasswordHash = redactionMarker
		b, err := json.Marshal(d)
		if err != nil {
			return false, err
		}
		rec.Event.Data = b
		return true, nil
	case EventUserUpdated:
		var d UserUpdatedData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return false, err
		}
		emailAlready := d.Email == nil || *d.Email == redactionMarker
		nameAlready := d.DisplayName == nil || *d.DisplayName == redactionMarker
		if emailAlready && nameAlready {
			return false, nil // already redacted (or never carried PII to begin with)
		}
		redacted := redactionMarker
		if d.Email != nil {
			d.Email = &redacted
		}
		if d.DisplayName != nil {
			d.DisplayName = &redacted
		}
		b, err := json.Marshal(d)
		if err != nil {
			return false, err
		}
		rec.Event.Data = b
		return true, nil
	case EventUserPasswordReset:
		var d UserPasswordResetData
		if err := json.Unmarshal(rec.Event.Data, &d); err != nil {
			return false, err
		}
		if d.PasswordHash == redactionMarker {
			return false, nil // already redacted
		}
		d.PasswordHash = redactionMarker
		b, err := json.Marshal(d)
		if err != nil {
			return false, err
		}
		rec.Event.Data = b
		return true, nil
	default:
		// EventUserStatusChanged, EventUserAdminChanged, EventUserDeleted (and any future,
		// unrecognized type) carry no PII fields -- nothing to redact, left byte-for-byte alone.
		return false, nil
	}
}

// redactFile rewrites one NDJSON journal file in place (tmp file + atomic rename, same pattern
// persistSeq already uses), redacting every record for localUID. Returns how many records were
// redacted and whether the file's own bytes actually changed (a file with no matching records
// is left completely untouched, not needlessly rewritten).
func redactFile(path string, localUID int) (int, bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	var out []byte
	count := 0
	changed := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			// Corrupt line -- same "skip, don't fail the whole read" tolerance readFile already
			// has; passed through unchanged rather than dropped, since we can't safely tell
			// whether it belongs to this user.
			out = append(out, line...)
			out = append(out, '\n')
			continue
		}
		uid, ok := eventLocalUID(rec.Event.Data)
		if ok && uid == localUID {
			didRedact, err := redactPII(&rec)
			if err != nil {
				return count, changed, fmt.Errorf("redact record seq=%d: %w", rec.Sequence, err)
			}
			if didRedact {
				count++
				changed = true
				newLine, err := json.Marshal(rec)
				if err != nil {
					return count, changed, fmt.Errorf("marshal redacted record seq=%d: %w", rec.Sequence, err)
				}
				out = append(out, newLine...)
				out = append(out, '\n')
				continue
			}
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	if err := sc.Err(); err != nil {
		return count, changed, err
	}
	if !changed {
		return 0, false, nil
	}

	tmp := path + ".redact-tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return count, changed, fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return count, changed, fmt.Errorf("rename: %w", err)
	}
	return count, changed, nil
}

func (l *FileEventLog) recoverSeq() (uint64, error) {
	data, err := os.ReadFile(l.seqFile)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("userlog: read seq file: %w", err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("userlog: parse seq: %w", err)
	}
	return n, nil
}

func (l *FileEventLog) persistSeq(seq uint64) error {
	data := strconv.FormatUint(seq, 10) + "\n"
	tmp := l.seqFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return fmt.Errorf("userlog: write seq tmp: %w", err)
	}
	if err := os.Rename(tmp, l.seqFile); err != nil {
		return fmt.Errorf("userlog: rename seq: %w", err)
	}
	return nil
}
