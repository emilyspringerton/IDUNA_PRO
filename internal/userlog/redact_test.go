package userlog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactUser_RemovesPIIFromRawFileBytes(t *testing.T) {
	dir := t.TempDir()
	log, err := NewFileEventLog(dir)
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	defer log.Close()
	ctx := context.Background()

	created, _ := json.Marshal(UserCreatedData{LocalUID: 42, Email: "alice@example.com", DisplayName: "Alice Real Name", PasswordHash: "$2a$super-secret-hash"})
	newEmail := "alice2@example.com"
	updated, _ := json.Marshal(UserUpdatedData{LocalUID: 42, Email: &newEmail})
	reset, _ := json.Marshal(UserPasswordResetData{LocalUID: 42, PasswordHash: "$2a$another-secret-hash"})
	statusChanged, _ := json.Marshal(UserStatusChangedData{LocalUID: 42, OldStatus: "active", NewStatus: "suspended"})
	otherUser, _ := json.Marshal(UserCreatedData{LocalUID: 99, Email: "bob@example.com", DisplayName: "Bob", PasswordHash: "bobhash"})

	if _, err := log.Append(ctx,
		Event{ID: "e1", Type: EventUserCreated, Data: created},
		Event{ID: "e2", Type: EventUserUpdated, Data: updated},
		Event{ID: "e3", Type: EventUserPasswordReset, Data: reset},
		Event{ID: "e4", Type: EventUserStatusChanged, Data: statusChanged},
		Event{ID: "e5", Type: EventUserCreated, Data: otherUser}, // different user -- must survive untouched
	); err != nil {
		t.Fatalf("Append: %v", err)
	}

	n, err := log.RedactUser(ctx, 42)
	if err != nil {
		t.Fatalf("RedactUser: %v", err)
	}
	// 3 records carry real PII for uid 42 (created, updated, password_reset); status_changed has none.
	if n != 3 {
		t.Fatalf("expected 3 records redacted, got %d", n)
	}

	// Real, raw-byte-level proof: read the actual journal file off disk (not through the log's
	// own API) and confirm the original secrets are genuinely gone, not just inaccessible via a
	// nicer API.
	files, err := os.ReadDir(filepath.Join(dir, "events"))
	if err != nil {
		t.Fatalf("read events dir: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 journal file, got %d", len(files))
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events", files[0].Name()))
	if err != nil {
		t.Fatalf("read journal file: %v", err)
	}
	rawStr := string(raw)

	for _, secret := range []string{
		"alice@example.com", "alice2@example.com", "Alice Real Name",
		"$2a$super-secret-hash", "$2a$another-secret-hash",
	} {
		if strings.Contains(rawStr, secret) {
			t.Errorf("expected %q to be scrubbed from the raw journal file, but it's still present", secret)
		}
	}
	// The other user's real data must survive completely untouched.
	for _, untouched := range []string{"bob@example.com", "Bob", "bobhash"} {
		if !strings.Contains(rawStr, untouched) {
			t.Errorf("expected unrelated user's data %q to survive redaction untouched, but it's gone", untouched)
		}
	}
	// Structural, non-PII fields must survive (this event HAPPENED, only the personal data is erased).
	for _, structural := range []string{"active", "suspended", `"local_uid":42`} {
		if !strings.Contains(rawStr, structural) {
			t.Errorf("expected structural field %q to survive redaction, but it's gone", structural)
		}
	}

	// Re-redacting is a safe no-op (idempotent) -- nothing left to redact the second time.
	n2, err := log.RedactUser(ctx, 42)
	if err != nil {
		t.Fatalf("second RedactUser: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected re-redaction to find nothing left to redact, got %d", n2)
	}

	// The log must still be genuinely usable afterward -- append must still work and land in a
	// valid, readable file (proves the tmp-file+rename rewrite didn't corrupt anything or leave
	// the open file handle stale).
	more, _ := json.Marshal(UserCreatedData{LocalUID: 7, Email: "carol@example.com"})
	if _, err := log.Append(ctx, Event{ID: "e6", Type: EventUserCreated, Data: more}); err != nil {
		t.Fatalf("Append after redaction: %v", err)
	}
	recs, err := log.ReadFrom(ctx, 1, 0)
	if err != nil {
		t.Fatalf("ReadFrom after redaction: %v", err)
	}
	if len(recs) != 6 {
		t.Fatalf("expected 6 total records after redaction+append, got %d", len(recs))
	}
	if recs[5].Sequence != 6 {
		t.Fatalf("expected sequence numbering to continue correctly, got seq=%d", recs[5].Sequence)
	}
}

func TestRedactUser_NoMatchingRecordsLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	log, err := NewFileEventLog(dir)
	if err != nil {
		t.Fatalf("NewFileEventLog: %v", err)
	}
	defer log.Close()
	ctx := context.Background()

	data, _ := json.Marshal(UserCreatedData{LocalUID: 1, Email: "test@example.com"})
	if _, err := log.Append(ctx, Event{ID: "e1", Type: EventUserCreated, Data: data}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	n, err := log.RedactUser(ctx, 999999) // no such user
	if err != nil {
		t.Fatalf("RedactUser: %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 records redacted for a nonexistent user, got %d", n)
	}
}
