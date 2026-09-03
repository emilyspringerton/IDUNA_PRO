package userlog

import (
	"context"
	"encoding/json"
	"testing"
)

func TestFileEventLog_AppendAndRead(t *testing.T) {
	dir := t.TempDir()
	log, err := NewFileEventLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	ctx := context.Background()

	data, _ := json.Marshal(UserCreatedData{LocalUID: 1, Email: "test@example.com"})
	ev := Event{
		ID:   "ev-001",
		Type: EventUserCreated,
		Data: json.RawMessage(data),
	}
	recs, err := log.Append(ctx, ev)
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if len(recs) != 1 || recs[0].Sequence != 1 {
		t.Fatalf("expected seq=1, got %v", recs)
	}

	got, err := log.ReadFrom(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if len(got) != 1 || got[0].Event.ID != "ev-001" {
		t.Errorf("ReadFrom: unexpected %v", got)
	}
}

func TestFileEventLog_SequenceMonotonic(t *testing.T) {
	dir := t.TempDir()
	log, err := NewFileEventLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	ctx := context.Background()
	data, _ := json.Marshal(UserCreatedData{LocalUID: 0})
	for i := range 5 {
		_, err := log.Append(ctx, Event{
			ID:   "ev-" + string(rune('a'+i)),
			Type: EventUserCreated,
			Data: json.RawMessage(data),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	latest, _ := log.LatestSeq(ctx)
	if latest != 5 {
		t.Errorf("expected latest=5 got %d", latest)
	}
}

func TestFileEventLog_ReplayAfterReopen(t *testing.T) {
	dir := t.TempDir()
	data, _ := json.Marshal(UserCreatedData{LocalUID: 42, Email: "re@test.com"})

	func() {
		log, _ := NewFileEventLog(dir)
		defer log.Close()
		ctx := context.Background()
		log.Append(ctx, Event{ID: "e1", Type: EventUserCreated, Data: json.RawMessage(data)})
		log.Append(ctx, Event{ID: "e2", Type: EventUserCreated, Data: json.RawMessage(data)})
	}()

	// Reopen — should recover seq=2.
	log2, err := NewFileEventLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer log2.Close()

	latest, _ := log2.LatestSeq(context.Background())
	if latest != 2 {
		t.Errorf("after reopen: expected latest=2 got %d", latest)
	}

	// Append again — seq should continue from 3.
	recs, _ := log2.Append(context.Background(), Event{
		ID:   "e3",
		Type: EventUserUpdated,
		Data: json.RawMessage(data),
	})
	if recs[0].Sequence != 3 {
		t.Errorf("expected seq=3 after reopen, got %d", recs[0].Sequence)
	}
}

func TestFileEventLog_ReadFromMidStream(t *testing.T) {
	dir := t.TempDir()
	log, _ := NewFileEventLog(dir)
	defer log.Close()
	ctx := context.Background()

	data, _ := json.Marshal(UserCreatedData{LocalUID: 1})
	for i := range 5 {
		log.Append(ctx, Event{
			ID:   "x" + string(rune('0'+i)),
			Type: EventUserCreated,
			Data: json.RawMessage(data),
		})
	}

	recs, _ := log.ReadFrom(ctx, 3, 0)
	if len(recs) != 3 { // seq 3,4,5
		t.Errorf("expected 3 records from seq 3, got %d", len(recs))
	}
	if recs[0].Sequence != 3 {
		t.Errorf("first record seq: want 3, got %d", recs[0].Sequence)
	}
}
