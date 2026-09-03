package userlog

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// WebmasterCredentials is the structure of var/webmaster.json (gitignored).
// Only used at first boot to seed uid=0.
type WebmasterCredentials struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

// SeedWebmaster reads var/webmaster.json and ensures uid=0 exists in the projector.
// Idempotent: if uid=0 already exists, the file is not re-read and no event is appended.
//
// credPath is typically filepath.Join(idunaRoot, "var", "webmaster.json").
func SeedWebmaster(ctx context.Context, credPath string, log EventLog, proj UserProjector) error {
	// Replay any unapplied events first so the projector reflects current state.
	if err := ReplayUnapplied(ctx, log, proj); err != nil {
		return fmt.Errorf("webmaster seed replay: %w", err)
	}

	existing, err := proj.GetByUID(ctx, 0)
	if err != nil {
		return fmt.Errorf("webmaster check uid=0: %w", err)
	}
	if existing != nil {
		return nil // already seeded
	}

	data, err := os.ReadFile(credPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("webmaster.json not found at %s — create it with email/password/display_name to seed uid=0", credPath)
	}
	if err != nil {
		return fmt.Errorf("read webmaster.json: %w", err)
	}

	var creds WebmasterCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("parse webmaster.json: %w", err)
	}
	if creds.Email == "" || creds.Password == "" {
		return fmt.Errorf("webmaster.json: email and password are required")
	}
	if creds.DisplayName == "" {
		creds.DisplayName = "webmaster"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash webmaster password: %w", err)
	}

	payload, _ := json.Marshal(UserCreatedData{
		LocalUID:     0,
		Email:        creds.Email,
		DisplayName:  creds.DisplayName,
		PasswordHash: string(hash),
	})
	ev := Event{
		ID:          uuid.New().String(),
		Type:        EventUserCreated,
		Source:      "idunapro/bootstrap",
		OccurredAt:  time.Now().UTC(),
		OperatorUID: 0,
		Data:        json.RawMessage(payload),
	}
	records, err := log.Append(ctx, ev)
	if err != nil {
		return fmt.Errorf("append webmaster create event: %w", err)
	}
	if err := proj.Apply(ctx, records[0]); err != nil {
		return fmt.Errorf("apply webmaster create event: %w", err)
	}
	if err := proj.AdvanceCursor(ctx, records[0].Sequence); err != nil {
		return fmt.Errorf("advance cursor after webmaster seed: %w", err)
	}
	return nil
}

// ReplayUnapplied reads all event-log records after the projector's cursor
// and applies them. Call at startup to catch up after a restart.
func ReplayUnapplied(ctx context.Context, log EventLog, proj UserProjector) error {
	cursor, err := proj.Cursor(ctx)
	if err != nil {
		return fmt.Errorf("replay: read cursor: %w", err)
	}
	records, err := log.ReadFrom(ctx, cursor+1, 0)
	if err != nil {
		return fmt.Errorf("replay: read log: %w", err)
	}
	for _, rec := range records {
		if err := proj.Apply(ctx, rec); err != nil {
			return fmt.Errorf("replay: apply seq=%d: %w", rec.Sequence, err)
		}
		if err := proj.AdvanceCursor(ctx, rec.Sequence); err != nil {
			return fmt.Errorf("replay: advance cursor: %w", err)
		}
	}
	return nil
}
