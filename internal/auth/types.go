package auth

import "time"

// DailyTokenStat is one day's aggregate token usage extracted from Apple metadata.
type DailyTokenStat struct {
	Date   string `json:"date"`   // "YYYY-MM-DD" UTC
	Tokens int64  `json:"tokens"` // sum of metadata.tokens_used for all Apples that day
}

// Subscription tracks a user's Emily+ plan status.
type Subscription struct {
	ID        int64
	UserID    string
	Plan      string    // "emily_plus"
	Status    string    // "active" | "cancelled" | "expired"
	ExpiresAt time.Time // zero value = perpetual
	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsActive returns true if the subscription grants cap.query.full.
func (s *Subscription) IsActive() bool {
	if s == nil || s.Status != "active" {
		return false
	}
	return s.ExpiresAt.IsZero() || time.Now().UTC().Before(s.ExpiresAt)
}

// Monitor is a check-in (heartbeat / cron / deadman) monitor. Services POST to
// its unique check-in URL to confirm they are alive; if they don't within the
// timeout window, the alerting worker fires Slack/email notifications.
//
// Kind determines alerting semantics:
//   - heartbeat: alert if no check-in within timeout+grace (default)
//   - cron:      same alerting; indicates a scheduled task (timeout_seconds = expected interval)
//   - deadman:   zero-tolerance; alert immediately after timeout, grace_seconds ignored
type Monitor struct {
	ID                 int64      `json:"id"`
	Name               string     `json:"name"`
	Slug               string     `json:"slug"` // unique token in check-in URL
	Kind               string     `json:"kind"` // heartbeat | cron | deadman
	TimeoutSeconds     int        `json:"timeout_seconds"`
	GraceSeconds       int        `json:"grace_seconds"`
	Owner              string     `json:"owner"` // agent_name or user_id
	LastCheckinAt      *time.Time `json:"last_checkin_at,omitempty"`
	AlertedAt          *time.Time `json:"alerted_at,omitempty"`
	AlertSlackChannel  string     `json:"alert_slack_channel,omitempty"`
	AlertEmail         string     `json:"alert_email,omitempty"`
	Status             string     `json:"status"` // unknown | healthy | failing
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// IsOverdue returns true when the monitor has exceeded its deadline.
// Deadline is kind-sensitive:
//   - heartbeat / cron: timeout + grace from last check-in (or creation if never checked in)
//   - deadman:          timeout only — grace_seconds is ignored for zero-tolerance monitors
func (m *Monitor) IsOverdue(now time.Time) bool {
	grace := m.GraceSeconds
	if m.Kind == "deadman" {
		grace = 0
	}
	base := m.CreatedAt
	if m.LastCheckinAt != nil {
		base = *m.LastCheckinAt
	}
	deadline := base.Add(time.Duration(m.TimeoutSeconds+grace) * time.Second)
	return now.After(deadline)
}

type User struct {
	ID                 [16]byte
	IDString           string // UUID string, set by IAM store; takes precedence when non-empty
	Handle             string
	Email              string
	Permissions        []string
	Status             string
	Roles              []string
	HonorAccepted      bool
	HonorCurrentSHA    string
	HonorCurrentVer    int
	HonorCurrentText   string
	HonorAcceptedAtUTC *time.Time
}
