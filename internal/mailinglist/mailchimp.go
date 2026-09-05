package mailinglist

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MailchimpClient forwards subscribers to Mailchimp. IDUNA's own encrypted
// store (Store, above) is the system of record — Mailchimp is a downstream
// sync target for actually sending email, not the authoritative copy. If
// Mailchimp is unreachable or misconfigured, the subscribe path still
// succeeds; sync failures are logged and best-effort only.
type MailchimpClient struct {
	APIKey string // format: <key>-<datacenter>, e.g. ...-us21
	ListID string
	http   *http.Client
}

func NewMailchimpClient(apiKey, listID string) *MailchimpClient {
	return &MailchimpClient{
		APIKey: apiKey,
		ListID: listID,
		http:   &http.Client{Timeout: 8 * time.Second},
	}
}

func (c *MailchimpClient) datacenter() string {
	parts := strings.Split(c.APIKey, "-")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}

// Subscribe upserts a member into the client's default ListID. Equivalent to
// SubscribeToList(email, c.ListID) — see that doc for the opt-in contract.
func (c *MailchimpClient) Subscribe(email string) error {
	return c.SubscribeToList(email, c.ListID)
}

// SubscribeToList upserts a member into a specific Mailchimp audience with
// status_if_new "pending" — Mailchimp's own double opt-in: the subscriber
// must click the confirmation email Mailchimp sends before they're actually
// subscribed. This is the founder-approved proof-of-consent mechanism (see
// EMILY/BACKLOG.md SECTION 152/153) — do not change status_if_new to
// "subscribed" without revisiting that decision.
//
// listID lets callers target an audience other than the client's default
// (e.g. a product-specific waitlist kept separate from the general
// okemily.com list) — see EMILY/BACKLOG.md SECTION 163.
func (c *MailchimpClient) SubscribeToList(email, listID string) error {
	if c.APIKey == "" || listID == "" {
		return fmt.Errorf("mailchimp not configured (MAILCHIMP_API_KEY or list ID unset)")
	}
	dc := c.datacenter()
	if dc == "" {
		return fmt.Errorf("mailchimp API key missing datacenter suffix")
	}

	lower := strings.ToLower(strings.TrimSpace(email))
	hash := md5.Sum([]byte(lower))
	subscriberHash := hex.EncodeToString(hash[:])

	body, err := json.Marshal(map[string]any{
		"email_address": lower,
		"status_if_new": "pending",
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://%s.api.mailchimp.com/3.0/lists/%s/members/%s", dc, listID, subscriberHash)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("anystring", c.APIKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("mailchimp request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("mailchimp returned %d", resp.StatusCode)
	}
	return nil
}
