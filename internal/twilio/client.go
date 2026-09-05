// Package twilio is a real, minimal client for the exact Twilio REST API calls
// the CarePyre Console needs (kanban CP-SIP-242414/TWILLIO-API-124, "we can do all of the
// operations from the carepyre console side"). Auth is a Twilio API Key (SID + Secret) via
// HTTP Basic Auth -- Twilio's own documented alternative to the primary Account SID/Auth Token
// pair, matching what the founder's own real, live account key actually is.
//
// Real, live-found account-wide blocker (2026-09-05, see CarePyre/docs/... /
// PARENA/docs/TWILIO_SETUP_CHECKLIST.md's own "read this first" section): this account's Trust
// Hub compliance profile isn't approved yet, so CreateTrunk (and likely BuyPhoneNumber) fail
// with a real Twilio error (code 20003) until that human-only KYC step completes. This client
// does not paper over that -- CreateTrunk returns the real Twilio error message verbatim so the
// console can show it honestly, not a generic "something went wrong."
package twilio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	AccountSID   string
	APIKeySID    string
	APIKeySecret string
	http         *http.Client
	// BaseURL/TrunkingBaseURL default to the real Twilio hosts; overridable only for real,
	// direct testing against a local httptest.Server (never intended to point at a different
	// real host in production).
	BaseURL         string
	TrunkingBaseURL string
}

func NewClient(accountSID, apiKeySID, apiKeySecret string) *Client {
	return &Client{
		AccountSID:      accountSID,
		APIKeySID:       apiKeySID,
		APIKeySecret:    apiKeySecret,
		http:            &http.Client{Timeout: 10 * time.Second},
		BaseURL:         "https://api.twilio.com",
		TrunkingBaseURL: "https://trunking.twilio.com",
	}
}

// Configured reports whether real credentials are present -- the same nil-safe-fallback shape
// this codebase already uses for EventLog/Store (a handler checks this and responds "not
// configured" rather than panicking on a nil/empty client).
func (c *Client) Configured() bool {
	return c != nil && c.AccountSID != "" && c.APIKeySID != "" && c.APIKeySecret != ""
}

// TwilioError is a real, decoded Twilio API error body (their own documented shape:
// code/message/more_info/status) -- surfaced verbatim to the caller, not swallowed into a
// generic wrapper, so a real compliance block (code 20003) reads as what it actually is.
type TwilioError struct {
	Code     int    `json:"code"`
	Message  string `json:"message"`
	MoreInfo string `json:"more_info"`
	Status   int    `json:"status"`
}

func (e *TwilioError) Error() string {
	return fmt.Sprintf("twilio error %d: %s (%s)", e.Code, e.Message, e.MoreInfo)
}

func (c *Client) do(ctx context.Context, method, rawURL string, form url.Values, out any) error {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.APIKeySID, c.APIKeySecret)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("twilio request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read twilio response: %w", err)
	}
	if resp.StatusCode >= 300 {
		var terr TwilioError
		if jerr := json.Unmarshal(raw, &terr); jerr == nil && terr.Message != "" {
			return &terr
		}
		return fmt.Errorf("twilio returned HTTP %d: %s", resp.StatusCode, string(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode twilio response: %w", err)
		}
	}
	return nil
}

type Balance struct {
	AccountSID string `json:"account_sid"`
	Balance    string `json:"balance"`
	Currency   string `json:"currency"`
}

func (c *Client) GetBalance(ctx context.Context) (*Balance, error) {
	var bal Balance
	url := fmt.Sprintf("%s/2010-04-01/Accounts/%s/Balance.json", c.BaseURL, c.AccountSID)
	if err := c.do(ctx, http.MethodGet, url, nil, &bal); err != nil {
		return nil, err
	}
	return &bal, nil
}

type Trunk struct {
	SID          string `json:"sid"`
	FriendlyName string `json:"friendly_name"`
	DomainName   string `json:"domain_name"`
	Status       string `json:"status"`
}

type trunksResponse struct {
	Trunks []Trunk `json:"trunks"`
}

func (c *Client) ListTrunks(ctx context.Context) ([]Trunk, error) {
	var out trunksResponse
	if err := c.do(ctx, http.MethodGet, c.TrunkingBaseURL+"/v1/Trunks", nil, &out); err != nil {
		return nil, err
	}
	return out.Trunks, nil
}

// CreateTrunk makes a real Elastic SIP Trunk. Real, honest v0 scope: this alone is not a
// complete, callable trunk -- Termination auth (an IP ACL) and an Origination URI still need to
// be added as separate, real follow-up calls (AddIPACLToTrunk/AddOriginationURL, both real,
// separate Twilio resources) once this account's Trust Hub compliance clears and trunk creation
// itself stops failing.
func (c *Client) CreateTrunk(ctx context.Context, friendlyName, domainName string) (*Trunk, error) {
	form := url.Values{"FriendlyName": {friendlyName}, "DomainName": {domainName}}
	var t Trunk
	if err := c.do(ctx, http.MethodPost, c.TrunkingBaseURL+"/v1/Trunks", form, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

type PhoneNumber struct {
	SID          string `json:"sid"`
	PhoneNumber  string `json:"phone_number"`
	FriendlyName string `json:"friendly_name"`
}

type phoneNumbersResponse struct {
	IncomingPhoneNumbers []PhoneNumber `json:"incoming_phone_numbers"`
}

func (c *Client) ListPhoneNumbers(ctx context.Context) ([]PhoneNumber, error) {
	var out phoneNumbersResponse
	u := fmt.Sprintf("%s/2010-04-01/Accounts/%s/IncomingPhoneNumbers.json", c.BaseURL, c.AccountSID)
	if err := c.do(ctx, http.MethodGet, u, nil, &out); err != nil {
		return nil, err
	}
	return out.IncomingPhoneNumbers, nil
}
