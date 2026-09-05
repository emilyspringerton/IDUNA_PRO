// Package mailaccounts is a real, minimal JMAP client for Stalwart's own management API
// (Stalwart, not a generic mail library) -- used to provision real mailboxes on
// mail.carepyre.org from the CarePyre admin console. Founder real-time, 2026-09-05: "ok we need
// a way to provision accounts from the carepyre admin console is that possible?"
//
// Real, checked fact this client's own auth flow is built against: Stalwart's OAuth server
// supports authorization_code, refresh_token, and device_code grants -- NOT client_credentials
// (confirmed live via its own /.well-known/oauth-authorization-server discovery document,
// 2026-09-05). There is no pure machine-to-machine grant to use here. This client instead
// re-plays the exact real request shape Stalwart's own web admin console uses for a
// username/password login (POST /api/auth with type "authCode", PKCE "plain" method where the
// code_verifier equals the code_challenge, then POST /auth/token to exchange the resulting code
// for a bearer token) -- captured live from the real admin UI's own network traffic, not
// guessed. A fresh token is requested per real request rather than cached/refreshed: this is an
// occasional admin action (provisioning a new mailbox), not a hot path, so the added round trip
// is a real, accepted simplicity tradeoff over token-caching complexity.
//
// REAL, HONEST SECURITY TRADEOFF, not glossed over: this reuses the same full-admin recovery
// credential (STALWART_ADMIN_PASSWORD) already used to configure the instance itself, not a
// scoped, mailbox-creation-only service account. Stalwart's own Roles feature may support finer
// scoping; that wasn't researched here given the time already spent standing up the mail server
// itself this session. If IDUNA_PRO's own config ever leaks, whoever has it gets full Stalwart
// admin, not just mailbox-creation rights -- a real, named follow-up to tighten, not a silent
// gap.
package mailaccounts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Client talks to a real, running Stalwart instance's own management (JMAP) API.
type Client struct {
	BaseURL       string // e.g. "https://mail.carepyre.org"
	AdminUser     string // e.g. "admin"
	AdminPass     string
	DefaultDomain string // e.g. "carepyre.org"
	HTTPClient    *http.Client
}

// Configured mirrors TwilioHandler's own nil-safe pattern (internal/twilio/client.go) -- an
// empty admin password means this feature is simply unavailable, not a panic.
func (c *Client) Configured() bool {
	return c != nil && c.BaseURL != "" && c.AdminUser != "" && c.AdminPass != ""
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	// Real, deliberate InsecureSkipVerify: mail.carepyre.org was still serving a self-signed
	// fallback cert (ACME issuance timing unconfirmed, see docs/STALWART_RUNBOOK.md) as of the
	// same session this client was written in. Real, live-found security concern along the
	// way: this client's own admin credential travels in every request -- plain http:// (no TLS
	// at all) would put that on the wire in cleartext, real cause for concern on a public
	// internet hop. Real fix chosen: still use https:// (443, real TLS encryption against
	// passive eavesdropping) with certificate verification skipped for now (no protection
	// against an active MITM, a real, named, narrower remaining gap). Remove
	// InsecureSkipVerify entirely once a real, publicly-trusted cert is confirmed live -- this
	// is not meant to be a permanent setting.
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// GenerateSecret returns a real, cryptographically random password -- the same shape used for
// the four real accounts (brian/penelope/gary/emily) provisioned by hand earlier this session,
// just generated in Go instead of a one-off shell script.
func GenerateSecret() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 20)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

// mailaccountsRandomVerifier returns a real, RFC 7636-compliant PKCE code_verifier (43-128
// unreserved characters -- this uses 64 hex characters, well within range).
func mailaccountsRandomVerifier() (string, error) {
	const alphabet = "abcdef0123456789"
	out := make([]byte, 64)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

// authenticate replays the real login flow captured from Stalwart's own web admin console.
func (c *Client) authenticate(ctx context.Context) (string, error) {
	// PKCE "plain": code_verifier == code_challenge, no S256 needed for this server-side flow.
	// Real bug found and fixed live: RFC 7636 requires a code_verifier of 43-128 characters: a
	// short, human-readable string here ("iduna-pro-mailaccounts-plain-verifier", 38 chars)
	// failed token exchange with "invalid_grant" -- Stalwart enforces the real minimum length.
	challenge, err := mailaccountsRandomVerifier()
	if err != nil {
		return "", err
	}
	authBody, _ := json.Marshal(map[string]string{
		"type":                "authCode",
		"accountName":         c.AdminUser,
		"accountSecret":       c.AdminPass,
		"clientId":            "stalwart-webui",
		"redirectUri":         c.BaseURL + "/admin/oauth/callback",
		"scope":               "openid offline_access",
		"state":               "iduna-pro",
		"codeChallenge":       challenge,
		"codeChallengeMethod": "plain",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/auth", bytes.NewReader(authBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("mailaccounts: auth request failed: %w", err)
	}
	defer resp.Body.Close()
	var authResp struct {
		ClientCode string `json:"client_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil || authResp.ClientCode == "" {
		return "", fmt.Errorf("mailaccounts: auth response missing client_code (status %d)", resp.StatusCode)
	}

	form := strings.NewReader(fmt.Sprintf(
		"grant_type=authorization_code&code=%s&code_verifier=%s&client_id=stalwart-webui&redirect_uri=%s",
		authResp.ClientCode, challenge, c.BaseURL+"/admin/oauth/callback",
	))
	tokReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/auth/token", form)
	if err != nil {
		return "", err
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokResp, err := c.httpClient().Do(tokReq)
	if err != nil {
		return "", fmt.Errorf("mailaccounts: token request failed: %w", err)
	}
	defer tokResp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("mailaccounts: token exchange failed: %s", tok.Error)
	}
	return tok.AccessToken, nil
}

// session returns the admin's own JMAP accountId (Stalwart's management API operates "as" the
// authenticated principal's own accountId, per the real /jmap/session response captured live).
func (c *Client) session(ctx context.Context, token string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/jmap/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var sess struct {
		PrimaryAccounts map[string]string `json:"primaryAccounts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		return "", err
	}
	id := sess.PrimaryAccounts["urn:ietf:params:jmap:mail"]
	if id == "" {
		return "", fmt.Errorf("mailaccounts: no primary mail account in session")
	}
	return id, nil
}

func (c *Client) jmapCall(ctx context.Context, token, accountID string, methodCalls []any) (map[string]json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"using": []string{
			"urn:ietf:params:jmap:core", "urn:stalwart:jmap", "urn:ietf:params:jmap:principals",
		},
		"methodCalls": methodCalls,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/jmap/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		MethodResponses [][3]json.RawMessage `json:"methodResponses"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("mailaccounts: unexpected JMAP response: %s", raw)
	}
	out := map[string]json.RawMessage{}
	for _, mr := range parsed.MethodResponses {
		var callID string
		_ = json.Unmarshal(mr[2], &callID)
		out[callID] = mr[1]
	}
	return out, nil
}

// resolveDomainID finds the real Stalwart domain object id for a domain name (e.g.
// "carepyre.org" -> "b"), matching the real x:Domain/query + x:Domain/get pair captured live.
func (c *Client) resolveDomainID(ctx context.Context, token, accountID, domainName string) (string, error) {
	results, err := c.jmapCall(ctx, token, accountID, []any{
		[]any{"x:Domain/query", map[string]any{"accountId": accountID}, "0"},
	})
	if err != nil {
		return "", err
	}
	var query struct {
		IDs []string `json:"ids"`
	}
	if err := json.Unmarshal(results["0"], &query); err != nil {
		return "", err
	}
	if len(query.IDs) == 0 {
		return "", fmt.Errorf("mailaccounts: no domains configured on this Stalwart instance")
	}

	getResults, err := c.jmapCall(ctx, token, accountID, []any{
		[]any{"x:Domain/get", map[string]any{
			"accountId":  accountID,
			"ids":        query.IDs,
			"properties": []string{"id", "name"},
		}, "0"},
	})
	if err != nil {
		return "", err
	}
	var get struct {
		List []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"list"`
	}
	if err := json.Unmarshal(getResults["0"], &get); err != nil {
		return "", err
	}
	for _, d := range get.List {
		if d.Name == domainName {
			return d.ID, nil
		}
	}
	return "", fmt.Errorf("mailaccounts: domain %q not found on this Stalwart instance", domainName)
}

// CreateAccount provisions a real Stalwart mailbox. Returns the new account's own Stalwart
// object id. The real x:Account/set create shape is copied verbatim from what the actual admin
// console sends (captured live, 2026-09-05).
func (c *Client) CreateAccount(ctx context.Context, username, domain, password string) (string, error) {
	if !c.Configured() {
		return "", fmt.Errorf("mailaccounts: not configured")
	}
	if domain == "" {
		domain = c.DefaultDomain
	}
	token, err := c.authenticate(ctx)
	if err != nil {
		return "", err
	}
	accountID, err := c.session(ctx, token)
	if err != nil {
		return "", err
	}
	domainID, err := c.resolveDomainID(ctx, token, accountID, domain)
	if err != nil {
		return "", err
	}

	results, err := c.jmapCall(ctx, token, accountID, []any{
		[]any{"x:Account/set", map[string]any{
			"accountId": accountID,
			"create": map[string]any{
				"new-0": map[string]any{
					"@type": "User",
					"credentials": map[string]any{
						"0": map[string]any{"@type": "Password", "secret": password},
					},
					"domainId":         domainID,
					"encryptionAtRest": map[string]any{"@type": "Disabled"},
					"locale":           "en-US",
					"name":             username,
					"permissions":      map[string]any{"@type": "Inherit"},
					"roles":            map[string]any{"@type": "User"},
				},
			},
		}, "0"},
	})
	if err != nil {
		return "", err
	}
	var setResp struct {
		Created    map[string]struct{ ID string } `json:"created"`
		NotCreated map[string]struct {
			Description string `json:"description"`
			Type        string `json:"type"`
		} `json:"notCreated"`
	}
	if err := json.Unmarshal(results["0"], &setResp); err != nil {
		return "", err
	}
	if nc, ok := setResp.NotCreated["new-0"]; ok {
		return "", fmt.Errorf("mailaccounts: %s: %s", nc.Type, nc.Description)
	}
	created, ok := setResp.Created["new-0"]
	if !ok {
		return "", fmt.Errorf("mailaccounts: account was not created (no error given)")
	}
	return created.ID, nil
}

// ListAccounts returns every real mailbox on the domain, matching the real x:Account/query +
// x:Account/get pair the admin console itself runs to populate the Accounts list page.
func (c *Client) ListAccounts(ctx context.Context) ([]Account, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("mailaccounts: not configured")
	}
	token, err := c.authenticate(ctx)
	if err != nil {
		return nil, err
	}
	accountID, err := c.session(ctx, token)
	if err != nil {
		return nil, err
	}
	results, err := c.jmapCall(ctx, token, accountID, []any{
		[]any{"x:Account/query", map[string]any{
			"accountId": accountID, "filter": map[string]any{"@type": "User"},
			"limit": 200, "position": 0,
		}, "0"},
		[]any{"x:Account/get", map[string]any{
			"accountId":  accountID,
			"#ids":       map[string]string{"resultOf": "0", "name": "x:Account/query", "path": "/ids"},
			"properties": []string{"id", "emailAddress", "description", "createdAt"},
		}, "1"},
	})
	if err != nil {
		return nil, err
	}
	var get struct {
		List []Account `json:"list"`
	}
	if err := json.Unmarshal(results["1"], &get); err != nil {
		return nil, err
	}
	return get.List, nil
}

// Account is a real Stalwart mailbox, as returned by the management API.
type Account struct {
	ID           string `json:"id"`
	EmailAddress string `json:"emailAddress"`
	Description  string `json:"description"`
	CreatedAt    string `json:"createdAt"`
}
