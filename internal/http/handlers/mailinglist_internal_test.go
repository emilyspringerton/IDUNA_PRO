package handlers

import (
	"testing"

	"idunapro/internal/mailinglist"
)

// TestResolveMailchimpClient_NoStoredSettingsFallsBackToEnvConfig -- S245-03
// must never break EINHORN's own (or any tenant's) existing env-var-only
// setup: with nothing stored, the env-configured h.Mailchimp is returned
// unchanged.
func TestResolveMailchimpClient_NoStoredSettingsFallsBackToEnvConfig(t *testing.T) {
	store, err := mailinglist.Open(t.TempDir() + "/mailinglist.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	vault := mailinglist.NewVault()
	salt, _ := mailinglist.NewSalt()
	ct, nonce, _ := mailinglist.NewCanary("pw", salt)
	if err := store.InitVault(salt, ct, nonce); err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	if err := vault.Unlock("pw", salt, ct, nonce); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	envClient := mailinglist.NewMailchimpClient("env-key-us1", "env-list")
	h := &MailingListHandler{Store: store, Vault: vault, Mailchimp: envClient}

	got := h.resolveMailchimpClient()
	if got != envClient {
		t.Fatalf("expected the env-configured client back, got %+v", got)
	}
}

// TestResolveMailchimpClient_StoredSettingsTakePriority -- the real S245-03
// guarantee: once an admin sets per-instance settings, they win over
// whatever env var configured the instance at startup.
func TestResolveMailchimpClient_StoredSettingsTakePriority(t *testing.T) {
	store, err := mailinglist.Open(t.TempDir() + "/mailinglist.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	vault := mailinglist.NewVault()
	salt, _ := mailinglist.NewSalt()
	ct, nonce, _ := mailinglist.NewCanary("pw", salt)
	if err := store.InitVault(salt, ct, nonce); err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	if err := vault.Unlock("pw", salt, ct, nonce); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	apiKeyCT, apiKeyNonce, _ := vault.Encrypt([]byte("stored-key-us5"))
	listIDCT, listIDNonce, _ := vault.Encrypt([]byte("stored-list"))
	if err := store.SetMailchimpSettings(apiKeyCT, apiKeyNonce, listIDCT, listIDNonce); err != nil {
		t.Fatalf("SetMailchimpSettings: %v", err)
	}

	h := &MailingListHandler{Store: store, Vault: vault, Mailchimp: mailinglist.NewMailchimpClient("env-key-us1", "env-list")}

	got := h.resolveMailchimpClient()
	if got == nil || got.APIKey != "stored-key-us5" || got.ListID != "stored-list" {
		t.Fatalf("expected stored settings to win, got %+v", got)
	}
}

// TestResolveMailchimpClient_LockedVaultFallsBackToEnvConfig -- if the
// vault is locked, stored (encrypted) settings can't be read at all --
// must fall back rather than error out or silently drop Mailchimp sync
// when a working env-configured client already exists.
func TestResolveMailchimpClient_LockedVaultFallsBackToEnvConfig(t *testing.T) {
	store, err := mailinglist.Open(t.TempDir() + "/mailinglist.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	// Populate settings while briefly unlocked, then lock again to simulate
	// a restart that hasn't been re-unlocked yet.
	vault := mailinglist.NewVault()
	salt, _ := mailinglist.NewSalt()
	ct, nonce, _ := mailinglist.NewCanary("pw", salt)
	if err := store.InitVault(salt, ct, nonce); err != nil {
		t.Fatalf("InitVault: %v", err)
	}
	if err := vault.Unlock("pw", salt, ct, nonce); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	apiKeyCT, apiKeyNonce, _ := vault.Encrypt([]byte("stored-key"))
	listIDCT, listIDNonce, _ := vault.Encrypt([]byte("stored-list"))
	if err := store.SetMailchimpSettings(apiKeyCT, apiKeyNonce, listIDCT, listIDNonce); err != nil {
		t.Fatalf("SetMailchimpSettings: %v", err)
	}
	vault.Lock()

	envClient := mailinglist.NewMailchimpClient("env-key-us1", "env-list")
	h := &MailingListHandler{Store: store, Vault: vault, Mailchimp: envClient}

	got := h.resolveMailchimpClient()
	if got != envClient {
		t.Fatalf("expected fallback to env-configured client while locked, got %+v", got)
	}
}
