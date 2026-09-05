package mailinglist

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVault_WrongPassphraseRejected(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	ct, nonce, err := NewCanary("correct horse battery staple", salt)
	if err != nil {
		t.Fatalf("NewCanary: %v", err)
	}

	v := NewVault()
	if !v.Locked() {
		t.Fatal("expected new vault to be locked")
	}

	if err := v.Unlock("wrong passphrase", salt, ct, nonce); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
	if !v.Locked() {
		t.Fatal("vault must stay locked after a failed unlock attempt")
	}
}

func TestVault_CorrectPassphraseUnlocksAndRoundtrips(t *testing.T) {
	salt, _ := NewSalt()
	ct, nonce, err := NewCanary("correct horse battery staple", salt)
	if err != nil {
		t.Fatalf("NewCanary: %v", err)
	}

	v := NewVault()
	if err := v.Unlock("correct horse battery staple", salt, ct, nonce); err != nil {
		t.Fatalf("Unlock with correct passphrase failed: %v", err)
	}
	if v.Locked() {
		t.Fatal("expected vault to be unlocked")
	}

	email := []byte("test@example.com")
	ciphertext, nonce2, err := v.Encrypt(email)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := v.Decrypt(ciphertext, nonce2)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != string(email) {
		t.Fatalf("roundtrip mismatch: got %q want %q", plain, email)
	}
}

func TestVault_EncryptFailsWhenLocked(t *testing.T) {
	v := NewVault()
	if _, _, err := v.Encrypt([]byte("x")); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
	if _, err := v.Decrypt([]byte("x"), []byte("y")); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestVault_LockDiscardsKey(t *testing.T) {
	salt, _ := NewSalt()
	ct, nonce, _ := NewCanary("pw", salt)

	v := NewVault()
	if err := v.Unlock("pw", salt, ct, nonce); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	v.Lock()
	if !v.Locked() {
		t.Fatal("expected vault to be locked after Lock()")
	}
	if _, _, err := v.Encrypt([]byte("x")); err != ErrLocked {
		t.Fatalf("expected ErrLocked after Lock(), got %v", err)
	}
}

// TestVault_UnlockFromKeyFile -- S245-01's real, core guarantee: a key read
// from a file unlocks exactly like a correct passphrase does, and a wrong
// key file is rejected the same way a wrong passphrase is (ErrWrongPassword,
// vault stays locked) -- no separate error type for callers to special-case.
func TestVault_UnlockFromKeyFile(t *testing.T) {
	key, err := NewFileKey()
	if err != nil {
		t.Fatalf("NewFileKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected a 32-byte key, got %d bytes", len(key))
	}
	ct, nonce, err := NewCanaryFromKey(key)
	if err != nil {
		t.Fatalf("NewCanaryFromKey: %v", err)
	}

	keyPath := filepath.Join(t.TempDir(), "mailinglist.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	v := NewVault()
	if err := v.UnlockFromKeyFile(keyPath, ct, nonce); err != nil {
		t.Fatalf("UnlockFromKeyFile with correct key failed: %v", err)
	}
	if v.Locked() {
		t.Fatal("expected vault to be unlocked")
	}

	email := []byte("test@example.com")
	ciphertext, encNonce, err := v.Encrypt(email)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := v.Decrypt(ciphertext, encNonce)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != string(email) {
		t.Fatalf("roundtrip mismatch: got %q want %q", plain, email)
	}
}

// TestVault_UnlockFromKeyFile_WrongKeyRejected -- a key file that doesn't
// match the stored canary must be rejected, not silently accepted into a
// vault that would then produce garbage on every real encrypt/decrypt.
func TestVault_UnlockFromKeyFile_WrongKeyRejected(t *testing.T) {
	realKey, _ := NewFileKey()
	ct, nonce, err := NewCanaryFromKey(realKey)
	if err != nil {
		t.Fatalf("NewCanaryFromKey: %v", err)
	}

	wrongKey, _ := NewFileKey()
	keyPath := filepath.Join(t.TempDir(), "mailinglist.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(wrongKey)), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	v := NewVault()
	if err := v.UnlockFromKeyFile(keyPath, ct, nonce); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword for a mismatched key file, got %v", err)
	}
	if !v.Locked() {
		t.Fatal("vault must stay locked after a failed key-file unlock attempt")
	}
}

// TestStore_InitVault_KeyFileMode -- file-key mode stores an empty salt
// (unused, since there's no Argon2 derivation) rather than skipping the
// column, so InitVault/VaultMeta stay a single shared code path for both
// unlock modes.
func TestStore_InitVault_KeyFileMode(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	key, _ := NewFileKey()
	ct, nonce, err := NewCanaryFromKey(key)
	if err != nil {
		t.Fatalf("NewCanaryFromKey: %v", err)
	}
	if err := s.InitVault([]byte{}, ct, nonce); err != nil {
		t.Fatalf("InitVault with empty salt should succeed: %v", err)
	}

	gotSalt, gotCT, gotNonce, err := s.VaultMeta()
	if err != nil {
		t.Fatalf("VaultMeta: %v", err)
	}
	if len(gotSalt) != 0 {
		t.Errorf("expected empty salt in key-file mode, got %d bytes", len(gotSalt))
	}
	if string(gotCT) != string(ct) || string(gotNonce) != string(nonce) {
		t.Error("canary ciphertext/nonce round-trip mismatch")
	}
}

// TestStore_ListForExport -- S245-02's real read path: rows come back in
// insertion order, ciphertext untouched (this method never decrypts).
func TestStore_ListForExport(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	id1, err := s.AddSubscriber([]byte("ct1"), []byte("n1"), "v1", "general")
	if err != nil {
		t.Fatalf("AddSubscriber 1: %v", err)
	}
	id2, err := s.AddSubscriber([]byte("ct2"), []byte("n2"), "v1", "stinkies")
	if err != nil {
		t.Fatalf("AddSubscriber 2: %v", err)
	}
	if err := s.MarkMailchimpSynced(id1); err != nil {
		t.Fatalf("MarkMailchimpSynced: %v", err)
	}

	records, err := s.ListForExport()
	if err != nil {
		t.Fatalf("ListForExport: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].ID != id1 || string(records[0].EmailCiphertext) != "ct1" || !records[0].MailchimpSynced {
		t.Errorf("record 0 mismatch: %+v", records[0])
	}
	if records[1].ID != id2 || string(records[1].EmailCiphertext) != "ct2" || records[1].Source != "stinkies" || records[1].MailchimpSynced {
		t.Errorf("record 1 mismatch: %+v", records[1])
	}
}

// TestStore_MailchimpSettings_NotConfiguredByDefault -- S245-03's real
// backward-compatible starting state: a brand-new store has no stored
// settings, so callers fall back to the env-var-configured client.
func TestStore_MailchimpSettings_NotConfiguredByDefault(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	_, _, _, _, ok, err := s.MailchimpSettings()
	if err != nil {
		t.Fatalf("MailchimpSettings: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false on a brand-new store")
	}
}

// TestStore_SetMailchimpSettings_RoundtripsAndUpserts -- a second Set call
// replaces the first (single-row config), not appends.
func TestStore_SetMailchimpSettings_RoundtripsAndUpserts(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if err := s.SetMailchimpSettings([]byte("key1-ct"), []byte("key1-n"), []byte("list1-ct"), []byte("list1-n")); err != nil {
		t.Fatalf("SetMailchimpSettings 1: %v", err)
	}
	apiKeyCT, _, listIDCT, _, ok, err := s.MailchimpSettings()
	if err != nil || !ok {
		t.Fatalf("MailchimpSettings after first set: ok=%v err=%v", ok, err)
	}
	if string(apiKeyCT) != "key1-ct" || string(listIDCT) != "list1-ct" {
		t.Fatalf("unexpected first-set values: apiKeyCT=%q listIDCT=%q", apiKeyCT, listIDCT)
	}

	if err := s.SetMailchimpSettings([]byte("key2-ct"), []byte("key2-n"), []byte("list2-ct"), []byte("list2-n")); err != nil {
		t.Fatalf("SetMailchimpSettings 2: %v", err)
	}
	apiKeyCT2, _, listIDCT2, _, ok2, err := s.MailchimpSettings()
	if err != nil || !ok2 {
		t.Fatalf("MailchimpSettings after second set: ok=%v err=%v", ok2, err)
	}
	if string(apiKeyCT2) != "key2-ct" || string(listIDCT2) != "list2-ct" {
		t.Fatalf("expected second set to replace the first, got apiKeyCT=%q listIDCT=%q", apiKeyCT2, listIDCT2)
	}
}

func TestStore_InitVaultRefusesDoubleInit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	salt, _ := NewSalt()
	ct, nonce, _ := NewCanary("pw", salt)

	if err := s.InitVault(salt, ct, nonce); err != nil {
		t.Fatalf("first InitVault should succeed: %v", err)
	}
	if err := s.InitVault(salt, ct, nonce); err == nil {
		t.Fatal("expected second InitVault to be refused (would orphan existing data)")
	}
}

func TestStore_AddSubscriberAndMarkSynced(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	id, err := s.AddSubscriber([]byte("ciphertext"), []byte("nonce"), "v1", "general")
	if err != nil {
		t.Fatalf("AddSubscriber: %v", err)
	}
	if err := s.MarkMailchimpSynced(id); err != nil {
		t.Fatalf("MarkMailchimpSynced: %v", err)
	}
}

func TestStore_AddSubscriber_SourceDefaultsToGeneral(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	id, err := s.AddSubscriber([]byte("ciphertext"), []byte("nonce"), "v1", "")
	if err != nil {
		t.Fatalf("AddSubscriber: %v", err)
	}
	var source string
	if err := s.db.QueryRow(`SELECT source FROM subscribers WHERE id = ?`, id).Scan(&source); err != nil {
		t.Fatalf("query source: %v", err)
	}
	if source != "general" {
		t.Errorf("source = %q, want %q", source, "general")
	}
}

func TestStore_AddSubscriber_CustomSource(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir + "/test.db")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	id, err := s.AddSubscriber([]byte("ciphertext"), []byte("nonce"), "v1", "stinkies")
	if err != nil {
		t.Fatalf("AddSubscriber: %v", err)
	}
	var source string
	if err := s.db.QueryRow(`SELECT source FROM subscribers WHERE id = ?`, id).Scan(&source); err != nil {
		t.Fatalf("query source: %v", err)
	}
	if source != "stinkies" {
		t.Errorf("source = %q, want %q", source, "stinkies")
	}
}
