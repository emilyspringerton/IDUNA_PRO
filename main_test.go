package main

import (
	"os"
	"path/filepath"
	"testing"

	"idunapro/internal/mailinglist"
)

// TestMailingListAutoUnlock_FirstBootGeneratesAndUnlocks -- S245-01's real
// "just works with no operator" guarantee: on a brand-new store, the helper
// generates a key, persists it to the key file, initializes the vault, and
// ends with the vault unlocked in-process.
func TestMailingListAutoUnlock_FirstBootGeneratesAndUnlocks(t *testing.T) {
	dir := t.TempDir()
	store, err := mailinglist.Open(filepath.Join(dir, "mailinglist.db"))
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer store.Close()

	keyPath := filepath.Join(dir, "mailinglist.key")
	v := mailinglist.NewVault()

	if err := mailingListAutoUnlock(store, v, keyPath); err != nil {
		t.Fatalf("mailingListAutoUnlock: %v", err)
	}
	if v.Locked() {
		t.Fatal("expected vault to be unlocked after first-boot auto-unlock")
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file to be written: %v", err)
	}
}

// TestMailingListAutoUnlock_RebootReusesExistingKeyFile -- a second process
// start against an already-initialized store must reuse the existing key
// file (never regenerate one, which would permanently orphan already-stored
// subscriber ciphertext) and still end up unlocked.
func TestMailingListAutoUnlock_RebootReusesExistingKeyFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mailinglist.db")
	keyPath := filepath.Join(dir, "mailinglist.key")

	store, err := mailinglist.Open(dbPath)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	v1 := mailinglist.NewVault()
	if err := mailingListAutoUnlock(store, v1, keyPath); err != nil {
		t.Fatalf("first boot: %v", err)
	}
	keyFileContents, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file after first boot: %v", err)
	}
	store.Close()

	// Simulate a restart: fresh Store handle over the same file, fresh Vault.
	store2, err := mailinglist.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer store2.Close()
	v2 := mailinglist.NewVault()
	if err := mailingListAutoUnlock(store2, v2, keyPath); err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if v2.Locked() {
		t.Fatal("expected vault to be unlocked after reboot auto-unlock")
	}
	keyFileContentsAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file after second boot: %v", err)
	}
	if string(keyFileContents) != string(keyFileContentsAfter) {
		t.Fatal("key file must not be regenerated on an already-initialized store")
	}
}
