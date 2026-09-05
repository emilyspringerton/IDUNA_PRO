package mailaccounts

import "testing"

func TestEncryptDecryptSecret_RoundTrip(t *testing.T) {
	key := []byte("some-real-server-secret")
	plaintext := "correct horse battery staple"

	enc, err := EncryptSecret(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if enc == plaintext {
		t.Fatal("EncryptSecret returned plaintext unchanged")
	}

	got, err := DecryptSecret(key, enc)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}
	if got != plaintext {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptDecryptSecret_KeyMismatch(t *testing.T) {
	enc, err := EncryptSecret([]byte("key-one"), "secret")
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	if _, err := DecryptSecret([]byte("key-two"), enc); err == nil {
		t.Fatal("expected DecryptSecret to fail with the wrong key")
	}
}

func TestEncryptSecret_EmptyKey(t *testing.T) {
	if _, err := EncryptSecret(nil, "secret"); err == nil {
		t.Fatal("expected EncryptSecret to reject an empty key")
	}
}
