package mailaccounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// EncryptSecret and DecryptSecret hold the real Stalwart mailbox password an admin-provisioned
// mail_account_credentials row needs to be RETRIEVABLE (see that migration's own header comment
// for why this is a deliberate reversal of this repo's earlier "never persist a generated
// password" stance): AES-256-GCM under a server-side-only key, never plaintext at rest.
//
// The key argument is whatever raw bytes MAIL_CREDENTIALS_KEY (or its fallback) supplies -- it is
// hashed with SHA-256 first so any non-empty string works as a key regardless of its own length,
// the same normalization trick sip_accounts.go's own HMAC provisioning key relies on.
func encryptionKey(key []byte) [32]byte {
	return sha256.Sum256(key)
}

func EncryptSecret(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("encryption key is empty")
	}
	k := encryptionKey(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptSecret(key []byte, encoded string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("encryption key is empty")
	}
	k := encryptionKey(key)
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
