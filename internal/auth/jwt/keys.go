package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"os"
)

const defaultKID = "iduna-key-01"

// Keys holds an ECDSA P-256 key pair and the key ID used in JWT headers.
type Keys struct {
	Private *ecdsa.PrivateKey
	KeyID   string
}

// GenerateKeys creates a new P-256 key pair with kid "iduna-key-01".
func GenerateKeys() (*Keys, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keys{Private: priv, KeyID: defaultKID}, nil
}

// LoadOrGenerateKeys loads keys from a JSON file at path. If the file does
// not exist, it generates a new key and persists it.
func LoadOrGenerateKeys(path string) (*Keys, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		k, err := GenerateKeys()
		if err != nil {
			return nil, err
		}
		if err := saveKeys(path, k); err != nil {
			return nil, err
		}
		return k, nil
	}
	return loadKeys(path)
}

// serialisedKey is the on-disk JSON format.
type serialisedKey struct {
	KID string `json:"kid"`
	D   string `json:"d"` // big-endian hex of private scalar
	X   string `json:"x"` // big-endian hex of public X
	Y   string `json:"y"` // big-endian hex of public Y
}

func saveKeys(path string, k *Keys) error {
	sk := serialisedKey{
		KID: k.KeyID,
		D:   k.Private.D.Text(16),
		X:   k.Private.PublicKey.X.Text(16),
		Y:   k.Private.PublicKey.Y.Text(16),
	}
	b, err := json.MarshalIndent(sk, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func loadKeys(path string) (*Keys, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sk serialisedKey
	if err := json.Unmarshal(b, &sk); err != nil {
		return nil, err
	}
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
	}
	priv.D = new(big.Int)
	priv.D.SetString(sk.D, 16)
	priv.PublicKey.X = new(big.Int)
	priv.PublicKey.X.SetString(sk.X, 16)
	priv.PublicKey.Y = new(big.Int)
	priv.PublicKey.Y.SetString(sk.Y, 16)
	kid := sk.KID
	if kid == "" {
		kid = defaultKID
	}
	return &Keys{Private: priv, KeyID: kid}, nil
}
