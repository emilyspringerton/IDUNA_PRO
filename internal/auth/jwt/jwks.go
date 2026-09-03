package jwt

import (
	"encoding/base64"
	"math/big"
)

// JWKS returns the JWK Set representation of the public key as a plain Go map
// ready for JSON encoding.
func (k *Keys) JWKS() map[string]any {
	pub := &k.Private.PublicKey

	// P-256 field size is 32 bytes; pad to full width.
	xBytes := padTo32(pub.X)
	yBytes := padTo32(pub.Y)

	key := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
		"kid": k.KeyID,
		"use": "sig",
		"alg": "ES256",
	}
	return map[string]any{
		"keys": []any{key},
	}
}

func padTo32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
