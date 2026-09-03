package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Sign creates an ES256 JWT with the provided claims map.
// It adds the "alg", "typ", and "kid" header fields automatically.
func Sign(k *Keys, claims map[string]any) (string, error) {
	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": k.KeyID,
	}
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	hEnc := base64.RawURLEncoding.EncodeToString(hBytes)
	cEnc := base64.RawURLEncoding.EncodeToString(cBytes)
	sigInput := hEnc + "." + cEnc

	digest := sha256.Sum256([]byte(sigInput))
	r, s, err := ecdsa.Sign(rand.Reader, k.Private, digest[:])
	if err != nil {
		return "", err
	}

	// Encode r and s as fixed-size 32-byte big-endian; concatenate for the sig.
	sig := append(padTo32(r), padTo32(s)...)
	sigEnc := base64.RawURLEncoding.EncodeToString(sig)

	return sigInput + "." + sigEnc, nil
}

// Verify parses and verifies an ES256 JWT. Returns the claims map or an error.
func Verify(k *Keys, tokenStr string) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: malformed token")
	}

	// Verify header
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad header encoding: %w", err)
	}
	var header map[string]string
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, fmt.Errorf("jwt: bad header json: %w", err)
	}
	if header["alg"] != "ES256" {
		return nil, fmt.Errorf("jwt: unexpected alg %q", header["alg"])
	}

	// Verify signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad sig encoding: %w", err)
	}
	if len(sigBytes) != 64 {
		return nil, errors.New("jwt: unexpected sig length")
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	sigInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(sigInput))

	if !ecdsa.Verify(&k.Private.PublicKey, digest[:], r, s) {
		return nil, errors.New("jwt: signature verification failed")
	}

	// Decode claims
	cBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad claims encoding: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(cBytes, &claims); err != nil {
		return nil, fmt.Errorf("jwt: bad claims json: %w", err)
	}

	// Check expiry
	if exp, ok := claims["exp"]; ok {
		var expUnix int64
		switch v := exp.(type) {
		case float64:
			expUnix = int64(v)
		case json.Number:
			expUnix, _ = v.Int64()
		}
		if expUnix > 0 && time.Now().Unix() > expUnix {
			return nil, errors.New("jwt: token expired")
		}
	}

	return claims, nil
}
