package google

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const googleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// GoogleClaims holds the fields we extract from a verified Google ID token.
type GoogleClaims struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

// jwkCache caches the Google public key set with a 1-hour TTL.
var jwkCache struct {
	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetchAt time.Time
}

// Verify verifies a Google ID token and returns the parsed claims.
// If googleClientID is empty, the aud check is skipped (useful in dev).
func Verify(ctx context.Context, idToken string, googleClientID string) (*GoogleClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("google: malformed id_token")
	}

	// Decode header to get kid and alg.
	hBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("google: bad header encoding: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, fmt.Errorf("google: bad header json: %w", err)
	}

	keys, err := getGoogleKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("google: fetching certs: %w", err)
	}
	pubKey, ok := keys[header.Kid]
	if !ok {
		return nil, fmt.Errorf("google: no key found for kid %q", header.Kid)
	}

	// Verify signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("google: bad sig encoding: %w", err)
	}
	sigInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(sigInput))
	if err := rsa.VerifyPKCS1v15(pubKey, 0x04, digest[:], sigBytes); err != nil {
		return nil, fmt.Errorf("google: signature invalid: %w", err)
	}

	// Decode claims.
	cBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("google: bad claims encoding: %w", err)
	}
	var raw struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Iss           string `json:"iss"`
		Aud           any    `json:"aud"`
		Exp           int64  `json:"exp"`
	}
	if err := json.Unmarshal(cBytes, &raw); err != nil {
		return nil, fmt.Errorf("google: bad claims json: %w", err)
	}

	// Validate expiry.
	if time.Now().Unix() > raw.Exp {
		return nil, errors.New("google: id_token expired")
	}

	// Validate issuer.
	validIssuers := map[string]bool{
		"accounts.google.com":         true,
		"https://accounts.google.com": true,
	}
	if !validIssuers[raw.Iss] {
		return nil, fmt.Errorf("google: unexpected issuer %q", raw.Iss)
	}

	// Validate audience if a client ID is configured.
	if googleClientID != "" {
		if !audMatches(raw.Aud, googleClientID) {
			return nil, fmt.Errorf("google: aud mismatch")
		}
	}

	return &GoogleClaims{
		Sub:           raw.Sub,
		Email:         raw.Email,
		EmailVerified: raw.EmailVerified,
		Name:          raw.Name,
	}, nil
}

func audMatches(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// getGoogleKeys returns cached RSA public keys, refreshing every hour.
func getGoogleKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	jwkCache.mu.Lock()
	defer jwkCache.mu.Unlock()

	if jwkCache.keys != nil && time.Since(jwkCache.fetchAt) < time.Hour {
		return jwkCache.keys, nil
	}

	keys, err := fetchGoogleKeys(ctx)
	if err != nil {
		return nil, err
	}
	jwkCache.keys = keys
	jwkCache.fetchAt = time.Now()
	return keys, nil
}

func fetchGoogleKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleCertsURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}

	out := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		out[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}
	return out, nil
}
