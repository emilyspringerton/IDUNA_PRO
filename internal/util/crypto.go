package util

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode"
)

const crockfordAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"

func SHA256Bytes(in []byte) [32]byte {
	return sha256.Sum256(in)
}

func Base64URLRandom(nbytes int) (string, error) {
	buf := make([]byte, nbytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func NormalizeUserCode(input string) string {
	var b strings.Builder
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

func GenerateUserCode() (display string, normalized string, err error) {
	const partLen = 4
	raw := make([]byte, partLen*2)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	makeChar := func(v byte) byte { return crockfordAlphabet[int(v)%len(crockfordAlphabet)] }
	left := []byte{makeChar(raw[0]), makeChar(raw[1]), makeChar(raw[2]), makeChar(raw[3])}
	right := []byte{makeChar(raw[4]), makeChar(raw[5]), makeChar(raw[6]), makeChar(raw[7])}
	display = string(left) + "-" + string(right)
	normalized = NormalizeUserCode(display)
	return
}
