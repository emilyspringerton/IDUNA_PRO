package util

import (
	"crypto/rand"
	"fmt"
)

// NewUUID generates a random UUID v4 using crypto/rand.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Set version 4 bits (bits 12-15 of byte 6)
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits (bits 6-7 of byte 8)
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
