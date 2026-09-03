package store_test

import (
	"testing"

	"idunapro/internal/util"
)

// TestUUIDFormat verifies the UUID generator used by the IAM store produces
// valid v4 UUID strings.
func TestUUIDFormat(t *testing.T) {
	id, err := util.NewUUID()
	if err != nil {
		t.Fatalf("NewUUID: %v", err)
	}
	if len(id) != 36 {
		t.Errorf("expected UUID length 36, got %d: %q", len(id), id)
	}
	// Verify the version nibble (position 14) is '4'
	if id[14] != '4' {
		t.Errorf("expected version 4 at position 14, got %q in %q", id[14], id)
	}
	// Verify the variant nibble (position 19) is '8', '9', 'a', or 'b'
	v := id[19]
	if v != '8' && v != '9' && v != 'a' && v != 'b' {
		t.Errorf("expected RFC 4122 variant at position 19, got %q in %q", v, id)
	}
}

func TestUUIDUniqueness(t *testing.T) {
	seen := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		id, err := util.NewUUID()
		if err != nil {
			t.Fatalf("NewUUID: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate UUID generated: %q", id)
		}
		seen[id] = true
	}
}
