package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveBareSectionID_AssignsNextFreeNumber -- S235-01: a bare "S<section>" reference gets
// resolved to the next real, actually-unused item number under that section, read from the live
// file, not guessed.
func TestResolveBareSectionID_AssignsNextFreeNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "BACKLOG.md")
	seed := "# BACKLOG\n\n## SECTION 203: TEST (2026-09-03)\n\n" +
		"- [ ] **S203-01: first.** Real body.\n" +
		"- [x] **S203-04: fourth, already exists (the real collision this fix prevents).** Real body.\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}

	got := resolveBareSectionID(path, "S203")
	if got != "S203-05" {
		t.Errorf("resolveBareSectionID(%q) = %q, want S203-05 (next after the real max, S203-04)", "S203", got)
	}
}

// TestResolveBareSectionID_EmptySectionStartsAtOne -- a section with zero existing real items
// (or one that doesn't exist yet at all) still resolves to a real, usable id.
func TestResolveBareSectionID_EmptySectionStartsAtOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "BACKLOG.md")
	if err := os.WriteFile(path, []byte("# BACKLOG\n\n## SECTION 1: OTHER (2026-09-03)\n\n- [ ] **S1-01: unrelated.** Real body.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := resolveBareSectionID(path, "S999"); got != "S999-01" {
		t.Errorf("resolveBareSectionID(%q) = %q, want S999-01", "S999", got)
	}
}

// TestResolveBareSectionID_FullIDUnchanged -- the existing, still-fully-supported path: a
// caller who already gave a specific, full id is returned completely untouched.
func TestResolveBareSectionID_FullIDUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "BACKLOG.md")
	if err := os.WriteFile(path, []byte("# BACKLOG\n\n## SECTION 203: TEST (2026-09-03)\n\n- [ ] **S203-01: x.** y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"S203-04", "GFD-SYNC", "S1-01"} {
		if got := resolveBareSectionID(path, id); got != id {
			t.Errorf("resolveBareSectionID(%q) = %q, want unchanged %q", id, got, id)
		}
	}
}

// TestResolveBareSectionID_MissingFileFallsBackToOne -- a real read failure (missing/unreadable
// file) is a best-effort fallback to "-01", not an error that blocks card creation.
func TestResolveBareSectionID_MissingFileFallsBackToOne(t *testing.T) {
	if got := resolveBareSectionID("/nonexistent/path/BACKLOG.md", "S500"); got != "S500-01" {
		t.Errorf("resolveBareSectionID with a missing file = %q, want S500-01 (honest fallback)", got)
	}
}

// TestResolveBareSectionID_ThreeDigitSuffixNotZeroPadded -- matches the real, already-live id
// shape (S202-200, this session's own found-live example) once a section's real numbering has
// grown past 99.
func TestResolveBareSectionID_ThreeDigitSuffixNotZeroPadded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "BACKLOG.md")
	if err := os.WriteFile(path, []byte("# BACKLOG\n\n## SECTION 202: TEST (2026-09-03)\n\n- [ ] **S202-99: x.** y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := resolveBareSectionID(path, "S202"); got != "S202-100" {
		t.Errorf("resolveBareSectionID(%q) = %q, want S202-100 (not zero-padded past 99)", "S202", got)
	}
}
