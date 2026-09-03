package backlog

import (
	"strings"
	"testing"
)

const sample = `# EMILY BACKLOG

## SECTION 232: GFD/MINECRAFT CHAT BRIDGE BUG + IDUNA KANBAN NAV (2026-09-02)

Founder real-time, two parts: "so the chat bridge works from minecraft..."

- [ ] **S232-01: GFD↔EINHORN_SURVIVAL chat bridge is one-directional — logged, not fixed.**
  Founder-confirmed: Minecraft chat reaches the GFD (DragonsNShit) GUI client; typing in that
  client does not reach Minecraft. Traced (not fixed) to a real, likely root cause.
- [x] **S232-02: surfaced the already-built IDUNA kanban interface in the Back Office nav.**
  Added one link to the shared nav.

## SECTION 233: PRESS-RELEASE PROVIDER/SUBTYPE (2026-09-02)

- [x] **S233-01: real SourceProvider field, end to end.** Fixed a real bug.
- [ ] **S233-04: "fix" — both real HTTP bugs fixed, webdriver now works end to end against a
  real browser.** Founder's one-word follow-up to S233-03's diagnosis.
`

func TestParse_RealShapeMultiLineTitle(t *testing.T) {
	items := Parse(sample)
	if len(items) != 4 {
		t.Fatalf("expected 4 items, got %d: %+v", len(items), items)
	}

	got := items[0]
	if got.ID != "S232-01" {
		t.Errorf("ID = %q, want S232-01", got.ID)
	}
	if got.Checked {
		t.Errorf("S232-01 should be unchecked")
	}
	if got.Section != 232 {
		t.Errorf("Section = %d, want 232", got.Section)
	}
	wantTitle := "GFD↔EINHORN_SURVIVAL chat bridge is one-directional — logged, not fixed."
	if got.Title != wantTitle {
		t.Errorf("Title = %q, want %q", got.Title, wantTitle)
	}

	if !items[1].Checked {
		t.Errorf("S232-02 should be checked")
	}

	// S233-04's own real, multi-line bold title (the exact shape that
	// motivated the (?s) non-greedy regex in the first place).
	last := items[3]
	if last.ID != "S233-04" {
		t.Fatalf("ID = %q, want S233-04", last.ID)
	}
	if last.Section != 233 {
		t.Errorf("Section = %d, want 233", last.Section)
	}
	wantLast := `"fix" — both real HTTP bugs fixed, webdriver now works end to end against a real browser.`
	if last.Title != wantLast {
		t.Errorf("Title = %q, want %q", last.Title, wantLast)
	}
}

func TestParse_NoSectionHeadingYieldsZero(t *testing.T) {
	items := Parse("- [ ] **S1-01: no section above this line.**\n")
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Section != 0 {
		t.Errorf("Section = %d, want 0 (no heading seen yet)", items[0].Section)
	}
}

func TestByID(t *testing.T) {
	items := Parse(sample)
	idx := ByID(items)
	if _, ok := idx["S232-01"]; !ok {
		t.Fatalf("expected S232-01 in index")
	}
	if idx["S233-01"].Title == "" {
		t.Errorf("expected a real title for S233-01")
	}
	if _, ok := idx["S999-99"]; ok {
		t.Errorf("did not expect a match for a nonexistent id")
	}
}

// TestParse_NonNumericID -- real, live-found bug (2026-09-02): the item
// regex used to require S\d+-\d+, silently never matching a real,
// already-live id like "GFD-SYNC" (a real founder-created kanban card).
func TestParse_NonNumericID(t *testing.T) {
	items := Parse("- [ ] **GFD-SYNC: sync REDGARDEN tech into GFD.** Real body.\n")
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].ID != "GFD-SYNC" {
		t.Errorf("ID = %q, want GFD-SYNC", items[0].ID)
	}
	idx := ByID(items)
	if _, ok := idx["GFD-SYNC"]; !ok {
		t.Errorf("expected GFD-SYNC to be findable via ByID")
	}
	if _, _, _, found := ExtractItemRaw("- [ ] **GFD-SYNC: sync REDGARDEN tech into GFD.** Real body.\n", "GFD-SYNC"); !found {
		t.Errorf("expected GFD-SYNC to be findable via ExtractItemRaw")
	}
}

func TestExtractItemRaw_MultiLineTitleStopsAtNextItem(t *testing.T) {
	raw, start, end, found := ExtractItemRaw(sample, "S233-04")
	if !found {
		t.Fatalf("expected to find S233-04")
	}
	if !strings.HasPrefix(raw, `- [ ] **S233-04:`) {
		t.Errorf("raw should start with the item's own line, got: %q", raw)
	}
	if !strings.Contains(raw, "real browser.") {
		t.Errorf("raw should include the item's own real continuation line, got: %q", raw)
	}
	if sample[start:end] != raw {
		t.Errorf("start/end offsets don't match the returned raw text")
	}
	// S233-04 is the last item in the sample, so its raw span should run to
	// the real end of the file.
	if end != len(sample) {
		t.Errorf("expected end == len(sample) (last item, no trailing section), got end=%d len=%d", end, len(sample))
	}
}

func TestExtractItemRaw_StopsAtNextSectionHeading(t *testing.T) {
	raw, _, _, found := ExtractItemRaw(sample, "S232-02")
	if !found {
		t.Fatalf("expected to find S232-02")
	}
	if strings.Contains(raw, "SECTION 233") {
		t.Errorf("raw should stop before the next section heading, got: %q", raw)
	}
	if strings.Contains(raw, "S233-01") {
		t.Errorf("raw should not bleed into the next section's own item, got: %q", raw)
	}
}

func TestExtractItemRaw_NotFound(t *testing.T) {
	if _, _, _, found := ExtractItemRaw(sample, "S999-99"); found {
		t.Errorf("expected not found for a nonexistent id")
	}
}

func TestParseFile_MissingFileIsRealError(t *testing.T) {
	if _, err := ParseFile("/nonexistent/path/BACKLOG.md"); err == nil {
		t.Errorf("expected a real error for a missing file, got nil")
	}
}
