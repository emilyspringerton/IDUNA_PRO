// Package backlog is a real, mechanical, read-time parser over
// EMILY/BACKLOG.md -- the golden, git-authoritative backlog file every repo's
// own CLAUDE.md already points at. It exists to bridge the kanban
// prioritization layer (internal/http/handlers/kanban.go) to the real,
// current contents of that file (founder real-time, 2026-09-02: "get the
// backlog working with the kanban" -- the kanban board and its cards were
// real but completely disconnected from the actual backlog text; cards had
// to be hand-typed with no live connection at all).
//
// Design, matching this session's own real event-sourcing precedent
// (PARENA's stdlib/log/jsonl.prn + projector.prn, shipped the same session):
// BACKLOG.md's own git history is the real event log; this package is a
// cheap, rebuildable, read-time PROJECTION over it, not a second store.
// kanban_cards (kanban.go's own real table) still only ever tracks
// queue+position by backlog_item_id -- BACKLOG.md itself stays the one
// authoritative source of an item's actual title/checked-state, exactly as
// kanban.go's own doc comment already states. Nothing here writes to
// BACKLOG.md or duplicates its content into a database.
package backlog

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Item is one real "- [ ] **S###-##: title...**" line found in BACKLOG.md,
// tagged with the "## SECTION N: ..." heading it falls under.
type Item struct {
	ID           string `json:"id"`            // e.g. "S233-01"
	Title        string `json:"title"`         // the bold summary text, whitespace-normalized (may have spanned multiple real lines)
	Checked      bool   `json:"checked"`       // true for "- [x]", false for "- [ ]"
	Section      int    `json:"section"`       // e.g. 233; 0 if the item appears before any "## SECTION" heading
	SectionTitle string `json:"section_title"` // the section heading's own trailing text
	Line         int    `json:"line"`          // 1-indexed line number of the "- [ ]"/"- [x]" line itself
}

var (
	sectionRe = regexp.MustCompile(`(?m)^## SECTION (\d+): (.*)$`)
	// (?s) so the bold title can span multiple real lines (a common real
	// shape in this file -- a long summary wraps well before the closing
	// **), matched non-greedily up to the FIRST closing "**".
	//
	// The id group used to be hardcoded `S\d+-\d+` -- found live,
	// load-bearing, 2026-09-02 (a real completion attempt against a real
	// kanban-created item silently failed to find its own real,
	// just-written BACKLOG.md line): a real, already-live id,
	// `GFD-SYNC` (a real card the founder created via the kanban UI, not a
	// synthetic test), doesn't match `S\d+-\d+` at all -- it was NEVER
	// findable by ByID/ExtractItemRaw, which also means
	// syncNewItemToBacklogGitIfMissing's own "already exists" check always
	// silently reported false for it, a real, latent duplicate-append risk
	// for the exact next time a card for that same id got created. Widened
	// to any identifier starting with a letter and continuing with
	// letters/digits/underscore/hyphen up to the real ":" boundary --
	// matches every real id shape actually seen in this file (`S202-27`,
	// `S233-04`, `GFD-SYNC`, `S1-01`) without being so permissive it could
	// swallow real title text.
	itemRe = regexp.MustCompile(`(?ms)^- \[([ xX])\] \*\*([A-Za-z][A-Za-z0-9_-]*):\s*(.*?)\*\*`)
)

// ParseFile reads path and parses it. A missing/unreadable file is a real
// error, not a silently-empty result -- callers (the kanban inbox endpoint)
// should surface that rather than pretend the backlog is empty.
func ParseFile(path string) ([]Item, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(string(data)), nil
}

// Parse scans text for every real item line, in file order.
func Parse(text string) []Item {
	lineForOffset := newLineIndex(text)

	type sectionMark struct {
		offset int
		num    int
		title  string
	}
	var sections []sectionMark
	for _, m := range sectionRe.FindAllStringSubmatchIndex(text, -1) {
		n, _ := strconv.Atoi(text[m[2]:m[3]])
		sections = append(sections, sectionMark{
			offset: m[0],
			num:    n,
			title:  strings.TrimSpace(text[m[4]:m[5]]),
		})
	}
	sectionFor := func(off int) (int, string) {
		num, title := 0, ""
		for _, s := range sections {
			if s.offset > off {
				break
			}
			num, title = s.num, s.title
		}
		return num, title
	}

	var items []Item
	for _, m := range itemRe.FindAllStringSubmatchIndex(text, -1) {
		checked := strings.ToLower(text[m[2]:m[3]]) == "x"
		id := text[m[4]:m[5]]
		title := normalizeWhitespace(text[m[6]:m[7]])
		sec, secTitle := sectionFor(m[0])
		items = append(items, Item{
			ID:           id,
			Title:        title,
			Checked:      checked,
			Section:      sec,
			SectionTitle: secTitle,
			Line:         lineForOffset(m[0]),
		})
	}
	return items
}

// ExtractItemRaw returns the exact, real raw text span for the item with
// the given id -- from its own "- [ ]"/"- [x]" line through (but not
// including) whatever comes next: the next real item, the next real
// "## SECTION" heading, or end of file, whichever is earliest. A real,
// mechanical "cut precisely this one item's own block, continuation lines
// and all" operation -- used by the kanban "move to done" action
// (2026-09-02, founder real-time: "it should be moved to a different
// section of the backlog for archive") to relocate an item's own complete
// real text rather than just flipping its checkbox in place.
func ExtractItemRaw(text, id string) (raw string, start int, end int, found bool) {
	itemMatches := itemRe.FindAllStringSubmatchIndex(text, -1)
	sectionMatches := sectionRe.FindAllStringIndex(text, -1)
	for i, m := range itemMatches {
		if text[m[4]:m[5]] != id {
			continue
		}
		start = m[0]
		end = len(text)
		if i+1 < len(itemMatches) {
			end = itemMatches[i+1][0]
		}
		for _, sm := range sectionMatches {
			if sm[0] > start && sm[0] < end {
				end = sm[0]
			}
		}
		return text[start:end], start, end, true
	}
	return "", 0, 0, false
}

// ByID indexes items by ID for O(1) lookup (e.g. joining a kanban card's
// own backlog_item_id against the live parse to show its real current
// title/checked-state). A duplicate ID (shouldn't happen in a real,
// well-formed BACKLOG.md) keeps the LAST occurrence, matching this file's
// own established "later entry wins" convention elsewhere (docindex.go).
func ByID(items []Item) map[string]Item {
	out := make(map[string]Item, len(items))
	for _, it := range items {
		out[it.ID] = it
	}
	return out
}

func normalizeWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// newLineIndex returns a function mapping a byte offset into text to its
// 1-indexed line number, via one upfront O(n) scan + binary search per
// query -- avoids an O(n) re-scan per item on a ~million-character real
// file.
func newLineIndex(text string) func(offset int) int {
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return func(offset int) int {
		i := sort.SearchInts(starts, offset+1) - 1
		if i < 0 {
			i = 0
		}
		return i + 1
	}
}
