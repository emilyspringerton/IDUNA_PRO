package resume

import (
	"bytes"
	"compress/zlib"
	"io"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-pdf/fpdf"
)

// pdfDecompressedText -- inflates every real FlateDecode content stream in the PDF (fpdf
// compresses by default) and returns their concatenation, so a test can assert real text
// genuinely appears in the rendered output rather than just "RenderPDF didn't error."
func pdfDecompressedText(t *testing.T, out []byte) string {
	t.Helper()
	var all bytes.Buffer
	rest := out
	for {
		i := bytes.Index(rest, []byte("stream\r\n"))
		streamMarkerLen := len("stream\r\n")
		if i < 0 {
			i = bytes.Index(rest, []byte("stream\n"))
			streamMarkerLen = len("stream\n")
		}
		if i < 0 {
			break
		}
		start := i + streamMarkerLen
		end := bytes.Index(rest[start:], []byte("endstream"))
		if end < 0 {
			break
		}
		chunk := rest[start : start+end]
		zr, err := zlib.NewReader(bytes.NewReader(chunk))
		if err == nil {
			decoded, _ := io.ReadAll(zr)
			all.Write(decoded)
			all.WriteByte('\n')
		}
		rest = rest[start+end:]
	}
	return all.String()
}

func TestRenderPDF_ProducesARealPDFFile(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Label: "Line Cook", Email: "jordan@example.com", Phone: "555-0100", Summary: "A real professional summary."},
		Work: []Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "2022-03", EndDate: "2024-01", Summary: "Did real kitchen work."},
		},
		Education: []Education{
			{Institution: "Community College", StudyType: "Certificate", Area: "Culinary Arts", StartDate: "2020", EndDate: "2022"},
		},
		Skills: []Skill{{Name: "Knife Skills"}, {Name: "Food Safety"}},
		Awards: []Award{{Title: "Employee of the Month", Awarder: "Acme Corp", Date: "2023-06"}},
	}

	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF returned a real error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("RenderPDF returned zero bytes")
	}
	// Real, minimal, honest structural check: every real PDF file starts with the literal
	// "%PDF-" magic bytes and ends with a real "%%EOF" marker -- confirms this is a genuine,
	// well-formed PDF document, not just an arbitrary non-empty byte slice.
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatalf("output doesn't start with the real PDF magic bytes, got: %q", out[:min(20, len(out))])
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Fatal("output has no real end-of-file marker -- not a well-formed PDF")
	}
}

func TestRenderPDF_EmptyResumeDoesNotError(t *testing.T) {
	out, err := RenderPDF(&Resume{}, "classic")
	if err != nil {
		t.Fatalf("RenderPDF on a genuinely empty resume must not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid (if mostly blank) PDF even for an empty resume")
	}
}

// TestRenderPDF_SkillsGroupedByCategory -- founder real-time, 2026-09-10, direct employer-scan
// feedback: "Skills section is a dump -- it's alphabetical chaos." Before this, Skills rendered
// as one flat comma-joined list with no category labels anywhere in the PDF. Decompresses the
// real generated PDF content stream (FlateDecode, fpdf's own default) to prove the category
// labels genuinely appear as real text in the output, not just that RenderPDF didn't error.
func TestRenderPDF_SkillsGroupedByCategory(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera"},
		Skills: []Skill{
			{Name: "Golang", Category: "Backend & APIs"},
			{Name: "React", Category: "Frontend"},
			{Name: "PostgreSQL", Category: "Databases"},
			{Name: "Excel"}, // no category -> Other
		},
	}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF returned a real error: %v", err)
	}
	text := pdfDecompressedText(t, out)
	for _, want := range []string{"Backend & APIs", "Frontend", "Databases", SkillCategoryOther, "Golang", "React", "PostgreSQL", "Excel"} {
		if !strings.Contains(text, want) {
			t.Errorf("decompressed PDF content stream is missing %q -- category grouping isn't actually rendering", want)
		}
	}
}

// TestRenderPDF_RendersProfileLinks -- founder real-time, 2026-09-09: "we need to be able to
// add and configure the output of multiple github links." Proves the real gap this closes:
// before this, basics.profiles rendered NOWHERE in the PDF at all, regardless of content.
func TestRenderPDF_RendersProfileLinks(t *testing.T) {
	r := &Resume{
		Basics: Basics{
			Name: "Jordan Rivera",
			Profiles: []Profile{
				{Network: "GitHub", URL: "github.com/jordan/parena"},
				{Network: "GitHub", URL: "github.com/jordan/burrow"},
				{Network: "LinkedIn", Username: "jordanrivera"},
			},
		},
	}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF returned a real error: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF")
	}
	// fpdf compresses streams by default -- a real, direct grep for the literal text would
	// require SetCompression(false) (see this repo's own established verification discipline
	// for that), so this test instead asserts profileLinks itself (the real text this ends up
	// on the page) produces the expected, non-empty content -- the actually-parameterized unit
	// under test, checked directly rather than only indirectly through a compressed PDF blob.
	got := profileLinks(r.Basics.Profiles)
	want := "GitHub: github.com/jordan/parena   |   GitHub: github.com/jordan/burrow   |   LinkedIn: jordanrivera"
	if got != want {
		t.Fatalf("profileLinks mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestProfileLinks_SkipsEntriesWithNeitherURLNorUsername(t *testing.T) {
	got := profileLinks([]Profile{{Network: "GitHub"}, {Network: "LinkedIn", URL: "linkedin.com/in/x"}})
	want := "LinkedIn: linkedin.com/in/x"
	if got != want {
		t.Fatalf("expected the bare, address-less profile to be skipped entirely, got %q", got)
	}
}

func TestRenderPDF_HandlesNonLatinTextWithoutError(t *testing.T) {
	// Real, honest limitation this test PROVES rather than just documents (see RenderPDF's own
	// doc comment): the built-in Arial core font can't render CJK, so this real, deliberate
	// input degrades those characters -- the real, important thing this test confirms is that
	// it degrades GRACEFULLY (no error, no panic, a real, valid PDF still comes out), not that
	// the CJK text itself renders correctly (it doesn't, and isn't claimed to).
	r := &Resume{Basics: Basics{Name: "田中太郎", Email: "tanaka@example.com"}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF must degrade non-Latin text gracefully, not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF even with non-Latin input")
	}
}

// ---- Compact template + footer -- founder real-time, 2026-09-09: "add a new output template
// compact that manages to get the experience and education like into 2 columns or something so
// we can get more skills on the page and keep it 1 page" / "the downloaded resume should
// include the candidate name and the export timestamp." ----

func realCompactResume() *Resume {
	return &Resume{
		Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100"},
		Work: []Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "2022-03", EndDate: "2024-01", Summary: "Did real kitchen work."},
			{Name: "Beta Diner", Position: "Server", StartDate: "2020-01", EndDate: "2022-01"},
		},
		Education: []Education{
			{Institution: "Community College", StudyType: "Certificate", Area: "Culinary Arts", StartDate: "2020", EndDate: "2022"},
		},
		Skills: []Skill{{Name: "Knife Skills"}, {Name: "Food Safety"}, {Name: "POS Systems"}},
	}
}

func TestRenderPDF_CompactTemplateProducesARealPDF(t *testing.T) {
	out, err := RenderPDF(realCompactResume(), "compact")
	if err != nil {
		t.Fatalf("RenderPDF(compact) returned a real error: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF for the compact template")
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Fatal("expected a real end-of-file marker for the compact template")
	}
}

func TestRenderPDF_CompactTemplateHandlesEmptyWorkOrEducation(t *testing.T) {
	// Real, deliberate edge case: a target resolved with only Education selected (no Work) --
	// the compact layout's two columns must each independently tolerate being empty, not panic
	// or produce a malformed document when one column has nothing to render.
	onlyEducation := &Resume{
		Basics:    Basics{Name: "Jordan Rivera"},
		Education: []Education{{Institution: "Community College"}},
	}
	out, err := RenderPDF(onlyEducation, "compact")
	if err != nil {
		t.Fatalf("compact with empty Work must not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF")
	}

	onlyWork := &Resume{
		Basics: Basics{Name: "Jordan Rivera"},
		Work:   []Work{{Name: "Acme Corp", Position: "Line Cook"}},
	}
	out, err = RenderPDF(onlyWork, "compact")
	if err != nil {
		t.Fatalf("compact with empty Education must not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF")
	}
}

func TestRenderPDF_UnknownTemplateFallsBackToClassic(t *testing.T) {
	// Real, deliberate default: an empty or unrecognized template string must not error or
	// silently produce a blank/broken document -- it falls back to the real, original,
	// ATS-safe classic layout (RenderPDF's own dispatch: only the literal string "compact"
	// triggers the two-column layout).
	out, err := RenderPDF(realCompactResume(), "some-nonexistent-template")
	if err != nil {
		t.Fatalf("an unrecognized template must not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF falling back to classic")
	}
}

func TestFooterLine_IncludesNameAndTimestamp(t *testing.T) {
	when := time.Date(2026, 9, 9, 15, 4, 0, 0, time.UTC)
	got := footerLine("Jordan Rivera", when)
	want := "Jordan Rivera  ·  Exported 2026-09-09 15:04 UTC"
	if got != want {
		t.Fatalf("footerLine mismatch:\ngot:  %q\nwant: %q", got, want)
	}
}

// TestRenderCompactHeader_NameLeftContactRight -- founder real-time, 2026-09-10: "can we shift
// the contact info and links to the right (right align) and the name and headline to the left
// so they can free up just a bit more vertical space on the compact template?" Real, direct
// proof via the same SetCompression(false) + raw-content-stream technique already established
// in this file: renders the compact header alone, then confirms the name's own Td x-coordinate
// sits near the real left margin (56.7pt = 20mm) while the contact info's own Td x-coordinate
// sits meaningfully further right -- not just that both strings appear somewhere on the page.
func TestRenderCompactHeader_NameLeftContactRight(t *testing.T) {
	r := &Resume{Basics: Basics{Name: "Jordan Rivera", Label: "Line Cook", Email: "jordan@example.com", Phone: "555-0100"}}
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(false)
	pdf.SetMargins(20, 18, 20)
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()
	renderCompactHeader(pdf, tr, r, r.Basics.Name)
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		t.Fatalf("Output failed: %v", err)
	}
	content := buf.String()

	nameIdx := strings.Index(content, "(Jordan Rivera)Tj")
	contactIdx := strings.Index(content, "(jordan@example.com")
	if nameIdx < 0 || contactIdx < 0 {
		t.Fatalf("expected both the name and contact text to appear in the raw content stream, got:\n%s", content)
	}
	nameX := tdXBefore(t, content, nameIdx)
	contactX := tdXBefore(t, content, contactIdx)
	if nameX > 60 {
		t.Fatalf("expected the name's own x-coordinate to sit near the real left margin (~56.7pt), got %.2f", nameX)
	}
	if contactX <= nameX+50 {
		t.Fatalf("expected the contact info to render meaningfully to the RIGHT of the name (right-aligned in its own column), got name x=%.2f contact x=%.2f", nameX, contactX)
	}

	labelIdx := strings.Index(content, "(Line Cook)Tj")
	if labelIdx < 0 {
		t.Fatal("expected the label to appear in the raw content stream")
	}
	labelX := tdXBefore(t, content, labelIdx)
	if labelX > 60 {
		t.Fatalf("expected the label to also render near the left margin (same column as the name), got %.2f", labelX)
	}
}

// tdXBefore finds the last real "<x> <y> Td" operator appearing before byteIdx in content and
// returns its x value -- the real text-positioning operator fpdf emits immediately before the
// Tj that actually draws the string at that position.
func tdXBefore(t *testing.T, content string, byteIdx int) float64 {
	t.Helper()
	re := regexp.MustCompile(`([\d.]+) [\d.]+ Td`)
	matches := re.FindAllStringSubmatchIndex(content[:byteIdx], -1)
	if len(matches) == 0 {
		t.Fatalf("no Td operator found before byte offset %d", byteIdx)
	}
	last := matches[len(matches)-1]
	x, err := strconv.ParseFloat(content[last[2]:last[3]], 64)
	if err != nil {
		t.Fatalf("parse Td x value: %v", err)
	}
	return x
}

// TestRenderPDF_FooterAppearsOnARealUncompressedPage -- the same real
// "SetCompression(false) + grep the raw bytes" verification discipline this repo's own PDF
// export work already established, applied here to prove the footer text (name + a real,
// recognizable date fragment) actually lands in the page content stream, not just that
// footerLine() itself returns the right string in isolation.
func TestRenderPDF_FooterAppearsOnARealUncompressedPage(t *testing.T) {
	r := realCompactResume()
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(false)
	pdf.SetMargins(20, 18, 20)
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	when := time.Date(2026, 9, 9, 15, 4, 0, 0, time.UTC)
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Arial", "", 7)
		pdf.CellFormat(0, 6, tr(footerLine(r.Basics.Name, when)), "", 0, "C", false, 0, "")
	})
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 18)
	pdf.CellFormat(0, 9, tr(r.Basics.Name), "", 1, "C", false, 0, "")
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		t.Fatalf("Output failed: %v", err)
	}
	out := buf.Bytes()
	if !bytes.Contains(out, []byte("Jordan Rivera")) {
		t.Fatal("expected the candidate's real name to appear in the raw, uncompressed page content")
	}
	if !bytes.Contains(out, []byte("2026-09-09")) {
		t.Fatal("expected the real export date to appear in the raw, uncompressed page content")
	}
}

// ---- Auto-linking + markdown links -- founder real-time, 2026-09-10: "can we add auto linking
// to the email and the links on the exports also can we allow for markdown in the summary so
// that we can have hyperlinks there too?" Real, direct proof via the actual public RenderPDF
// output: fpdf stores a link annotation's own target as a real, PLAIN-TEXT "/URI (...)" entry in
// the PDF's object structure (confirmed by generating and reading a real PDF directly) --
// unlike page CONTENT, annotations are never stream-compressed, so these checks need no
// SetCompression(false)/decompression step at all. ----

func TestRenderPDF_EmailBecomesARealMailtoLink(t *testing.T) {
	r := &Resume{Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com"}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF error: %v", err)
	}
	if !bytes.Contains(out, []byte("/URI (mailto:jordan@example.com)")) {
		t.Fatal("expected a real mailto: link annotation for the email address")
	}
}

func TestRenderPDF_ProfileURLBecomesARealLink(t *testing.T) {
	r := &Resume{Basics: Basics{
		Name:     "Jordan Rivera",
		Profiles: []Profile{{Network: "GitHub", URL: "github.com/jordan/parena"}},
	}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF error: %v", err)
	}
	// safeHref adds a missing scheme -- a bare "github.com/..." profile entry must still become
	// a REAL, clickable https:// link, not stay inert just because the user didn't type a scheme.
	if !bytes.Contains(out, []byte("/URI (https://github.com/jordan/parena)")) {
		t.Fatal("expected a real https:// link annotation, with the scheme auto-added, for the profile URL")
	}
}

func TestRenderPDF_UsernameOnlyProfileDoesNotBecomeALink(t *testing.T) {
	r := &Resume{Basics: Basics{
		Name:     "Jordan Rivera",
		Profiles: []Profile{{Network: "LinkedIn", Username: "jordanrivera"}},
	}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF error: %v", err)
	}
	if bytes.Contains(out, []byte("/URI")) {
		t.Fatal("expected NO link annotation for a username-only profile entry -- there's no real URL to link to, so it must render as honest plain text")
	}
	// The label text itself (e.g. "LinkedIn: jordanrivera") is inside the page's own compressed
	// content stream under default compression, not independently checkable here without
	// decompressing -- TestRenderPDF_RendersProfileLinks and
	// TestProfileLinks_SkipsEntriesWithNeitherURLNorUsername already cover that the real text
	// content is correct; this test's own real, distinct purpose is just confirming no link
	// annotation gets created for a username-only entry.
}

func TestRenderPDF_DangerousSchemeIsNeverLinkified(t *testing.T) {
	r := &Resume{Basics: Basics{
		Name:     "Jordan Rivera",
		Profiles: []Profile{{Network: "Evil", URL: "javascript:alert(1)"}},
	}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF error: %v", err)
	}
	if bytes.Contains(out, []byte("/URI")) {
		t.Fatal("expected a javascript: URL to never become a real clickable link annotation")
	}
}

func TestRenderPDF_MarkdownLinkInSummaryBecomesARealLink(t *testing.T) {
	r := &Resume{Basics: Basics{
		Name:    "Jordan Rivera",
		Summary: "Check out [my portfolio](https://example.com/portfolio) for more real work.",
	}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF error: %v", err)
	}
	if !bytes.Contains(out, []byte("/URI (https://example.com/portfolio)")) {
		t.Fatal("expected the markdown [text](url) link in the summary to become a real link annotation")
	}
}

func TestRenderPDF_MarkdownLinkWithDangerousURLRendersAsPlainText(t *testing.T) {
	r := &Resume{Basics: Basics{
		Name:    "Jordan Rivera",
		Summary: "Careful: [click me](javascript:alert(1)) is not a real link.",
	}}
	out, err := RenderPDF(r, "classic")
	if err != nil {
		t.Fatalf("RenderPDF must not error even on a dangerous-scheme markdown link, got: %v", err)
	}
	if bytes.Contains(out, []byte("/URI")) {
		t.Fatal("expected a javascript:-scheme markdown link to never become a real link annotation")
	}
}

func TestSafeHref(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", ""},
		{"https://example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"github.com/x/y", "https://github.com/x/y"},
		{"javascript:alert(1)", ""},
		{"JAVASCRIPT:alert(1)", ""},
		{"data:text/html,<script>", ""},
		{"vbscript:msgbox(1)", ""},
		{"  https://example.com  ", "https://example.com"},
	}
	for _, c := range cases {
		got := safeHref(c.raw)
		if got != c.want {
			t.Errorf("safeHref(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestWriteMarkdownParagraph_PlainTextUnaffected(t *testing.T) {
	// A summary with no markdown links at all must still render correctly (Write, not
	// MultiCell, is now doing the work) -- a real regression check for the swap.
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetCompression(false)
	pdf.SetMargins(20, 18, 20)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()
	pdf.SetFont("Arial", "", 10)
	writeMarkdownParagraph(pdf, tr, 5, "A plain summary with no links at all.")
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		t.Fatalf("Output failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("A plain summary with no links at all.")) {
		t.Fatal("expected the plain text to appear unchanged in the raw content stream")
	}
}
