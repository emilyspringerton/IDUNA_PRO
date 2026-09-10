// Package resume — RenderPDF closes the real "Layer 3" gap named honestly throughout this
// feature's own design docs since it was first scoped: verify (verify.go) proves the DATA is
// machine-readable, but real ATS-readability is also a property of the RENDERED DOCUMENT —
// tables, multi-column layouts, and image-only text are real, well-documented ATS parsing
// pitfalls at the rendering layer, not the data layer. Until now, console.html's own
// "Preview & templates" panel only ever rendered a screen preview (HTML/CSS); this is the
// real, downloadable file.
package resume

import (
	"bytes"
	"regexp"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// RenderPDF renders r into a real, downloadable PDF document — built with github.com/go-pdf/fpdf
// (the maintained fork of jung-kurt/gofpdf), a real, pure Go, no-cgo PDF library, matching this
// whole repo's own established "no cgo" discipline (modernc.org/sqlite's own real reason for
// existing).
//
// template selects the layout:
//   - "" or "classic" (the default, and the ONLY layout that existed before 2026-09-09): one
//     real, deliberately plain, single-column, real-selectable-text layout (never an image).
//     Real, structural safety matters far more than color for a real ATS parser — tables and
//     multi-column layouts are a real, well-documented ATS parsing pitfall (a parser reading
//     strictly left-to-right across the full page width can interleave column content into
//     garbled order). This is the ATS-safe choice.
//   - "compact": founder real-time, 2026-09-09: "add a new output template compact that manages
//     to get the experience and education like into 2 columns or something so we can get more
//     skills on the page and keep it 1 page." A real, deliberate, OPT-IN trade-off: Experience
//     and Education render side by side to free vertical space for a fuller Skills section,
//     genuinely more likely to fit dense content onto one page — at the real cost of the same
//     ATS-parsing-order risk "classic" was built specifically to avoid. Named honestly, not
//     hidden: choose "classic" for a submission going through an automated ATS, "compact" for a
//     human reviewer or a printed copy where density matters more.
//
// Real, honest, named limitation shared by both templates: fpdf's built-in "Arial" core font
// (used here — no font file ships with this repo, so an embedded/TTF font is real, separate,
// un-attempted work) only renders the Windows-1252 (Latin-1-ish) character set.
// UnicodeTranslatorFromDescriptor("") transliterates real UTF-8 input down to that real
// encoding — correct for English and most Western European accented text, but a real name/field
// containing e.g. CJK or Cyrillic characters will render as "?" or drop those characters, not a
// silent corruption of anything ELSE on the page.
//
// Real, honest, named limitation specific to "compact": if either column's own content
// (Experience or Education) is unusually long, fpdf's own automatic page-break can trigger mid-
// column, starting a new page at the page's own left margin rather than continuing inside that
// column — this template is optimized for the common case of a full page's worth of content,
// not a hard 1-page guarantee for arbitrarily long resumes.
//
// Every generated PDF (both templates) carries a real footer — founder real-time, same message:
// "the downloaded resume should include the candidate name and the export timestamp" — the
// candidate's own name plus the real moment this specific file was generated, repeated on every
// page via fpdf's own real SetFooterFunc (not just appended once after the last line of content).
func RenderPDF(r *Resume, template string) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 18, 20)
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	b := r.Basics
	name := b.Name
	if name == "" {
		name = "Resume"
	}
	exportedAt := time.Now().UTC()
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Arial", "", 7)
		pdf.SetTextColor(140, 140, 140)
		pdf.CellFormat(0, 6, tr(footerLine(name, exportedAt)), "", 0, "C", false, 0, "")
		pdf.SetTextColor(0, 0, 0)
	})
	pdf.AddPage()

	if template == "compact" {
		renderCompactHeader(pdf, tr, r, name)
	} else {
		renderClassicHeader(pdf, tr, r, name)
	}

	if b.Summary != "" {
		left, _, _, _ := pdf.GetMargins()
		pdf.SetX(left)
		pdf.SetFont("Arial", "", 10)
		writeMarkdownParagraph(pdf, tr, 5, b.Summary)
		pdf.Ln(7)
	}

	if template == "compact" {
		renderCompactExperienceEducation(pdf, tr, r)
	} else {
		renderClassicExperienceEducation(pdf, tr, r)
	}

	if len(r.Skills) > 0 {
		pdfSectionTitle(pdf, tr, "Skills")
		names := make([]string, 0, len(r.Skills))
		for _, s := range r.Skills {
			if s.Name != "" {
				names = append(names, s.Name)
			}
		}
		pdf.SetFont("Arial", "", 10)
		pdf.MultiCell(0, 5, tr(strings.Join(names, ", ")), "", "L", false)
		pdf.Ln(2)
	}

	if len(r.Awards) > 0 {
		pdfSectionTitle(pdf, tr, "Awards")
		for _, a := range r.Awards {
			pdfEntryHeading(pdf, tr, a.Title, a.Awarder, a.Date)
			pdf.Ln(2)
		}
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// footerLine -- founder real-time, 2026-09-09: "the downloaded resume should include the
// candidate name and the export timestamp." A pure, real, directly-testable function (rather
// than inlining the format string only inside the fpdf footer closure) — exactly what appears
// at the bottom of every page of every generated PDF, regardless of template.
func footerLine(name string, exportedAt time.Time) string {
	return name + "  ·  Exported " + exportedAt.Format("2006-01-02 15:04 MST")
}

// pdfSegment is one piece of a real, possibly-linked run of text -- e.g. one "Network: address"
// profile entry, or the email address, rendered as its own real clickable link when url is set.
type pdfSegment struct {
	text string
	url  string // "" = plain text, no link
}

// contactSegments builds the real, per-field segments for a Basics contact line -- founder
// real-time, 2026-09-10: "can we add auto linking to the email." Email becomes a real mailto:
// link; phone stays plain text (never asked to be linkified, and a bare phone number has no
// single, unambiguous link scheme the way an email address does).
func contactSegments(b Basics) []pdfSegment {
	var segs []pdfSegment
	if b.Email != "" {
		segs = append(segs, pdfSegment{text: b.Email, url: "mailto:" + b.Email})
	}
	if b.Phone != "" {
		segs = append(segs, pdfSegment{text: b.Phone})
	}
	return segs
}

// pdfProfileSegments builds one real segment per profile entry (see profileLinks' own doc
// comment for the real "address = URL, falling back to username" convention this mirrors) --
// founder real-time, 2026-09-10: "can we add auto linking to... the links on the exports."
// Only a profile with a real URL gets a real, clickable link (via safeHref, which also adds a
// missing https:// scheme to a bare "github.com/x/y"-style entry) -- a username-only entry has
// no real URL to link to, so it renders as honest plain text rather than a guessed-at link.
func pdfProfileSegments(profiles []Profile) []pdfSegment {
	segs := make([]pdfSegment, 0, len(profiles))
	for _, p := range profiles {
		address := p.URL
		if address == "" {
			address = p.Username
		}
		if address == "" {
			continue
		}
		label := joinNonEmpty(": ", p.Network, address)
		if label == "" {
			continue
		}
		seg := pdfSegment{text: label}
		if p.URL != "" {
			seg.url = safeHref(p.URL)
		}
		segs = append(segs, seg)
	}
	return segs
}

// pdfSegmentsWidth measures the real rendered width segments (joined by sep) would take using
// the pdf's CURRENT font -- caller must SetFont first, matching whatever will actually be drawn.
func pdfSegmentsWidth(pdf *fpdf.Fpdf, tr func(string) string, segments []pdfSegment, sep string) float64 {
	total := 0.0
	for i, s := range segments {
		if i > 0 {
			total += pdf.GetStringWidth(sep)
		}
		total += pdf.GetStringWidth(tr(s.text))
	}
	return total
}

// pdfDrawSegments draws segments left-to-right starting at the CURRENT cursor, each a real
// clickable link (rendered in a real "this is a link" blue) when its own url is set, separated
// by sep (always plain, never linked/colored). Leaves Y unchanged -- the caller advances it.
func pdfDrawSegments(pdf *fpdf.Fpdf, tr func(string) string, segments []pdfSegment, sep string, h float64) {
	for i, s := range segments {
		if i > 0 {
			pdf.CellFormat(pdf.GetStringWidth(sep), h, sep, "", 0, "L", false, 0, "")
		}
		text := tr(s.text)
		w := pdf.GetStringWidth(text)
		if s.url != "" {
			pdf.SetTextColor(0, 0, 200)
			pdf.CellFormat(w, h, text, "", 0, "L", false, 0, s.url)
			pdf.SetTextColor(0, 0, 0)
		} else {
			pdf.CellFormat(w, h, text, "", 0, "L", false, 0, "")
		}
	}
}

const pdfSegmentSep = "   |   "

// renderClassicHeader -- the original, centered-stack header: name, label, contact, and links
// each on their own full-width, center-aligned line. Contact/links now render as real, per-
// segment clickable links (email -> mailto:, each profile with a real URL -> that URL) instead
// of inert text, centered as a WHOLE group (real width measured first, then the starting X
// computed so the group sits centered) since CellFormat's own "C" align mode can't center a
// sequence of independently-linked/colored segments the way a single plain string could.
func renderClassicHeader(pdf *fpdf.Fpdf, tr func(string) string, r *Resume, name string) {
	b := r.Basics
	left, _, right, _ := pdf.GetMargins()
	pageW, _ := pdf.GetPageSize()
	contentW := pageW - left - right

	pdf.SetFont("Arial", "B", 18)
	pdf.CellFormat(0, 9, tr(name), "", 1, "C", false, 0, "")
	if b.Label != "" {
		pdf.SetFont("Arial", "I", 11)
		pdf.CellFormat(0, 6, tr(b.Label), "", 1, "C", false, 0, "")
	}

	if segs := contactSegments(b); len(segs) > 0 {
		pdf.SetFont("Arial", "", 10)
		w := pdfSegmentsWidth(pdf, tr, segs, pdfSegmentSep)
		pdf.SetX(left + (contentW-w)/2)
		pdfDrawSegments(pdf, tr, segs, pdfSegmentSep, 6)
		pdf.Ln(6)
	}
	if segs := pdfProfileSegments(b.Profiles); len(segs) > 0 {
		pdf.SetFont("Arial", "", 9)
		w := pdfSegmentsWidth(pdf, tr, segs, pdfSegmentSep)
		pdf.SetX(left + (contentW-w)/2)
		pdfDrawSegments(pdf, tr, segs, pdfSegmentSep, 6)
		pdf.Ln(6)
	}
	pdf.Ln(3)
}

// renderCompactHeader -- founder real-time, 2026-09-10: "can we shift the contact info and links
// to the right (right align) and the name and headline to the left so they can free up just a
// bit more vertical space on the compact template?" Name+label sit LEFT, contact+links sit
// RIGHT, sharing two rows instead of four separate centered lines -- a real, direct vertical-
// space saving in the same spirit as the compact template's own two-column Experience/Education
// layout. Row 1 (name/contact) always renders (name always has a real "Resume" fallback); row 2
// (label/links) is skipped entirely when both are empty, rather than rendering a blank row.
// Contact/links render as real, per-segment clickable links (see renderClassicHeader's own doc
// comment) right-aligned as a whole group against the real right margin.
func renderCompactHeader(pdf *fpdf.Fpdf, tr func(string) string, r *Resume, name string) {
	b := r.Basics
	left, _, right, _ := pdf.GetMargins()
	pageW, _ := pdf.GetPageSize()
	contentW := pageW - left - right
	leftW := contentW * 0.6
	rightEdge := pageW - right

	pdf.SetX(left)
	pdf.SetFont("Arial", "B", 18)
	pdf.CellFormat(leftW, 9, tr(name), "", 0, "L", false, 0, "")
	pdf.SetFont("Arial", "", 10)
	if segs := contactSegments(b); len(segs) > 0 {
		w := pdfSegmentsWidth(pdf, tr, segs, pdfSegmentSep)
		pdf.SetXY(rightEdge-w, pdf.GetY())
		pdfDrawSegments(pdf, tr, segs, pdfSegmentSep, 9)
	}
	pdf.Ln(9)

	linkSegs := pdfProfileSegments(b.Profiles)
	if b.Label != "" || len(linkSegs) > 0 {
		pdf.SetX(left)
		pdf.SetFont("Arial", "I", 11)
		pdf.CellFormat(leftW, 6, tr(b.Label), "", 0, "L", false, 0, "")
		pdf.SetFont("Arial", "", 9)
		if len(linkSegs) > 0 {
			w := pdfSegmentsWidth(pdf, tr, linkSegs, pdfSegmentSep)
			pdf.SetXY(rightEdge-w, pdf.GetY())
			pdfDrawSegments(pdf, tr, linkSegs, pdfSegmentSep, 6)
		}
		pdf.Ln(6)
	}
	pdf.Ln(3)
}

// renderClassicExperienceEducation -- the original, single-column, ATS-safe layout: Experience
// then Education, each entry full width, unchanged from this feature's first PDF export pass.
func renderClassicExperienceEducation(pdf *fpdf.Fpdf, tr func(string) string, r *Resume) {
	if len(r.Work) > 0 {
		pdfSectionTitle(pdf, tr, "Experience")
		for _, w := range r.Work {
			endDate := w.EndDate
			if endDate == "" {
				endDate = "Present"
			}
			pdfEntryHeading(pdf, tr, w.Position, w.Name, joinNonEmpty(" — ", w.StartDate, endDate))
			if w.Summary != "" {
				pdf.SetFont("Arial", "", 10)
				pdf.MultiCell(0, 5, tr(w.Summary), "", "L", false)
			}
			pdf.Ln(2)
		}
	}

	if len(r.Education) > 0 {
		pdfSectionTitle(pdf, tr, "Education")
		for _, e := range r.Education {
			endDate := e.EndDate
			if endDate == "" {
				endDate = "Present"
			}
			pdfEntryHeading(pdf, tr, e.Institution, joinNonEmpty(", ", e.StudyType, e.Area), joinNonEmpty(" — ", e.StartDate, endDate))
			pdf.Ln(2)
		}
	}
}

// colState tracks one manually-managed column's own x/width/current-y cursor. fpdf's own
// newline handling (both CellFormat's ln=1/2 and MultiCell's internal line breaks) always
// resets X to the PAGE's own left margin, never to an arbitrary column start — so every single
// draw call in a column explicitly re-sets (x, y) first via SetXY, then reads GetY() back
// afterward, rather than trusting fpdf's own cursor to stay inside the column on its own.
type colState struct {
	x, w, y float64
}

func (c *colState) sectionTitle(pdf *fpdf.Fpdf, tr func(string) string, title string) {
	pdf.SetFont("Arial", "B", 11)
	pdf.SetXY(c.x, c.y)
	pdf.CellFormat(c.w, 6, tr(title), "B", 2, "L", false, 0, "")
	c.y = pdf.GetY() + 1
}

// entryHeading -- the compact column's own real, narrower analog of the classic template's
// pdfEntryHeading: title and dates go on SEPARATE lines (not side by side on one line) since a
// real column this narrow doesn't have the horizontal room for both.
func (c *colState) entryHeading(pdf *fpdf.Fpdf, tr func(string) string, title, sub, dates string) {
	pdf.SetFont("Arial", "B", 9)
	pdf.SetXY(c.x, c.y)
	pdf.MultiCell(c.w, 4.2, tr(title), "", "L", false)
	c.y = pdf.GetY()
	if dates != "" {
		pdf.SetFont("Arial", "", 8)
		pdf.SetXY(c.x, c.y)
		pdf.CellFormat(c.w, 4, tr(dates), "", 2, "L", false, 0, "")
		c.y = pdf.GetY()
	}
	if sub != "" {
		pdf.SetFont("Arial", "I", 8)
		pdf.SetXY(c.x, c.y)
		pdf.MultiCell(c.w, 4, tr(sub), "", "L", false)
		c.y = pdf.GetY()
	}
}

func (c *colState) summary(pdf *fpdf.Fpdf, tr func(string) string, text string) {
	if text == "" {
		return
	}
	pdf.SetFont("Arial", "", 8)
	pdf.SetXY(c.x, c.y)
	pdf.MultiCell(c.w, 4, tr(text), "", "L", false)
	c.y = pdf.GetY()
}

// renderCompactExperienceEducation -- founder real-time, 2026-09-09: "add a new output template
// compact that manages to get the experience and education like into 2 columns or something so
// we can get more skills on the page and keep it 1 page." Experience renders in a wider left
// column, Education in a narrower right column, side by side starting from the SAME y — freeing
// the vertical space Education's own full-width blocks would otherwise cost in the classic
// layout. Skills/Awards resume full width below the taller of the two columns (rendered by the
// caller, RenderPDF, exactly as in the classic layout).
func renderCompactExperienceEducation(pdf *fpdf.Fpdf, tr func(string) string, r *Resume) {
	left, _, right, _ := pdf.GetMargins()
	pageW, _ := pdf.GetPageSize()
	contentW := pageW - left - right
	const gutter = 6.0
	leftW := contentW*0.60 - gutter/2
	rightW := contentW - leftW - gutter
	startY := pdf.GetY()

	leftCol := &colState{x: left, w: leftW, y: startY}
	rightCol := &colState{x: left + leftW + gutter, w: rightW, y: startY}

	if len(r.Work) > 0 {
		leftCol.sectionTitle(pdf, tr, "Experience")
		for _, w := range r.Work {
			endDate := w.EndDate
			if endDate == "" {
				endDate = "Present"
			}
			leftCol.entryHeading(pdf, tr, w.Position, w.Name, joinNonEmpty(" — ", w.StartDate, endDate))
			leftCol.summary(pdf, tr, w.Summary)
			leftCol.y += 2
		}
	}

	if len(r.Education) > 0 {
		rightCol.sectionTitle(pdf, tr, "Education")
		for _, e := range r.Education {
			endDate := e.EndDate
			if endDate == "" {
				endDate = "Present"
			}
			rightCol.entryHeading(pdf, tr, e.Institution, joinNonEmpty(", ", e.StudyType, e.Area), joinNonEmpty(" — ", e.StartDate, endDate))
			rightCol.y += 2
		}
	}

	endY := leftCol.y
	if rightCol.y > endY {
		endY = rightCol.y
	}
	pdf.SetXY(left, endY+2)
}

func pdfSectionTitle(pdf *fpdf.Fpdf, tr func(string) string, title string) {
	pdf.SetFont("Arial", "B", 12)
	pdf.CellFormat(0, 7, tr(title), "B", 1, "L", false, 0, "")
	pdf.Ln(1)
}

// pdfEntryHeading -- one real, shared layout for a Work/Education/Award entry's own header
// line: a bold title on the left, real dates right-aligned on the SAME line (a real, standard
// resume convention, not a CarePyre invention), an optional italic subtitle line beneath.
func pdfEntryHeading(pdf *fpdf.Fpdf, tr func(string) string, title, sub, dates string) {
	pdf.SetFont("Arial", "B", 10)
	pdf.CellFormat(130, 5, tr(title), "", 0, "L", false, 0, "")
	pdf.SetFont("Arial", "", 9)
	pdf.CellFormat(0, 5, tr(dates), "", 1, "R", false, 0, "")
	if sub != "" {
		pdf.SetFont("Arial", "I", 9)
		pdf.CellFormat(0, 5, tr(sub), "", 1, "L", false, 0, "")
	}
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// profileLinks -- founder real-time, 2026-09-09: "we need to be able to add and configure the
// output of multiple github links." Renders every profile as one real "Network: address" pair
// (the URL if set, else the username -- a real profile with neither is skipped entirely rather
// than printing a bare, meaningless "GitHub:"), joined onto one line under the contact info.
// Real, deliberate ordering choice: profiles render in the SAME order they appear in
// b.Profiles, so a Target's own real, chosen selection order is respected, not resorted.
// Built on pdfProfileSegments (2026-09-10, added for real per-segment PDF hyperlinks) so the
// plain-text and clickable-link renderings share one real source of truth for which profiles
// get included and how their label text is built, rather than two independent copies.
func profileLinks(profiles []Profile) string {
	segs := pdfProfileSegments(profiles)
	parts := make([]string, len(segs))
	for i, s := range segs {
		parts[i] = s.text
	}
	return strings.Join(parts, "   |   ")
}

// safeHref -- founder real-time, 2026-09-10: "can we add auto linking to the email and the
// links on the exports." Returns a normalized, safe URL to actually use as a real hyperlink
// target, or "" if raw should NOT be turned into a clickable link at all -- a narrow, real
// safety measure against dangerous schemes (javascript:, data:, vbscript:, file:) a user-
// controlled field could otherwise smuggle into a real, clickable PDF link. A URL with no
// recognized scheme at all (the common real case for a bare "github.com/x/y"-style profile
// entry) gets a real https:// prefix added so it's actually clickable instead of silently
// staying inert.
func safeHref(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)
	for _, dangerous := range []string{"javascript:", "data:", "vbscript:", "file:"} {
		if strings.HasPrefix(lower, dangerous) {
			return ""
		}
	}
	for _, safe := range []string{"http://", "https://", "mailto:", "tel:"} {
		if strings.HasPrefix(lower, safe) {
			return raw
		}
	}
	return "https://" + raw
}

// markdownLinkRe matches a real, narrow markdown-link subset: [text](url). No bold/italic/
// headers/images -- a real, deliberate v0 boundary (founder asked specifically for "hyperlinks
// there too," not a full markdown renderer), and no nested-bracket or escaped-paren support --
// the common, real case a resume summary actually needs.
var markdownLinkRe = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

// writeMarkdownParagraph -- founder real-time, 2026-09-10: "can we allow for markdown in the
// summary so that we can have hyperlinks there too?" Uses fpdf's own Write/WriteLinkString --
// deliberately NOT MultiCell -- because those are the real, documented fpdf primitives for
// mixing plain and linked text within one real, word-wrapping paragraph flow (MultiCell has no
// equivalent mixed-content mode; see Write's own doc comment: "current position is left just at
// the end of the text," letting consecutive Write/WriteLinkString calls chain into one flowing
// paragraph). A [text](url) whose url doesn't survive safeHref's own scheme check renders as
// its own literal, un-linked markdown text -- never silently dropped.
func writeMarkdownParagraph(pdf *fpdf.Fpdf, tr func(string) string, h float64, text string) {
	lastEnd := 0
	for _, m := range markdownLinkRe.FindAllStringSubmatchIndex(text, -1) {
		if m[0] > lastEnd {
			pdf.Write(h, tr(text[lastEnd:m[0]]))
		}
		linkText := text[m[2]:m[3]]
		url := safeHref(text[m[4]:m[5]])
		if url != "" {
			pdf.SetTextColor(0, 0, 200)
			pdf.WriteLinkString(h, tr(linkText), url)
			pdf.SetTextColor(0, 0, 0)
		} else {
			pdf.Write(h, tr(text[m[0]:m[1]]))
		}
		lastEnd = m[1]
	}
	if lastEnd < len(text) {
		pdf.Write(h, tr(text[lastEnd:]))
	}
}
