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

	pdf.SetFont("Arial", "B", 18)
	pdf.CellFormat(0, 9, tr(name), "", 1, "C", false, 0, "")
	if b.Label != "" {
		pdf.SetFont("Arial", "I", 11)
		pdf.CellFormat(0, 6, tr(b.Label), "", 1, "C", false, 0, "")
	}
	if contact := joinNonEmpty("   |   ", b.Email, b.Phone); contact != "" {
		pdf.SetFont("Arial", "", 10)
		pdf.CellFormat(0, 6, tr(contact), "", 1, "C", false, 0, "")
	}
	if links := profileLinks(b.Profiles); links != "" {
		pdf.SetFont("Arial", "", 9)
		pdf.CellFormat(0, 6, tr(links), "", 1, "C", false, 0, "")
	}
	pdf.Ln(3)

	if b.Summary != "" {
		pdf.SetFont("Arial", "", 10)
		pdf.MultiCell(0, 5, tr(b.Summary), "", "L", false)
		pdf.Ln(2)
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
func profileLinks(profiles []Profile) string {
	parts := make([]string, 0, len(profiles))
	for _, p := range profiles {
		address := p.URL
		if address == "" {
			address = p.Username
		}
		if address == "" {
			continue
		}
		label := joinNonEmpty(": ", p.Network, address)
		if label != "" {
			parts = append(parts, label)
		}
	}
	return strings.Join(parts, "   |   ")
}
