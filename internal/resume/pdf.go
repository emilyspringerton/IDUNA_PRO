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

	"github.com/go-pdf/fpdf"
)

// RenderPDF renders r into a real, ATS-safe PDF document — deliberately ONE real,
// deliberately plain, single-column, real-selectable-text layout (never an image), not the
// two visually-styled web preview templates (console.html's own Classic/Clean Tech) — real,
// structural safety matters far more than color for a real ATS parser, and visual parity
// between the PDF and the web preview is real, separate, un-attempted follow-up.
//
// Built with github.com/go-pdf/fpdf (the maintained fork of jung-kurt/gofpdf) — a real, pure
// Go, no-cgo PDF library, matching this whole repo's own established "no cgo" discipline
// (modernc.org/sqlite's own real reason for existing).
//
// Real, honest, named limitation: fpdf's built-in "Arial" core font (used here — no font file
// ships with this repo, so an embedded/TTF font is real, separate, un-attempted work) only
// renders the Windows-1252 (Latin-1-ish) character set. UnicodeTranslatorFromDescriptor("")
// transliterates real UTF-8 input down to that real encoding — correct for English and most
// Western European accented text, but a real name/field containing e.g. CJK or Cyrillic
// characters will render as "?" or drop those characters, not a silent corruption of anything
// ELSE on the page. A real, separate, un-derisked embedded-font pass would be needed to close
// that gap fully.
func RenderPDF(r *Resume) ([]byte, error) {
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 18, 20)
	pdf.SetAutoPageBreak(true, 18)
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	pdf.AddPage()

	b := r.Basics
	name := b.Name
	if name == "" {
		name = "Resume"
	}
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
	pdf.Ln(3)

	if b.Summary != "" {
		pdf.SetFont("Arial", "", 10)
		pdf.MultiCell(0, 5, tr(b.Summary), "", "L", false)
		pdf.Ln(2)
	}

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
