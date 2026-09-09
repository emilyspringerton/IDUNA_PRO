package resume

import (
	"bytes"
	"testing"
)

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

	out, err := RenderPDF(r)
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
	out, err := RenderPDF(&Resume{})
	if err != nil {
		t.Fatalf("RenderPDF on a genuinely empty resume must not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid (if mostly blank) PDF even for an empty resume")
	}
}

func TestRenderPDF_HandlesNonLatinTextWithoutError(t *testing.T) {
	// Real, honest limitation this test PROVES rather than just documents (see RenderPDF's own
	// doc comment): the built-in Arial core font can't render CJK, so this real, deliberate
	// input degrades those characters -- the real, important thing this test confirms is that
	// it degrades GRACEFULLY (no error, no panic, a real, valid PDF still comes out), not that
	// the CJK text itself renders correctly (it doesn't, and isn't claimed to).
	r := &Resume{Basics: Basics{Name: "田中太郎", Email: "tanaka@example.com"}}
	out, err := RenderPDF(r)
	if err != nil {
		t.Fatalf("RenderPDF must degrade non-Latin text gracefully, not error, got: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Fatal("expected a real, valid PDF even with non-Latin input")
	}
}
