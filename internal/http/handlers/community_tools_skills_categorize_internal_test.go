package handlers

import "testing"

// Real, canned Vertex generateContent response shape (matches the exact real structure
// gfd_item_proposals.go's own generateItemProposal already parses, and the real shape live-
// verified against the actual endpoint before that file was written) -- lets
// parseCategorizeVertexResponse be tested without a live, gcloud-authenticated network call.
const fakeVertexCategorizeResponse = `{
  "candidates": [
    {
      "content": {
        "parts": [
          {"text": "[{\"name\":\"Golang\",\"category\":\"Backend & APIs\"},{\"name\":\"React\",\"category\":\"Frontend\"},{\"name\":\"Woodworking\",\"category\":\"Not A Real Category\"}]"}
        ]
      },
      "finishReason": "STOP"
    }
  ]
}`

func TestParseCategorizeVertexResponse_RealShapeParsesCleanly(t *testing.T) {
	out, err := parseCategorizeVertexResponse([]byte(fakeVertexCategorizeResponse))
	if err != nil {
		t.Fatalf("real Vertex response shape must parse cleanly, got: %v", err)
	}
	if out["golang"] != "Backend & APIs" {
		t.Errorf("expected golang -> Backend & APIs, got %q (full map: %+v)", out["golang"], out)
	}
	if out["react"] != "Frontend" {
		t.Errorf("expected react -> Frontend, got %q", out["react"])
	}
}

func TestParseCategorizeVertexResponse_UnrecognizedCategoryNormalizedToOther(t *testing.T) {
	// A model hallucinating a category string that isn't one of the six real, known buckets (or
	// "Other" itself) must never be trusted verbatim -- normalized so every stored Category value
	// this handler ever writes is one of the real, known values GroupSkillsByCategory expects.
	out, err := parseCategorizeVertexResponse([]byte(fakeVertexCategorizeResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["woodworking"] != "Other" {
		t.Errorf("expected an unrecognized model category to normalize to Other, got %q", out["woodworking"])
	}
}

func TestParseCategorizeVertexResponse_NameMatchingIsCaseInsensitiveTrimmed(t *testing.T) {
	raw := `{"candidates":[{"content":{"parts":[{"text":"[{\"name\":\"  Kubernetes \",\"category\":\"Cloud & Infrastructure\"}]"}]},"finishReason":"STOP"}]}`
	out, err := parseCategorizeVertexResponse([]byte(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The map key itself is lowercased+trimmed by parseCategorizeVertexResponse so the caller
	// (ServeHTTP) can match it back against a skill's own name the same way, regardless of
	// whatever whitespace/casing the model happened to echo back.
	if out["kubernetes"] != "Cloud & Infrastructure" {
		t.Errorf("expected a case/whitespace-normalized match, got map: %+v", out)
	}
}

func TestParseCategorizeVertexResponse_NoCandidatesIsARealError(t *testing.T) {
	_, err := parseCategorizeVertexResponse([]byte(`{"candidates":[]}`))
	if err == nil {
		t.Fatal("expected a real error for a response with no candidates, got nil")
	}
}

func TestParseCategorizeVertexResponse_ModelReturnedNonJSONIsARealError(t *testing.T) {
	raw := `{"candidates":[{"content":{"parts":[{"text":"not json at all"}]},"finishReason":"STOP"}]}`
	_, err := parseCategorizeVertexResponse([]byte(raw))
	if err == nil {
		t.Fatal("expected a real error when the model's own text isn't valid JSON, got nil")
	}
}

func TestParseCategorizeVertexResponse_MalformedOuterEnvelopeIsARealError(t *testing.T) {
	_, err := parseCategorizeVertexResponse([]byte(`not even json`))
	if err == nil {
		t.Fatal("expected a real error for a malformed outer Vertex envelope, got nil")
	}
}
