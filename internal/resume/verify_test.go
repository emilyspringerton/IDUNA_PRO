package resume

import "testing"

func TestVerify_EmptyResumeFailsRequiredFields(t *testing.T) {
	r := &Resume{}
	got := Verify(r)
	if got.Passed {
		t.Fatal("an empty resume must not pass verification")
	}
	if !hasFailedRule(got, "basics.name-present") {
		t.Error("expected basics.name-present to fail on an empty resume")
	}
	if !hasFailedRule(got, "basics.email-present") {
		t.Error("expected basics.email-present to fail on an empty resume")
	}
	if !hasFailedRule(got, "has-work-or-education") {
		t.Error("expected has-work-or-education to fail on an empty resume")
	}
}

func TestVerify_MinimalRealResumePasses(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100"},
		Work: []Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "2022-03", EndDate: "2024-01"},
		},
	}
	got := Verify(r)
	if !got.Passed {
		t.Fatalf("expected a real, complete minimal resume to pass verification, got: %+v", got.Checks)
	}
}

func TestVerify_CurrentPositionWithNoEndDatePasses(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100"},
		Work: []Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "2024-01"}, // no EndDate — still current
		},
	}
	got := Verify(r)
	if !got.Passed {
		t.Fatalf("a real current position (no endDate) must not fail verification, got: %+v", got.Checks)
	}
}

func TestVerify_FreeTextDateFailsAsRealATSPitfall(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100"},
		Work: []Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "Summer 2022"},
		},
	}
	got := Verify(r)
	if got.Passed {
		t.Fatal("a real free-text date ('Summer 2022') must fail verification — the exact real ATS pitfall this tool exists to catch")
	}
	if !hasFailedRule(got, "work[0].startDate") {
		t.Errorf("expected work[0].startDate to fail, got: %+v", got.Checks)
	}
}

func TestVerify_MissingEmployerNameFlagged(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com", Phone: "555-0100"},
		Work: []Work{
			{Position: "Line Cook", StartDate: "2022-03"}, // no Name (employer)
		},
	}
	got := Verify(r)
	if got.Passed {
		t.Fatal("a work entry with no employer name must fail verification")
	}
	if !hasFailedRule(got, "work[0].employer-present") {
		t.Errorf("expected work[0].employer-present to fail, got: %+v", got.Checks)
	}
}

func TestVerify_MissingPhoneFlaggedButNotFatalToOtherChecks(t *testing.T) {
	r := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Email: "jordan@example.com"}, // no phone
		Work: []Work{
			{Name: "Acme Corp", Position: "Line Cook", StartDate: "2022-03", EndDate: "2024-01"},
		},
	}
	got := Verify(r)
	if got.Passed {
		t.Fatal("a resume with no phone must fail verification (Layer 2)")
	}
	if !hasFailedRule(got, "basics.phone-present") {
		t.Errorf("expected basics.phone-present to fail, got: %+v", got.Checks)
	}
	if hasFailedRule(got, "basics.name-present") || hasFailedRule(got, "basics.email-present") {
		t.Error("a missing phone shouldn't cause unrelated, present fields to be reported as failed")
	}
}

func TestLooksLikeISODate(t *testing.T) {
	cases := map[string]bool{
		"2022":         true,
		"2022-03":      true,
		"2022-03-15":   true,
		"Summer 2022":  false,
		"":             false,
		"22-03":        false, // real, deliberate v0 scope: full 4-digit year only
		"2022-3":       false, // real, deliberate v0 scope: 2-digit month/day only
		"2022-03-15-1": false,
	}
	for in, want := range cases {
		if got := looksLikeISODate(in); got != want {
			t.Errorf("looksLikeISODate(%q) = %v, want %v", in, got, want)
		}
	}
}

func hasFailedRule(res VerifyResult, rule string) bool {
	for _, c := range res.Checks {
		if c.Rule == rule && !c.Passed {
			return true
		}
	}
	return false
}
