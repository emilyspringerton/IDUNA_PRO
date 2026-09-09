package resume

import "testing"

func TestResolve_FiltersToOnlyIncludedEntries(t *testing.T) {
	master := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Summary: "Master summary"},
		Work: []Work{
			{ID: "w1", Name: "Acme Corp", Position: "Line Cook"},
			{ID: "w2", Name: "Beta Diner", Position: "Server"},
		},
		Education: []Education{
			{ID: "e1", Institution: "Community College"},
		},
		Skills: []Skill{
			{ID: "s1", Name: "Customer Service"},
			{ID: "s2", Name: "Python"},
		},
		Awards: []Award{
			{ID: "a1", Title: "Employee of the Month"},
		},
	}
	master.Basics.Profiles = []Profile{
		{ID: "p1", Network: "GitHub", URL: "github.com/jordan/parena"},
		{ID: "p2", Network: "GitHub", URL: "github.com/jordan/burrow"},
	}
	target := &Target{
		ID:                   "t1",
		Name:                 "Kitchen jobs",
		IncludedWorkIDs:      []string{"w1"},
		IncludedEducationIDs: []string{"e1"},
		IncludedSkillIDs:     []string{"s1"},
		IncludedAwardIDs:     nil, // deliberately none
		IncludedProfileIDs:   []string{"p2"},
	}

	got := Resolve(master, target)

	if len(got.Work) != 1 || got.Work[0].ID != "w1" {
		t.Fatalf("expected only w1 in resolved Work, got: %+v", got.Work)
	}
	if len(got.Education) != 1 || got.Education[0].ID != "e1" {
		t.Fatalf("expected only e1 in resolved Education, got: %+v", got.Education)
	}
	if len(got.Skills) != 1 || got.Skills[0].ID != "s1" {
		t.Fatalf("expected only s1 in resolved Skills, got: %+v", got.Skills)
	}
	if len(got.Awards) != 0 {
		t.Fatalf("expected zero Awards (none included), got: %+v", got.Awards)
	}
	if len(got.Basics.Profiles) != 1 || got.Basics.Profiles[0].ID != "p2" {
		t.Fatalf("expected only p2 (the burrow link) in resolved Profiles, got: %+v", got.Basics.Profiles)
	}
	if got.Basics.Name != "Jordan Rivera" {
		t.Errorf("Basics.Name should pass through unfiltered, got %q", got.Basics.Name)
	}
}

// TestResolve_MultipleGitHubProfilesCanBeSelectedIndependently -- founder real-time,
// 2026-09-09: "we need to be able to add and configure the output of multiple github links."
// Two Profile entries with the IDENTICAL Network value ("GitHub") are real and distinguishable
// purely by their own stable ID -- proves this works even when Network alone can't disambiguate.
func TestResolve_MultipleGitHubProfilesCanBeSelectedIndependently(t *testing.T) {
	master := &Resume{
		Basics: Basics{
			Profiles: []Profile{
				{ID: "p1", Network: "GitHub", URL: "github.com/jordan/parena"},
				{ID: "p2", Network: "GitHub", URL: "github.com/jordan/burrow"},
				{ID: "p3", Network: "GitHub", URL: "github.com/jordan/carepyre"},
			},
		},
	}
	target := &Target{ID: "t1", IncludedProfileIDs: []string{"p1", "p3"}}

	got := Resolve(master, target)

	if len(got.Basics.Profiles) != 2 {
		t.Fatalf("expected exactly 2 of the 3 GitHub links, got: %+v", got.Basics.Profiles)
	}
	gotIDs := map[string]bool{got.Basics.Profiles[0].ID: true, got.Basics.Profiles[1].ID: true}
	if !gotIDs["p1"] || !gotIDs["p3"] {
		t.Fatalf("expected p1 and p3 specifically, got: %+v", got.Basics.Profiles)
	}
}

func TestResolve_EmptySelectionResolvesToEmpty(t *testing.T) {
	master := &Resume{
		Work: []Work{{ID: "w1", Name: "Acme Corp"}},
	}
	target := &Target{ID: "t1", Name: "Empty target"}

	got := Resolve(master, target)

	if len(got.Work) != 0 {
		t.Fatalf("a target selecting nothing must resolve to zero work entries, got: %+v", got.Work)
	}
}

func TestResolve_TextOverridesApply(t *testing.T) {
	master := &Resume{
		Basics: Basics{Name: "Jordan Rivera", Label: "Line Cook", Summary: "Master summary"},
	}
	override := "Tailored summary for this opportunity"
	labelOverride := "Kitchen Professional"
	target := &Target{
		ID:              "t1",
		Name:            "Tailored",
		SummaryOverride: &override,
		LabelOverride:   &labelOverride,
	}

	got := Resolve(master, target)

	if got.Basics.Summary != override {
		t.Errorf("expected the target's own SummaryOverride to apply, got %q", got.Basics.Summary)
	}
	if got.Basics.Label != labelOverride {
		t.Errorf("expected the target's own LabelOverride to apply, got %q", got.Basics.Label)
	}
	if got.Basics.Name != "Jordan Rivera" {
		t.Error("Basics.Name has no override field and must pass through unchanged")
	}
}

func TestResolve_NilOverridesLeaveMasterTextUnchanged(t *testing.T) {
	master := &Resume{Basics: Basics{Summary: "Master summary", Label: "Master label"}}
	target := &Target{ID: "t1", Name: "No overrides"}

	got := Resolve(master, target)

	if got.Basics.Summary != "Master summary" {
		t.Errorf("a nil SummaryOverride must leave the master's own summary unchanged, got %q", got.Basics.Summary)
	}
	if got.Basics.Label != "Master label" {
		t.Errorf("a nil LabelOverride must leave the master's own label unchanged, got %q", got.Basics.Label)
	}
}

func TestResolve_DoesNotMutateMaster(t *testing.T) {
	master := &Resume{
		Work: []Work{{ID: "w1"}, {ID: "w2"}},
	}
	target := &Target{ID: "t1", IncludedWorkIDs: []string{"w1"}}

	_ = Resolve(master, target)

	if len(master.Work) != 2 {
		t.Fatalf("Resolve must never mutate the real master resume it was given, master.Work is now: %+v", master.Work)
	}
}
