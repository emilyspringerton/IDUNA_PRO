package resume

import "testing"

func TestGroupSkillsByCategory_CanonicalOrderOtherLast(t *testing.T) {
	skills := []Skill{
		{Name: "Leadership"}, // no category -> Other
		{Name: "Go", Category: "Backend & APIs"},
		{Name: "React", Category: "Frontend"},
		{Name: "Team leadership", Category: "Leadership & Process"},
		{Name: "PostgreSQL", Category: "Databases"},
	}
	groups := GroupSkillsByCategory(skills)

	if len(groups) != 5 {
		t.Fatalf("expected 5 real buckets (4 canonical categories present + Other), got %d: %+v", len(groups), groups)
	}
	// Canonical categories must appear in SkillCategories' own declared order, regardless of the
	// order skills were given in -- an employer scanning always sees Backend & APIs before
	// Frontend before Databases before Leadership & Process, not whatever order the data happened
	// to arrive in.
	wantOrder := []string{"Backend & APIs", "Frontend", "Databases", "Leadership & Process", SkillCategoryOther}
	for i, g := range groups {
		if g.Category != wantOrder[i] {
			t.Errorf("bucket %d: got category %q, want %q (full order: %+v)", i, g.Category, wantOrder[i], groups)
		}
	}
	if groups[len(groups)-1].Category != SkillCategoryOther {
		t.Fatalf("Other must sort last, got last bucket %q", groups[len(groups)-1].Category)
	}
	if len(groups[len(groups)-1].Skills) != 1 || groups[len(groups)-1].Skills[0].Name != "Leadership" {
		t.Fatalf("expected the uncategorized 'Leadership' skill in the Other bucket, got %+v", groups[len(groups)-1])
	}
}

func TestGroupSkillsByCategory_EmptyCategoryTreatedAsOther(t *testing.T) {
	skills := []Skill{{Name: "Excel"}, {Name: "PowerPoint", Category: "Other"}}
	groups := GroupSkillsByCategory(skills)
	if len(groups) != 1 {
		t.Fatalf("an empty Category and an explicit 'Other' Category must land in the SAME bucket, got %d buckets: %+v", len(groups), groups)
	}
	if groups[0].Category != SkillCategoryOther || len(groups[0].Skills) != 2 {
		t.Fatalf("expected one Other bucket with both skills, got %+v", groups[0])
	}
}

func TestGroupSkillsByCategory_UnrecognizedCategoryNeverDropped(t *testing.T) {
	// A stale category value (e.g. from an older AI run, or a hand-typed value that doesn't
	// exactly match one of the six canonical strings) must still render SOMEWHERE, never
	// silently vanish -- this is a resume; a missing skill is a real, meaningful data-loss bug.
	skills := []Skill{{Name: "Woodworking", Category: "Hobbies"}}
	groups := GroupSkillsByCategory(skills)
	if len(groups) != 1 || groups[0].Category != "Hobbies" || len(groups[0].Skills) != 1 {
		t.Fatalf("an unrecognized category must still appear as its own real bucket, got %+v", groups)
	}
}

func TestGroupSkillsByCategory_PreservesWithinBucketOrder(t *testing.T) {
	skills := []Skill{
		{Name: "Java", Category: "Backend & APIs"},
		{Name: "Python", Category: "Backend & APIs"},
		{Name: "Golang", Category: "Backend & APIs"},
	}
	groups := GroupSkillsByCategory(skills)
	if len(groups) != 1 {
		t.Fatalf("expected one bucket, got %d", len(groups))
	}
	got := []string{groups[0].Skills[0].Name, groups[0].Skills[1].Name, groups[0].Skills[2].Name}
	want := []string{"Java", "Python", "Golang"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("within-bucket order not preserved: got %v, want %v", got, want)
		}
	}
}

func TestGroupSkillsByCategory_EmptyInputProducesNoBuckets(t *testing.T) {
	groups := GroupSkillsByCategory(nil)
	if len(groups) != 0 {
		t.Fatalf("expected zero buckets for zero skills, got %d: %+v", len(groups), groups)
	}
}
