package resume

import "testing"

// TestSortByRecency_NewOngoingEntryMovesToTop -- the real, exact bug report (kanban card
// CVB-12434, founder real-time): "the work history needs to auto sort i put a new one
// 2006-present and it went to the bottom of the resume instead of the top." Two OLD, already-
// ended jobs are inserted first, then a brand-new ongoing one ("2006-present" i.e. a real
// StartDate with no EndDate) is appended LAST -- exactly reproducing the reported sequence --
// and must end up FIRST after sorting.
func TestSortByRecency_NewOngoingEntryMovesToTop(t *testing.T) {
	r := &Resume{
		Work: []Work{
			{Name: "Old Co", StartDate: "2010-01", EndDate: "2015-01"},
			{Name: "Newer Co", StartDate: "2015-02", EndDate: "2020-01"},
			{Name: "Current Co", StartDate: "2006", EndDate: ""}, // the newly-added, ongoing entry
		},
	}
	SortByRecency(r)
	if r.Work[0].Name != "Current Co" {
		t.Fatalf("expected the ongoing entry to sort to the TOP regardless of insertion order, got order: %v", workNames(r.Work))
	}
	if r.Work[1].Name != "Newer Co" || r.Work[2].Name != "Old Co" {
		t.Fatalf("expected the two ended jobs to still sort most-recent-end-date-first, got order: %v", workNames(r.Work))
	}
}

func TestSortByRecency_TwoOngoingEntriesBreakTiesByStartDate(t *testing.T) {
	r := &Resume{
		Work: []Work{
			{Name: "Older Ongoing", StartDate: "2018-01"},
			{Name: "Newer Ongoing", StartDate: "2023-06"},
		},
	}
	SortByRecency(r)
	if r.Work[0].Name != "Newer Ongoing" {
		t.Fatalf("expected the more recently STARTED ongoing entry to rank first as a tie-breaker, got order: %v", workNames(r.Work))
	}
}

func TestSortByRecency_EducationAndAwardsSortTheSameWay(t *testing.T) {
	r := &Resume{
		Education: []Education{
			{Institution: "Old School", StartDate: "2000", EndDate: "2004"},
			{Institution: "New School", StartDate: "2020", EndDate: "2022"},
		},
		Awards: []Award{
			{Title: "Old Award", Date: "2015"},
			{Title: "New Award", Date: "2024"},
		},
	}
	SortByRecency(r)
	if r.Education[0].Institution != "New School" {
		t.Fatalf("expected Education to sort most-recent-first too, got: %+v", r.Education)
	}
	if r.Awards[0].Title != "New Award" {
		t.Fatalf("expected Awards to sort most-recent-first too, got: %+v", r.Awards)
	}
}

func TestSortByRecency_ToleratesEmptyAndMalformedDates(t *testing.T) {
	// Real, honest edge case: a genuinely blank entry (no dates at all -- distinct from a real
	// "2006-present" entry, which DOES have a real start date) must not panic, and a malformed
	// date string must degrade to sorting as the oldest/earliest rather than erroring.
	r := &Resume{
		Work: []Work{
			{Name: "Totally Blank"},
			{Name: "Malformed", StartDate: "not-a-date", EndDate: "also-not-a-date"},
			{Name: "Real Entry", StartDate: "2020", EndDate: "2021"},
		},
	}
	SortByRecency(r) // must not panic
	if len(r.Work) != 3 {
		t.Fatalf("expected all 3 entries to survive sorting, got %d", len(r.Work))
	}
}

func TestSortByRecency_StableForEntriesWithIdenticalDates(t *testing.T) {
	// sort.SliceStable -- two entries with the identical real recency key must keep their
	// original relative order rather than being shuffled arbitrarily.
	r := &Resume{
		Work: []Work{
			{Name: "First", StartDate: "2020", EndDate: "2021"},
			{Name: "Second", StartDate: "2020", EndDate: "2021"},
		},
	}
	SortByRecency(r)
	if r.Work[0].Name != "First" || r.Work[1].Name != "Second" {
		t.Fatalf("expected a stable sort to preserve original order for identical dates, got: %v", workNames(r.Work))
	}
}

func TestDateSortKey_RealFormats(t *testing.T) {
	cases := []struct {
		date string
		want int
	}{
		{"", 0},
		{"2020", 20201231},
		{"2020-06", 20200631},
		{"2020-06-15", 20200615},
		{"garbage", 0},
	}
	for _, c := range cases {
		got := dateSortKey(c.date)
		if got != c.want {
			t.Errorf("dateSortKey(%q) = %d, want %d", c.date, got, c.want)
		}
	}
}

func workNames(work []Work) []string {
	names := make([]string, len(work))
	for i, w := range work {
		names[i] = w.Name
	}
	return names
}
