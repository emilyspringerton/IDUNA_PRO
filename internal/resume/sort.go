package resume

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

// SortByRecency reorders r.Work, r.Education, and r.Awards to the real, standard resume
// convention -- most recent first -- founder real-time, 2026-09-09 (via the IDUNA kanban board,
// CVB-12434): "the work history needs to auto sort i put a new one 2006-present and it went to
// the bottom of the resume instead of the top." Called from saveResume, the one real, shared
// persistence choke point every write path (the whole-document PUT and every single-entry
// POST/PATCH/DELETE primitive) already reduces to -- so the STORED, canonical order is always
// correct, and every reader (GET, the PDF export, a Target's own resolved view) sees it for
// free without duplicating this sort in multiple places.
//
// An entry with no end date (a currently-ongoing position) sorts as the MOST recent — the real,
// standard convention a current job is listed first, ahead of anything that already ended, no
// matter how recently. Awards get the identical real treatment via their own single Date field.
func SortByRecency(r *Resume) {
	sort.SliceStable(r.Work, func(i, j int) bool {
		return recencyKey(r.Work[i].StartDate, r.Work[i].EndDate) > recencyKey(r.Work[j].StartDate, r.Work[j].EndDate)
	})
	sort.SliceStable(r.Education, func(i, j int) bool {
		return recencyKey(r.Education[i].StartDate, r.Education[i].EndDate) > recencyKey(r.Education[j].StartDate, r.Education[j].EndDate)
	})
	sort.SliceStable(r.Awards, func(i, j int) bool {
		return dateSortKey(r.Awards[i].Date) > dateSortKey(r.Awards[j].Date)
	})
}

// recencyKey packs (end, start) into one comparable int64 so a single ">" comparison sorts by
// end date first, start date as the real tie-breaker (e.g. two positions that both ended in
// 2022 rank by which one started later) -- without needing a multi-field comparator. A missing
// end date (EndDate == "") is real, deliberate math.MaxInt32 -- "still ongoing" always outranks
// any entry with an actual end date, however recent.
func recencyKey(startDate, endDate string) int64 {
	end := int64(math.MaxInt32)
	if endDate != "" {
		end = int64(dateSortKey(endDate))
	}
	start := int64(dateSortKey(startDate))
	return end*100000000 + start
}

// dateSortKey converts a real JSON Resume date string (YYYY, YYYY-MM, or YYYY-MM-DD -- the same
// three real formats verify.go's own looksLikeISODate already establishes) into a comparable
// YYYYMMDD-shaped integer. A coarse, month/day-less date (just "2020") defaults the missing
// parts to the LATEST plausible value within that period (2020-12-31) -- this key is used to
// rank "most recent," so a year-only date should still compare sensibly against a more precise
// same-year date rather than always losing to it. An empty or unparseable string returns 0 --
// a real, honest "sorts as the oldest/earliest possible," never a guess at "now."
func dateSortKey(date string) int {
	if date == "" {
		return 0
	}
	parts := strings.SplitN(date, "-", 3)
	year, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	month, day := 12, 31
	if len(parts) > 1 {
		if m, err := strconv.Atoi(parts[1]); err == nil && m >= 1 && m <= 12 {
			month = m
		}
	}
	if len(parts) > 2 {
		if d, err := strconv.Atoi(parts[2]); err == nil && d >= 1 && d <= 31 {
			day = d
		}
	}
	return year*10000 + month*100 + day
}
