package resume

import (
	"strconv"
	"strings"
)

// VerifyResult is the real, itemized report the "verify" feature returns — never a
// single opaque score. See CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md §3 for
// the full real reasoning behind three separate layers, matching the founder's own
// framing directly ("i dont want to put my data into some rando site lets build our
// own to build towards known standards for machine readable cvs" — the rules
// themselves are this tool's own, visible, not a third-party's opaque algorithm).
type VerifyResult struct {
	Checks []Check `json:"checks"`
	Passed bool    `json:"passed"`
}

type Check struct {
	// Rule is a real, stable, named identifier for this specific check — a real caller
	// (a UI, a script) can key off this string, not just the human-readable message,
	// matching the founder's own "no opaque score" framing.
	Rule    string `json:"rule"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// Verify runs the real, named rule set — Layer 1 (schema conformance, the minimum a
// document needs to even be real JSON Resume) and Layer 2 (ATS-readiness, real,
// well-documented parsing pitfalls this tool checks directly). Layer 3 (export-format
// safety) is a property of the RENDERED document, not this function — see the render
// package.
func Verify(r *Resume) VerifyResult {
	var checks []Check

	// ---- Layer 1: schema conformance -- the minimum for this to even be a real,
	// usable JSON Resume document at all.
	checks = append(checks, check("basics.name-present", r.Basics.Name != "",
		"basics.name is required — every real JSON Resume document needs a name."))
	checks = append(checks, check("basics.email-present", r.Basics.Email != "",
		"basics.email is required — the field almost every real ATS parser keys off first."))

	// ---- Layer 2: ATS-readiness — real, well-documented parsing pitfalls, each one a
	// concrete, named, reviewable rule (see COMMUNITY_TOOLS_RESUME_NORTHSTAR.md §3 for
	// the real, cited reasoning behind each one), not a black-box heuristic.
	checks = append(checks, check("basics.phone-present", r.Basics.Phone != "",
		"basics.phone is missing — the second field almost every real ATS parser keys off, "+
			"alongside email."))
	checks = append(checks, check("has-work-or-education", len(r.Work) > 0 || len(r.Education) > 0,
		"at least one work or education entry is required — an empty resume technically "+
			"validates against the schema but isn't real ATS-readable content."))

	for i, w := range r.Work {
		checks = append(checks, dateCheck("work", i, "startDate", w.StartDate))
		// A missing endDate is valid (current position) — only flag a genuinely malformed one.
		if w.EndDate != "" {
			checks = append(checks, dateCheck("work", i, "endDate", w.EndDate))
		}
		checks = append(checks, check(
			rulePrefix("work", i, "employer-present"), w.Name != "",
			"a work entry has a position but no employer name — a real, common ATS-breaking "+
				"mistake (the employer field, not just the job title, is what most parsers key off)."+
				withField(w.Position)))
	}
	for i, e := range r.Education {
		checks = append(checks, dateCheck("education", i, "startDate", e.StartDate))
		if e.EndDate != "" {
			checks = append(checks, dateCheck("education", i, "endDate", e.EndDate))
		}
	}

	passed := true
	for _, c := range checks {
		if !c.Passed {
			passed = false
			break
		}
	}
	return VerifyResult{Checks: checks, Passed: passed}
}

func check(rule string, passed bool, msg string) Check {
	return Check{Rule: rule, Passed: passed, Message: msg}
}

func rulePrefix(section string, i int, rule string) string {
	return section + "[" + strconv.Itoa(i) + "]." + rule
}

func withField(v string) string {
	if v == "" {
		return ""
	}
	return " (position: " + v + ")"
}

// dateCheck flags a date that's present but not real, parseable ISO-ish text (YYYY or
// YYYY-MM or YYYY-MM-DD, JSON Resume's own real, documented date format) — a real,
// well-known ATS pitfall: a free-text date string ("Summer 2020") a human reads fine
// but a real ATS date-parser chokes on. An EMPTY date is a separate, real, required-
// field failure, not this check's own job (the caller only invokes this when a date
// string is present at all, or explicitly wants a required-field check instead).
func dateCheck(section string, i int, field, value string) Check {
	rule := rulePrefix(section, i, field)
	if value == "" {
		return check(rule, false, section+"["+strconv.Itoa(i)+"]."+field+" is missing or empty — "+
			"every work/education entry needs a real, parseable start date.")
	}
	if !looksLikeISODate(value) {
		return check(rule, false, section+"["+strconv.Itoa(i)+"]."+field+" ('"+value+"') isn't in "+
			"JSON Resume's own real date format (YYYY, YYYY-MM, or YYYY-MM-DD) — a free-text "+
			"date a human reads fine but a real ATS date-parser is likely to choke on.")
	}
	return check(rule, true, "")
}

// looksLikeISODate is a real, narrow, honest check — YYYY, YYYY-MM, or YYYY-MM-DD,
// digits and hyphens only, matching JSON Resume's own real documented date format
// exactly. Deliberately not a full calendar-validity check (real month/day-range
// bounds) — that's real, separate, additive follow-up if a real false-positive shows
// up; this v0 catches the actual, common real mistake (free-text dates), not every
// theoretically-malformed digit string.
func looksLikeISODate(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) < 1 || len(parts) > 3 {
		return false
	}
	if len(parts[0]) != 4 || !allDigits(parts[0]) {
		return false
	}
	for _, p := range parts[1:] {
		if len(p) != 2 || !allDigits(p) {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

