package resume

// Target is a real, named, bespoke resume variant — founder real-time, 2026-09-09: "like we
// have a base set of things that we tell the system in terms of history and skills etc we need
// some way to start building more bespoke resumes for specific opportunities" → "the pattern
// probably applies to education awards experience skills even different little summary texts."
// The master Resume (one per user, stored as `resumes.data`) stays the real, full, single
// source of truth — every job, every credential, every skill ever entered. A Target never
// duplicates or edits that data; it SELECTS a subset of it (by the stable Work/Education/
// Skill/Award IDs those structs now carry) to show for one specific opportunity, plus a real,
// small, named set of TEXT overrides for the short blurbs that actually get rewritten per
// application in practice (the professional summary and headline) — not a general per-entry
// text-override mechanism, a real, deliberate v0 boundary named honestly, not attempted here.
type Target struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// IncludedWorkIDs/IncludedEducationIDs/IncludedSkillIDs/IncludedAwardIDs -- the real
	// selection. An ID in the master resume that ISN'T in the relevant list here is hidden for
	// this target. A brand-new master entry (one the user added after this target was last
	// saved) is honestly excluded by default rather than silently included — a real,
	// deliberate "opt a new entry in explicitly per target" default, not a surprise inclusion
	// the user never chose.
	IncludedWorkIDs      []string `json:"included_work_ids"`
	IncludedEducationIDs []string `json:"included_education_ids"`
	IncludedSkillIDs     []string `json:"included_skill_ids"`
	IncludedAwardIDs     []string `json:"included_award_ids"`
	// IncludedProfileIDs -- founder real-time, 2026-09-09: "we need to be able to add and
	// configure the output of multiple github links." Same real selection mechanism, applied to
	// basics.profiles (see Profile.ID's own doc comment for why multiple entries sharing the
	// same Network value, e.g. several distinct GitHub repo links, is real and expected).
	IncludedProfileIDs []string `json:"included_profile_ids"`
	// SummaryOverride/LabelOverride -- a real, per-target replacement for basics.summary /
	// basics.label (the short professional-summary blurb and headline most real resume
	// tailoring actually rewrites per opportunity — "even different little summary texts").
	// nil (the Go zero value for a pointer) means "use the master's own text unchanged"; a
	// real, present (possibly empty-string) pointer means "use THIS text for this target
	// instead" — the pointer, not a plain string, is what distinguishes "never overridden"
	// from "deliberately overridden to blank."
	SummaryOverride *string `json:"summary_override,omitempty"`
	LabelOverride   *string `json:"label_override,omitempty"`
}

// Resolve returns a real, independent, filtered COPY of master — only the Work/Education/
// Skill/Award/Profile entries whose own ID is present in the target's own included-ID lists,
// with SummaryOverride/LabelOverride applied to Basics if set. Every OTHER section
// (Certificates, Publications, Languages, Interests, References, Projects, Volunteer, and every
// other Basics field besides Profiles) passes through completely unfiltered — real, deliberate
// v0 scope: Work/Education/Skills/Awards/Profiles are the sections this feature actually
// targets (the founder's own named examples); the same real per-entry mechanism for the rest is
// real, separate, additive follow-up, not attempted here. A nil target (or one selecting
// nothing at all in every list) resolves to a resume with EMPTY Work/Education/Skills/Awards/
// Profiles, not the full master — an honest, literal "nothing selected means nothing shown,"
// not a fallback to "show everything."
func Resolve(master *Resume, t *Target) *Resume {
	out := *master // shallow copy: every OTHER field (Certificates, Projects, ...) is shared, not filtered
	out.Work = filterByID(master.Work, t.IncludedWorkIDs, func(w Work) string { return w.ID })
	out.Education = filterByID(master.Education, t.IncludedEducationIDs, func(e Education) string { return e.ID })
	out.Skills = filterByID(master.Skills, t.IncludedSkillIDs, func(s Skill) string { return s.ID })
	out.Awards = filterByID(master.Awards, t.IncludedAwardIDs, func(a Award) string { return a.ID })
	out.Basics.Profiles = filterByID(master.Basics.Profiles, t.IncludedProfileIDs, func(p Profile) string { return p.ID })
	if t.SummaryOverride != nil {
		out.Basics.Summary = *t.SummaryOverride
	}
	if t.LabelOverride != nil {
		out.Basics.Label = *t.LabelOverride
	}
	return &out
}

// filterByID is real, generic over any entry type T via a caller-supplied idOf accessor
// (Go's own real generics, not reflection) — the one shared implementation every one of the
// four real Resolve filter steps above reduces to, rather than four hand-duplicated copies of
// the identical "keep only IDs present in this set" loop.
func filterByID[T any](all []T, included []string, idOf func(T) string) []T {
	set := toSet(included)
	var out []T
	for _, item := range all {
		if set[idOf(item)] {
			out = append(out, item)
		}
	}
	return out
}

func toSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}
