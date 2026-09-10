package resume

// skill_categories.go -- the real, founder-specified Skills grouping (founder real-time,
// 2026-09-10, direct employer-scan feedback on the rendered resume: "Skills section is a dump --
// it's alphabetical chaos. Employers scan, they don't read linearly... Reorganize by category").
// SkillCategories names the exact six buckets given: Backend & APIs, Frontend, Cloud &
// Infrastructure, Security & Reliability, Databases, Leadership & Process. SkillCategoryOther is
// the real, honest catch-all for anything that genuinely fits none of the six -- never a reason
// to drop a skill silently.
//
// A Skill's own Category field (model.go) is populated either manually or via the real Vertex AI
// auto-categorize endpoint (community_tools_skills_categorize.go); GroupSkillsByCategory is the
// one real, shared bucketing choke point both pdf.go and any future screen-rendering helper
// should use, so the PDF export and the on-screen preview never drift into two different
// groupings of the same data.
var SkillCategories = []string{
	"Backend & APIs",
	"Frontend",
	"Cloud & Infrastructure",
	"Security & Reliability",
	"Databases",
	"Leadership & Process",
}

// SkillCategoryOther is used both as the real fallback bucket label and to normalize an empty
// Category field for grouping purposes -- a skill with no Category set renders in the same
// bucket as one explicitly marked "Other", never in a bucket of its own.
const SkillCategoryOther = "Other"

// SkillGroup is one real, named bucket of skills, in the order GroupSkillsByCategory decided.
type SkillGroup struct {
	Category string
	Skills   []Skill
}

// GroupSkillsByCategory buckets skills by their own Category field (empty treated as
// SkillCategoryOther), ordered: the six canonical SkillCategories first (only buckets that
// actually have a skill in them), then SkillCategoryOther, then any unrecognized category value
// (a stale AI run using a slightly different label, or a manual edit) in first-seen order -- a
// skill is never dropped just because its own category doesn't match anything expected. Each
// bucket's own skills keep their original relative order.
func GroupSkillsByCategory(skills []Skill) []SkillGroup {
	buckets := map[string][]Skill{}
	var firstSeenOrder []string
	for _, s := range skills {
		cat := s.Category
		if cat == "" {
			cat = SkillCategoryOther
		}
		if _, ok := buckets[cat]; !ok {
			firstSeenOrder = append(firstSeenOrder, cat)
		}
		buckets[cat] = append(buckets[cat], s)
	}

	var order []string
	seen := map[string]bool{}
	for _, cat := range SkillCategories {
		if len(buckets[cat]) > 0 {
			order = append(order, cat)
			seen[cat] = true
		}
	}
	if len(buckets[SkillCategoryOther]) > 0 {
		order = append(order, SkillCategoryOther)
		seen[SkillCategoryOther] = true
	}
	for _, cat := range firstSeenOrder {
		if !seen[cat] {
			order = append(order, cat)
			seen[cat] = true
		}
	}

	out := make([]SkillGroup, 0, len(order))
	for _, cat := range order {
		out = append(out, SkillGroup{Category: cat, Skills: buckets[cat]})
	}
	return out
}
