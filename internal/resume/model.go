// Package resume defines CarePyre's own real "community tools" resume/CV builder data
// model — a direct, field-for-field mirror of the real JSON Resume schema
// (jsonresume.org, fetched and checked live, not assumed from memory), the actual
// "known standard for machine readable CVs" the founder's own framing named. See
// CarePyre/docs/COMMUNITY_TOOLS_RESUME_NORTHSTAR.md §2 for the full real reasoning
// behind mirroring the schema directly rather than inventing a CarePyre-specific
// shape: a user's data stays trivially exportable as valid JSON Resume, and "does this
// conform to the known standard" is a real, mechanical structural question, not a
// subjective one.
//
// Real, honest history: originally scoped and built as its own standalone app
// (CVBuilder, backed by a dedicated IDUNA_PRO instance) before the founder's own
// real-time correction — "build it into carepyre... as part of the community tools" —
// redirected it here, reusing CarePyre's own already-live IDUNA_PRO instance instead.
// This package is the one real piece of that original work carried over unchanged: the
// data model itself never depended on which app hosted it.
//
// Every field uses `omitempty` so a genuinely absent section serializes as a real,
// valid JSON Resume document (the schema itself makes every section optional except
// `basics`) rather than a document cluttered with empty arrays/objects a real JSON
// Resume consumer would have to specially tolerate.
package resume

// Resume is the real, top-level document — one per user in CVBuilder's own v0 scope
// (NORTHSTAR.md §6 Phase 1: "one resume per authenticated user to start").
type Resume struct {
	Basics       Basics        `json:"basics"`
	Work         []Work        `json:"work,omitempty"`
	Volunteer    []Volunteer   `json:"volunteer,omitempty"`
	Education    []Education   `json:"education,omitempty"`
	Awards       []Award       `json:"awards,omitempty"`
	Certificates []Certificate `json:"certificates,omitempty"`
	Publications []Publication `json:"publications,omitempty"`
	Skills       []Skill       `json:"skills,omitempty"`
	Languages    []Language    `json:"languages,omitempty"`
	Interests    []Interest    `json:"interests,omitempty"`
	References   []Reference   `json:"references,omitempty"`
	Projects     []Project     `json:"projects,omitempty"`
	Meta         *Meta         `json:"meta,omitempty"`
}

type Location struct {
	Address     string `json:"address,omitempty"`
	PostalCode  string `json:"postalCode,omitempty"`
	City        string `json:"city,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	Region      string `json:"region,omitempty"`
}

type Profile struct {
	Network  string `json:"network,omitempty"`
	Username string `json:"username,omitempty"`
	URL      string `json:"url,omitempty"`
}

type Basics struct {
	Name     string    `json:"name,omitempty"`
	Label    string    `json:"label,omitempty"`
	Image    string    `json:"image,omitempty"`
	Email    string    `json:"email,omitempty"`
	Phone    string    `json:"phone,omitempty"`
	URL      string    `json:"url,omitempty"`
	Summary  string    `json:"summary,omitempty"`
	Location Location  `json:"location,omitempty"`
	Profiles []Profile `json:"profiles,omitempty"`
}

type Work struct {
	// ID -- founder real-time, 2026-09-09: "we need to be able to build the resume as data
	// like certain jobs we can show and hide from a specific target resume." A real,
	// deliberate CarePyre extension beyond strict JSON Resume (jsonresume.org's own schema has
	// no id field on a work entry) -- needed so a real, named Target (target.go) can reference
	// a specific entry stably, surviving reordering/edits to OTHER entries, the same real
	// reason any list-of-records needs a stable key rather than array position. Auto-assigned
	// server-side (SaveMasterResume, community_tools.go) whenever a saved entry arrives with
	// no ID (a genuinely new entry) -- the client never needs a UUID library. Exported (not
	// internal-only) so a real client fetching the master resume can see and reference these
	// same IDs when building/editing a Target's own selection.
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Location    string   `json:"location,omitempty"`
	Description string   `json:"description,omitempty"`
	Position    string   `json:"position,omitempty"`
	URL         string   `json:"url,omitempty"`
	StartDate   string   `json:"startDate,omitempty"`
	EndDate     string   `json:"endDate,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Highlights  []string `json:"highlights,omitempty"`
}

type Volunteer struct {
	Organization string   `json:"organization,omitempty"`
	Position     string   `json:"position,omitempty"`
	URL          string   `json:"url,omitempty"`
	StartDate    string   `json:"startDate,omitempty"`
	EndDate      string   `json:"endDate,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Highlights   []string `json:"highlights,omitempty"`
}

type Education struct {
	// ID -- see Work.ID's own doc comment; identical real reasoning, applied here too.
	ID          string   `json:"id,omitempty"`
	Institution string   `json:"institution,omitempty"`
	URL         string   `json:"url,omitempty"`
	Area        string   `json:"area,omitempty"`
	StudyType   string   `json:"studyType,omitempty"`
	StartDate   string   `json:"startDate,omitempty"`
	EndDate     string   `json:"endDate,omitempty"`
	Score       string   `json:"score,omitempty"`
	Courses     []string `json:"courses,omitempty"`
}

type Award struct {
	// ID -- see Work.ID's own doc comment for the full real reasoning. Founder real-time, same
	// day: "the pattern probably applies to education awards experience skills" -- Award gets
	// the identical real targeting mechanism.
	ID      string `json:"id,omitempty"`
	Title   string `json:"title,omitempty"`
	Date    string `json:"date,omitempty"`
	Awarder string `json:"awarder,omitempty"`
	Summary string `json:"summary,omitempty"`
}

type Certificate struct {
	Name   string `json:"name,omitempty"`
	Date   string `json:"date,omitempty"`
	URL    string `json:"url,omitempty"`
	Issuer string `json:"issuer,omitempty"`
}

type Publication struct {
	Name        string `json:"name,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	ReleaseDate string `json:"releaseDate,omitempty"`
	URL         string `json:"url,omitempty"`
	Summary     string `json:"summary,omitempty"`
}

type Skill struct {
	// ID -- see Work.ID's own doc comment for the full real reasoning. Founder real-time,
	// same day: "this is probably most useful in the skills section" -- real-world resume
	// tailoring commonly means emphasizing a different SKILL SUBSET per opportunity (e.g.
	// "Python, Data Analysis" for one role vs. "Customer Service, POS Systems" for another)
	// at least as often as hiding a whole job, so Skill gets the identical real targeting
	// mechanism Work/Education already have.
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Level    string   `json:"level,omitempty"`
	Keywords []string `json:"keywords,omitempty"`
}

type Language struct {
	Language string `json:"language,omitempty"`
	Fluency  string `json:"fluency,omitempty"`
}

type Interest struct {
	Name     string   `json:"name,omitempty"`
	Keywords []string `json:"keywords,omitempty"`
}

type Reference struct {
	Name      string `json:"name,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type Project struct {
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Highlights  []string `json:"highlights,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	StartDate   string   `json:"startDate,omitempty"`
	EndDate     string   `json:"endDate,omitempty"`
	URL         string   `json:"url,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Entity      string   `json:"entity,omitempty"`
	Type        string   `json:"type,omitempty"`
}

type Meta struct {
	Canonical    string `json:"canonical,omitempty"`
	Version      string `json:"version,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}
