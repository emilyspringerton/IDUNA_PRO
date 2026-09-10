// community_tools_skills_categorize.go — real Vertex AI auto-categorization for a resume's own
// Skills section (founder real-time, 2026-09-10, direct employer-scan feedback on the rendered
// resume: "Skills section is a dump -- it's alphabetical chaos. Employers scan, they don't read
// linearly... I think we need to build google vertex AI into it like we have for the
// DragonsNShit item builder so that vertex can auto organize the skills for us perhaps even into
// categories"). Reuses the exact real Vertex AI credential/call pattern IDUNA's own GFD Item
// Builder already established (`IDUNA/internal/http/handlers/gfd_item_proposals.go`): real ADC
// via `gcloud auth print-access-token` (no static API key stored anywhere), the same
// project-d24a71e9-2daf-4b2d-917/us-central1 project, gemini-2.5-flash, and
// `generationConfig.responseMimeType: application/json` so the model's own response is real,
// direct JSON with no markdown-fence stripping needed — duplicated rather than imported since
// IDUNA and IDUNA_PRO are separate Go modules with no shared internal package for this today
// (same real reason gfd_item_proposals.go itself duplicates emily.cli's own gcloudAccessToken).
//
// One real, deliberate difference from that file's own per-item design: categorization sends the
// caller's WHOLE uncategorized skill list in a single Vertex call (cheaper, faster, and lets the
// model see the full list at once for more internally-consistent bucketing) rather than one call
// per skill.
//
// Real, deliberate scope: only skills with an empty Category are ever sent for categorization --
// a skill a user (or a prior run of this same endpoint) already categorized keeps that value
// untouched, so clicking "Auto-organize with AI" again is always safe and never silently
// overwrites a manual correction.
package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"idunapro/internal/resume"
)

const (
	resumeSkillsVertexProject = "project-d24a71e9-2daf-4b2d-917"
	resumeSkillsVertexRegion  = "us-central1"
	resumeSkillsVertexModel   = "gemini-2.5-flash"
)

// CommunityToolsSkillsCategorizeHandler serves POST /api/v1/community-tools/resume/skills/categorize.
// Registered as its own exact-path mux entry in main.go, alongside (not instead of) the generic
// CommunityToolsEntryHandler[resume.Skill] registered at the "/resume/skills/" subtree prefix --
// Go's net/http ServeMux always prefers an exact-path match over a subtree ("/...) one, so this
// specific path is never swallowed by the generic per-ID PATCH/DELETE handler.
type CommunityToolsSkillsCategorizeHandler struct {
	DB *sql.DB
}

func (h *CommunityToolsSkillsCategorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	uidPtr := callerLocalUID(r)
	if uidPtr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	uid := *uidPtr

	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var names []string
	for i := range res.Skills {
		if res.Skills[i].Category == "" && res.Skills[i].Name != "" {
			names = append(names, res.Skills[i].Name)
		}
	}
	if len(names) == 0 {
		// Real, honest no-op: nothing uncategorized to do, not an error -- the same "an empty
		// resume is a real, valid starting state" judgment call this whole feature already makes
		// elsewhere (CommunityToolsHandler.get's own doc comment).
		writeJSON(w, http.StatusOK, res.Skills)
		return
	}

	token, err := gcloudAccessTokenForResumeSkills()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "vertex auth: " + err.Error()})
		return
	}

	assigned, err := categorizeSkills(r.Context(), token, names)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "vertex: " + err.Error()})
		return
	}

	// Matched back case-insensitively by name -- the model is asked to echo each name back
	// verbatim, but never TRUSTED to: a returned name that doesn't match anything on the caller's
	// own list is simply not applied to any skill, never guessed onto the wrong one.
	for i := range res.Skills {
		if res.Skills[i].Category != "" {
			continue
		}
		if cat, ok := assigned[strings.ToLower(strings.TrimSpace(res.Skills[i].Name))]; ok {
			res.Skills[i].Category = cat
		}
	}

	if err := saveResume(r.Context(), h.DB, uid, res); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, res.Skills)
}

// gcloudAccessTokenForResumeSkills mirrors gfd_item_proposals.go's own real
// gcloudAccessTokenForItemProposals exactly (real ADC via the gcloud CLI, no static API key).
func gcloudAccessTokenForResumeSkills() (string, error) {
	out, err := exec.Command("gcloud", "auth", "print-access-token").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// categorizeSkills asks Vertex to bucket every given name into one of resume.SkillCategories (or
// resume.SkillCategoryOther) in a single real call, returning a lowercased-trimmed-name ->
// category map. Any category the model returns that isn't one of the real, known values is
// normalized to resume.SkillCategoryOther rather than trusted verbatim -- the caller (Skills
// grouping) needs to be able to rely on every stored Category being one of the real, known
// buckets.
func categorizeSkills(ctx context.Context, token string, names []string) (map[string]string, error) {
	prompt := fmt.Sprintf(`You are organizing the Skills section of a resume so a real human recruiter can scan it quickly, not a machine. Bucket EACH of the following skill names into exactly one of these categories:
- %s
- %s (use this ONLY if a skill genuinely fits none of the categories above)

Real guidance on how to group: programming languages, backend frameworks, API design/auth concepts (REST, GraphQL, OAuth, JWT, RBAC) go under "Backend & APIs"; UI frameworks, markup/styling, and frontend build tooling go under "Frontend"; container/orchestration/deploy tooling and cloud-provider services go under "Cloud & Infrastructure"; threat modeling, zero trust, secure design, and compliance concepts go under "Security & Reliability"; database engines and query languages go under "Databases"; people/process/leadership skills go under "Leadership & Process".

Skill names (return every single one, do not skip any, do not rename or reword them -- echo each name back EXACTLY as given):
%s

Return ONLY a JSON array, one object per skill, each shaped exactly {"name": string, "category": string}.`, strings.Join(resume.SkillCategories, "\n- "), resume.SkillCategoryOther, strings.Join(names, "\n"))

	url := fmt.Sprintf(
		"https://%s-aiplatform.googleapis.com/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		resumeSkillsVertexRegion, resumeSkillsVertexProject, resumeSkillsVertexRegion, resumeSkillsVertexModel,
	)
	body, _ := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{"role": "user", "parts": []map[string]string{{"text": prompt}}},
		},
		"generationConfig": map[string]any{"responseMimeType": "application/json"},
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vertex ai %d: %s", resp.StatusCode, string(raw))
	}

	return parseCategorizeVertexResponse(raw)
}

// parseCategorizeVertexResponse is the real, pure (no network) half of categorizeSkills' own
// work -- split out so the JSON-parsing/normalization logic is directly unit-testable against a
// canned Vertex response body, without needing a live gcloud-authenticated call (this sandbox has
// no active gcloud account, matching gfd_item_proposals.go's own real, live-verified-elsewhere
// precedent rather than something testable end to end in every environment).
func parseCategorizeVertexResponse(raw []byte) (map[string]string, error) {
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse vertex response: %w", err)
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		reason := "no candidates"
		if len(parsed.Candidates) > 0 {
			reason = parsed.Candidates[0].FinishReason
		}
		return nil, fmt.Errorf("no content in vertex response (finishReason=%q)", reason)
	}
	text := parsed.Candidates[0].Content.Parts[0].Text

	var pairs []struct {
		Name     string `json:"name"`
		Category string `json:"category"`
	}
	if err := json.Unmarshal([]byte(text), &pairs); err != nil {
		return nil, fmt.Errorf("model returned non-matching JSON: %w", err)
	}

	valid := map[string]bool{resume.SkillCategoryOther: true}
	for _, c := range resume.SkillCategories {
		valid[c] = true
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		cat := p.Category
		if !valid[cat] {
			cat = resume.SkillCategoryOther
		}
		out[strings.ToLower(strings.TrimSpace(p.Name))] = cat
	}
	return out, nil
}
