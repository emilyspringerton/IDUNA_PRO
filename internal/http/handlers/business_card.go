// Package handlers — business_card.go: real, new work, founder real-time (2026-09-22): "in
// carepyre if there is a resume configured can we generate some business card tools powered by
// the qr code stuff port it to IDUNAPRO."
//
// "if there is a resume configured" means a real, non-empty resume -- loadResume (community_
// tools.go) already returns a valid, empty *resume.Resume{} for a user who's never saved one
// (a real, deliberate "no error, just empty" design for the resume editor itself), so this file
// draws its own, explicit line: Basics.Name non-empty is what "configured" means here. An empty
// shell is not a business card.
//
// One QR code per user, deterministic slug "card-<uid>" (upserted, not re-created, every time --
// a second POST just retargets the SAME already-printed/saved QR image, the entire point of the
// qr.go registry this reuses via QRHandler.UpsertBySlug), pointing at this user's own real,
// public GET /card/{uid}.vcf -- a real vCard 3.0 (RFC 6350-shaped) document generated live from
// their saved resume Basics. Scanning the QR code offers "Add Contact" on essentially every real
// phone camera app -- the actual real-world behavior a "business card" QR code needs, not a
// generic webpage link.
package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"idunapro/internal/resume"
)

// BusinessCardHandler serves POST /api/v1/community-tools/business-card (community-tools.access
// gated, same as every other community-tools route in this file's own sibling
// community_tools.go).
type BusinessCardHandler struct {
	DB *sql.DB
	QR *QRHandler
	// PublicBaseURL is this server's own real public base URL (e.g.
	// https://console.carepyre.org) -- used to build the target_url the QR code points at
	// (/card/{uid}.vcf), independent of QR.BaseURL (which builds the /q/{slug} redirect URL
	// itself -- two real, separate URLs, only coincidentally often the same host).
	PublicBaseURL string
}

func (h *BusinessCardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load resume"})
		return
	}
	if strings.TrimSpace(res.Basics.Name) == "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "no resume configured yet -- add your name under Community Tools > Resume first",
		})
		return
	}

	slug := "card-" + strconv.Itoa(uid)
	targetURL := strings.TrimRight(h.PublicBaseURL, "/") + "/card/" + strconv.Itoa(uid) + ".vcf"
	label := "Business card: " + res.Basics.Name

	card, err := h.QR.UpsertBySlug(r.Context(), slug, targetURL, label, "user:"+strconv.Itoa(uid))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create business card QR code: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, card)
}

// BusinessCardVCardHandler serves the real, public GET /card/{uid}.vcf endpoint the QR code's
// own target_url points at -- no auth, matching app_releases.go's/qr.go's own established "write
// is gated, read/use is not" convention. A phone camera app fetches this directly.
type BusinessCardVCardHandler struct {
	DB *sql.DB
}

func (h *BusinessCardVCardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	uidStr := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/card/"), ".vcf")
	uid, err := strconv.Atoi(uidStr)
	if err != nil || uid <= 0 {
		http.NotFound(w, r)
		return
	}
	res, err := loadResume(r.Context(), h.DB, uid)
	if err != nil {
		http.Error(w, "could not load resume", http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(res.Basics.Name) == "" {
		http.NotFound(w, r)
		return
	}
	vcf := renderVCard(res.Basics)
	w.Header().Set("Content-Type", "text/vcard; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.vcf"`, vcardSafeFilename(res.Basics.Name)))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(vcf))
}

// vcardEscape applies RFC 6350's own real, required escaping for a vCard property VALUE:
// backslash, comma, semicolon, and newline each get backslash-escaped, in that order (backslash
// first, or a later escape's own inserted backslash would itself get re-escaped).
func vcardEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, ",", `\,`)
	s = strings.ReplaceAll(s, ";", `\;`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func vcardSafeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r == '/' || r == '\\' || r == '"' {
			b.WriteRune('_')
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if out == "" {
		return "contact"
	}
	return out
}

// renderVCard builds a real, minimal, valid vCard 3.0 document (RFC 6350's own predecessor
// format, still the most broadly compatible one across real phone contact apps -- 4.0 adds
// little a business card needs and support is less universal). FN/N are required by the spec;
// N is a real, best-effort split of Name into (family;given;;;) -- resume.Basics has no separate
// given/family fields, so a single-space split is the honest limit here, named not hidden.
func renderVCard(b resume.Basics) string {
	var sb strings.Builder
	sb.WriteString("BEGIN:VCARD\r\n")
	sb.WriteString("VERSION:3.0\r\n")
	sb.WriteString("FN:" + vcardEscape(b.Name) + "\r\n")

	given, family := b.Name, ""
	if i := strings.LastIndex(b.Name, " "); i >= 0 {
		given, family = b.Name[:i], b.Name[i+1:]
	}
	sb.WriteString("N:" + vcardEscape(family) + ";" + vcardEscape(given) + ";;;\r\n")

	if b.Label != "" {
		sb.WriteString("TITLE:" + vcardEscape(b.Label) + "\r\n")
	}
	if b.Email != "" {
		sb.WriteString("EMAIL;TYPE=INTERNET:" + vcardEscape(b.Email) + "\r\n")
	}
	if b.Phone != "" {
		sb.WriteString("TEL;TYPE=CELL:" + vcardEscape(b.Phone) + "\r\n")
	}
	if b.URL != "" {
		sb.WriteString("URL:" + vcardEscape(b.URL) + "\r\n")
	}
	if b.Summary != "" {
		sb.WriteString("NOTE:" + vcardEscape(b.Summary) + "\r\n")
	}
	if b.Location.City != "" || b.Location.Region != "" || b.Location.CountryCode != "" {
		sb.WriteString("ADR;TYPE=WORK:;;" + vcardEscape(b.Location.Address) + ";" +
			vcardEscape(b.Location.City) + ";" + vcardEscape(b.Location.Region) + ";" +
			vcardEscape(b.Location.PostalCode) + ";" + vcardEscape(b.Location.CountryCode) + "\r\n")
	}
	for _, p := range b.Profiles {
		if p.URL != "" {
			sb.WriteString("URL;TYPE=" + vcardEscape(strings.ToUpper(orDefault(p.Network, "PROFILE"))) + ":" + vcardEscape(p.URL) + "\r\n")
		}
	}
	sb.WriteString("END:VCARD\r\n")
	return sb.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
