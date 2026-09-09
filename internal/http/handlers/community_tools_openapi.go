package handlers

import (
	_ "embed"
	"net/http"
)

// communityToolsOpenAPISpec -- the real, machine-readable schema for every Community Tools
// resume/target route, embedded directly into the binary at compile time (no runtime file
// dependency, matching this whole feature's own no-cgo/self-contained discipline). Founder
// real-time, 2026-09-09: "ensure that all of the features we have have good api because i am
// going to ask agents to work with those primitives" -- an agent bootstrapping against this API
// can fetch this document instead of needing to read Go source. Real, genuine JSON (not YAML
// served under a misleading ".json" URL) -- OpenAPI supports JSON natively, so the served
// content type and the URL's own extension actually agree.
//
//go:embed openapi/community_tools.json
var communityToolsOpenAPISpec []byte

// CommunityToolsOpenAPIHandler serves GET /api/v1/community-tools/openapi.json — deliberately
// public (no auth, no community-tools.access check): this document describes the SHAPE of the
// API, not any caller's own data, the same real reasoning JWKSHandler already applies to its
// own public key set.
type CommunityToolsOpenAPIHandler struct{}

func (h *CommunityToolsOpenAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(communityToolsOpenAPISpec)
}
