package store

import "testing"

func TestHashAgentSecret_Deterministic(t *testing.T) {
	h1 := hashAgentSecret("agent-1", "mysecret")
	h2 := hashAgentSecret("agent-1", "mysecret")
	if h1 != h2 {
		t.Errorf("same inputs produced different hashes: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex string, got len %d: %q", len(h1), h1)
	}
}

func TestHashAgentSecret_DifferentInputs(t *testing.T) {
	h1 := hashAgentSecret("agent-1", "secret-A")
	h2 := hashAgentSecret("agent-1", "secret-B")
	h3 := hashAgentSecret("agent-2", "secret-A")
	if h1 == h2 {
		t.Error("different secrets should produce different hashes")
	}
	if h1 == h3 {
		t.Error("different agent IDs should produce different hashes (salt prevents precomputation)")
	}
}
