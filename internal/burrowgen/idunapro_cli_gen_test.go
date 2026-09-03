package burrowgen

import "testing"

// Real regression coverage for the PARENA-compiled decision logic behind `idunapro health` --
// generated code has DO NOT EDIT on it, but the real contract it implements (see
// PARENA/stdlib/idunapro/cli_mod.prn) is exactly what a real CLI host depends on, so it earns
// the same real test coverage any other hand-written package in this repo would.
//
// Real, third-pass update (2026-09-03): HealthMessage/HealthExitCode replaced
// InterpretHealthResponse/ExitCodeForHealth wholesale once BURROW's Go target shipped real
// match-on-a-user-defenum support -- PARENA now decides the presentation message directly
// (via ClassifyHealth -> HealthStatus), not just the pass/fail Result this file's own tests
// previously covered.

func TestClassifyHealth(t *testing.T) {
	if got := ClassifyHealth(200, true); got.Tag != 0 {
		t.Fatalf("expected Healthy (tag 0) for 200+ok, got %+v", got)
	}
	if got := ClassifyHealth(500, true); got.Tag != 1 {
		t.Fatalf("expected BadStatus (tag 1) for non-200, got %+v", got)
	}
	if got := ClassifyHealth(200, false); got.Tag != 2 {
		t.Fatalf("expected NotOk (tag 2) for 200+not-ok body, got %+v", got)
	}
}

func TestHealthMessage(t *testing.T) {
	if got := HealthMessage(200, true); got != "IDUNA_PRO instance is healthy" {
		t.Fatalf("unexpected healthy message: %q", got)
	}
	if got := HealthMessage(503, true); got != "unexpected HTTP status (real endpoint responded, but not with 200)" {
		t.Fatalf("unexpected bad-status message: %q", got)
	}
	if got := HealthMessage(200, false); got != "endpoint responded 200 but its own body reported not-ok" {
		t.Fatalf("unexpected not-ok message: %q", got)
	}
}

func TestHealthExitCode(t *testing.T) {
	if got := HealthExitCode(200, true); got != 0 {
		t.Fatalf("expected exit 0 for healthy, got %d", got)
	}
	if got := HealthExitCode(200, false); got != 1 {
		t.Fatalf("expected exit 1 for body not ok, got %d", got)
	}
	if got := HealthExitCode(503, true); got != 1 {
		t.Fatalf("expected exit 1 for bad status, got %d", got)
	}
}
