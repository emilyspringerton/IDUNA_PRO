package burrowgen

import "testing"

// Real regression coverage for the PARENA-compiled decision logic behind `idunapro health` --
// generated code has DO NOT EDIT on it, but the real contract it implements (see
// PARENA/stdlib/idunapro/cli_mod.prn) is exactly what a real CLI host depends on, so it earns
// the same real test coverage any other hand-written package in this repo would.

func TestInterpretHealthResponse_Healthy(t *testing.T) {
	r := InterpretHealthResponse(200, true)
	if r.Tag != 1 || r.Value.(string) != "IDUNA_PRO instance is healthy" {
		t.Fatalf("expected Ok(healthy), got %+v", r)
	}
}

func TestInterpretHealthResponse_BadStatus(t *testing.T) {
	r := InterpretHealthResponse(500, true)
	if r.Tag != 0 {
		t.Fatalf("expected Err for non-200 status, got %+v", r)
	}
}

func TestInterpretHealthResponse_BodyNotOK(t *testing.T) {
	r := InterpretHealthResponse(200, false)
	if r.Tag != 0 {
		t.Fatalf("expected Err for body.ok=false, got %+v", r)
	}
}

func TestExitCodeForHealth(t *testing.T) {
	if got := ExitCodeForHealth(200, true); got != 0 {
		t.Fatalf("expected exit 0 for healthy, got %d", got)
	}
	if got := ExitCodeForHealth(200, false); got != 1 {
		t.Fatalf("expected exit 1 for body not ok, got %d", got)
	}
	if got := ExitCodeForHealth(503, true); got != 1 {
		t.Fatalf("expected exit 1 for bad status, got %d", got)
	}
}
