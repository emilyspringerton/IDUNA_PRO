package util

import "testing"

func TestNormalizeUserCode(t *testing.T) {
	got := NormalizeUserCode(" f4k7-9q2m ")
	if got != "F4K79Q2M" {
		t.Fatalf("unexpected normalized code: %s", got)
	}
}

func TestGenerateUserCodeNoAmbiguousChars(t *testing.T) {
	for i := 0; i < 100; i++ {
		display, norm, err := GenerateUserCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(display) != 9 || display[4] != '-' {
			t.Fatalf("bad display code format: %s", display)
		}
		for _, ch := range norm {
			if ch == 'I' || ch == 'L' || ch == 'O' || ch == 'U' || ch == '0' || ch == '1' {
				t.Fatalf("ambiguous char found: %s", norm)
			}
		}
	}
}
