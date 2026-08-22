package api

import "testing"

func TestComposeQuotedEscapesDollar(t *testing.T) {
	got := composeQuoted("pa$$word")
	want := `"pa$$$$word"`
	if got != want {
		t.Fatalf("composeQuoted() = %q, want %q", got, want)
	}
}
