package utils

import "testing"

func TestFormatTimeStringForDisplayKeepsLocalChinaTime(t *testing.T) {
	got := FormatTimeStringForDisplay("2026-07-14 22:19:11")
	want := "2026-07-14 22:19:11"
	if got != want {
		t.Fatalf("FormatTimeStringForDisplay() = %q, want %q", got, want)
	}
}

func TestFormatTimeStringForDisplayConvertsTimezoneToChinaTime(t *testing.T) {
	got := FormatTimeStringForDisplay("2026-07-14T14:19:11Z")
	want := "2026-07-14 22:19:11"
	if got != want {
		t.Fatalf("FormatTimeStringForDisplay() = %q, want %q", got, want)
	}
}

func TestFormatTimeStringForDisplayParsesGoTimeWithChinaZone(t *testing.T) {
	got := FormatTimeStringForDisplay("2026-07-23 21:08:10.6505578 +0800 CST")
	want := "2026-07-23 21:08:10"
	if got != want {
		t.Fatalf("FormatTimeStringForDisplay() = %q, want %q", got, want)
	}
}

func TestParseTimeStringWithoutTimezoneUsesChinaTime(t *testing.T) {
	got, err := ParseTimeString("2026-07-14T22:19:11")
	if err != nil {
		t.Fatalf("ParseTimeString() error = %v", err)
	}
	if got.Format("-0700") != "+0800" {
		t.Fatalf("ParseTimeString() timezone offset = %q, want +0800", got.Format("-0700"))
	}
	if got.Format(displayTimeFormat) != "2026-07-14 22:19:11" {
		t.Fatalf("ParseTimeString() formatted = %q", got.Format(displayTimeFormat))
	}
}
