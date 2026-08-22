package service

import "testing"

func TestParseRTSPTargetPrefersExplicitPort(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"111.35.74.14:4553", 4553},
		{"rtsp://111.35.74.14:4553/Streaming/Channels/101", 4553},
		{"111.35.74.14", 4554},
		{"rtsp://111.35.74.14/Streaming/Channels/101", 4554},
	}

	for _, item := range cases {
		target, err := parseRTSPTarget(item.input, 4554)
		if err != nil {
			t.Fatalf("parseRTSPTarget(%q) returned error: %v", item.input, err)
		}
		if target.Port != item.want {
			t.Fatalf("parseRTSPTarget(%q) port = %d, want %d", item.input, target.Port, item.want)
		}
	}
}
