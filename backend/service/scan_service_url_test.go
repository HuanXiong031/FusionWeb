package service

import "testing"

func TestNormalizeReconURLTarget(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "root with slash",
			in:   "http://60.2.205.198:8090/",
			want: "http://60.2.205.198:8090",
		},
		{
			name: "root without slash",
			in:   "http://60.2.205.198:8090",
			want: "http://60.2.205.198:8090",
		},
		{
			name: "non-root keeps trailing slash",
			in:   "http://example.com/admin/",
			want: "http://example.com/admin/",
		},
		{
			name: "normalizes scheme host and drops fragment",
			in:   "HTTP://Example.COM/#section",
			want: "http://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeReconURLTarget(tt.in); got != tt.want {
				t.Fatalf("normalizeReconURLTarget(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReconURLTargetVariants(t *testing.T) {
	variants := reconURLTargetVariants("http://60.2.205.198:8090/")
	if len(variants) != 2 {
		t.Fatalf("expected canonical and slash variants, got %#v", variants)
	}
	if variants[0] != "http://60.2.205.198:8090" || variants[1] != "http://60.2.205.198:8090/" {
		t.Fatalf("unexpected variants: %#v", variants)
	}
}

func TestProtocolTargetURLUsesDetectedProtocolOnly(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		service  string
		want     string
	}{
		{
			name:     "detected ftp keeps scheme",
			protocol: "ftp",
			want:     "ftp://192.168.102.129:21",
		},
		{
			name:     "tcp without detected service is bare host port",
			protocol: "tcp",
			want:     "192.168.102.129:5040",
		},
		{
			name:     "guessed service is not passed into URL scheme",
			protocol: "tcp",
			service:  "",
			want:     "192.168.102.129:5040",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostPort := "192.168.102.129:5040"
			if tt.protocol == "ftp" {
				hostPort = "192.168.102.129:21"
			}
			if got := protocolTargetURL(hostPort, tt.protocol, tt.service); got != tt.want {
				t.Fatalf("protocolTargetURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectedPortServiceIgnoresGuessedService(t *testing.T) {
	extra := map[string]interface{}{
		"protocol":        "tcp",
		"service":         "smtp",
		"guessed_service": "smtp",
	}
	if got := detectedPortService(extra); got != "" {
		t.Fatalf("detectedPortService() = %q, want empty", got)
	}
}
