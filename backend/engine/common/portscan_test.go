package common

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

func TestIdentifyHTTPFallbackDetectsHTTPOnHighPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	result := identifyHTTPFallback(PortServiceResult{
		Host:     parsed.Hostname(),
		Port:     port,
		Protocol: "tcp",
		Address:  fmt.Sprintf("%s:%d", parsed.Hostname(), port),
	}, 1)

	if result.Protocol != "http" {
		t.Fatalf("expected http protocol, got %q", result.Protocol)
	}
	if result.Service != "HTTP" {
		t.Fatalf("expected HTTP service, got %q", result.Service)
	}
	if result.Banner == "" {
		t.Fatalf("expected HTTP status banner")
	}
}
