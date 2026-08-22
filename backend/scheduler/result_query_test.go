package scheduler

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTemplateInfoReadsInfoName(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "poc.yaml")
	content := []byte(`id: sample-template
info:
  name: YAML Display Name
  severity: high
  description: Example description
  tags: sample,rce
`)
	if err := os.WriteFile(templatePath, content, 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	info := loadTemplateInfo(templatePath, map[string]templateInfo{})

	if info.Name != "YAML Display Name" {
		t.Fatalf("expected YAML info.name, got %q", info.Name)
	}
	if info.Severity != "high" {
		t.Fatalf("expected severity high, got %q", info.Severity)
	}
	if info.Description != "Example description" {
		t.Fatalf("expected description, got %q", info.Description)
	}
}

func TestNormalizeReconResultURLUsesPortSchemeMap(t *testing.T) {
	portSchemes := map[string]string{
		"192.168.102.129:21": "ftp",
		"192.168.102.129:25": "",
	}

	if got := normalizeReconResultURL("http://192.168.102.129:21", portSchemes); got != "ftp://192.168.102.129:21" {
		t.Fatalf("expected ftp scheme, got %q", got)
	}
	if got := normalizeReconResultURL("http://192.168.102.129:25", portSchemes); got != "192.168.102.129:25" {
		t.Fatalf("expected bare host:port for unrecognized service, got %q", got)
	}
	if got := normalizeReconResultURL("https://192.168.102.129:25", portSchemes); got != "192.168.102.129:25" {
		t.Fatalf("expected https duplicate to normalize to bare host:port, got %q", got)
	}
}

func TestReconProtocolSchemeDoesNotFallbackToTCP(t *testing.T) {
	if got := reconProtocolScheme("tcp", ""); got != "" {
		t.Fatalf("expected no URL scheme for tcp-only result, got %q", got)
	}
	if got := reconProtocolScheme("tcp", "mysql"); got != "mysql" {
		t.Fatalf("expected detected service scheme, got %q", got)
	}
}

func TestDisplayPortServiceFallsBackToPortGuess(t *testing.T) {
	extra := map[string]interface{}{
		"protocol": "tcp",
		"service":  "tcp",
	}
	if got := displayPortService(extra, 25); got != "smtp" {
		t.Fatalf("expected guessed smtp service, got %q", got)
	}
}
