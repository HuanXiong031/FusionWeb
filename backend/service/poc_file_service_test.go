package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreatePocFileForceCategoryUsesRequestedFolder(t *testing.T) {
	root := t.TempDir()
	svc := &PocFileService{configPath: root}
	content := `id: save-dialog-test
info:
  name: Save Dialog Test
  author: fusionweb
  severity: info
  tags: nginx
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`

	if err := svc.CreatePocFile("TestFingerprint", "save-dialog-test", content, nil, true); err != nil {
		t.Fatalf("CreatePocFile returned error: %v", err)
	}

	expected := filepath.Join(root, "TestFingerprint", "save-dialog-test.yaml")
	if _, err := os.Stat(expected); err != nil {
		t.Fatalf("expected file to be saved under requested fingerprint folder: %v", err)
	}

	unexpected := filepath.Join(root, "nginx", "save-dialog-test.yaml")
	if _, err := os.Stat(unexpected); !os.IsNotExist(err) {
		t.Fatalf("file should not be saved under YAML-derived tag folder, stat error: %v", err)
	}
}
