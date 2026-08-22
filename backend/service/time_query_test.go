package service

import (
	"FusionWeb/backend/database"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func setupTimeQueryTestDB(t *testing.T) *sql.DB {
	t.Helper()

	oldDB := database.DB
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open test sqlite failed: %v", err)
	}

	schema := []string{
		`CREATE TABLE poc_scan_results (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id TEXT,
			target TEXT,
			template_id TEXT,
			severity TEXT,
			name TEXT,
			author TEXT DEFAULT '',
			tags TEXT DEFAULT '',
			discovered_at DATETIME
		)`,
		`CREATE TABLE task_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			task_id TEXT,
			level TEXT,
			stage TEXT,
			message TEXT,
			metadata TEXT,
			created_at DATETIME
		)`,
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create schema failed: %v", err)
		}
	}

	database.DB = db
	t.Cleanup(func() {
		database.DB = oldDB
		_ = db.Close()
	})

	return db
}

func TestPocScanResultQueryConvertsISOTimeToChinaTime(t *testing.T) {
	db := setupTimeQueryTestDB(t)
	if _, err := db.Exec(`INSERT INTO poc_scan_results (task_id, target, template_id, severity, name, discovered_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"task-time", "https://example.test", "tpl-time", "high", "time vuln", "2026-07-14T14:19:11Z"); err != nil {
		t.Fatalf("insert poc result failed: %v", err)
	}

	result, err := NewPocScanResultService().GetResults("task-time", "", 1, 10, nil)
	if err != nil {
		t.Fatalf("GetResults failed: %v", err)
	}
	list, ok := result["list"].([]map[string]interface{})
	if !ok {
		t.Fatalf("list has unexpected type %T", result["list"])
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 result, got %d", len(list))
	}
	if got := list[0]["discovered_at"]; got != "2026-07-14 22:19:11" {
		t.Fatalf("discovered_at = %#v, want %q", got, "2026-07-14 22:19:11")
	}
}

func TestLogExportConvertsISOTimeToChinaTime(t *testing.T) {
	db := setupTimeQueryTestDB(t)
	if _, err := db.Exec(`INSERT INTO task_logs (task_id, level, stage, message, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"task-time", "INFO", "vuln", "exported log", "", "2026-07-14T14:19:11Z"); err != nil {
		t.Fatalf("insert task log failed: %v", err)
	}

	outputPath := filepath.Join(t.TempDir(), "task.log")
	if err := NewLogService("task-time", db).ExportLogs(outputPath); err != nil {
		t.Fatalf("ExportLogs failed: %v", err)
	}
	contentBytes, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read exported log failed: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "[2026-07-14 22:19:11] [INFO] exported log") {
		t.Fatalf("exported log content = %q, want formatted China time", content)
	}
}
