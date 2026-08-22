package scheduler

import (
	"FusionWeb/backend/database"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func setupResultQueryTimeTestDB(t *testing.T) *sql.DB {
	t.Helper()

	oldDB := database.DB
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open test sqlite failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE recon_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT,
		result_type TEXT,
		target TEXT,
		source TEXT,
		extra_data TEXT,
		discovered_at DATETIME
	)`); err != nil {
		t.Fatalf("create recon_results failed: %v", err)
	}

	database.DB = db
	t.Cleanup(func() {
		database.DB = oldDB
		_ = db.Close()
	})
	return db
}

func TestGetReconResultsKeepsDatabaseChinaTimeString(t *testing.T) {
	db := setupResultQueryTimeTestDB(t)
	if _, err := db.Exec(`INSERT INTO recon_results (task_id, result_type, target, source, extra_data, discovered_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"task-time", "url", "http://example.test", "httpx", `{}`, "2026-07-14 22:19:11"); err != nil {
		t.Fatalf("insert recon result failed: %v", err)
	}

	results, err := (&TaskScheduler{}).GetReconResults("task-time", "url")
	if err != nil {
		t.Fatalf("GetReconResults failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if got := results[0]["discoveredAt"]; got != "2026-07-14 22:19:11" {
		t.Fatalf("discoveredAt = %#v, want %q", got, "2026-07-14 22:19:11")
	}
}

func TestGetReconResultsConvertsISOTimeToChinaTime(t *testing.T) {
	db := setupResultQueryTimeTestDB(t)
	if _, err := db.Exec(`INSERT INTO recon_results (task_id, result_type, target, source, extra_data, discovered_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"task-time", "url", "http://example.test", "httpx", `{}`, "2026-07-14T14:19:11Z"); err != nil {
		t.Fatalf("insert recon result failed: %v", err)
	}

	results, err := (&TaskScheduler{}).GetReconResults("task-time", "url")
	if err != nil {
		t.Fatalf("GetReconResults failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if got := results[0]["discoveredAt"]; got != "2026-07-14 22:19:11" {
		t.Fatalf("discoveredAt = %#v, want %q", got, "2026-07-14 22:19:11")
	}
}
