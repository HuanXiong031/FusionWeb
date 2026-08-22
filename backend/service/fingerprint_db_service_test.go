package service

import (
	"FusionWeb/backend/database"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func setupFingerprintTestDB(t *testing.T) *sql.DB {
	t.Helper()

	oldDB := database.DB
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open test sqlite failed: %v", err)
	}

	schema := []string{
		`CREATE TABLE passive_fingerprints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			rules TEXT,
			is_blacklisted INTEGER DEFAULT 0,
			is_enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_by INTEGER,
			UNIQUE(name, created_by)
		)`,
		`CREATE TABLE active_fingerprints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			rules TEXT,
			is_blacklisted INTEGER DEFAULT 0,
			is_enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			created_by INTEGER,
			UNIQUE(name, created_by)
		)`,
		`CREATE TABLE blacklist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			category TEXT NOT NULL,
			item TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(category, item)
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

func TestToggleBlacklistSyncsFingerprintBlacklistCategory(t *testing.T) {
	db := setupFingerprintTestDB(t)
	if _, err := db.Exec(`INSERT INTO passive_fingerprints (name, rules, is_blacklisted, is_enabled) VALUES ('Azkaban-Web-Client', 'body="azkaban"', 0, 1)`); err != nil {
		t.Fatalf("insert fingerprint failed: %v", err)
	}

	service := &FingerprintDBService{}
	if err := service.ToggleBlacklist("Azkaban-Web-Client"); err != nil {
		t.Fatalf("toggle blacklist on failed: %v", err)
	}

	var isBlacklisted int
	if err := db.QueryRow(`SELECT is_blacklisted FROM passive_fingerprints WHERE name = 'Azkaban-Web-Client'`).Scan(&isBlacklisted); err != nil {
		t.Fatalf("query fingerprint flag failed: %v", err)
	}
	if isBlacklisted != 1 {
		t.Fatalf("expected fingerprint flag to be 1, got %d", isBlacklisted)
	}

	var blacklistCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM blacklist WHERE category = 'fingerprint' AND item = 'Azkaban-Web-Client'`).Scan(&blacklistCount); err != nil {
		t.Fatalf("query blacklist failed: %v", err)
	}
	if blacklistCount != 1 {
		t.Fatalf("expected fingerprint blacklist item, got %d", blacklistCount)
	}

	if err := service.ToggleBlacklist("Azkaban-Web-Client"); err != nil {
		t.Fatalf("toggle blacklist off failed: %v", err)
	}
	if err := db.QueryRow(`SELECT is_blacklisted FROM passive_fingerprints WHERE name = 'Azkaban-Web-Client'`).Scan(&isBlacklisted); err != nil {
		t.Fatalf("query fingerprint flag after removal failed: %v", err)
	}
	if isBlacklisted != 0 {
		t.Fatalf("expected fingerprint flag to be 0, got %d", isBlacklisted)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM blacklist WHERE category = 'fingerprint' AND item = 'Azkaban-Web-Client'`).Scan(&blacklistCount); err != nil {
		t.Fatalf("query blacklist after removal failed: %v", err)
	}
	if blacklistCount != 0 {
		t.Fatalf("expected fingerprint blacklist item to be removed, got %d", blacklistCount)
	}
}

func TestBlacklistServiceSyncsFingerprintFlags(t *testing.T) {
	db := setupFingerprintTestDB(t)
	if _, err := db.Exec(`INSERT INTO passive_fingerprints (name, rules, is_blacklisted, is_enabled) VALUES ('Passive-FP', 'body="passive"', 0, 1)`); err != nil {
		t.Fatalf("insert passive fingerprint failed: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO active_fingerprints (name, rules, is_blacklisted, is_enabled) VALUES ('Active-FP', 'path="/active"', 0, 1)`); err != nil {
		t.Fatalf("insert active fingerprint failed: %v", err)
	}

	service := &BlacklistService{}
	if err := service.AddToBlacklistWithCategory("fingerprint", "Passive-FP"); err != nil {
		t.Fatalf("add fingerprint blacklist failed: %v", err)
	}
	if got := queryFingerprintBlacklistFlag(t, db, "passive_fingerprints", "Passive-FP"); got != 1 {
		t.Fatalf("expected passive fingerprint flag to be 1 after add, got %d", got)
	}

	if err := service.RemoveFromBlacklistWithCategory("fingerprint", "Passive-FP"); err != nil {
		t.Fatalf("remove fingerprint blacklist failed: %v", err)
	}
	if got := queryFingerprintBlacklistFlag(t, db, "passive_fingerprints", "Passive-FP"); got != 0 {
		t.Fatalf("expected passive fingerprint flag to be 0 after remove, got %d", got)
	}

	if err := service.SaveBlacklistByCategory(BlacklistConfig{"fingerprint": {"Active-FP"}}); err != nil {
		t.Fatalf("save fingerprint blacklist failed: %v", err)
	}
	if got := queryFingerprintBlacklistFlag(t, db, "passive_fingerprints", "Passive-FP"); got != 0 {
		t.Fatalf("expected passive fingerprint flag to stay 0 after save, got %d", got)
	}
	if got := queryFingerprintBlacklistFlag(t, db, "active_fingerprints", "Active-FP"); got != 1 {
		t.Fatalf("expected active fingerprint flag to be 1 after save, got %d", got)
	}
}

func queryFingerprintBlacklistFlag(t *testing.T, db *sql.DB, tableName, name string) int {
	t.Helper()
	var value int
	if err := db.QueryRow(`SELECT is_blacklisted FROM `+tableName+` WHERE name = ?`, name).Scan(&value); err != nil {
		t.Fatalf("query %s blacklist flag failed: %v", tableName, err)
	}
	return value
}
