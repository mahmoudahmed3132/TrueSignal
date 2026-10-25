package store

import (
	"database/sql"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	DB *sql.DB
}

func NewStore(dbPath string) (*SQLiteStore, error) {
	// Enable WAL mode, set a 5-second busy timeout to prevent locking, and enable Foreign Keys
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// Connection Pooling for SQLite performance
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)

	// Read-only containers have no writable /tmp, so keep SQLite temp files
	// next to the database (the writable volume).
	tempDir := strings.ReplaceAll(filepath.Dir(dbPath), "'", "''")
	_, err = db.Exec("PRAGMA temp_store_directory = '" + tempDir + "';")
	if err != nil {
		log.Printf("Warning: Failed to set SQLite temp_store_directory: %v", err)
	}

	db.SetConnMaxLifetime(5 * time.Minute)

	if err := RunMigrations(db, dbPath); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := InitializeDefaultConfig(db); err != nil {
		return nil, fmt.Errorf("failed to initialize default config: %w", err)
	}

	log.Println("[DB] Database initialized successfully in WAL mode.")
	return &SQLiteStore{DB: db}, nil
}

func InitializeDefaultConfig(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := initializeDefaultConfigTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// DefaultRegistryURL is the public sensor registry (registry-pages branch of
// the public distribution repository; the source repository is private).
const DefaultRegistryURL = "https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-dist/registry-pages"

// legacyRegistryURL was the default before the source repository went
// private. It stops resolving then, so a Hub still on it is moved to
// DefaultRegistryURL; a custom registry_url is left alone.
const legacyRegistryURL = "https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/registry-pages"

func initializeDefaultConfigTx(tx *sql.Tx) error {
	defaults := map[string]string{
		"is_armed":                    "true",
		"webhook_type":                "ntfy",
		"webhook_url":                 "",
		"webhook_events":              "critical,high,medium,low",
		"auto_archive_days":           "0",
		"auto_purge_days":             "0",
		"siem_address":                "",
		"siem_protocol":               "tcp",
		"siem_format":                 "rfc5424",
		"siem_token":                  "",
		"registry_url":                DefaultRegistryURL,
		"acknowledged_wizard_release": "",
	}

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range defaults {
		if _, err := stmt.Exec(k, v); err != nil {
			return err
		}
	}

	if _, err := tx.Exec("UPDATE config SET value = ? WHERE key = 'registry_url' AND value = ?", DefaultRegistryURL, legacyRegistryURL); err != nil {
		return err
	}

	return nil
}
