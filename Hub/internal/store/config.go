package store

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

func (s *SQLiteStore) GetConfigValue(key string) (string, error) {
	var value string
	err := s.DB.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	return value, err
}

func (s *SQLiteStore) UpdateConfigValue(key, value string) error {
	_, err := s.DB.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, value)
	return err
}

func (s *SQLiteStore) GetAllConfig() (map[string]string, error) {
	rows, err := s.DB.Query("SELECT key, value FROM config")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	kv := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		kv[k] = v
	}
	return kv, nil
}

func (s *SQLiteStore) CompleteSetup(adminHash, hubEndpoint string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('admin_hash', ?)", adminHash)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('hub_endpoint', ?)", hubEndpoint)
	if err != nil {
		return err
	}
	_, err = tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('is_setup', 'true')")
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLiteStore) UpdateConfigBatch(req map[string]interface{}) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	validWebhooks := map[string]bool{"ntfy": true, "gotify": true, "discord": true, "slack": true, "none": true}
	validProtocols := map[string]bool{"tcp": true, "udp": true, "tls": true, "elastic": true, "logscale": true}
	validFormats := map[string]bool{"rfc5424": true, "ecs": true}

	for key, val := range req {
		switch key {
		case "hub_endpoint", "webhook_url", "siem_address", "siem_token", "registry_url", "whitelisted_sources", "known_scanners", "acknowledged_wizard_release":
			if strVal, ok := val.(string); ok {
				if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, strVal); err != nil {
					return err
				}
			}
		case "webhook_type":
			if strVal, ok := val.(string); ok && validWebhooks[strings.ToLower(strVal)] {
				if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, strings.ToLower(strVal)); err != nil {
					return err
				}
			}
		case "siem_protocol":
			if strVal, ok := val.(string); ok && validProtocols[strings.ToLower(strVal)] {
				if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, strings.ToLower(strVal)); err != nil {
					return err
				}
			}
		case "siem_format":
			if strVal, ok := val.(string); ok && validFormats[strings.ToLower(strVal)] {
				if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, strings.ToLower(strVal)); err != nil {
					return err
				}
			}
		case "auto_archive_days", "auto_purge_days", "auto_purge_heartbeats_days", "update_check_interval_hours":
			if numVal, ok := val.(float64); ok {
				if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, strconv.Itoa(int(numVal))); err != nil {
					return err
				}
			}
		case "webhook_events":
			if arrVal, ok := val.([]interface{}); ok {
				var events []string
				for _, v := range arrVal {
					if str, ok := v.(string); ok {
						events = append(events, str)
					}
				}
				if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", key, strings.Join(events, ",")); err != nil {
					return err
				}
			}
		}
	}

	return tx.Commit()
}

// captureMasterKey is the Hub's honeytoken/capture master key (see
// services/honeytoken). It is kept across a factory reset together with the
// honeytokens unless the caller purges them.
const captureMasterKey = "capture_master_key"

// FactoryReset wipes the database back to a blank slate. Honeytokens and the
// capture master key survive unless purgeHoneytokens is set: lures carrying
// them stay on disk after nodes are wiped (uninstall never deletes lures), and
// dropping them would turn those lures into credentials nobody recognises.
func (s *SQLiteStore) FactoryReset(purgeHoneytokens bool) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // Rollback on any error.

	var masterKey string
	if !purgeHoneytokens {
		if err := tx.QueryRow("SELECT value FROM config WHERE key = ?", captureMasterKey).Scan(&masterKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}

	// Wipe all tables. The order is important for manual deletion without cascades.
	// It is best practice to be explicit, even though ON DELETE CASCADE is enabled.
	queries := []string{
		"DELETE FROM events",
		"DELETE FROM sensor_status_changes",
		"DELETE FROM node_sensors",
		"DELETE FROM nodes",
		"DELETE FROM config",
		// Reset the autoincrement counter for the events table.
		"DELETE FROM sqlite_sequence WHERE name = 'events'",
	}
	if purgeHoneytokens {
		queries = append(queries, "DELETE FROM honeytokens")
	}

	for _, q := range queries {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}

	// Re-initialize default config within the same transaction.
	if err := initializeDefaultConfigTx(tx); err != nil {
		return err
	}
	if masterKey != "" {
		if _, err := tx.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", captureMasterKey, masterKey); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// FactoryResetDryRun calculates the number of rows that would be deleted
func (s *SQLiteStore) FactoryResetDryRun(purgeHoneytokens bool) (map[string]int, error) {
	stats := make(map[string]int)

	queries := map[string]string{
		"events":                "SELECT COUNT(*) FROM events",
		"sensor_status_changes": "SELECT COUNT(*) FROM sensor_status_changes",
		"node_sensors":          "SELECT COUNT(*) FROM node_sensors",
		"nodes":                 "SELECT COUNT(*) FROM nodes",
	}
	if purgeHoneytokens {
		queries["honeytokens"] = "SELECT COUNT(*) FROM honeytokens"
	}

	for key, query := range queries {
		var count int
		if err := s.DB.QueryRow(query).Scan(&count); err != nil {
			return nil, err
		}
		stats[key] = count
	}

	return stats, nil
}
