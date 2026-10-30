package store

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/truesignal/hub/internal/models"
)

func (s *SQLiteStore) InsertEvent(e *models.Event, nowStr string, detailsStr string) (int, error) {
	res, err := s.DB.Exec(`
		INSERT INTO events (node_id, sensor_id, timestamp, event_trigger, severity, source, target, details, is_read, is_archived)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.NodeID, e.SensorID, nowStr, e.EventTrigger, e.Severity, e.Source, e.Target, detailsStr,
		boolToInt(e.IsRead), boolToInt(e.IsArchived))
	if err != nil {
		return 0, err
	}
	lastInsertID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return int(lastInsertID), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// IsSensorRegistered reports whether a sensor is installed on the node. Events
// no longer carry a foreign key (they outlive sensor removal), so ingestion
// checks registration explicitly.
func (s *SQLiteStore) IsSensorRegistered(nodeID, sensorID string) (bool, error) {
	var n int
	err := s.DB.QueryRow(
		"SELECT COUNT(*) FROM node_sensors WHERE node_id = ? AND sensor_id = ?",
		nodeID, sensorID,
	).Scan(&n)
	return n > 0, err
}

func (s *SQLiteStore) IsSensorSilenced(nodeID, sensorID string) (bool, error) {
	var isSilencedInt int
	err := s.DB.QueryRow(
		"SELECT is_silenced FROM node_sensors WHERE node_id = ? AND sensor_id = ?",
		nodeID, sensorID,
	).Scan(&isSilencedInt)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil // Default to not silenced if somehow not found
		}
		return false, err
	}
	return isSilencedInt == 1, nil
}

func (s *SQLiteStore) GetEvents(isArchived int, nodeID string, sensorID string) ([]models.Event, error) {
	query := "SELECT id, timestamp, sensor_id, node_id, event_trigger, severity, source, target, details, is_read, is_archived FROM events WHERE is_archived = ?"
	args := []interface{}{isArchived}

	if nodeID != "" {
		query += " AND node_id = ?"
		args = append(args, nodeID)
	}
	if sensorID != "" {
		query += " AND sensor_id = ?"
		args = append(args, sensorID)
	}

	query += " ORDER BY id DESC"

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var e models.Event
		var detailsStr string
		var isReadInt, isArchivedInt int

		if err := rows.Scan(
			&e.ID, &e.Timestamp, &e.SensorID, &e.NodeID,
			&e.EventTrigger, &e.Severity, &e.Source, &e.Target, &detailsStr,
			&isReadInt, &isArchivedInt,
		); err != nil {
			return nil, err
		}

		e.IsRead = isReadInt == 1
		e.IsArchived = isArchivedInt == 1
		if detailsStr != "" {
			e.Details = json.RawMessage(detailsStr)
		} else {
			e.Details = json.RawMessage("{}")
		}
		events = append(events, e)
	}

	if events == nil {
		events = []models.Event{}
	}

	return events, nil
}

func (s *SQLiteStore) GetUnreadEventCount() (int, error) {
	var count int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM events WHERE is_read = 0 AND is_archived = 0").Scan(&count)
	return count, err
}

func (s *SQLiteStore) MarkEventRead(eventID string) error {
	_, err := s.DB.Exec("UPDATE events SET is_read = 1 WHERE id = ?", eventID)
	return err
}

func (s *SQLiteStore) MarkAllEventsRead() error {
	_, err := s.DB.Exec("UPDATE events SET is_read = 1 WHERE is_read = 0")
	return err
}

func (s *SQLiteStore) ArchiveEvent(eventID string) error {
	_, err := s.DB.Exec("UPDATE events SET is_archived = 1, is_read = 1 WHERE id = ?", eventID)
	return err
}

func (s *SQLiteStore) ArchiveAllEvents() error {
	_, err := s.DB.Exec("UPDATE events SET is_archived = 1, is_read = 1 WHERE is_archived = 0")
	return err
}

func (s *SQLiteStore) GetEventCount() (int, error) {
	var count int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM events").Scan(&count)
	return count, err
}

func (s *SQLiteStore) ClearAllEvents() error {
	_, err := s.DB.Exec("DELETE FROM events")
	return err
}

// EnforceRetention automatically archives and deletes old events based on configured days
func (s *SQLiteStore) EnforceRetention(archiveDays, purgeDays, purgeHeartbeatsDays int) error {
	now := time.Now().UTC()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Auto-Archive (if enabled)
	if archiveDays > 0 {
		archiveCutoff := now.AddDate(0, 0, -archiveDays).Format(time.RFC3339)
		if _, err := tx.Exec("UPDATE events SET is_archived = 1 WHERE timestamp < ? AND is_archived = 0", archiveCutoff); err != nil {
			return err
		}
	}

	// 2. Auto-Purge (if enabled)
	if purgeDays > 0 {
		purgeCutoff := now.AddDate(0, 0, -purgeDays).Format(time.RFC3339)
		if _, err := tx.Exec("DELETE FROM events WHERE timestamp < ?", purgeCutoff); err != nil {
			return err
		}
	}

	// 3. Auto-Purge Heartbeats (if enabled)
	if purgeHeartbeatsDays > 0 {
		purgeCutoff := now.AddDate(0, 0, -purgeHeartbeatsDays).Format(time.RFC3339)
		if _, err := tx.Exec(`
			DELETE FROM sensor_status_changes 
			WHERE timestamp < ? 
			AND id NOT IN (
				SELECT id FROM (
					SELECT id, ROW_NUMBER() OVER(PARTITION BY node_id, sensor_id ORDER BY timestamp DESC) as rn 
					FROM sensor_status_changes
				) WHERE rn = 1
			)
			AND id NOT IN (
				SELECT id FROM (
					SELECT id, ROW_NUMBER() OVER(PARTITION BY node_id, sensor_id ORDER BY timestamp DESC) as rn 
					FROM sensor_status_changes
					WHERE timestamp <= ?
				) WHERE rn = 1
			)
		`, purgeCutoff, purgeCutoff); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// SourceActivity aggregates the events of one source.
type SourceActivity struct {
	Source    string
	Events    int
	Decoys    int
	FirstSeen string
	LastSeen  string
}

// GetSourceActivity groups all events (active and archived) by source,
// skipping the triggers in exclude (Hub liveness). Timestamps are RFC 3339
// UTC strings, so MIN/MAX order them correctly.
func (s *SQLiteStore) GetSourceActivity(exclude []string, excludeSources ...string) ([]SourceActivity, error) {
	query := `SELECT source, COUNT(*), COUNT(DISTINCT node_id || '/' || sensor_id), MIN(timestamp), MAX(timestamp)
		FROM events`
	args := make([]interface{}, 0, len(exclude)+len(excludeSources))
	var where []string
	if len(exclude) > 0 {
		where = append(where, "event_trigger NOT IN ("+strings.TrimSuffix(strings.Repeat("?,", len(exclude)), ",")+")")
		for _, t := range exclude {
			args = append(args, t)
		}
	}
	if len(excludeSources) > 0 {
		where = append(where, "source NOT IN ("+strings.TrimSuffix(strings.Repeat("?,", len(excludeSources)), ",")+")")
		for _, src := range excludeSources {
			args = append(args, src)
		}
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " GROUP BY source"
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceActivity{}
	for rows.Next() {
		var a SourceActivity
		if err := rows.Scan(&a.Source, &a.Events, &a.Decoys, &a.FirstSeen, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetEventsBySource returns every event (active and archived) from one
// source, oldest first, at most limit rows (the most recent ones).
func (s *SQLiteStore) GetEventsBySource(source string, limit int) ([]models.Event, error) {
	rows, err := s.DB.Query(`SELECT id, timestamp, sensor_id, node_id, event_trigger, severity, source, target, details, is_read, is_archived
		FROM (SELECT * FROM events WHERE source = ? ORDER BY timestamp DESC, id DESC LIMIT ?)
		ORDER BY timestamp ASC, id ASC`, source, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Event{}
	for rows.Next() {
		var e models.Event
		var detailsStr string
		var isReadInt, isArchivedInt int
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SensorID, &e.NodeID, &e.EventTrigger, &e.Severity,
			&e.Source, &e.Target, &detailsStr, &isReadInt, &isArchivedInt); err != nil {
			return nil, err
		}
		e.IsRead, e.IsArchived = isReadInt == 1, isArchivedInt == 1
		e.Details = json.RawMessage(detailsStr)
		if detailsStr == "" {
			e.Details = json.RawMessage("{}")
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
