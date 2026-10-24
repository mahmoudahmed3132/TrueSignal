package store

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/truesignal/hub/internal/models"
)

const honeytokenColumns = `id, username, secret, node_id, sensor_id, created_at, last_used_at, use_count`

func scanHoneytoken(row interface{ Scan(...any) error }) (models.Honeytoken, error) {
	var h models.Honeytoken
	err := row.Scan(&h.ID, &h.Username, &h.Secret, &h.NodeID, &h.SensorID, &h.CreatedAt, &h.LastUsedAt, &h.UseCount)
	return h, err
}

// GetHoneytoken returns the honeytoken planted by a sensor, or nil.
func (s *SQLiteStore) GetHoneytoken(nodeID, sensorID string) (*models.Honeytoken, error) {
	h, err := scanHoneytoken(s.DB.QueryRow(`SELECT `+honeytokenColumns+` FROM honeytokens WHERE node_id = ? AND sensor_id = ?`, nodeID, sensorID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// InsertHoneytoken stores a new honeytoken. It fails on a duplicate username
// or a second token for the same sensor.
func (s *SQLiteStore) InsertHoneytoken(h models.Honeytoken) error {
	_, err := s.DB.Exec(`INSERT INTO honeytokens (`+honeytokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, '', 0)`,
		h.ID, h.Username, h.Secret, h.NodeID, h.SensorID, h.CreatedAt)
	return err
}

// FindHoneytokens returns honeytokens whose username (case-insensitive) is
// in the given set.
func (s *SQLiteStore) FindHoneytokens(usernames []string) ([]models.Honeytoken, error) {
	if len(usernames) == 0 {
		return nil, nil
	}
	args := make([]any, len(usernames))
	for i, u := range usernames {
		args[i] = u
	}
	rows, err := s.DB.Query(`SELECT `+honeytokenColumns+` FROM honeytokens WHERE username IN (`+placeholders(len(usernames))+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Honeytoken
	for rows.Next() {
		h, err := scanHoneytoken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RecordHoneytokenUse bumps the use counter and last-used time.
func (s *SQLiteStore) RecordHoneytokenUse(id, ts string) error {
	_, err := s.DB.Exec(`UPDATE honeytokens SET use_count = use_count + 1, last_used_at = ? WHERE id = ?`, ts, id)
	return err
}

// ListHoneytokens returns all honeytokens, newest first.
func (s *SQLiteStore) ListHoneytokens() ([]models.Honeytoken, error) {
	rows, err := s.DB.Query(`SELECT ` + honeytokenColumns + ` FROM honeytokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Honeytoken{}
	for rows.Next() {
		h, err := scanHoneytoken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
