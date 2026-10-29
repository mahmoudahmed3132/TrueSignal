package store

import (
	"database/sql"
	"errors"

	"github.com/truesignal/hub/internal/models"
)

const beaconColumns = `id, token, type, name, memo, domain, created_at, last_used_at, use_count`

func scanBeacon(row interface{ Scan(...any) error }) (models.Beacon, error) {
	var b models.Beacon
	err := row.Scan(&b.ID, &b.Token, &b.Type, &b.Name, &b.Memo, &b.Domain, &b.CreatedAt, &b.LastUsedAt, &b.UseCount)
	return b, err
}

// InsertBeacon stores a new beacon. It fails on a duplicate token.
func (s *SQLiteStore) InsertBeacon(b models.Beacon) error {
	_, err := s.DB.Exec(`INSERT INTO beacons (`+beaconColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, '', 0)`,
		b.ID, b.Token, b.Type, b.Name, b.Memo, b.Domain, b.CreatedAt)
	return err
}

// GetBeacon returns a beacon by ID, or nil.
func (s *SQLiteStore) GetBeacon(id string) (*models.Beacon, error) {
	return s.oneBeacon(`SELECT `+beaconColumns+` FROM beacons WHERE id = ?`, id)
}

// GetBeaconByToken returns the beacon carrying token, or nil.
func (s *SQLiteStore) GetBeaconByToken(token string) (*models.Beacon, error) {
	return s.oneBeacon(`SELECT `+beaconColumns+` FROM beacons WHERE token = ?`, token)
}

func (s *SQLiteStore) oneBeacon(query, arg string) (*models.Beacon, error) {
	b, err := scanBeacon(s.DB.QueryRow(query, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListBeacons returns all beacons, newest first.
func (s *SQLiteStore) ListBeacons() ([]models.Beacon, error) {
	rows, err := s.DB.Query(`SELECT ` + beaconColumns + ` FROM beacons ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Beacon{}
	for rows.Next() {
		b, err := scanBeacon(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// DeleteBeacon removes a beacon. Its past events are kept; a later use of
// the token is reported as an unknown beacon.
func (s *SQLiteStore) DeleteBeacon(id string) (bool, error) {
	res, err := s.DB.Exec(`DELETE FROM beacons WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// RecordBeaconUse bumps the use counter and last-used time.
func (s *SQLiteStore) RecordBeaconUse(id, ts string) error {
	_, err := s.DB.Exec(`UPDATE beacons SET use_count = use_count + 1, last_used_at = ? WHERE id = ?`, ts, id)
	return err
}

// BeaconDomains returns the zones configured on deployed Token Receivers
// (TS_BEACON_DOMAIN), so new beacons point at a zone something answers.
func (s *SQLiteStore) BeaconDomains(receiverSensorID string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT DISTINCT lower(trim(json_extract(config_values, '$.TS_BEACON_DOMAIN'), ' .'))
		FROM node_sensors WHERE sensor_id = ? AND json_valid(config_values)`, receiverSensorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d sql.NullString
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		if d.Valid && d.String != "" {
			out = append(out, d.String)
		}
	}
	return out, rows.Err()
}
