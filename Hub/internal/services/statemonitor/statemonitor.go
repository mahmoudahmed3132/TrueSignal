package statemonitor

import (
	"context"
	"database/sql"
	"log"
	"sync"
	"time"
)

type Broadcaster interface {
	Broadcast(topic string, payload interface{})
}

// EventEmitter records Hub-raised events through the normal event pipeline.
type EventEmitter interface {
	EmitSystemEvent(nodeID, sensorID, trigger, severity string, details map[string]any)
}

const (
	pollInterval      = 15 * time.Second
	heartbeatTimeout  = 60 * time.Second
	stoppedEscalation = 5 * time.Minute
	// escalationWindow bounds re-alerting after a Hub restart to recent outages.
	escalationWindow = 24 * time.Hour
	triggerLost       = "sensor_heartbeat_lost"
)

type StateMonitor struct {
	db          *sql.DB
	broadcaster Broadcaster
	events      EventEmitter

	// escalated remembers offline status rows already alerted on, so each
	// outage pages once. It is in-memory: after a Hub restart a sensor that is
	// still down is alerted once more, which is the safe direction.
	mu        sync.Mutex
	escalated map[int64]bool
}

func NewStateMonitor(db *sql.DB, broadcaster Broadcaster, events EventEmitter) *StateMonitor {
	return &StateMonitor{
		db:          db,
		broadcaster: broadcaster,
		events:      events,
		escalated:   make(map[int64]bool),
	}
}

func (s *StateMonitor) Start(ctx context.Context) {
	log.Println("[StateMonitor] Worker started.")
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[StateMonitor] StateMonitor stopped.")
			return
		case <-ticker.C:
			s.monitor(time.Now().UTC())
		}
	}
}

type sensorState struct {
	nodeID, sensorID string
	lastHeartbeat    sql.NullString
	statusID         sql.NullInt64
	status           sql.NullString
	statusTime       sql.NullString
}

func (s *StateMonitor) monitor(now time.Time) {
	rows, err := s.db.Query(`
		SELECT ns.node_id, ns.sensor_id, ns.last_heartbeat, sc.id, sc.status, sc.timestamp
		FROM node_sensors ns
		LEFT JOIN sensor_status_changes sc ON sc.id = (
			SELECT id FROM sensor_status_changes
			WHERE node_id = ns.node_id AND sensor_id = ns.sensor_id
			ORDER BY timestamp DESC, id DESC LIMIT 1
		)
	`)
	if err != nil {
		log.Printf("[ERROR] StateMonitor failed to query node_sensors: %v", err)
		return
	}
	var states []sensorState
	for rows.Next() {
		var st sensorState
		if err := rows.Scan(&st.nodeID, &st.sensorID, &st.lastHeartbeat, &st.statusID, &st.status, &st.statusTime); err != nil {
			continue
		}
		states = append(states, st)
	}
	rows.Close()

	cutoff := now.Add(-heartbeatTimeout).Format(time.RFC3339)
	nowStr := now.Format(time.RFC3339)

	for _, st := range states {
		stale := !st.lastHeartbeat.Valid || st.lastHeartbeat.String < cutoff

		switch {
		case stale && (!st.status.Valid || st.status.String == "online"):
			res, err := s.db.Exec(`
				INSERT INTO sensor_status_changes (node_id, sensor_id, status, timestamp)
				VALUES (?, ?, 'offline', ?)
			`, st.nodeID, st.sensorID, nowStr)
			if err != nil {
				log.Printf("[WARNING] StateMonitor failed to insert offline status: %v", err)
				continue
			}
			s.broadcaster.Broadcast("UPDATE_NODE", map[string]interface{}{
				"nodeId":          st.nodeID,
				"trigger_refresh": true,
			})
			s.broadcaster.Broadcast("SYNC_CHARTS", nil)

			// A sensor that has never been seen (pending deployment) is not an
			// outage; one that was online and went silent is.
			if st.status.Valid && st.status.String == "online" {
				id, _ := res.LastInsertId()
				s.alert(id, st, "heartbeat_timeout")
			}

		case st.status.Valid && st.status.String == "offline" && st.statusID.Valid:
			// Gracefully stopped (or already alerted) sensor: escalate once if it
			// has not come back within the grace period.
			since, err := time.Parse(time.RFC3339, st.statusTime.String)
			if err != nil || now.Sub(since) < stoppedEscalation || now.Sub(since) > escalationWindow {
				continue
			}
			if !s.wasOnlineBefore(st, st.statusID.Int64) {
				continue // never deployed: pending, not an outage
			}
			s.alert(st.statusID.Int64, st, "not_restarted_after_stop")
		}
	}
}

func (s *StateMonitor) wasOnlineBefore(st sensorState, statusID int64) bool {
	var exists int
	err := s.db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM sensor_status_changes
		              WHERE node_id = ? AND sensor_id = ? AND status = 'online' AND id < ?)
	`, st.nodeID, st.sensorID, statusID).Scan(&exists)
	return err == nil && exists == 1
}

func (s *StateMonitor) alert(statusID int64, st sensorState, reason string) {
	s.mu.Lock()
	if s.escalated[statusID] {
		s.mu.Unlock()
		return
	}
	s.escalated[statusID] = true
	s.mu.Unlock()

	if s.events == nil {
		return
	}
	details := map[string]any{"reason": reason, "timeout_sec": int(heartbeatTimeout.Seconds())}
	if st.lastHeartbeat.Valid {
		details["last_heartbeat"] = st.lastHeartbeat.String
	}
	s.events.EmitSystemEvent(st.nodeID, st.sensorID, triggerLost, "high", details)
}
