package sensor

import (
	"errors"
	"log"
	"strings"
	"time"

	"github.com/truesignal/hub/internal/models"
)

// Store defines exactly what the Sensor service needs from internal/store
type Store interface {
	ProcessHeartbeat(nodeID, sensorID, configRev, nowStr string) (bool, error)
	MarkSensorOffline(nodeID, sensorID, offlineTime string) error
	UpdateSensorSilence(nodeID, sensorID string, silenceVal int) error
	GetSensorLastHeartbeat(nodeID, sensorID string) (string, error)
	GetSensorLatestStatus(nodeID, sensorID string) (string, error)
	InsertStatusChange(nodeID, sensorID, status, timestamp string) error
	HasSensorBeenOnline(nodeID, sensorID string) (bool, error)
}

// Broadcaster defines how the service sends real-time updates
type Broadcaster interface {
	Broadcast(topic string, payload interface{})
}

// EventEmitter records Hub-raised events (sensor liveness) through the normal
// event pipeline so they reach storage, the SIEM and notifications.
type EventEmitter interface {
	EmitSystemEvent(nodeID, sensorID, trigger, severity string, details map[string]any)
}

type Service struct {
	store       Store
	broadcaster Broadcaster
	events      EventEmitter
}

var ErrSensorNotRegistered = errors.New("sensor not registered")

// Liveness event triggers. Severities are chosen so that a deliberate stop is
// visible but not paged, while a sensor that stays dark is (see statemonitor).
const (
	TriggerSensorStopped   = "sensor_stopped"
	TriggerSensorRecovered = "sensor_recovered"
	TriggerHeartbeatLost   = "sensor_heartbeat_lost"
)

func NewService(store Store, broadcaster Broadcaster, events EventEmitter) *Service {
	return &Service{
		store:       store,
		broadcaster: broadcaster,
		events:      events,
	}
}

func (s *Service) emit(nodeID, sensorID, trigger, severity string, details map[string]any) {
	if s.events != nil {
		s.events.EmitSystemEvent(nodeID, sensorID, trigger, severity, details)
	}
}

// ProcessHeartbeat handles the core logic of a sensor checking in
func (s *Service) ProcessHeartbeat(nodeID, sensorID, configRev string) error {
	nowStr := time.Now().UTC().Format(time.RFC3339)

	latestStatus, err := s.store.GetSensorLatestStatus(nodeID, sensorID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch latest status for node %s sensor %s: %v", nodeID, sensorID, err)
	}

	// If the recorded state in sensor_status_changes is not "online",
	// this incoming heartbeat marks an online transition.
	isOffline := (latestStatus != "online")

	_, err = s.store.ProcessHeartbeat(nodeID, sensorID, configRev, nowStr)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return ErrSensorNotRegistered
		}
		log.Printf("[ERROR] Heartbeat DB update failed for node %s: %v", nodeID, err)
		return err
	}

	if isOffline {
		if err := s.store.InsertStatusChange(nodeID, sensorID, "online", nowStr); err != nil {
			log.Printf("[WARNING] Failed to log status change: %v", err)
		}
		// Only a return from a known-offline state is a recovery; the very
		// first heartbeat of a newly deployed sensor is not, even though the
		// state monitor records a never-seen sensor as offline (pending).
		if latestStatus == "offline" && s.wasOnline(nodeID, sensorID) {
			s.emit(nodeID, sensorID, TriggerSensorRecovered, "info", map[string]any{"config_rev": configRev})
		}
		s.broadcaster.Broadcast("NODE_SYNCED", map[string]interface{}{
			"nodeId": nodeID,
		})
		s.broadcaster.Broadcast("SYNC_CHARTS", nil)
	}

	s.broadcaster.Broadcast("SENSOR_HEARTBEAT", map[string]interface{}{
		"nodeId":    nodeID,
		"sensorId":  sensorID,
		"timestamp": nowStr,
	})

	return nil
}

// ProcessOffline graceful forces a sensor into an offline state
func (s *Service) ProcessOffline(nodeID, sensorID, reason string) error {
	// Push lastHeartbeat 2 hours into the past to instantly force deriveStatus() to return "down"
	offlineTime := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)

	if err := s.store.MarkSensorOffline(nodeID, sensorID, offlineTime); err != nil {
		log.Printf("[ERROR] Failed to set offline status for node %s sensor %s: %v", nodeID, sensorID, err)
		return err
	}

	reason = strings.ToValidUTF8(reason, "?")
	if len(reason) > 128 {
		reason = reason[:128]
	}
	log.Printf("[INFO] Sensor %s on node %s went offline gracefully (Reason: %q)", sensorID, nodeID, reason)

	s.broadcaster.Broadcast("UPDATE_NODE", map[string]interface{}{
		"nodeId":          nodeID,
		"trigger_refresh": true,
	})

	_ = s.store.InsertStatusChange(nodeID, sensorID, "offline", time.Now().UTC().Format(time.RFC3339))

	// A stop is routine during `truesignal apply`, but it is also how an
	// intruder would quietly disable a decoy. Record it; the state monitor
	// escalates if the sensor does not come back.
	s.emit(nodeID, sensorID, TriggerSensorStopped, "low", map[string]any{"reason": reason})

	return nil
}

// ToggleSilence turns alerting on or off for a specific sensor
func (s *Service) ToggleSilence(nodeID, sensorID string, isSilenced bool) error {
	silenceVal := 0
	if isSilenced {
		silenceVal = 1
	}

	if err := s.store.UpdateSensorSilence(nodeID, sensorID, silenceVal); err != nil {
		return err
	}

	s.broadcaster.Broadcast("SILENCE_SENSOR", map[string]interface{}{
		"nodeId":     nodeID,
		"sensorId":   sensorID,
		"isSilenced": isSilenced,
	})

	return nil
}

// wasOnline reports whether the sensor was ever online before (the status
// row this heartbeat just inserted aside, there must be an earlier one).
func (s *Service) wasOnline(nodeID, sensorID string) bool {
	ok, err := s.store.HasSensorBeenOnline(nodeID, sensorID)
	if err != nil {
		log.Printf("[WARNING] Failed to check sensor history for %s/%s: %v", nodeID, sensorID, err)
		return true // keep reporting recoveries rather than hide one
	}
	return ok
}
