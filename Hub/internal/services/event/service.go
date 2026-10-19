package event

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/truesignal/hub/internal/models"
)

type Store interface {
	InsertEvent(e *models.Event, timestamp string, detailsJSON string) (int, error)
	UpdateNodeLastHeartbeat(nodeID, sensorID, timestamp string) error
	IsSensorRegistered(nodeID, sensorID string) (bool, error)
	IsSensorSilenced(nodeID, sensorID string) (bool, error)
	GetEvents(isArchived int, nodeID, sensorID string) ([]models.Event, error)
	GetUnreadEventCount() (int, error)
	MarkEventRead(eventID string) error
	MarkAllEventsRead() error
	ArchiveEvent(eventID string) error
	ArchiveAllEvents() error
	GetEventCount() (int, error)
	ClearAllEvents() error
	GetConfigValue(key string) (string, error)
	EnforceRetention(archiveDays, purgeDays, purgeHeartbeatsDays int) error
}

type Broadcaster interface {
	Broadcast(topic string, payload interface{})
}

type SiemService interface {
	QueueEvent(event models.Event)
}

type NotifyService interface {
	Dispatch(event models.Event)
}

// ErrSensorNotRegistered is returned when an event names a sensor that is not
// installed on the authenticated node.
var ErrSensorNotRegistered = errors.New("sensor_not_registered")

// SystemSource is the event source used for events the Hub raises itself
// (sensor liveness), as opposed to events reported by sensors.
const SystemSource = "truesignal-hub"

const (
	maxShortFieldLen = 256
	maxDetailsBytes  = 64 * 1024
)

type Service struct {
	store         Store
	broadcaster   Broadcaster
	siemService   SiemService
	notifyService NotifyService
}

func NewService(store Store, broadcaster Broadcaster, siemService SiemService, notifyService NotifyService) *Service {
	return &Service{
		store:         store,
		broadcaster:   broadcaster,
		siemService:   siemService,
		notifyService: notifyService,
	}
}

func clampField(v, fallback string) string {
	v = strings.TrimSpace(strings.ToValidUTF8(v, "?"))
	if v == "" {
		return fallback
	}
	if len(v) > maxShortFieldLen {
		v = v[:maxShortFieldLen]
	}
	return v
}

// normalizeDetails guarantees the stored details are a JSON object, so every
// consumer (UI, SIEM, export) can rely on the shape.
func normalizeDetails(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "{}"
	}
	if len(trimmed) > maxDetailsBytes {
		b, _ := json.Marshal(map[string]any{"truncated": true, "original_bytes": len(trimmed)})
		return string(b)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &obj); err == nil {
		return trimmed
	}
	b, _ := json.Marshal(map[string]json.RawMessage{"value": json.RawMessage(trimmed)})
	return string(b)
}

func (s *Service) isWhitelisted(source string) bool {
	whitelistedSources, err := s.store.GetConfigValue("whitelisted_sources")
	if err != nil || whitelistedSources == "" {
		return false
	}
	for _, candidate := range strings.Split(whitelistedSources, ",") {
		if strings.TrimSpace(candidate) == source {
			return true
		}
	}
	return false
}

// ProcessEvent handles incoming events from sensors, pushes them to the SIEM, and triggers notifications.
//
// Events from whitelisted sources are still stored (archived, read) and still
// forwarded to the SIEM flagged whitelisted=true: the whitelist suppresses
// noise for operators, it never destroys evidence.
func (s *Service) ProcessEvent(e *models.Event, nodeID string) error {
	nowStr := time.Now().UTC().Format(time.RFC3339)

	// Never trust server-side fields supplied in the request body.
	e.ID = 0
	e.Count = 0
	e.NodeID = nodeID
	e.IsRead = false
	e.IsArchived = false
	e.Whitelisted = false

	e.SensorID = clampField(e.SensorID, "")
	e.EventTrigger = clampField(e.EventTrigger, "alert")
	e.Source = clampField(e.Source, "Unknown")
	e.Target = clampField(e.Target, "Unknown")
	if sev, ok := models.NormalizeSeverity(e.Severity); !ok {
		log.Printf("[WARNING] Event from node %s sensor %s has invalid severity %q; stored as %q", nodeID, e.SensorID, e.Severity, sev)
		e.Severity = sev
	} else {
		e.Severity = sev
	}
	detailsStr := normalizeDetails(e.Details)
	e.Details = json.RawMessage(detailsStr)

	registered, err := s.store.IsSensorRegistered(nodeID, e.SensorID)
	if err != nil {
		return err
	}
	if !registered {
		return ErrSensorNotRegistered
	}

	if s.isWhitelisted(e.Source) {
		e.Whitelisted = true
		e.IsArchived = true
		e.IsRead = true
	}

	lastInsertID, err := s.store.InsertEvent(e, nowStr, detailsStr)
	if err != nil {
		log.Printf("[ERROR] Failed to insert event for node %s/sensor %s: %v", nodeID, e.SensorID, err)
		return err
	}

	e.ID = lastInsertID
	e.Timestamp = nowStr
	e.Count = 1

	if e.Source != SystemSource {
		s.store.UpdateNodeLastHeartbeat(nodeID, e.SensorID, nowStr)
	}

	s.siemService.QueueEvent(*e)

	if e.Whitelisted {
		return nil
	}

	isSilenced, err := s.store.IsSensorSilenced(nodeID, e.SensorID)
	if err != nil {
		log.Printf("[WARNING] Failed to check silence status for node %s/sensor %s: %v", nodeID, e.SensorID, err)
	}
	if !isSilenced {
		s.notifyService.Dispatch(*e)
	}

	s.broadcaster.Broadcast("NEW_EVENT", *e)
	return nil
}

// EmitSystemEvent records an event raised by the Hub itself (e.g. a sensor
// stopped heartbeating) through the same pipeline as sensor events, so it is
// stored, forwarded to the SIEM and notified.
func (s *Service) EmitSystemEvent(nodeID, sensorID, trigger, severity string, details map[string]any) {
	raw, _ := json.Marshal(details)
	e := &models.Event{
		SensorID:     sensorID,
		EventTrigger: trigger,
		Severity:     severity,
		Source:       SystemSource,
		Target:       sensorID,
		Details:      raw,
	}
	if err := s.ProcessEvent(e, nodeID); err != nil {
		log.Printf("[WARNING] Failed to record system event %s for %s/%s: %v", trigger, nodeID, sensorID, err)
	}
}

func (s *Service) GetEvents(isArchived int, nodeID, sensorID string) ([]models.Event, error) {
	return s.store.GetEvents(isArchived, nodeID, sensorID)
}

func (s *Service) GetUnreadCount() (int, error) {
	return s.store.GetUnreadEventCount()
}

func (s *Service) MarkSingleEventRead(eventID string) error { return s.store.MarkEventRead(eventID) }
func (s *Service) MarkEventsRead() error                    { return s.store.MarkAllEventsRead() }
func (s *Service) ArchiveEvent(eventID string) error        { return s.store.ArchiveEvent(eventID) }
func (s *Service) ArchiveAll() error                        { return s.store.ArchiveAllEvents() }

func (s *Service) ClearEvents(dryrun bool, ip string) (int, error) {
	if dryrun {
		return s.store.GetEventCount()
	}
	log.Printf("[!] AUDIT: Database purged by IP %s", ip)
	return 0, s.store.ClearAllEvents()
}

func (s *Service) StartRetentionWorker(ctx context.Context) {
	log.Println("[Retention] Worker started.")

	// Wake up every hour to check retention
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[Retention] Worker stopped.")
			return
		case <-ticker.C:
			archiveStr, _ := s.store.GetConfigValue("auto_archive_days")
			purgeStr, _ := s.store.GetConfigValue("auto_purge_days")
			purgeHeartbeatsStr, _ := s.store.GetConfigValue("auto_purge_heartbeats_days")

			archiveDays, _ := strconv.Atoi(archiveStr)
			purgeDays, _ := strconv.Atoi(purgeStr)
			purgeHeartbeatsDays, _ := strconv.Atoi(purgeHeartbeatsStr)

			if archiveDays > 0 || purgeDays > 0 || purgeHeartbeatsDays > 0 {
				if err := s.store.EnforceRetention(archiveDays, purgeDays, purgeHeartbeatsDays); err != nil {
					log.Printf("[WARNING] Event retention task failed: %v", err)
				}
			}
		}
	}
}
