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
	"github.com/truesignal/hub/internal/services/honeytoken"
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

// HoneytokenMatcher recognises planted credentials in an event.
type HoneytokenMatcher interface {
	Match(e models.Event) ([]honeytoken.Match, error)
	RecordUse(id string) error
}

// ErrSensorNotRegistered is returned when an event names a sensor that is not
// installed on the authenticated node.
var ErrSensorNotRegistered = errors.New("sensor_not_registered")

// ErrReservedTrigger is returned when a sensor reports a trigger only the Hub
// may raise (honeytoken_used), so a compromised decoy cannot forge one.
var ErrReservedTrigger = errors.New("reserved_trigger")

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
	honeytokens   HoneytokenMatcher
}

// SetHoneytokenMatcher enables honeytoken detection on incoming events.
func (s *Service) SetHoneytokenMatcher(m HoneytokenMatcher) { s.honeytokens = m }

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
	if strings.TrimSpace(e.EventTrigger) == honeytoken.Trigger {
		return ErrReservedTrigger
	}
	return s.process(e, nodeID, false)
}

// process stores and routes an event. hubRaised marks events the Hub
// generates itself from evidence (honeytoken use): they are never suppressed
// by the source whitelist, because a planted credential is never used
// legitimately.
func (s *Service) process(e *models.Event, nodeID string, hubRaised bool) error {
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

	if !hubRaised && s.isWhitelisted(e.Source) {
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
	s.checkHoneytokens(*e)

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

// checkHoneytokens raises a critical honeytoken_used event for every planted
// credential found in e. It runs for whitelisted sources too.
func (s *Service) checkHoneytokens(e models.Event) {
	if s.honeytokens == nil {
		return
	}
	matches, err := s.honeytokens.Match(e)
	if err != nil {
		log.Printf("[WARNING] Honeytoken check failed for event %d: %v", e.ID, err)
		return
	}
	var details map[string]any
	_ = json.Unmarshal(e.Details, &details)
	for _, m := range matches {
		raw, _ := json.Marshal(map[string]any{
			"honeytoken_id":       m.Token.ID,
			"honeytoken_username": m.Token.Username,
			"matched_on":          m.MatchedOn,
			"planted_node_id":     m.Token.NodeID,
			"planted_sensor_id":   m.Token.SensorID,
			"triggering_event_id": e.ID,
			"triggering_trigger":  e.EventTrigger,
			"protocol":            details["protocol"],
			"dst_port":            details["dst_port"],
		})
		alert := &models.Event{
			SensorID:     e.SensorID,
			EventTrigger: honeytoken.Trigger,
			Severity:     "critical",
			Source:       e.Source,
			Target:       e.Target,
			Details:      raw,
		}
		if err := s.process(alert, e.NodeID, true); err != nil {
			log.Printf("[WARNING] Failed to record honeytoken use %s: %v", m.Token.ID, err)
			continue
		}
		if err := s.honeytokens.RecordUse(m.Token.ID); err != nil {
			log.Printf("[WARNING] Failed to record honeytoken use count %s: %v", m.Token.ID, err)
		}
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
