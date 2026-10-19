package event

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/truesignal/hub/internal/models"
)

type fakeStore struct {
	inserted   []models.Event
	registered bool
	whitelist  string
}

func (f *fakeStore) InsertEvent(e *models.Event, _ string, details string) (int, error) {
	cp := *e
	cp.Details = json.RawMessage(details)
	f.inserted = append(f.inserted, cp)
	return len(f.inserted), nil
}
func (f *fakeStore) UpdateNodeLastHeartbeat(string, string, string) error { return nil }
func (f *fakeStore) IsSensorRegistered(string, string) (bool, error)      { return f.registered, nil }
func (f *fakeStore) IsSensorSilenced(string, string) (bool, error)        { return false, nil }
func (f *fakeStore) GetEvents(int, string, string) ([]models.Event, error) {
	return nil, nil
}
func (f *fakeStore) GetUnreadEventCount() (int, error) { return 0, nil }
func (f *fakeStore) MarkEventRead(string) error        { return nil }
func (f *fakeStore) MarkAllEventsRead() error          { return nil }
func (f *fakeStore) ArchiveEvent(string) error         { return nil }
func (f *fakeStore) ArchiveAllEvents() error           { return nil }
func (f *fakeStore) GetEventCount() (int, error)       { return 0, nil }
func (f *fakeStore) ClearAllEvents() error             { return nil }
func (f *fakeStore) GetConfigValue(key string) (string, error) {
	if key == "whitelisted_sources" {
		return f.whitelist, nil
	}
	return "", nil
}
func (f *fakeStore) EnforceRetention(int, int, int) error { return nil }

type counter struct{ n int }

func (c *counter) Broadcast(string, interface{}) { c.n++ }

type siemRec struct{ events []models.Event }

func (s *siemRec) QueueEvent(e models.Event) { s.events = append(s.events, e) }

type notifyRec struct{ n int }

func (n *notifyRec) Dispatch(models.Event) { n.n++ }

func newSvc(st *fakeStore) (*Service, *counter, *siemRec, *notifyRec) {
	b, s, n := &counter{}, &siemRec{}, &notifyRec{}
	return NewService(st, b, s, n), b, s, n
}

func TestProcessEvent_NormalisesAndRejectsUntrustedFields(t *testing.T) {
	st := &fakeStore{registered: true}
	svc, _, _, _ := newSvc(st)

	e := &models.Event{SensorID: "s1", Severity: "BOGUS", Details: json.RawMessage(`[1,2]`), IsArchived: true, IsRead: true, ID: 99}
	if err := svc.ProcessEvent(e, "n1"); err != nil {
		t.Fatal(err)
	}
	got := st.inserted[0]
	if got.Severity != "medium" || got.EventTrigger != "alert" || got.Source != "Unknown" || got.Target != "Unknown" {
		t.Errorf("defaults/normalisation not applied: %+v", got)
	}
	if got.IsArchived || got.IsRead || got.NodeID != "n1" {
		t.Errorf("client-supplied server fields must be ignored: %+v", got)
	}
	if string(got.Details) != `{"value":[1,2]}` {
		t.Errorf("non-object details must be wrapped, got %s", got.Details)
	}
}

func TestProcessEvent_WhitelistedIsStoredAndForwardedButNotNotified(t *testing.T) {
	st := &fakeStore{registered: true, whitelist: "10.0.0.5, 10.0.0.6"}
	svc, ws, siem, notify := newSvc(st)

	if err := svc.ProcessEvent(&models.Event{SensorID: "s1", Severity: "high", Source: "10.0.0.6"}, "n1"); err != nil {
		t.Fatal(err)
	}
	if len(st.inserted) != 1 || !st.inserted[0].IsArchived || !st.inserted[0].IsRead {
		t.Fatalf("whitelisted event must be stored archived+read: %+v", st.inserted)
	}
	if len(siem.events) != 1 || !siem.events[0].Whitelisted {
		t.Fatalf("whitelisted event must reach the SIEM flagged: %+v", siem.events)
	}
	if notify.n != 0 || ws.n != 0 {
		t.Fatalf("whitelisted event must not notify or broadcast (notify=%d ws=%d)", notify.n, ws.n)
	}
}

func TestProcessEvent_UnregisteredSensor(t *testing.T) {
	svc, _, _, _ := newSvc(&fakeStore{registered: false})
	err := svc.ProcessEvent(&models.Event{SensorID: "ghost"}, "n1")
	if !errors.Is(err, ErrSensorNotRegistered) {
		t.Fatalf("expected ErrSensorNotRegistered, got %v", err)
	}
}
