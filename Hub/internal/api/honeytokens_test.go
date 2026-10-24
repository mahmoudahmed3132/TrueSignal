package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/models"
)

type fakeHoneytokenLister []models.Honeytoken

func (f fakeHoneytokenLister) List() ([]models.Honeytoken, error) { return f, nil }

func TestListHoneytokensJSONAndCSV(t *testing.T) {
	h := NewHoneytokenHandler(fakeHoneytokenLister{{ID: "ht_1", Username: "svc_etl0a1b", Secret: "s3cr3t-Value!", NodeID: "node-a", SensorID: "ts-sensor-file-canary", CreatedAt: "2026-10-24T00:00:00Z"}})

	rec := httptest.NewRecorder()
	h.ListHoneytokens(rec, httptest.NewRequest("GET", "/api/v2/honeytokens", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"username":"svc_etl0a1b"`) || strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Fatalf("json = %d %s", rec.Code, rec.Body)
	}

	rec = httptest.NewRecorder()
	h.ListHoneytokens(rec, httptest.NewRequest("GET", "/api/v2/honeytokens?format=csv", nil))
	want := "username,honeytoken_id,planted_node_id,planted_sensor_id,created_at\nsvc_etl0a1b,ht_1,node-a,ts-sensor-file-canary,2026-10-24T00:00:00Z\n"
	if rec.Body.String() != want || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv = %q (%s)", rec.Body, rec.Header().Get("Content-Type"))
	}
}
