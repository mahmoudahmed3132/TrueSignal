package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/store"
)

func TestGetReportValidation(t *testing.T) {
	st, err := store.NewStore(filepath.Join(t.TempDir(), "report.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB.Close()
	h := NewAnalyticsHandler(st)

	get := func(q string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.GetReport(w, httptest.NewRequest(http.MethodGet, "/api/v2/report"+q, nil))
		return w
	}
	for q, want := range map[string]int{
		"":                               http.StatusOK,
		"?from=2026-10-01&to=2026-10-08": http.StatusOK,
		"?from=2026-10-01T00:00:00Z":     http.StatusOK,
		"?from=yesterday":                http.StatusBadRequest,
		"?from=2026-10-08&to=2026-10-01": http.StatusBadRequest,
		"?from=2024-01-01&to=2026-01-01": http.StatusBadRequest, // over 366 days
	} {
		if w := get(q); w.Code != want {
			t.Errorf("%q = %d, want %d (%s)", q, w.Code, want, w.Body)
		}
	}
	if w := get("?from=2026-10-01&to=2026-10-08"); !strings.Contains(w.Body.String(), `"daily":[{"date":"2026-10-01"`) {
		t.Errorf("body = %s", w.Body)
	}
}
