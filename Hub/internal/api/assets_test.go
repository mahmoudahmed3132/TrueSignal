package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type memConfig struct{ v map[string]string }

func (m *memConfig) GetConfigValue(k string) (string, error) { return m.v[k], nil }
func (m *memConfig) UpdateConfigValue(k, v string) error     { m.v[k] = v; return nil }

func TestAssetsHandler(t *testing.T) {
	st := &memConfig{v: map[string]string{}}
	h := NewAssetsHandler(st)

	put := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ReplaceAssets(w, httptest.NewRequest(http.MethodPut, "/api/v2/assets", strings.NewReader(body)))
		return w
	}

	if w := put(`{"assets":[{"name":" pg-primary ","address":"10.20.4.17","criticality":"CRITICAL","owner":"payments","tags":["pci"]}]}`); w.Code != http.StatusOK {
		t.Fatalf("valid PUT = %d %s", w.Code, w.Body)
	}
	if !strings.Contains(st.v["assets"], `"name":"pg-primary"`) || !strings.Contains(st.v["assets"], `"criticality":"critical"`) {
		t.Fatalf("stored = %s", st.v["assets"])
	}

	w := httptest.NewRecorder()
	h.ListAssets(w, httptest.NewRequest(http.MethodGet, "/api/v2/assets", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"owner":"payments"`) {
		t.Fatalf("GET = %d %s", w.Code, w.Body)
	}

	before := st.v["assets"]
	for name, body := range map[string]string{
		"bad address":   `{"assets":[{"name":"x","address":"10.0.0.0/40"}]}`,
		"unknown field": `{"assets":[],"extra":1}`,
		"not json":      `nope`,
	} {
		if w := put(body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	if st.v["assets"] != before {
		t.Fatal("a rejected PUT changed the inventory")
	}

	if w := put(`{"assets":[]}`); w.Code != http.StatusOK || st.v["assets"] != "[]" {
		t.Fatalf("clearing = %d, stored %q", w.Code, st.v["assets"])
	}
}
