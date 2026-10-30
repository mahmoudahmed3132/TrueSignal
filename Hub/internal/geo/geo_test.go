package geo

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func copyFixture(t *testing.T, name, dst string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	path := filepath.Join(t.TempDir(), "geoip", "dbip-city-lite.mmdb")
	copyFixture(t, "dbip-city-test.mmdb", path)
	s := New(path, false)
	t.Cleanup(s.Close)
	return s
}

func TestLookup(t *testing.T) {
	s := newTestService(t)
	loc := s.Lookup("81.2.69.160")
	if loc == nil || loc.CountryCode != "GB" || loc.City != "London" || loc.Region != "England" ||
		loc.Lat != 51.5142 || loc.Lon != -0.0931 || loc.Basis != "source" || loc.Address != "81.2.69.160" {
		t.Fatalf("loc = %+v", loc)
	}
	if loc := s.Lookup("[2a02:c7f::1]:443"); loc == nil || loc.CountryCode != "DE" {
		t.Fatalf("IPv6 with port: %+v", loc)
	}
	if loc := s.Lookup("203.0.113.9:51234"); loc == nil || loc.City != "Ashburn" {
		t.Fatalf("IPv4 with port: %+v", loc)
	}
	// Internal and unparseable sources are never looked up (10/8 is in the
	// fixture on purpose).
	for _, src := range []string{"10.1.2.3", "192.168.1.1", "100.64.1.1", "127.0.0.1", "fe80::1", "fd00::1", "Wizard Firedrill", "", "8.8.8.8"} {
		if loc := s.Lookup(src); loc != nil {
			t.Errorf("%q located: %+v", src, loc)
		}
	}
}

func TestForEventPrefersPublicClientSubnet(t *testing.T) {
	s := newTestService(t)
	loc := s.ForEvent("81.2.69.1", map[string]any{"client_subnet": "198.51.100.77/24"})
	if loc == nil || loc.CountryCode != "EG" || loc.Basis != "client_subnet" || loc.Address != "198.51.100.0" {
		t.Fatalf("loc = %+v", loc)
	}
	// A private or malformed subnet falls back to the source.
	for _, cs := range []any{"10.0.0.0/8", "nonsense", 42} {
		if loc := s.ForEvent("81.2.69.1", map[string]any{"client_subnet": cs}); loc == nil || loc.Basis != "source" {
			t.Errorf("%v: %+v", cs, loc)
		}
	}
}

func TestNilAndMissingDatabase(t *testing.T) {
	var s *Service
	if s.Lookup("81.2.69.1") != nil || s.Status().Enabled || s.Status().Attribution == "" {
		t.Fatal("nil service must find nothing and still carry the attribution")
	}
	m := New(filepath.Join(t.TempDir(), "missing.mmdb"), true)
	if m.Lookup("81.2.69.1") != nil || m.Status().Enabled || m.Status().LastError != "" {
		t.Fatalf("missing file: %+v", m.Status())
	}
}

func TestRejectsNonCityAndKeepsCurrent(t *testing.T) {
	s := newTestService(t)
	// Replace the file with a Country database: rejected, London still found.
	copyFixture(t, "dbip-country-test.mmdb", s.path)
	future := time.Now().Add(time.Minute)
	os.Chtimes(s.path, future, future)
	if err := s.Reload(); err == nil {
		t.Fatal("Country database accepted")
	}
	if loc := s.Lookup("81.2.69.1"); loc == nil || loc.City != "London" {
		t.Fatalf("previous database lost: %+v", loc)
	}
	if st := s.Status(); !st.Enabled || st.LastError == "" || st.DatabaseType != "DBIP-City-Lite" {
		t.Fatalf("status = %+v", st)
	}
}

func gzipped(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(raw)
	zw.Close()
	return buf.Bytes()
}

func TestDownload(t *testing.T) {
	city, country := gzipped(t, "dbip-city-test.mmdb"), gzipped(t, "dbip-country-test.mmdb")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/city.mmdb.gz":
			w.Write(city)
		case "/country.mmdb.gz":
			w.Write(country)
		case "/garbage.mmdb.gz":
			w.Write([]byte("not gzip"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := New(filepath.Join(t.TempDir(), "geoip", "dbip-city-lite.mmdb"), true)
	defer s.Close()
	ctx := context.Background()
	if err := s.download(ctx, srv.Client(), srv.URL+"/missing.mmdb.gz"); !errors.Is(err, ErrNotPublished) {
		t.Fatalf("404: err = %v", err)
	}
	if err := s.download(ctx, srv.Client(), srv.URL+"/city.mmdb.gz"); err != nil {
		t.Fatal(err)
	}
	if loc := s.Lookup("81.2.69.1"); loc == nil || loc.City != "London" {
		t.Fatalf("downloaded database not loaded: %+v", loc)
	}
	for _, bad := range []string{"/country.mmdb.gz", "/garbage.mmdb.gz"} {
		if err := s.download(ctx, srv.Client(), srv.URL+bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if loc := s.Lookup("81.2.69.1"); loc == nil || loc.City != "London" {
		t.Fatal("a rejected download replaced the database")
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(filepath.Dir(s.path))
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestClientSubnetDetails(t *testing.T) {
	if ClientSubnetDetails([]byte(`{"username":"root"}`)) != nil {
		t.Error("decoded details without a client subnet")
	}
	if d := ClientSubnetDetails([]byte(`{"client_subnet":"198.51.100.0/24"}`)); d["client_subnet"] != "198.51.100.0/24" {
		t.Errorf("d = %v", d)
	}
	if (*Service)(nil).Enabled() || !newTestService(t).Enabled() {
		t.Error("Enabled")
	}
}
