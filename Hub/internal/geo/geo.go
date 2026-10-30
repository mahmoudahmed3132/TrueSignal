// Package geo places public source addresses on the map using a DB-IP IP to
// City Lite database (MMDB, the GeoIP2-City layout; CC BY 4.0, so every view
// of the data must credit DB-IP).
//
// Lookups are resolved when events are read or forwarded and never stored,
// like the ATT&CK mapping and the asset inventory, so a database update
// applies to past events too. Internal addresses (private, CGNAT, loopback,
// link-local, ULA) are never looked up: the decoys sit in internal space,
// so the map fills mainly from beacons opened outside.
//
// The database is a file: TS_GEOIP_DB, or geoip/dbip-city-lite.mmdb next to
// the Hub database. The Hub re-reads it when it changes. With
// TS_GEOIP_AUTO_UPDATE=true it downloads the current month's file from
// download.db-ip.com itself (outbound HTTPS; off by default).
package geo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Attribution is the credit CC BY 4.0 requires wherever the data is shown.
const (
	Attribution    = "IP Geolocation by DB-IP"
	AttributionURL = "https://db-ip.com"
)

// Location is where an address is, as far as the database knows.
type Location struct {
	CountryCode string  `json:"countryCode"`
	Country     string  `json:"country"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	// Basis is what was located: "source" (the event's source address) or
	// "client_subnet" (a DNS beacon's EDNS Client Subnet, which is closer
	// to the person than the resolver in source).
	Basis string `json:"basis"`
	// Address is the address looked up (the subnet's network address for
	// client_subnet).
	Address string `json:"address"`
}

// record is the part of a City record TrueSignal uses.
type record struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Status describes the loaded database for the UI and the report.
type Status struct {
	Enabled        bool   `json:"enabled"`
	Path           string `json:"path"`
	DatabaseType   string `json:"databaseType,omitempty"`
	BuildDate      string `json:"buildDate,omitempty"`
	AutoUpdate     bool   `json:"autoUpdate"`
	LastError      string `json:"lastError,omitempty"`
	Attribution    string `json:"attribution"`
	AttributionURL string `json:"attributionUrl"`
}

// Service owns the open database. Its zero value (or nil) finds nothing.
type Service struct {
	path       string
	autoUpdate bool

	mu      sync.RWMutex // Close must not run concurrently with lookups
	db      *maxminddb.Reader
	modTime time.Time
	size    int64
	lastErr string
}

// New prepares a service for the database at path and loads it if present.
func New(path string, autoUpdate bool) *Service {
	s := &Service{path: path, autoUpdate: autoUpdate}
	if err := s.Reload(); err != nil && !os.IsNotExist(err) {
		log.Printf("[GeoIP] %v", err)
	}
	return s
}

// validate checks that a database is a City database TrueSignal can use.
func validate(db *maxminddb.Reader) error {
	t := db.Metadata.DatabaseType
	if !strings.Contains(strings.ToLower(t), "city") {
		return fmt.Errorf("database type %q is not a City database (want DB-IP IP to City Lite)", t)
	}
	return nil
}

// Reload opens the file if it changed since the last load. A file that
// fails to open or validate leaves the previous database in use.
func (s *Service) Reload() error {
	if s == nil || s.path == "" {
		return nil
	}
	fi, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.setErr("")
		}
		return err
	}
	s.mu.RLock()
	same := s.db != nil && fi.ModTime().Equal(s.modTime) && fi.Size() == s.size
	s.mu.RUnlock()
	if same {
		return nil
	}
	db, err := openSnapshot(s.path)
	if err == nil {
		if err = validate(db); err != nil {
			db.Close()
		}
	}
	if err != nil {
		err = fmt.Errorf("%s: %w", s.path, err)
		s.setErr(err.Error())
		return err
	}
	s.mu.Lock()
	old := s.db
	s.db, s.modTime, s.size, s.lastErr = db, fi.ModTime(), fi.Size(), ""
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
	log.Printf("[GeoIP] Loaded %s (%s, built %s)", s.path, db.Metadata.DatabaseType, time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02"))
	return nil
}

func (s *Service) setErr(msg string) {
	s.mu.Lock()
	s.lastErr = msg
	s.mu.Unlock()
}

// openSnapshot opens a private copy of path. The reader memory-maps its
// file, so opening path itself would let an operator who overwrites it in
// place (cp) corrupt or crash the live database. The copy is unlinked as
// soon as it is mapped; the mapping keeps it alive until Close.
func openSnapshot(path string) (*maxminddb.Reader, error) {
	src, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	dst, err := os.CreateTemp(filepath.Dir(path), ".loaded-*.mmdb")
	if err != nil {
		return nil, err
	}
	defer os.Remove(dst.Name())
	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return maxminddb.Open(dst.Name())
}

// Close releases the database.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
}

// Enabled reports whether a database is loaded.
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db != nil
}

// ClientSubnetDetails decodes an event's details only when they can hold a
// client subnet, so locating a page of events doesn't parse every one.
func ClientSubnetDetails(raw []byte) map[string]any {
	if !bytes.Contains(raw, []byte(`"client_subnet"`)) {
		return nil
	}
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	return d
}

func (s *Service) Status() Status {
	st := Status{Attribution: Attribution, AttributionURL: AttributionURL}
	if s == nil {
		return st
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	st.Path, st.AutoUpdate, st.LastError = s.path, s.autoUpdate, s.lastErr
	if s.db != nil {
		st.Enabled = true
		st.DatabaseType = s.db.Metadata.DatabaseType
		st.BuildDate = time.Unix(int64(s.db.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02")
	}
	return st
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Public reports whether addr is worth locating: not private, CGNAT,
// loopback, link-local, multicast or unspecified.
func Public(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !cgnat.Contains(addr)
}

// Lookup locates a source string (an IP, or an IP with a port). Names and
// internal addresses return nil.
func (s *Service) Lookup(source string) *Location {
	if s == nil {
		return nil
	}
	if host, _, err := net.SplitHostPort(source); err == nil {
		source = host
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil {
		return nil
	}
	return s.lookup(addr, "source")
}

// ForEvent locates the event's origin: a DNS beacon's EDNS Client Subnet
// when it carries a public one, else the source address.
func (s *Service) ForEvent(source string, details map[string]any) *Location {
	if s == nil {
		return nil
	}
	if cs, ok := details["client_subnet"].(string); ok {
		if p, err := netip.ParsePrefix(cs); err == nil {
			if loc := s.lookup(p.Masked().Addr(), "client_subnet"); loc != nil {
				return loc
			}
		}
	}
	return s.Lookup(source)
}

func (s *Service) lookup(addr netip.Addr, basis string) *Location {
	addr = addr.Unmap()
	if !Public(addr) {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil
	}
	var r record
	res := s.db.Lookup(addr)
	if !res.Found() || res.Decode(&r) != nil {
		return nil
	}
	if r.Country.ISOCode == "" && r.Location.Latitude == nil {
		return nil
	}
	loc := &Location{
		CountryCode: r.Country.ISOCode,
		Country:     r.Country.Names["en"],
		City:        r.City.Names["en"],
		Basis:       basis,
		Address:     addr.String(),
	}
	if len(r.Subdivisions) > 0 {
		loc.Region = r.Subdivisions[0].Names["en"]
	}
	if r.Location.Latitude != nil && r.Location.Longitude != nil {
		loc.Lat, loc.Lon = *r.Location.Latitude, *r.Location.Longitude
	}
	return loc
}
