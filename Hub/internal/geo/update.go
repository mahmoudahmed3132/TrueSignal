package geo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// DB-IP publishes the Lite database monthly at a predictable URL. There is
// no signature to check, so the file is trusted to HTTPS and then has to
// open and validate as a City database before it replaces the current one.
const (
	downloadURL       = "https://download.db-ip.com/free/dbip-city-lite-%s.mmdb.gz"
	maxCompressed     = 256 << 20
	maxDecompressed   = 1 << 30
	downloadTimeout   = 15 * time.Minute
	updateCheckPeriod = 24 * time.Hour
)

// ErrNotPublished means DB-IP has no file for that month (yet).
var ErrNotPublished = errors.New("not published")

// StartUpdater keeps the database current when auto-update is on: at start
// and daily, it fetches the current month's file if the loaded one is from
// an earlier month (or none is loaded, falling back to last month's). It
// also re-reads the file hourly, so an operator-provided file is picked up
// without a restart.
func (s *Service) StartUpdater(ctx context.Context) {
	if s == nil || s.path == "" {
		return
	}
	reload := time.NewTicker(time.Hour)
	defer reload.Stop()
	var update <-chan time.Time
	if s.autoUpdate {
		s.updateIfStale(ctx, time.Now().UTC())
		t := time.NewTicker(updateCheckPeriod)
		defer t.Stop()
		update = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-reload.C:
			if err := s.Reload(); err != nil && !os.IsNotExist(err) {
				log.Printf("[GeoIP] %v", err)
			}
		case <-update:
			s.updateIfStale(ctx, time.Now().UTC())
		}
	}
}

func (s *Service) loadedMonth() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ""
	}
	return time.Unix(int64(s.db.Metadata.BuildEpoch), 0).UTC().Format("2006-01")
}

func (s *Service) updateIfStale(ctx context.Context, now time.Time) {
	current := now.Format("2006-01")
	loaded := s.loadedMonth()
	if loaded >= current {
		return
	}
	months := []string{current}
	if loaded == "" {
		months = append(months, now.AddDate(0, -1, 0).Format("2006-01"))
	}
	var err error
	for _, m := range months {
		if err = s.download(ctx, http.DefaultClient, fmt.Sprintf(downloadURL, m)); err == nil {
			return
		}
		if !errors.Is(err, ErrNotPublished) {
			break
		}
	}
	msg := fmt.Sprintf("auto-update failed: %v", err)
	s.setErr(msg)
	log.Printf("[GeoIP] %s", msg)
}

// download fetches a gzipped MMDB from url, validates it and swaps it in.
func (s *Service) download(ctx context.Context, client *http.Client, url string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "TrueSignal-Hub")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%s: %w", url, ErrNotPublished)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxCompressed))
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".dbip-*.mmdb")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	n, err := io.Copy(tmp, io.LimitReader(gz, maxDecompressed+1))
	if err == nil && n > maxDecompressed {
		err = fmt.Errorf("%s: larger than %d bytes", url, maxDecompressed)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	db, err := maxminddb.Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	err = validate(db)
	db.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	log.Printf("[GeoIP] Downloaded %s", url)
	return s.Reload()
}
