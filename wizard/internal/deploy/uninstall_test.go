package deploy

import (
	"reflect"
	"testing"
)

func TestParseDecoyFiles(t *testing.T) {
	compose := []byte(`
services:
  fim-decoy-provisioner:
    environment:
      - TS_DECOY_FILES=/opt/.env.backup,/var/www/html/a$$b.php
  ts-sensor-file-canary:
    environment:
      - TS_SENSOR_ID=ts-sensor-file-canary
      - TS_DECOY_FILES=/opt/.env.backup,/var/www/html/a$$b.php
`)
	got := parseDecoyFiles(compose)
	want := []string{"/opt/.env.backup", "/var/www/html/a$b.php"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
