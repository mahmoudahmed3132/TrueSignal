package config

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/services/siem"
)

func TestValidateConfigUpdate(t *testing.T) {
	cases := []struct {
		name    string
		req     map[string]interface{}
		wantErr bool
	}{
		{"valid webhook type", map[string]interface{}{"webhookType": "Slack"}, false},
		{"none webhook type", map[string]interface{}{"webhookType": "none"}, false},
		{"unknown webhook type", map[string]interface{}{"webhookType": "teams"}, true},
		{"tls protocol", map[string]interface{}{"siemProtocol": "TLS"}, false},
		{"unknown protocol", map[string]interface{}{"siemProtocol": "relp"}, true},
		{"non-string protocol", map[string]interface{}{"siemProtocol": 1.0}, true},
		{"valid severities", map[string]interface{}{"webhookEvents": []interface{}{"critical", "info"}}, false},
		{"unknown severity", map[string]interface{}{"webhookEvents": []interface{}{"critical", "urgent"}}, true},
		{"severities not a list", map[string]interface{}{"webhookEvents": "critical"}, true},
		{"elastic protocol", map[string]interface{}{"siemProtocol": "elastic"}, false},
		{"logscale protocol", map[string]interface{}{"siemProtocol": "LogScale"}, false},
		{"ecs format", map[string]interface{}{"siemFormat": "ECS"}, false},
		{"unknown format", map[string]interface{}{"siemFormat": "cef"}, true},
		{"non-string token", map[string]interface{}{"siemToken": 5.0}, true},
		{"multi-line token", map[string]interface{}{"siemToken": "abc\ndef"}, true},
		{"negative retention", map[string]interface{}{"autoPurgeDays": -1.0}, true},
		{"non-http registry", map[string]interface{}{"registryUrl": "file:///etc"}, true},
		{"unknown snake_case key", map[string]interface{}{"registry_url": "http://x"}, true},
		{"unknown typo key", map[string]interface{}{"webhookUrlx": "http://x"}, true},
		{"known key alongside unknown", map[string]interface{}{"webhookType": "ntfy", "bogus": 1.0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigUpdate(tc.req)
			if tc.wantErr {
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("expected ValidationError, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateSiemAddress(t *testing.T) {
	cases := []struct {
		protocol, address string
		wantErr           bool
	}{
		{"tcp", "siem.local:6514", false},
		{"tls", "siem.local", true},
		{"udp", "", false},
		{"tcp", "https://es:9200/logs-x", true},
		{"elastic", "https://es.example:9200/logs-truesignal-default", false},
		{"elastic", "https://es.example:9200", true},
		{"elastic", "http://es.example:9200/logs-truesignal-default", true},
		{"elastic", "https://user:pw@es.example:9200/logs-x", true},
		{"elastic", "es.example:9200", true},
		{"logscale", "https://cloud.us.humio.com/api/v1/ingest/hec", false},
		{"logscale", "https://cloud.us.humio.com/api/v1/ingest/hec?token=x", true},
		{"logscale", "siem.local:514", true},
	}
	for _, tc := range cases {
		err := validateSiemAddress(tc.protocol, tc.address)
		var ve *ValidationError
		if tc.wantErr != errors.As(err, &ve) {
			t.Errorf("%s %q: err=%v, wantErr=%v", tc.protocol, tc.address, err, tc.wantErr)
		}
	}
}

type tokenStore struct{ values map[string]string }

func (m *tokenStore) GetConfigValue(key string) (string, error)              { return m.values[key], nil }
func (m *tokenStore) CompleteSetup(adminHash, hubEndpoint string) error      { return nil }
func (m *tokenStore) GetAllConfig() (map[string]string, error)               { return m.values, nil }
func (m *tokenStore) UpdateConfigBatch(updates map[string]interface{}) error { return nil }
func (m *tokenStore) UpdateConfigValue(key, value string) error              { return nil }
func (m *tokenStore) FactoryReset(bool) error                                { return nil }
func (m *tokenStore) FactoryResetDryRun(bool) (map[string]int, error)        { return nil, nil }

func TestGetConfigNeverReturnsSiemToken(t *testing.T) {
	svc := &Service{store: &tokenStore{values: map[string]string{
		"siem_protocol": "elastic", "siem_token": "c2VjcmV0LWFwaS1rZXk=",
	}}}
	payload, err := svc.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(payload)
	if strings.Contains(string(b), "c2VjcmV0LWFwaS1rZXk=") {
		t.Fatalf("token leaked: %s", b)
	}
	if !payload.SiemTokenSet {
		t.Fatal("siemTokenSet should be true")
	}
}

type resetStore struct{ tokenStore }

func (m *resetStore) FactoryReset(bool) error {
	m.values = map[string]string{"admin_hash": m.values["admin_hash"], "siem_protocol": "tcp", "siem_format": "rfc5424"}
	return nil
}

type fakeSessions struct{}

func (fakeSessions) ClearAllSessions() {}
func (fakeSessions) ClearNodeCache()   {}

type fakeSiem struct{ last siem.Output }

func (f *fakeSiem) UpdateConfig(o siem.Output) { f.last = o }

type fakeNotify struct{ url string }

func (f *fakeNotify) UpdateConfig(_ bool, _, url, _ string) { f.url = url }
func (f *fakeNotify) UpdateIsArmed(bool)                    {}

func TestFactoryResetDropsLiveOutputs(t *testing.T) {
	st := &resetStore{tokenStore{values: map[string]string{
		"siem_protocol": "elastic", "siem_address": "https://es:9200/logs-x", "siem_token": "secret",
		"webhook_url": "https://hooks.example/abc",
	}}}
	sm, nt := &fakeSiem{last: siem.Output{Address: "https://es:9200/logs-x", Token: "secret"}}, &fakeNotify{url: "https://hooks.example/abc"}
	svc := &Service{store: st, sessionManager: fakeSessions{}, siemService: sm, notifyService: nt, dashboardPassword: "pw-123456789012"}
	if err := svc.FactoryReset("pw-123456789012", "127.0.0.1", false); err != nil {
		t.Fatal(err)
	}
	if sm.last.Address != "" || sm.last.Token != "" {
		t.Fatalf("SIEM output survived reset: %+v", sm.last)
	}
	if nt.url != "" {
		t.Fatalf("webhook survived reset: %q", nt.url)
	}
}
