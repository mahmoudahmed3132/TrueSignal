package config

import (
	"errors"
	"testing"
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
		{"bad siem address", map[string]interface{}{"siemAddress": "siem.local"}, true},
		{"good siem address", map[string]interface{}{"siemAddress": "siem.local:6514"}, false},
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
