package attack

import (
	"os"
	"regexp"
	"testing"
)

func TestFor(t *testing.T) {
	for trigger, want := range map[string]string{
		"network_scan_detected": "T1046",
		"icmp_scan_received":    "T1018",
		"ssh_login":             "T1021.004",
		"rdp_login":             "T1021.001",
		"rdp_connection":        "T1046",
		"mysql_login":           "T1110",
		"telnet_login":          "T1110",
		"mssql_connection":      "T1046",
		"ldaps_query":           "T1087.002",
		"web_path_probe":        "T1595.003",
		"decoy_file_accessed":   "T1552.001",
		"decoy_file_tampered":   "T1565.001",
		"honeytoken_used":       "T1078",
	} {
		m, ok := For(trigger)
		if !ok || m.Primary.ID != want {
			t.Errorf("For(%q) = %v %v, want %s", trigger, m.Primary.ID, ok, want)
		}
	}
	for _, unmapped := range []string{"web_page_view", "sensor_heartbeat_lost", "sensor_stopped", "sensor_recovered", "custom_anomaly_detected", ""} {
		if _, ok := For(unmapped); ok {
			t.Errorf("For(%q) is mapped; it must not be", unmapped)
		}
	}
}

func TestTechniquesWellFormed(t *testing.T) {
	id := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	tacticIDs := map[string]bool{}
	for _, tc := range TacticOrder {
		tacticIDs[tc.ID] = true
	}
	for _, tech := range Covered() {
		if !id.MatchString(tech.ID) || tech.Name == "" || len(tech.Tactics) == 0 {
			t.Errorf("malformed technique %+v", tech)
		}
		for _, tc := range tech.Tactics {
			if !tacticIDs[tc.ID] {
				t.Errorf("%s has unknown tactic %+v", tech.ID, tc)
			}
		}
	}
	// Valid Accounts is never a Credential Access technique in ATT&CK.
	for _, tc := range T1078.Tactics {
		if tc == CredentialAccess {
			t.Error("T1078 filed under Credential Access")
		}
	}
	if got := T1021_004.Reference(); got != "https://attack.mitre.org/techniques/T1021/004/" {
		t.Errorf("Reference = %s", got)
	}
	if got := T1078.TacticIDs(); got != "TA0001,TA0003,TA0004,TA0005" {
		t.Errorf("TacticIDs = %s", got)
	}
}

// The published mapping (Docs/siem/attack-mapping.md) must match the code.
func TestDocMatchesCode(t *testing.T) {
	b, err := os.ReadFile("../../../Docs/siem/attack-mapping.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for trigger, m := range exact {
		re := regexp.MustCompile("`" + regexp.QuoteMeta(trigger) + "`[^\n]*\\| " + regexp.QuoteMeta(m.Primary.ID) + " ")
		if !re.MatchString(doc) {
			t.Errorf("doc does not map %s to %s", trigger, m.Primary.ID)
		}
		for _, s := range m.Secondary {
			re := regexp.MustCompile("`" + regexp.QuoteMeta(trigger) + "`[^\n]*\\| " + regexp.QuoteMeta(s.ID) + " \\|")
			if !re.MatchString(doc) {
				t.Errorf("doc lacks secondary %s for %s", s.ID, trigger)
			}
		}
	}
}
