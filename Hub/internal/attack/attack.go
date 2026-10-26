// Package attack maps TrueSignal event triggers to MITRE ATT&CK
// (Enterprise) techniques and their tactics.
//
// The mapping is part of the SIEM contract (ECS threat.*, RFC 5424
// mitre_* parameters): change it deliberately, keep IDs stable, and record
// changes in CHANGELOG.md. A trigger that is not mapped (Hub liveness,
// web_page_view, community sensors) carries no ATT&CK data rather than a
// guess.
package attack

import (
	"sort"
	"strings"
)

// Framework is the ECS threat.framework value.
const Framework = "MITRE ATT&CK"

// Tactic is an ATT&CK Enterprise tactic.
type Tactic struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Technique is an ATT&CK technique or sub-technique with every tactic
// ATT&CK files it under.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []Tactic `json:"tactics"`
}

// Mapping is the ATT&CK view of one event: the primary technique the event
// evidences, plus techniques it may also indicate.
type Mapping struct {
	Primary   Technique   `json:"primary"`
	Secondary []Technique `json:"secondary,omitempty"`
}

// Tactics in kill-chain order (ATT&CK Enterprise matrix column order).
var (
	Reconnaissance      = Tactic{"TA0043", "Reconnaissance"}
	ResourceDevelopment = Tactic{"TA0042", "Resource Development"}
	InitialAccess       = Tactic{"TA0001", "Initial Access"}
	Execution           = Tactic{"TA0002", "Execution"}
	Persistence         = Tactic{"TA0003", "Persistence"}
	PrivilegeEscalation = Tactic{"TA0004", "Privilege Escalation"}
	DefenseEvasion      = Tactic{"TA0005", "Defense Evasion"}
	CredentialAccess    = Tactic{"TA0006", "Credential Access"}
	Discovery           = Tactic{"TA0007", "Discovery"}
	LateralMovement     = Tactic{"TA0008", "Lateral Movement"}
	Collection          = Tactic{"TA0009", "Collection"}
	CommandAndControl   = Tactic{"TA0011", "Command and Control"}
	Exfiltration        = Tactic{"TA0010", "Exfiltration"}
	Impact              = Tactic{"TA0040", "Impact"}
)

// TacticOrder is the matrix column order.
var TacticOrder = []Tactic{
	Reconnaissance, ResourceDevelopment, InitialAccess, Execution, Persistence,
	PrivilegeEscalation, DefenseEvasion, CredentialAccess, Discovery,
	LateralMovement, Collection, CommandAndControl, Exfiltration, Impact,
}

var validAccountsTactics = []Tactic{InitialAccess, Persistence, PrivilegeEscalation, DefenseEvasion}

// Techniques TrueSignal can evidence.
var (
	T1005     = Technique{"T1005", "Data from Local System", []Tactic{Collection}}
	T1018     = Technique{"T1018", "Remote System Discovery", []Tactic{Discovery}}
	T1021_001 = Technique{"T1021.001", "Remote Services: Remote Desktop Protocol", []Tactic{LateralMovement}}
	T1021_004 = Technique{"T1021.004", "Remote Services: SSH", []Tactic{LateralMovement}}
	T1046     = Technique{"T1046", "Network Service Discovery", []Tactic{Discovery}}
	T1069_002 = Technique{"T1069.002", "Permission Groups Discovery: Domain Groups", []Tactic{Discovery}}
	T1078     = Technique{"T1078", "Valid Accounts", validAccountsTactics}
	T1078_002 = Technique{"T1078.002", "Valid Accounts: Domain Accounts", validAccountsTactics}
	T1087_002 = Technique{"T1087.002", "Account Discovery: Domain Account", []Tactic{Discovery}}
	T1110     = Technique{"T1110", "Brute Force", []Tactic{CredentialAccess}}
	T1486     = Technique{"T1486", "Data Encrypted for Impact", []Tactic{Impact}}
	T1552_001 = Technique{"T1552.001", "Unsecured Credentials: Credentials In Files", []Tactic{CredentialAccess}}
	T1565_001 = Technique{"T1565.001", "Data Manipulation: Stored Data Manipulation", []Tactic{Impact}}
	T1590_002 = Technique{"T1590.002", "Gather Victim Network Information: DNS", []Tactic{Reconnaissance}}
	T1595_003 = Technique{"T1595.003", "Active Scanning: Wordlist Scanning", []Tactic{Reconnaissance}}
	T1602_001 = Technique{"T1602.001", "Data from Configuration Repository: SNMP (MIB Dump)", []Tactic{Collection}}
)

// exact maps full trigger names. Checked before the suffix rules.
var exact = map[string]Mapping{
	"network_scan_detected": {Primary: T1046},
	"icmp_scan_received":    {Primary: T1018},
	"tcp_connection":        {Primary: T1046},
	"tcp_session_payload":   {Primary: T1046},
	"ssh_login":             {Primary: T1021_004, Secondary: []Technique{T1110}},
	"rdp_login":             {Primary: T1021_001, Secondary: []Technique{T1110}},
	"ldap_login":            {Primary: T1110, Secondary: []Technique{T1078_002}},
	"ldaps_login":           {Primary: T1110, Secondary: []Technique{T1078_002}},
	"ldap_query":            {Primary: T1087_002, Secondary: []Technique{T1069_002}},
	"ldaps_query":           {Primary: T1087_002, Secondary: []Technique{T1069_002}},
	"web_login_attempt":     {Primary: T1110, Secondary: []Technique{T1078}},
	"web_path_probe":        {Primary: T1595_003},
	"snmp_query":            {Primary: T1602_001},
	"dns_query":             {Primary: T1018, Secondary: []Technique{T1590_002}},
	"decoy_file_accessed":   {Primary: T1552_001, Secondary: []Technique{T1005}},
	"decoy_file_tampered":   {Primary: T1565_001, Secondary: []Technique{T1486}},
	"honeytoken_used":       {Primary: T1078, Secondary: []Technique{T1552_001}},
}

// For returns the ATT&CK mapping of a trigger. Beyond the exact names,
// any <service>_login is credential guessing (T1110, Valid Accounts as
// secondary) and any <service>_connection is service discovery (T1046).
func For(trigger string) (Mapping, bool) {
	if m, ok := exact[trigger]; ok {
		return m, true
	}
	switch {
	case strings.HasSuffix(trigger, "_login"):
		return Mapping{Primary: T1110, Secondary: []Technique{T1078}}, true
	case strings.HasSuffix(trigger, "_connection"):
		return Mapping{Primary: T1046}, true
	}
	return Mapping{}, false
}

// Covered lists every technique some trigger can evidence, by ID.
func Covered() []Technique {
	seen := map[string]Technique{}
	add := func(t Technique) { seen[t.ID] = t }
	for _, m := range exact {
		add(m.Primary)
		for _, s := range m.Secondary {
			add(s)
		}
	}
	add(T1110)
	add(T1078)
	add(T1046)
	out := make([]Technique, 0, len(seen))
	for _, t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TacticIDs returns the IDs of a technique's tactics, comma-joined.
func (t Technique) TacticIDs() string {
	ids := make([]string, len(t.Tactics))
	for i, tc := range t.Tactics {
		ids[i] = tc.ID
	}
	return strings.Join(ids, ",")
}

// Reference is the technique's page on attack.mitre.org.
func (t Technique) Reference() string {
	return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(t.ID, ".", "/") + "/"
}
