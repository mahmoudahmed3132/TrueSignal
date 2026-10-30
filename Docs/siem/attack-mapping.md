# MITRE ATT&CK mapping

Every TrueSignal event whose trigger has a mapping carries one **primary** technique (the one it evidences, and the one counted in the Attack Navigator and the Navigator layer score) and optional **secondary** techniques (what it may also indicate). Source of truth: `Hub/internal/attack/attack.go`; a test fails if this table and the code disagree.

The mapping is derived when events are read or forwarded, never stored, so a change applies to past events too. It is part of the SIEM contract: change IDs only deliberately and record it in `CHANGELOG.md`.

| Trigger | Primary | Secondary | Primary tactics |
|---|---|---|---|
| `network_scan_detected` | T1046 Network Service Discovery | | Discovery |
| `icmp_scan_received` | T1018 Remote System Discovery | | Discovery |
| `tcp_connection` | T1046 Network Service Discovery | | Discovery |
| `tcp_session_payload` | T1046 Network Service Discovery | | Discovery |
| `ssh_login` | T1021.004 Remote Services: SSH | T1110 | Lateral Movement |
| `rdp_login` | T1021.001 Remote Services: Remote Desktop Protocol | T1110 | Lateral Movement |
| `ldap_login`, `ldaps_login` | T1110 Brute Force | T1078.002 | Credential Access |
| `ldap_query`, `ldaps_query` | T1087.002 Account Discovery: Domain Account | T1069.002 | Discovery |
| `web_login_attempt` | T1110 Brute Force | T1078 | Credential Access |
| `web_path_probe` | T1595.003 Active Scanning: Wordlist Scanning | | Reconnaissance |
| `snmp_query` | T1602.001 Data from Configuration Repository: SNMP (MIB Dump) | | Collection |
| `dns_query` | T1018 Remote System Discovery | T1590.002 | Discovery |
| `decoy_file_accessed` | T1552.001 Unsecured Credentials: Credentials In Files | T1005 | Credential Access |
| `decoy_file_tampered` | T1565.001 Data Manipulation: Stored Data Manipulation | T1486 | Impact |
| `honeytoken_used` | T1078 Valid Accounts | T1552.001 | Initial Access, Persistence, Privilege Escalation, Defense Evasion |
| any other `<service>_login` (`mysql`, `postgres`, `mssql`, `telnet`, `ftp`) | T1110 Brute Force | T1078 | Credential Access |
| any other `<service>_connection` | T1046 Network Service Discovery | | Discovery |

**Not mapped** (no ATT&CK data rather than a guess): `web_page_view` (opening a decoy page is not a technique by itself), Hub liveness (`sensor_stopped`, `sensor_heartbeat_lost`, `sensor_recovered`: usually an outage, not an attacker), `beacon_triggered` (what a beacon evidences depends on where it was planted, which only `details.beacon` and the operator know), and community-sensor triggers.

**Judgement calls.** `web_path_probe` uses T1595.003 although ATT&CK files Reconnaissance as pre-compromise: it is the closest technique for path brute-forcing. `decoy_file_tampered` cannot tell manipulation from encryption, so T1486 is secondary. T1078 keeps every tactic ATT&CK files it under; it is never a Credential Access technique.

## Where it appears

| Output | Fields |
|---|---|
| ECS (Elastic, LogScale, `siem_format=ecs`) | `threat.framework: "MITRE ATT&CK"`; `threat.technique.{id,name,reference}` (parent techniques, primary first); `threat.technique.subtechnique.{id,name,reference}`; `threat.tactic.{id,name,reference}` (the primary technique's tactics); `truesignal.attack` (the full mapping) |
| RFC 5424 syslog | structured data `mitre_technique="T1021.004" mitre_tactic="TA0008"` (comma-separated when several; both always present, empty when unmapped); JSON body `"attack"` (object or `null`) |
| Hub API | `attack` on every event (`GET /api/v2/events`, WebSocket `NEW_EVENT`); `GET /api/v2/attack`; `GET /api/v2/attack/layer` (ATT&CK Navigator layer, format 4.5) |

Example Elastic query (KQL) for lateral movement against decoys: `event.module: "truesignal" and threat.tactic.id: "TA0008"`. LogScale (HEC output, JSON parser, which flattens arrays to `threat.tactic.id[0]`, `[1]`, …): `event.module="truesignal" | array:contains("threat.tactic.id[]", value="TA0008")`. Shipped rules: `Docs/siem/detection-rules.md` (`truesignal-lateral-movement`).
