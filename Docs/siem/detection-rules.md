# Detection Rules

TrueSignal ships 16 Elastic Security rules (`Docs/siem/elastic/`) and a LogScale query for each (`Docs/siem/logscale/`). They cover every alert the Hub forwards, plus correlation, liveness and Hub audit. They read only fields the Hub emits (`Hub/internal/services/siem/{service.go,ecs.go}`, `Docs/siem-integration.md`). A test fails if a rule references a field no emitted document carries.

The honeytoken rule for **real** systems (`truesignal-honeytoken-authentication`) is separate. It matches other products' logs: `Docs/siem/honeytoken-detection.md`.

## How the set is built

- **One primary alert per decoy event.** Each forwarded alert matches exactly one of: a beacon rule, `honeytoken-used`, `lateral-movement` (SSH/RDP, TA0008), `decoy-login` (other logins), or the baseline `decoy-interaction` (everything else). Receiver saturation alerts only when sustained.
- **Escalations on top.** These add an alert to one already raised: `scan-then-touch` (correlation), `critical-asset-source` (asset criticality), `beacon-unexpected-country` (GeoIP, opt-in), `sensor-dark` (liveness) and `hub-login-bruteforce`.
- **Source lists.** Every rule drops `truesignal.whitelisted: true` and `truesignal.known_scanner: true`. The Hub never sets either flag on `honeytoken_used` or on a known beacon (`Hub/internal/services/event/service.go`). The filter is therefore safe on those rules too, and a test enforces it. `honeytoken-used` carries no list filter at all, to make that explicit.
- **Internal sources** are `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` and `fc00::/7` (the Hub's GeoIP "not public" set), plus any address on the Hub's **Assets** page (`truesignal.source_asset`). Put the corporate resolvers' and proxies' public egress addresses on the Assets page. Without them, a beacon resolved through your own resolvers looks external. [NOT IN PROJECT: the egress addresses.]
- **GeoIP** is trusted only when it describes the client. That means `truesignal.source_geo.basis: client_subnet` (a DNS beacon's EDNS Client Subnet), or `basis: source` on an HTTP beacon. On a DNS beacon, `source.ip` is the recursive resolver, so its country says nothing about who opened the beacon. `source.geo.*` only ever describes `source.ip`.
- **Severity.** Rules marked *mapped* take their severity from the event (`truesignal.severity`, or the asset criticality) and their risk from `event.severity`. An operator's per-sensor `TS_SEVERITY` therefore carries through.

| Rule | Type | Severity | Risk | Enabled |
|---|---|---|---|---|
| [`truesignal-beacon-triggered`](#truesignal-beacon-triggered) | query (KQL) | critical | 95 | yes |
| [`truesignal-beacon-internal-source`](#truesignal-beacon-internal-source) | query (KQL) | critical | 99 | yes |
| [`truesignal-beacon-unknown-token`](#truesignal-beacon-unknown-token) | query (KQL) | medium | 47 | yes |
| [`truesignal-beacon-unexpected-country`](#truesignal-beacon-unexpected-country) | query (KQL) | high | 80 | **no** |
| [`truesignal-receiver-saturated-sustained`](#truesignal-receiver-saturated-sustained) | threshold | medium | 47 | yes |
| [`truesignal-honeytoken-used`](#truesignal-honeytoken-used) | query (KQL) | critical | 99 | yes |
| [`truesignal-lateral-movement`](#truesignal-lateral-movement) | query (KQL) | critical (mapped) | 95 | yes |
| [`truesignal-decoy-login`](#truesignal-decoy-login) | query (KQL) | high (mapped) | 73 | yes |
| [`truesignal-decoy-interaction`](#truesignal-decoy-interaction) | query (KQL) | medium (mapped) | 47 | yes |
| [`truesignal-scan-then-touch`](#truesignal-scan-then-touch) | EQL sequence | high | 80 | yes |
| [`truesignal-critical-asset-source`](#truesignal-critical-asset-source) | query (KQL) | high (mapped) | 85 | yes |
| [`truesignal-sensor-heartbeat-lost`](#truesignal-sensor-heartbeat-lost) | query (KQL) | high | 73 | yes |
| [`truesignal-sensor-dark`](#truesignal-sensor-dark) | ES\|QL | high | 73 | yes |
| [`truesignal-hub-mfa-reset`](#truesignal-hub-mfa-reset) | query (KQL) | high | 73 | yes |
| [`truesignal-hub-defense-change`](#truesignal-hub-defense-change) | query (KQL) | low (mapped) | 21 | yes |
| [`truesignal-hub-login-bruteforce`](#truesignal-hub-login-bruteforce) | threshold | medium | 47 | yes |

## Deploying

### Elastic Security (8.13+; tested on 8.19)

1. Send the Hub's output to the data stream `logs-truesignal-default` and create the index template from `Docs/siem-integration.md` (`truesignal.details` must be `flattened`).
2. Import the rules through the API, one file per request:

   ```bash
   for f in Docs/siem/elastic/truesignal-*.json; do
     curl -sS -u "$ES_USER" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
       -X POST "$KIBANA_URL/api/detection_engine/rules" --data-binary @"$f"; echo
   done
   ```

   Or build one NDJSON file (`jq -c . Docs/siem/elastic/truesignal-*.json > truesignal-rules.ndjson`) and import it under **Security → Rules → Import**.
3. If your data stream name differs, change `index` in each rule (the ES|QL rule names the index in its `FROM`).
4. `truesignal-beacon-unexpected-country` ships disabled. Set its country list first.
5. All rule types used (query, EQL, threshold, ES|QL) run on the Basic license. Alert suppression (Platinum) is not used, so `truesignal-sensor-dark` repeats every hour while a sensor stays down.

### CrowdStrike Falcon LogScale / Next-Gen SIEM

1. Use the `logscale` output (HEC) with a JSON parser on the ingest token (`Docs/siem-integration.md`). The queries use the parser's field names: dotted paths (`truesignal.details.channel`), arrays as `name[0]` (searched with `array:contains("threat.tactic.id[]", …)`), and booleans as the strings `"true"`/`"false"`.
2. Create a scheduled search per file. The schedule and window are in each file's header, mirroring the Elastic rule. The action (email, webhook, Falcon Fusion workflow) is yours. [NOT IN PROJECT]
3. With the RFC 5424 syslog output, these queries do not apply as written: the fields live in structured data (`trigger`, `whitelisted`, `source_asset_criticality`, `source_geo_basis`…). Use the HEC or ECS stream outputs.

## Rules

### truesignal-beacon-triggered

**TrueSignal beacon triggered.** A Token Receiver resolved a beacon (DNS name, web bug or kubeconfig) that the Hub created. Beacons are planted where only an intruder looks, so a known beacon firing means the planted file or record was opened or used. Internal sources are left to truesignal-beacon-internal-source, so each beacon event raises one of the two.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | critical / 95 |
| ATT&CK | none (see note) |
| Files | `elastic/truesignal-beacon-triggered.json`, `logscale/truesignal-beacon-triggered.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"beacon_triggered" and truesignal.details.beacon.id:* and not (source.ip:("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16" or "100.64.0.0/10" or "fc00::/7") or truesignal.source_asset.name:*)
```

**Triage**

1. `truesignal.details.beacon.name` / `.type` name the planted object; the Hub's Beacons page shows where it was planted (memo).
2. Channel: `truesignal.details.channel`. DNS: `source.ip` is the **recursive resolver**, not the person; the client is nearer to `truesignal.details.client_subnet` when present. HTTP: `source.ip` is the client (or `truesignal.details.proxy`).
3. Location: use `truesignal.source_geo` only with its `basis`. `client_subnet` places the client; `source` on a DNS beacon places the resolver (often a public DNS provider).
4. Find who could read the planted object (share/repo/bucket access logs, EDR file-open telemetry around `@timestamp`).
5. `truesignal.details.repeats_since_last` > 0 means repeated use within the receiver cooldown.

**Expected false positives**

- A Wizard firedrill on the Token Receiver uses token `firedrill`, which is unknown to the Hub and raises truesignal-beacon-unknown-token instead.
- Security tooling that opens planted documents or resolves names in them (sandbox detonation, DLP crawlers, mail link scanners). Identify it, then move or re-plant the beacon; do not whitelist the resolver, the Hub ignores the lists for known beacons.

### truesignal-beacon-internal-source

**TrueSignal beacon triggered from inside the network.** A known beacon fired and the reporting source is internal: a private, CGNAT or ULA address, or an address on the Hub's Assets page (for example the public egress of the corporate resolvers). The planted object is being used from inside the network, so the reading host is compromised or an insider is involved.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | critical / 99 |
| ATT&CK | none (see note) |
| Files | `elastic/truesignal-beacon-internal-source.json`, `logscale/truesignal-beacon-internal-source.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"beacon_triggered" and truesignal.details.beacon.id:* and (source.ip:("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16" or "100.64.0.0/10" or "fc00::/7") or truesignal.source_asset.name:*)
```

**Triage**

1. DNS channel with an internal `source.ip`: it is one of your resolvers. Pull its query log for `truesignal.details.query_name` at `@timestamp` to get the real client.
2. `truesignal.source_asset.name` names the inventoried host or egress range; for an egress range, map it back through firewall/NAT logs (Palo Alto, FortiGate).
3. HTTP channel: `source.ip` (or `truesignal.details.proxy`) is the client or your proxy; use proxy logs for the user.
4. Contain the client host, then review what else it touched (other TrueSignal alerts from the same `source.ip`, EDR timeline).

**Expected false positives**

- Internal security tooling that resolves or fetches embedded URLs (sandbox, DLP, mail gateway) through the corporate resolvers or proxy.
- Assets entries that cover shared NAT ranges make every beacon resolved through them look internal; keep the asset ranges tight.

### truesignal-beacon-unknown-token

**TrueSignal beacon token not known to the Hub.** A Token Receiver reported an HMAC-valid token that matches no beacon on the Hub (truesignal.details.beacon_known: false). Either the beacon was deleted while copies are still in circulation, or a node holding the receiver key forged it. Unlike known beacons, these respect the whitelist and known-scanner lists.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | medium / 47 |
| ATT&CK | none (see note) |
| Files | `elastic/truesignal-beacon-unknown-token.json`, `logscale/truesignal-beacon-unknown-token.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"beacon_triggered" and truesignal.details.beacon_known:false and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

**Triage**

1. Check the Hub audit trail for `DELETE /api/v2/beacons/{beaconId}` before `@timestamp`; a deleted beacon still firing means its copies are still being opened.
2. Token `firedrill` with source `Wizard Firedrill` is a test.
3. Otherwise treat it as a forged report: the Token Receiver node (`host.name`) holds `TS_BEACON_KEY`; check that host's integrity.

**Expected false positives**

- Wizard firedrill (`truesignal.details.token: firedrill`).
- Beacons deleted on the Hub whose planted copies are still opened.

### truesignal-beacon-unexpected-country

**TrueSignal beacon located outside the expected countries.** A known beacon fired from outside the expected countries. The location is trusted only when it describes the client: an EDNS client subnet (truesignal.source_geo.basis: client_subnet) or the source address of an HTTP beacon. A DNS beacon located by its source is the resolver, so it is never used here. Ships disabled: set the expected-country list first.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | high / 80 |
| ATT&CK | none (see note) |
| Files | `elastic/truesignal-beacon-unexpected-country.json`, `logscale/truesignal-beacon-unexpected-country.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"beacon_triggered" and truesignal.details.beacon.id:* and (truesignal.source_geo.basis:"client_subnet" or (truesignal.source_geo.basis:"source" and truesignal.details.channel:"http")) and not truesignal.source_geo.countryCode:("EG")
```

**Triage**

**Before enabling:** Replace the country list in the query (`EG` is a placeholder) with every country your staff, VPN egress and cloud regions legitimately use. [NOT IN PROJECT]

1. This always accompanies truesignal-beacon-triggered for the same event; triage that alert and use this one as context.
2. `truesignal.source_geo.address` is the address that was located (the subnet network for `client_subnet`).

**Expected false positives**

- Travelling staff, VPN or cloud egress in another country, privacy relays (iCloud Private Relay, corporate SASE) that hide the client's country.

### truesignal-receiver-saturated-sustained

**TrueSignal Token Receiver saturated for 15 minutes.** A Token Receiver kept refusing connections on one listener for 15 minutes (three or more receiver_saturated reports; the sensor sends at most one per listener every 5 minutes). Sustained saturation is a flood against the internet-facing receiver and can hide beacon traffic.

| | |
|---|---|
| Type / schedule | threshold, every 5m, lookback `now-16m` |
| Severity / risk | medium / 47 |
| ATT&CK | T1498 (Impact) |
| Files | `elastic/truesignal-receiver-saturated-sustained.json`, `logscale/truesignal-receiver-saturated-sustained.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"receiver_saturated" and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

Threshold: `host.id, truesignal.details.listener` ≥ 3.

**Triage**

1. `truesignal.details.top_source_refusals` lists the heaviest sources; `truesignal.details.distinct_sources` shows whether it is one host or many.
2. `refused_per_source` high: a few sources (rate-limit or block them at the edge). `refused_total_cap` high: many sources, a distributed flood.
3. While saturated, beacons may be missed: look for beacon traffic in the edge firewall logs for the receiver's address.

**Expected false positives**

- Large recursive resolvers retrying aggressively after a delegation change on the beacon zone.
- Internet-wide scanners hitting HTTP port 80 on the DMZ address.

### truesignal-honeytoken-used

**TrueSignal honeytoken credential used against a decoy.** The Hub matched a planted honeytoken (a fabricated credential written into a File Canary lure) in a login against a decoy. The lure was read and its credential is being used. Raised by the Hub only (sensors cannot send it) and never subject to the whitelist or known-scanner lists, so this rule does not filter on them.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | critical / 99 |
| ATT&CK | T1078 (Initial Access), T1552.001 (Credential Access) |
| Files | `elastic/truesignal-honeytoken-used.json`, `logscale/truesignal-honeytoken-used.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"honeytoken_used"
```

**Triage**

1. `truesignal.details.planted_node_id` / `planted_sensor_id` name the lure; its `decoy_file_accessed` events show when and how it was read.
2. `truesignal.details.triggering_trigger` / `triggering_event_id` point at the login that used it; `source.ip` is the attacker's host.
3. Run truesignal-honeytoken-authentication (real systems) for the same `truesignal.details.honeytoken_username`.
4. Treat as active intrusion: contain `source.ip` and the host that read the lure.

**Expected false positives**

- None expected. Only someone who read a lure knows the credential; an administrator testing with it should use a firedrill instead.

### truesignal-lateral-movement

**TrueSignal lateral movement attempt against a decoy.** An SSH or RDP login against a decoy (ATT&CK tactic TA0008 in the Hub's mapping). Decoys mirror production hosts and have no users, so a remote-services login means a host on the network is moving laterally.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | critical, mapped from truesignal.severity / 95 (risk from `event.severity`) |
| ATT&CK | T1021.001 (Lateral Movement), T1021.004 (Lateral Movement) |
| Files | `elastic/truesignal-lateral-movement.json`, `logscale/truesignal-lateral-movement.logscale` |

```text
event.dataset:"truesignal.alert" and threat.tactic.id:"TA0008" and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

**Triage**

1. `source.ip` is the moving host. Contain it first if it is a server or a privileged workstation; `truesignal.source_asset` names it when inventoried.
2. `user.name` (RDP: `mstshash`/NTLM identity, `truesignal.details.workstation`) and SSH key fingerprints (`truesignal.details.key_fingerprint`) identify the credential or key in use.
3. Check the same source against real SSH/RDP servers (Falcon `UserLogon`, Windows 4624/4625 type 10) in the same hour.

**Expected false positives**

- Jump hosts or automation that sweep subnets with SSH (Ansible inventories that include the decoy range). Remove the decoy range from inventories; add the scanner to known scanners only if it is a scanner.

### truesignal-decoy-login

**TrueSignal login attempt against a decoy.** Someone tried to authenticate to a TrueSignal decoy service (LDAP/LDAPS, database, FTP/Telnet, web login). Decoys have no legitimate users, so any attempt is credential testing or use. SSH/RDP attempts are left to truesignal-lateral-movement and planted-credential use to truesignal-honeytoken-used.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | high, mapped from truesignal.severity / 73 (risk from `event.severity`) |
| ATT&CK | T1110 (Credential Access) |
| Files | `elastic/truesignal-decoy-login.json`, `logscale/truesignal-decoy-login.logscale` |

```text
event.dataset:"truesignal.alert" and event.category:"authentication" and not event.action:"honeytoken_used" and not threat.tactic.id:"TA0008" and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

**Triage**

1. `user.name` / `user.domain` is the account tried. Search your directory and real authentication logs for it from `source.ip`: the same credential is likely being tried on real systems.
2. `truesignal.source_asset` names the source host when it is inventoried; otherwise identify it via DHCP/EDR.
3. Passwords are HMAC'd (`truesignal.details.password_hmac`); compare with other decoy events to see whether the same password is sprayed.
4. Pivot on `source.ip` for other TrueSignal alerts (scan-then-touch, other decoys).

**Expected false positives**

- Vulnerability scanners and asset-discovery tools with credential checks: add them to the Hub's known scanners.
- Administrators testing a decoy. Use `truesignal firedrill` instead (source `Wizard Firedrill`).

### truesignal-decoy-interaction

**TrueSignal decoy interaction.** Baseline rule: any TrueSignal decoy alert not covered by a dedicated rule (scans, connections, queries, path probes, page views, file access and tampering). Every interaction with a decoy is suspicious by design; severity and risk follow the event. Beacons, receiver saturation, logins and honeytoken use have their own rules.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | medium, mapped from truesignal.severity / 47 (risk from `event.severity`) |
| ATT&CK | none (see note) |
| Files | `elastic/truesignal-decoy-interaction.json`, `logscale/truesignal-decoy-interaction.logscale` |

```text
event.dataset:"truesignal.alert" and event.kind:"alert" and not event.category:"authentication" and not event.action:("beacon_triggered" or "receiver_saturated") and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

**Triage**

1. `event.action` and `truesignal.details` say what was done; `threat.*` carries the ATT&CK mapping.
2. File Canary (`decoy_file_accessed`/`decoy_file_tampered`): `file.path` is the lure; find the process via EDR file telemetry on `host.name`.
3. Network decoys: identify `source.ip` and look for other TrueSignal alerts from it (scan-then-touch fires when it escalates).

**Expected false positives**

- Monitoring (ICMP/uptime checks, SNMP pollers), backup and inventory agents reaching the decoys: add them to the whitelist or known scanners on the Hub.
- Wizard firedrills (source `Wizard Firedrill`).

### truesignal-scan-then-touch

**TrueSignal scan followed by decoy interaction from the same source.** A source was seen scanning (network_scan_detected or icmp_scan_received) and, within an hour, interacted with a decoy beyond discovery (any medium-or-higher alert that is not a scan or a bare *_connection). Scan-then-touch separates an operator working through targets from background noise. Correlates across nodes by source.ip.

| | |
|---|---|
| Type / schedule | EQL sequence, every 5m, lookback `now-65m` |
| Severity / risk | high / 80 |
| ATT&CK | T1046 (Discovery) |
| Files | `elastic/truesignal-scan-then-touch.json`, `logscale/truesignal-scan-then-touch.logscale` |

```text
sequence by source.ip with maxspan=1h
  [any where event.dataset == "truesignal.alert" and event.action in ("network_scan_detected", "icmp_scan_received") and truesignal.whitelisted == false and truesignal.known_scanner == false]
  [any where event.dataset == "truesignal.alert" and event.kind == "alert" and event.severity >= 47 and not event.action in ("network_scan_detected", "icmp_scan_received") and not event.action like "*_connection" and truesignal.whitelisted == false and truesignal.known_scanner == false]
```

**Triage**

1. The sequence shows the scan (`host.name` of the scanning detector) and the follow-up (trigger, decoy, credentials tried).
2. Identify `source.ip` (`truesignal.source_asset`, DHCP, EDR) and check it for an interactive session or implant.
3. Escalate to an intrusion case if the follow-up is a login, file access or honeytoken.

**Expected false positives**

- Authorised penetration tests and vulnerability scans with authenticated checks: add the scanners to known scanners for the test window.

### truesignal-critical-asset-source

**TrueSignal decoy touched from a high-criticality asset.** A decoy was touched from an address the Hub's Assets page marks high or critical. A production system has no reason to talk to a decoy, so the asset itself is the likely compromised machine. Escalation on top of the per-event rule.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | high, mapped from truesignal.source_asset.criticality / 85 |
| ATT&CK | none (see note) |
| Files | `elastic/truesignal-critical-asset-source.json`, `logscale/truesignal-critical-asset-source.logscale` |

```text
event.dataset:"truesignal.alert" and event.kind:"alert" and truesignal.source_asset.criticality:("high" or "critical") and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

**Triage**

1. `truesignal.source_asset.name` is the asset; its owner is on the Hub's Assets page.
2. Pull the asset's EDR timeline around `@timestamp` (Falcon process tree for the connecting process).
3. Check for a recent change on the asset (deployment, new monitoring agent) before declaring compromise; then contain.

**Expected false positives**

- Monitoring, backup or inventory agents on the asset that sweep the decoy subnet.
- Asset ranges on the Assets page that are wider than the asset.

### truesignal-sensor-heartbeat-lost

**TrueSignal sensor stopped reporting.** The Hub raised sensor_heartbeat_lost: a sensor stopped heartbeating (reason heartbeat_timeout), or was stopped and not restarted within 5 minutes (reason not_restarted_after_stop). Either is an outage or an intruder disabling a decoy.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | high / 73 |
| ATT&CK | T1562.001 (Defense Evasion) |
| Files | `elastic/truesignal-sensor-heartbeat-lost.json`, `logscale/truesignal-sensor-heartbeat-lost.logscale` |

```text
event.dataset:"truesignal.alert" and event.action:"sensor_heartbeat_lost" and not truesignal.whitelisted:true and not truesignal.known_scanner:true
```

**Triage**

1. `truesignal.sensor_id` on `host.name`; `truesignal.details.reason` and `last_heartbeat`.
2. Check for a `sensor_stopped` on the same sensor shortly before (graceful stop) and for an operator change (`truesignal apply`, maintenance window).
3. Several sensors on one node at once: the node or Docker is down, or someone with root on the decoy host stopped it. Check the host.
4. truesignal-sensor-dark fires if it is still down after 30 minutes.

**Expected false positives**

- Planned maintenance, `truesignal apply` that replaces a container, node reboots.

### truesignal-sensor-dark

**TrueSignal sensor still down after 30 minutes.** A sensor's latest liveness event in the last 24 hours is sensor_heartbeat_lost, at least 30 minutes old, with no sensor_recovered after it. The decoy is blind. Re-alerts every run while it stays down (ES|QL aggregating rule).

| | |
|---|---|
| Type / schedule | ES|QL, every 1h, lookback `now-24h` |
| Severity / risk | high / 73 |
| ATT&CK | T1562.001 (Defense Evasion) |
| Files | `elastic/truesignal-sensor-dark.json`, `logscale/truesignal-sensor-dark.logscale` |

```text
FROM logs-truesignal-*
| WHERE event.dataset == "truesignal.alert" AND event.action IN ("sensor_heartbeat_lost", "sensor_recovered") AND truesignal.whitelisted == false AND truesignal.known_scanner == false
| EVAL lost = CASE(event.action == "sensor_heartbeat_lost", @timestamp, null), recovered = CASE(event.action == "sensor_recovered", @timestamp, null)
| STATS last_lost = MAX(lost), last_recovered = MAX(recovered) BY host.id, host.name, truesignal.sensor_id
| WHERE last_lost IS NOT NULL AND (last_recovered IS NULL OR last_recovered < last_lost) AND last_lost <= NOW() - 30 minutes
| KEEP host.id, host.name, truesignal.sensor_id, last_lost, last_recovered
```

**Triage**

1. The alert lists `host.name`, `truesignal.sensor_id`, `last_lost` and `last_recovered`.
2. Restore the sensor (`truesignal apply` on the node) or record the outage; a decoy an intruder disabled is evidence, so check the host before redeploying.
3. Stops alerting once the sensor heartbeats again (the Hub emits `sensor_recovered`) or 24 hours after the loss.

**Expected false positives**

- Decommissioned sensors removed without deleting them on the Hub (delete them, or the rule repeats for 24 hours).
- Long planned maintenance.

### truesignal-hub-mfa-reset

**TrueSignal Hub admin MFA reset or disabled.** The Hub admin's MFA was removed: the break-glass mfa-reset command (audited on the next Hub start, url.path cli:mfa-reset) or a successful POST /api/v2/auth/mfa/disable. Removing the second factor is the first step to a quiet takeover of the deception platform.

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | high / 73 |
| ATT&CK | T1556.006 (Defense Evasion) |
| Files | `elastic/truesignal-hub-mfa-reset.json`, `logscale/truesignal-hub-mfa-reset.logscale` |

```text
event.dataset:"truesignal.audit" and (url.path:"cli:mfa-reset" or (event.action:"POST /api/v2/auth/mfa/disable" and event.outcome:"success"))
```

**Triage**

1. Confirm with the Hub owner that the reset was requested (lost authenticator) and who ran it; mfa-reset needs shell access to the Hub host.
2. For the API path, `source.ip` is the admin session's client; check it against admin workstations.
3. Expect re-enrolment (`POST /api/v2/auth/mfa/enable`) soon after a legitimate reset.
4. If unexplained: rotate the admin password, re-enrol MFA, review all audit records since.

**Expected false positives**

- Legitimate recovery after a lost authenticator.
- MFA disabled during a planned rebuild.

### truesignal-hub-defense-change

**TrueSignal Hub change that can blind detection.** A successful admin change on the Hub that can suppress or erase detection: SIEM/webhook/whitelist/known-scanner config, disarming, silencing a sensor, deleting nodes, sensors, beacons or events, archiving all events, replacing the asset inventory, password change, recovery-code regeneration or factory reset. Change tracking for review; high for evidence destruction (clear events, factory reset).

| | |
|---|---|
| Type / schedule | query (KQL), every 5m, lookback `now-6m` |
| Severity / risk | low, mapped from event.action / 21 |
| ATT&CK | T1562.001 (Defense Evasion) |
| Files | `elastic/truesignal-hub-defense-change.json`, `logscale/truesignal-hub-defense-change.logscale` |

```text
event.dataset:"truesignal.audit" and event.outcome:"success" and event.action:("PATCH /api/v2/config" or "PATCH /api/v2/system/state" or "PATCH /api/v2/system/password" or "POST /api/v2/system/reset" or "PATCH /api/v2/nodes/{nodeId}/sensors/{sensorId}/silence" or "DELETE /api/v2/nodes/{nodeId}" or "DELETE /api/v2/nodes/{nodeId}/sensors/{sensorId}" or "DELETE /api/v2/events" or "PATCH /api/v2/events/archive-all" or "DELETE /api/v2/beacons/{beaconId}" or "PUT /api/v2/assets" or "POST /api/v2/auth/mfa/recovery-codes")
```

**Triage**

1. `event.action` is `METHOD /route`; `url.path` the concrete path (node and sensor IDs). Request bodies are never logged.
2. Match against the change calendar. `source.ip` is the admin's client.
3. `DELETE /api/v2/events` or `POST /api/v2/system/reset` outside a planned change: treat as tampering; events are still in the SIEM.

**Expected false positives**

- Every routine admin change. Review, do not page, except for the high-severity actions.

### truesignal-hub-login-bruteforce

**TrueSignal Hub admin login failures.** Five or more failed Hub dashboard logins (POST /login, HTTP 401 or 429) from one source in 10 minutes. The Hub locks out per IP and account-wide, but repeated failures mean someone is trying the admin password of the deception platform.

| | |
|---|---|
| Type / schedule | threshold, every 5m, lookback `now-11m` |
| Severity / risk | medium / 47 |
| ATT&CK | T1110 (Credential Access) |
| Files | `elastic/truesignal-hub-login-bruteforce.json`, `logscale/truesignal-hub-login-bruteforce.logscale` |

```text
event.dataset:"truesignal.audit" and event.action:"POST /login" and event.outcome:"failure"
```

Threshold: `source.ip` ≥ 5.

**Triage**

1. `source.ip` is the client as the Hub saw it. Behind a proxy it is only correct if `TS_TRUSTED_PROXIES` is set; otherwise it may be the proxy.
2. Check for a successful `POST /login` from the same source afterwards.
3. With MFA, each normal login first returns 401 `mfa_required`; a few failures per admin login are expected.

**Expected false positives**

- An admin with a wrong saved password or a script with a stale `TS_DASHBOARD_PASSWORD`.
- MFA logins (one 401 before the code is entered).

## Testing

The rules are tested against what the Hub really emits, not hand-written JSON.

1. `TestSIEMDetectionSamples` (`Hub/internal/services/event/siem_samples_test.go`, part of `go test ./...`) runs 57 scenarios (59 documents) through the real event pipeline: source lists, beacon resolution, the `honeytoken_used` raise, asset and GeoIP enrichment (DB-IP test fixture). Each scenario then goes through the real SIEM service's ECS output, captured over TCP. The result is `Docs/siem/testdata/detection-samples.ndjson`. The test fails when the output drifts from that file, so any change to the event shape or the ECS mapping forces the rules to be re-checked. Regenerate with `TS_UPDATE_SIEM_SAMPLES=1 go test ./internal/services/event -run TestSIEMDetectionSamples`.
2. `TestSIEMRuleFieldsExist` checks every field referenced in the Elastic queries and the LogScale queries against the sample documents, using LogScale's JSON-parser names for the latter. `TestSIEMRulesDocumented` checks that every rule has a LogScale twin and a section here.
3. `scripts/siem-rules/run-elastic.sh` starts Elasticsearch and Kibana 8.19.22 (digest-pinned) and replays the samples on a timeline (`offset_sec`). It imports every rule into the detection engine (including the disabled one), waits for one execution of each and compares the alerts with `scripts/siem-rules/expected-elastic.json`: exact source documents, plus severities where the rule maps them. The **SIEM Rules** workflow runs it when `Docs/siem/**` or `scripts/siem-rules/**` change. Negative cases are in the corpus: whitelisted and known-scanner sources, a scan with only connections after it, a touch before the scan, a sensor that recovered, a recent loss, a failed MFA disable, a denied config change, and a source with only three login failures.

**Not executed: the LogScale queries.** No LogScale instance is available to the project. They are field-checked against the samples and written to mirror the tested Elastic logic, but their syntax and results are unverified. Run each once against real data before relying on it, then record the result here.

## Known gaps

- **A dead Hub is invisible to the SIEM.** The Hub sends no periodic record (the honeytoken resync runs every 24 h only when honeytokens exist), so a stopped Hub or a broken SIEM output looks like a quiet night. A "no data" check needs a Hub heartbeat record, which is not built yet.
- Firedrills (`source: Wizard Firedrill`) raise real alerts by design; they test the path to the SOC. Expect them during node rollout.
- `truesignal-sensor-dark` looks back 24 hours. A sensor dark for longer stops re-alerting; the Hub's Fleet page still shows it.
- Internal ranges are fixed in the queries. If Kashier uses public address space internally, add it to the Assets page (preferred) or to the CIDR lists. [NOT IN PROJECT]
- Not covered here: Kashier index or repository naming, alert routing and on-call (open questions in `Docs/KNOWLEDGE-GAPS.md` §5).
