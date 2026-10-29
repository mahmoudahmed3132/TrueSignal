# SOC notice: TrueSignal Hub 2.3.0 SIEM changes

**To:** SOC / SIEM engineering. **Effective:** when the Hub is upgraded to `v2.3.0`. **Impact:** additive fields only; no field is renamed, removed or retyped, and no `eventTrigger` changes. Two things can still break or degrade existing content; they are listed first.

## Act before the upgrade

1. **Exclude known scanners wherever you exclude whitelisted sources.** 2.3.0 adds a second allow-list, *Known Scanners* (vulnerability scanners, monitoring). Their events are forwarded like whitelisted ones: archived in the Hub, never notified, `event.kind: event`, but flagged `known_scanner=true`, not `whitelisted=true`. A rule or dashboard that filters only on `whitelisted` will start alerting on scanner traffic.
   - ECS: `NOT truesignal.whitelisted:true AND NOT truesignal.known_scanner:true` (or alert only on `event.kind:alert`, which already excludes both).
   - Syslog: `whitelisted="false" known_scanner="false"`.
   - The shipped honeytoken rule needs no change: `honeytoken_used` ignores both lists.
2. **Check syslog parsers for anchoring on the end of the structured data.** Five parameters are appended after `whitelisted`. A parser that expects `whitelisted="…"]` (closing bracket right after it) or counts parameters from the end stops matching. Parsers that match by parameter name, or parse the JSON body, are unaffected.

## New fields

### RFC 5424 structured data (`truesignal@<PEN>`)

Appended in this order after `whitelisted`. Always present; empty string when not applicable, so positions are stable.

| Parameter | Value |
|---|---|
| `known_scanner` | `true` / `false` |
| `mitre_technique` | Primary ATT&CK technique ID, e.g. `T1021.004`. Empty for unmapped triggers |
| `mitre_tactic` | Primary technique's tactic IDs, comma-separated (`T1078` carries four: `TA0001,TA0003,TA0004,TA0005`) |
| `source_asset` | Name of the inventoried real host or range the source address belongs to |
| `source_asset_criticality` | `low` / `medium` / `high` / `critical`, as set in the Hub inventory |

### RFC 5424 JSON body

`known_scanner` (bool), `attack` (object: `primary` and `secondary` techniques with their tactics, `null` when unmapped), `source_asset` (`{name, criticality}`, `null` when none).

### ECS (`siem_format: ecs`, Elastic bulk, LogScale HEC)

| Field | Notes |
|---|---|
| `threat.framework` | `MITRE ATT&CK` |
| `threat.technique.id/name/reference` | Parent techniques, primary first, then secondary |
| `threat.technique.subtechnique.id/name/reference` | Sub-techniques (e.g. `T1021.004`) |
| `threat.tactic.id/name/reference` | Tactics of the **primary** technique only. A secondary technique's tactic (e.g. `T1110` → `TA0006`) is not listed here; read `truesignal.attack.secondary` for it |
| `truesignal.attack` | Same object as the syslog `attack` |
| `truesignal.known_scanner` | bool, always present |
| `truesignal.source_asset.name/criticality` | Present only when the source is inventoried |
| `tags` | Adds `known_scanner` for scanner sources |
| `event.kind` | `event` (not `alert`) for known-scanner sources |

`threat.*` is absent for unmapped triggers: `web_page_view`, Hub liveness (`sensor_stopped`, `sensor_heartbeat_lost`, `sensor_recovered`), audit records and community-sensor triggers. The trigger → technique table is `Docs/siem/attack-mapping.md`. The mapping is derived at forwarding time, so it can change in a later release; that will be announced the same way.

**Elastic mappings:** `threat.*` is covered by `ecs@mappings`; the `truesignal.*` additions map dynamically (keyword/boolean). No template change is needed. Existing indices accept the fields without a rollover.

## Sample (syslog)

```
<130>1 2026-10-29T09:14:03Z truesignal truesignalSensor - EVENT [truesignal@32473 event_id="4812" trigger="ssh_login" severity="critical" source="10.20.4.17" target="0.0.0.0:2222" node="node-1a2b3c4d" node_id="node-1a2b3c4d" sensor="ts-sensor-remote-access-decoy" whitelisted="false" known_scanner="false" mitre_technique="T1021.004" mitre_tactic="TA0008" source_asset="pg-primary" source_asset_criticality="critical"] {"attack":{"primary":{"id":"T1021.004","name":"Remote Services: SSH","tactics":[{"id":"TA0008","name":"Lateral Movement"}]},"secondary":[{"id":"T1110","name":"Brute Force","tactics":[{"id":"TA0006","name":"Credential Access"}]}]},"details":{"username":"root","auth_method":"password"},"event_id":4812,"known_scanner":false,"node":"node-1a2b3c4d","node_id":"node-1a2b3c4d","sensor_id":"ts-sensor-remote-access-decoy","severity":"critical","source":"10.20.4.17","source_asset":{"name":"pg-primary","criticality":"critical"},"target":"0.0.0.0:2222","timestamp":"2026-10-29T09:14:03Z","trigger":"ssh_login","whitelisted":false}
```

Host, node and asset names above are illustrative.

## What the new fields enable (optional, not shipped yet)

- Escalate any decoy hit whose `truesignal.source_asset.criticality` is `high` or `critical`: a real, inventoried production host is touching a decoy, which names the likely compromised machine.
- Lateral-movement view: `threat.tactic.id: TA0008` (SSH and RDP decoy logins).
- ATT&CK coverage dashboards keyed on `threat.technique.id`.

## Rollback

If the Hub is rolled back to 2.2.0 the new fields disappear (no data migration involved). Note that 2.2.0 does not understand CIDR entries in the whitelist; any CIDR-based whitelisting would stop applying and those sources would alert again.
