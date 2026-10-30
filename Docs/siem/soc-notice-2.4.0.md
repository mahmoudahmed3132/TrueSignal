# SOC notice: TrueSignal Hub 2.4.0 SIEM changes

**To:** SOC / SIEM engineering. **Effective:** when the Hub is upgraded to `v2.4.0`. It builds on 2.3.0; read `Docs/siem/soc-notice-2.3.0.md` first if you skipped that release.

**Impact:**
- Two new triggers and additive fields.
- **One behaviour change in ECS `user.*`**, listed first because it can break existing rules.

## Act before the upgrade

1. **ECS `user.name` loses the domain for `DOMAIN\user` binds and web logins.** Until now only `details.username` was split into `user.domain` / `user.name`. In 2.4.0 the split also applies to `bind_dn` (LDAP simple binds such as `CORP\jdoe`) and `attempted_username` (web logins). Real DNs (`cn=…,dc=…`) are not split. A rule matching `user.name: "CORP\\jdoe"` must now match `user.domain: CORP AND user.name: jdoe`. `truesignal.details.*` still carries the raw value.
2. **Syslog parsers: two more structured-data parameters.** `source_country` and `source_geo_basis` are appended after `source_asset_criticality`. They are always present. A parser that expects `source_asset_criticality="…"]` (closing bracket right after it) must be updated. Parsers that match by name are unaffected.
3. **Decide how to alert on `beacon_triggered`.** It is critical by design. A known beacon **ignores the whitelist and known-scanner lists**, like `honeytoken_used`, because the reporting resolver may be an allow-listed one. Route it at the honeytoken priority.

## New triggers

| Trigger | Severity | Meaning |
|---|---|---|
| `beacon_triggered` | `critical` (`medium` when `beacon_known=false`) | A beacon the Hub created was used: a DNS name was resolved, a web bug was loaded, or a kubeconfig was used by kubectl. `details.beacon` = `{id, name, type, domain}`, where `name` is where the operator planted it. `details.channel` = `dns` or `http`. DNS events: `source` is the **resolver**, `details.client_subnet` the client's network (EDNS Client Subnet), when sent. HTTP events: `source` is the client, plus `user_agent`. `beacon_known=false` means a valid token the Hub no longer has (a deleted beacon). Not ATT&CK-mapped. |
| `receiver_saturated` | `medium` | The internet-facing Token Receiver refused TCP connections: one source over its cap (4 DNS / 8 HTTP) or the total cap. At most one per 5 minutes per listener. `source` = the busiest refused address; `details`: `listener`, `refused_per_source`, `refused_total_cap`, `distinct_sources`, `top_source_refusals`. Sustained events mean someone is trying to blind the beacons. |

## New fields

### RFC 5424 structured data (`truesignal@<PEN>`)

Appended after `source_asset_criticality`, in this order:

| Parameter | Value |
|---|---|
| `source_country` | ISO country of the located address; empty when not located (internal source, no GeoIP database, unknown address) |
| `source_geo_basis` | `source` (the event's source address) or `client_subnet` (a DNS beacon's client subnet; `source` is then the resolver); empty when not located |

The JSON body gains `"source_geo"`: `{countryCode, country, region, city, lat, lon, basis, address}`, or `null`.

### ECS

| Field | Notes |
|---|---|
| `source.geo.country_iso_code`, `country_name`, `region_name`, `city_name`, `location` (geo_point) | Only when the location is `source.ip`'s (basis `source`) |
| `truesignal.source_geo` | Always when located, with `basis`. A client-subnet location appears **only** here, never in `source.geo` |
| `user.domain` / `user.name` | Also split from `bind_dn` and `attempted_username` (see "Act before the upgrade") |

GeoIP comes from DB-IP IP to City Lite and is approximate (VPN, Tor, cloud egress, mobile ranges). Only public addresses are located. Decoys sit in internal space, so most decoy hits carry no location; beacons opened outside do.

Elastic: `source.geo.location` is mapped as `geo_point` by `ecs@mappings`. No template change is needed.

## Changes in volume (no field change)

- **`web_path_probe` (Web Router Decoy 2.1.2):** this event is no longer hidden for 60 s after a `web_page_view` from the same source. Expect more path-probe events from scanners, now with `suppressed_since_last`.
- **Liveness:**
  - a newly deployed sensor no longer raises a spurious `sensor_recovered` on its first heartbeat;
  - `sensor_heartbeat_lost` with `reason=not_restarted_after_stop` now reports `timeout_sec: 300`.
- **Syslog delivery:** after a collector restart, records are no longer lost on the dead connection. The Hub reconnects first.

## Sample (syslog, DNS beacon placed by client subnet)

```
<130>1 2026-10-30T14:02:11Z truesignal truesignalSensor - EVENT [truesignal@32473 event_id="5120" trigger="beacon_triggered" severity="critical" source="8.8.8.8" target="DNS (cdn-assets.example.com)" node="node-7c1e90ab" node_id="node-7c1e90ab" sensor="ts-sensor-token-receiver" whitelisted="false" known_scanner="false" mitre_technique="" mitre_tactic="" source_asset="" source_asset_criticality="" source_country="GB" source_geo_basis="client_subnet"] {"attack":null,"details":{"token":"7syv6dynonkv6s5jrc7ctve6","channel":"dns","query_type":"A","resolver":"8.8.8.8","client_subnet":"81.2.69.0/24","beacon":{"id":"bc_4cf8cdd0","name":"finance share","type":"dns","domain":"cdn-assets.example.com"}},"event_id":5120,"known_scanner":false,"node":"node-7c1e90ab","node_id":"node-7c1e90ab","sensor_id":"ts-sensor-token-receiver","severity":"critical","source":"8.8.8.8","source_asset":null,"source_geo":{"countryCode":"GB","country":"United Kingdom","region":"England","city":"London","lat":51.5142,"lon":-0.0931,"basis":"client_subnet","address":"81.2.69.0"},"target":"DNS (cdn-assets.example.com)","timestamp":"2026-10-30T14:02:11Z","trigger":"beacon_triggered","whitelisted":false}
```

Here `source_country="GB"` is the **client subnet's** country (`source_geo_basis="client_subnet"`), not the resolver's (`8.8.8.8`). Rules on country must check the basis.

Host names, IDs and addresses above are illustrative.

## Suggested rules (not shipped)

- `beacon_triggered` with `details.beacon_known != false` → page, the same as `honeytoken_used`.
- `receiver_saturated` repeated over 15 minutes → investigate the source and the receiver's exposure.
- An internal resolver as the `source` of a DNS `beacon_triggered` → the beacon was used **inside** the network.

## Rollback

2.4.0 adds a schema migration (v5, the `beacons` table). Rolling back to 2.3.0 or 2.2.0 needs the pre-upgrade `.bak` (`Docs/operations.md` §7, case 2). Pinning the old image alone makes it refuse the database. The new fields disappear after a rollback.
