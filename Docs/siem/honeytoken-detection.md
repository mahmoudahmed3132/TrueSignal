# Honeytoken Detection Beyond the Decoys

The Hub raises `honeytoken_used` when a planted credential is tried against a TrueSignal decoy (rule `truesignal-honeytoken-used`, `Docs/siem/detection-rules.md`). Attackers also try stolen credentials against real systems: domain controllers, VPN, databases, and the endpoints the Falcon sensor covers. The Hub can't see those logins, but your SIEM can. This page connects them.

Honeytoken usernames (`svc_<word><4 hex>`) match no real account. **Any authentication event that names one is malicious, whether it succeeded or failed.** False positives arise only if someone creates a real account with that exact name.

## 1. Get the watchlist into the SIEM

| Path | How | Freshness |
|---|---|---|
| **Automatic (recommended)** | Configure the Hub's SIEM output (`Docs/siem-integration.md`). The Hub sends every honeytoken as an inventory record: on creation, at Hub start and every 24 h. Format: RFC 5424 `MSGID HONEYTOKEN` with SD-ID `truesignal-honeytoken@<PEN>`, or ECS `event.dataset: truesignal.honeytoken`, `event.kind: enrichment`, `user.name`, `threat.indicator.type: user-account`. | Within seconds of planting; the resync keeps it alive past index retention |
| **Lookup file** | `GET /api/v2/honeytokens?format=csv` (dashboard session) returns `username,honeytoken_id,planted_node_id,planted_sensor_id,created_at`. Upload it as a LogScale lookup file, an Elastic enrich source, or a Falcon custom IOA/watchlist. | Re-export when File Canary instances are added |

Records carry the username and where the token is planted, **never the password**.

## 2. Make sure the logins are logged

A honeytoken account does not exist in AD, so the attempts appear as failures:

- **Domain controllers:** enable *Audit Credential Validation* (4776), *Audit Kerberos Authentication Service* (4768/4771), *Audit Logon* (4624/4625) and *Audit Other Logon/Logoff Events*. A non-existent user produces 4625 with SubStatus `0xC0000064` and 4768 with result `0x6`; both carry `TargetUserName`.
- **Endpoints (Falcon):** `UserLogon` / `UserLogonFailed2` carry `UserName`.
- **VPN:** Palo Alto GlobalProtect and FortiGate SSL-VPN authentication logs carry the user. The Elastic integrations (`panw`, `fortinet_fortigate`) map it to `user.name`.
- **Databases:** enable failed-login logging (MySQL `log_error_verbosity=3` / audit plugin, PostgreSQL `log_connections`), and ship it.

## 3. Elastic Security

1. Send the Hub's output to the data stream `logs-truesignal-default` (`siemProtocol: elastic`), so the indicator records land in `logs-truesignal-*`.
2. Import `Docs/siem/elastic/truesignal-honeytoken-authentication.json`. Either use **Security → Rules → Import**, or `POST /api/detection_engine/rules` with the file as the body.
   - Type: **indicator match**. Source: `event.category:authentication and not event.module:truesignal` over the Windows, system, PAN-OS and FortiGate indices. Indicators: `event.dataset:"truesignal.honeytoken"` in `logs-truesignal-*`.
   - Mapping: `user.name` → `user.name`, or `winlog.event_data.TargetUserName` → `user.name`.
   - Severity critical, risk 99, every 5 minutes. MITRE T1552.001 (Credentials In Files) and T1078 (Valid Accounts).
3. Adjust `index` to the data streams you actually ingest. Matching is exact on the `keyword` value. The token is copied from the lure verbatim, so case normally matches. If your pipeline lowercases user names, lowercase the indicator side with an ingest pipeline as well.

To check it: create a honeytoken (deploy a File Canary), then run `runas /user:CORP\<token-username> cmd` on a test host and type any password. Within one rule interval, an alert should name the token.

## 4. CrowdStrike Falcon LogScale / Next-Gen SIEM

Upload the CSV export as the lookup file `truesignal-honeytokens.csv` in the repository you search. Then schedule this query, for example every 5 minutes over the last 10:

```text
// Falcon sensor logon telemetry
#event_simpleName=/^(UserLogon|UserLogonFailed2)$/
| UserName=*
| lower(UserName, as=honeytoken_user)
| match(file="truesignal-honeytokens.csv", field=honeytoken_user, column=username, ignoreCase=true, strict=true)
| table([@timestamp, ComputerName, aid, UserName, LogonType, honeytoken_id, planted_node_id, planted_sensor_id])
```

For Windows Security events shipped by the LogScale Collector, use the same `match()` with the `TargetUserName` field of event IDs 4624, 4625, 4768, 4771 and 4776. For VPN logs, use the parser's user field.

To keep the lookup file current without manual uploads, have a scheduled job fetch `?format=csv` from the Hub and upload it through the LogScale files API. When the Hub's own output is `logscale`, the `truesignal.honeytoken` records are also in your repository, so you can match against them with a join instead of a file. Use whichever your LogScale version and repository layout support.

## 5. Response

A hit on a real system means the lure named in the indicator (`planted_node_id`, `planted_sensor_id`) has been read. The source host of the authentication attempt is compromised or in attacker hands. Treat it as active intrusion. Pivot from `truesignal.honeytoken.planted_node_id` to that node's `decoy_file_accessed` events to find when the lure was read and by whom.

The field names and query syntax above follow the standard Elastic integrations and Falcon event schemas. Validate them against your ingest pipelines before relying on the rule.
