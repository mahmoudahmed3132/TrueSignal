# TrueSignal: Project Knowledge Reference

Built 2026-10-18 from a full read of commit `e2f83e9` on branch `claude/intelligent-albattani-dbxcqn`. Identifiers were updated for the TrueSignal rebrand (2026-10-19).
Every non-obvious claim cites `file:line`. Anything the repository does not support is marked **[NOT IN PROJECT]**.
Claims based on reading code but never executed are marked **(code-read, untested)**. Nothing in this document was run.

Status legend used throughout:
- **IMPL**: implemented in code.
- **CFG-UNTESTED**: configured or coded, but no test or CI exercises it.
- **PLANNED**: only described in docs or roadmap.
- **DOC-ONLY**: claimed in docs and contradicted or absent in code.

---

## 1. Identity and provenance

| Item | Value | Source |
|---|---|---|
| Upstream | HoneyWire by Andrea Termine (https://github.com/andreicscs/HoneyWire), AGPLv3 | `NOTICE`, `LICENSE` |
| Import | 3 commits on 2026-10-19 (+0300) by Mahmoud Halim: initial import, add `Hub/`, CodeQL v4 change | `git log` |
| Hub version | `2.1.0` | `Hub/internal/models/models.go:6` |
| Wizard version | `2.0.1` | `wizard/core/api/client.go:17` |
| Latest CHANGELOG entry | v2.0.1 (2026-06-26) | `CHANGELOG.md:20` |
| Rebrand | 2026-10-19: names, UI/logo, Go modules, CLI/paths, protocol prefixes (`TS_`, `ts-sensor-`, `ts_key_`, `ts_auth`), syslog identity, distribution endpoints. No functional change | `NOTICE`, `CHANGELOG.md` |
| Security/correctness pass | 2026-10-19: hashed node keys + rotation, setup token, digest pinning, sandbox hardening, liveness alerts, evidence retention, RFC 5424 syslog, sensor fidelity fixes, CI tests. This document reflects the post-pass code | `CHANGELOG.md` top entry |
| Stated purpose | the onboarding request literally contains `{{WHAT IT IS FOR}}` | onboarding request |

Upstream's own description: a "Distributed High-Signal Security Early-Warning System Builder" for internal networks. Its model is the high-fidelity tripwire: "If it trips, you have an intruder" (`README.md:33-40`).

---

## 2. Architecture

### 2.1 Components

| # | Component | Language / runtime | Status | Source |
|---|---|---|---|---|
| 1 | Hub API + store + workers | Go 1.26, chi v5, modernc SQLite (WAL, FK on), gorilla/websocket | IMPL | `Hub/cmd/hub/main.go`, `Hub/go.mod` |
| 2 | Hub UI | Vue 3 + Pinia + Tailwind + Chart.js, embedded via `go:embed` | IMPL | `Hub/ui/`, `Hub/ui/embed.go` |
| 3 | Wizard CLI (`truesignal`) | Go, must run as root | IMPL | `wizard/cmd/wizard/main.go:34-36` |
| 4 | Official sensors (5) | Go static binaries, distroless | IMPL | `Sensors/official/*` |
| 5 | Go SDK | Go | IMPL | `SDKs/go-truesignal/sdk.go` |
| 6 | Python SDK | Python + requests | IMPL, not used by any official sensor | `SDKs/python-truesignal/truesignal/__init__.py` |
| 7 | Sensor templates | Go / Python | IMPL (Python template bug, see GAPS) | `Sensors/templates/` |
| 8 | Registry (`registry-pages` branch) | static JSON | CFG-UNTESTED. The branch is not in this checkout | `.github/workflows/publish-sensor-registry.yml`, `scripts/build-registry-index.sh` |
| 9 | Installer | POSIX sh | IMPL; fetches from this repo's Releases (private repo, nothing released yet) | `install.sh` |
| 10 | Mock Hub | Python http.server | IMPL (CI contract test) | `scripts/mock_hub.py` |
| 11 | Community sensors | none present | PLANNED | `Sensors/community/README.md` |

### 2.2 Data flow: decoy interaction to alert

```
 attacker / insider
   |  TCP connect | ICMP echo | SYN/FIN/NULL/XMAS | file write/open | HTTP POST /login
   v
 +------------------------- NODE (Docker, project "truesignal") --------------------------+
 | sensor container (host netns)                                                         |
 |   detection logic (main.go) -> sdk.ReportEvent() -> chan(1000) -> eventLoop          |
 |   heartbeatLoop every 30s ---------------------------------------------+              |
 +-----------------------------|-------------------------------------------|--------------+
                               | POST /api/v2/event                        | POST /api/v2/heartbeat
                               | Authorization: Bearer ts_key_... (node key)| (configRev)
                               v                                           v
 +------------------------------- HUB (:8080, HTTP) -------------------------------------+
 | AgentAuthMiddleware: key -> nodeID (cached), rate limit 100/min/node, burst 100       |
 | EventService.ProcessEvent                                                             |
 |   0. reset server fields, clamp strings, details -> object, normalise severity        |
 |      sensorId not registered on this node? ---- yes --> 404                           |
 |   1. INSERT events (timestamp = Hub receive time, UTC)                                |
 |      source in whitelisted_sources? -> stored archived, SIEM whitelisted=true, STOP   |
 |   2. silenced? no -> NotifyService.Dispatch                                           |
 |        armed && webhook_url && type!=none && severity in webhook_events -> webhook   |
 |        (ntfy | gotify | discord | slack, 2/s, 10 retries)                            |
 |   3. SiemService.QueueEvent -> queue(5000) -> TCP|UDP|TLS RFC 5424 (10 retries)       |
 |   4. WebSocket broadcast NEW_EVENT -> UI                                              |
 | StateMonitor (15s): heartbeat > 60s old -> 'offline' + sensor_heartbeat_lost (high)   |
 | SensorService: /offline -> sensor_stopped (low); recovery -> sensor_recovered (info)  |
 |   (liveness events go through the same pipeline: DB, webhook, SIEM, WS)              |
 | AuditMiddleware: state-changing UI calls -> log + SIEM MSGID AUDIT                    |
 +---------------------------------------------------------------------------------------+
                               |
                               v
              SIEM / log collector [NOT IN PROJECT: no parser, index, rule or owner]
```
Sources: `Hub/internal/api/router.go`, `Hub/internal/api/middleware.go`, `Hub/internal/services/event/service.go` (`ProcessEvent`, `EmitSystemEvent`), `Hub/internal/services/notify/service.go`, `Hub/internal/services/siem/service.go`, `Hub/internal/services/statemonitor/statemonitor.go`, `Hub/internal/services/sensor/service.go`.

### 2.3 Deployment (control-plane) flow

```
 UI: add sensor to node + env values --> node_sensors row, nodes.pending_config=1
 Node (root): truesignal apply
   GET /api/v2/nodes/compose (node key)
     Hub: resolve version (deployed_version or latest compatible) -> FetchSpecificManifest from registry_url
          -> ValidateManifest -> BuildEnv(defaults < user < system) -> BuildService (sandbox baseline)
          -> YAML (TS_HUB_KEY = node key, TS_CONFIG_REV = rev_xxxxxxxx)
   wizard: deep-diff vs /opt/truesignal/sensors/truesignal-compose.yml
          -> write -> docker compose pull (failure tolerated) -> up -d --remove-orphans
          -> after 3s, if any service is exited/restarting -> restore previous compose
 Sensors heartbeat with TS_CONFIG_REV; Hub marks the node synced when every sensor reports the desired rev
```
Sources: `Hub/internal/services/compose/service.go:187-`, `Hub/internal/compose/builder.go`, `wizard/internal/commands/apply.go`, `wizard/internal/deploy/apply.go`, `Hub/internal/store/sensors.go:23-`.

### 2.4 Trust model (as documented)
Only the Hub is trusted. Wizard, manifests and sensor telemetry are untrusted (`THREATMODEL.md:7-30,114-122`).
Accepted risks: post-delivery compose tampering on the node (Risk-01), and the API key on the CLI during linking (Risk-02) (`THREATMODEL.md:104-110`).

In practice the wizard executes whatever compose the Hub returns, as root, so a Hub compromise means root on every node at its next `apply`. `THREATMODEL.md` T4 acknowledges this: "Signed deployment artifact enforcement (planned)".

---

## 3. Inventory: decoys and lures

There are **no deployed-instance definitions** in the repo: no node list, no hostnames, no IPs, no subnets, no per-site config. These are **[NOT IN PROJECT]**. The table lists sensor *types* and their default lures.

| Sensor (ID) | Type | Placement (where it runs) | Default lure / bait | Detection source | eventTrigger | Default severity | Status |
|---|---|---|---|---|---|---|---|
| `ts-sensor-tcp-tarpit` v2.0.2 | network tarpit / service decoy | node, `network_mode: host`, UID 0, +NET_BIND_SERVICE | listens on `TS_DECOY_PORTS` (default `{{ availablePort 2222 }},{{ availablePort 3306 }}`; code fallback 2222,3306); per-port banners `TS_TARPIT_BANNERS` (default SSH banner on 22 and 2222 only; `TS_TARPIT_BANNER` global fallback, default empty); mode hold/echo/close | accepted TCP connection (full handshake) | `tcp_connection` (on connect), `tcp_session_payload` (on close if data was captured) | high | IMPL |
| `ts-sensor-icmp-canary` v2.1.2 | network canary | node, host netns, UID 0, +NET_RAW | none. Passive raw ICMP socket | ICMP Echo (type 8) and Timestamp (type 13) to the host; throttled per source (`TS_ICMP_COOLDOWN`, 60s) with `suppressed_since_last` | `icmp_scan_received` | low | IMPL |
| `ts-sensor-network-scan-detector` v2.1.2 | network IDS-lite | node, host netns, UID 0, +NET_RAW, AF_PACKET/SOCK_DGRAM IPv4, inbound frames only (`PACKET_OUTGOING` skipped) | none | TCP SYN to ≥`TS_SCAN_THRESHOLD`(5) unique non-ignored ports within `TS_SCAN_WINDOW`(5s), or any single NULL/FIN/XMAS/0x2B probe | `network_scan_detected` | high | IMPL |
| `ts-sensor-file-canary` v2.0.1 | file lure + FIM | node; init container (UID 0, +DAC_OVERRIDE, read-only rootfs, `cap_drop: ALL`, no network, rw bind of parent dirs) creates files; main container UID 65532, ro file binds under `/canaries` | `TS_DECOY_FILES` default: web host `/var/www/html/.backup-config.php`; DB host `/var/lib/db/dump.sql.bak`; else `/opt/.env.backup`; plus `/home/admin/vpn_keys.txt` if >1 matched service. New files get plausible content by filename (`FileCanary/lure.go`); existing files are never overwritten | inotify: MODIFY, CLOSE_WRITE, ATTRIB, DELETE_SELF, MOVE_SELF; OPEN/ACCESS when `TS_ALERT_ON_OPEN=true` (default true); per-file dedupe `TS_ALERT_COOLDOWN` (10s) | `decoy_file_tampered`, `decoy_file_accessed` | critical | IMPL |
| `ts-sensor-web-router-decoy` v2.1.0 | web credential lure | node, host netns, UID 0, +NET_BIND_SERVICE, port `TS_BIND_PORT` (default `{{ availablePort 8080 }}`) | skin engine (`TS_SKIN`: router (default; "<brand> Router Login" with per-brand footer from `TS_ROUTER_BRAND`), nas, vpn, webmail, admin, basic; or `TS_SKIN_JSON`; `Docs/sensors/web-skins.md`) | HTTP POST to the skin's login path, or Basic auth; GET `/` and other paths (rate-limited per source, 60s) | `web_login_attempt` (critical), `web_page_view`, `web_path_probe` (medium) | critical | IMPL |

Sources, in row order:
- `Sensors/official/TcpTarpit/{tcp-tarpit.json,main.go:18-26,109-174}`
- `Sensors/official/IcmpCanary/{icmp-canary.json,main.go:44,67-122}`
- `Sensors/official/NetworkScanDetector/{network-scan-detector.json,main.go:30-68,102-116,170-221,231-329}`
- `Sensors/official/FileCanary/{file-canary.json,main.go:16-157,217-246}`
- `Sensors/official/WebRouterDecoy/{web-router-decoy.json,main.go:221-236,264-265,324-370}`

**Honeytokens** (credentials, API keys, cloud keys, canary documents, DNS tokens, AD objects): **[NOT IN PROJECT]**. `README.md:51` mentions PDF canary tokens and DNS sinkholes only as examples of what a community sensor *could* be.
The wizard defines unused lure-name generators (`randWebFile` → `wp-config.old.php`, `.env.staging`, `config.bak.php`, `aws_s3_keys.txt`; `randDBFile` → `dump_2023.sql`, `db_backup_prod.sql`, `.pgpass.old`, `migration_rollback.sql`; `TrapPath`). No manifest references them (`wizard/internal/commands/discover.go` `renderManifestTemplates`).

**Templates** (not decoys): `ts-sensor-custom-template` (Go) and `ts-sensor-python-template` (Python) emit `custom_anomaly_detected` every 60s from a hard-coded source `192.168.1.100` (`Sensors/templates/go-sensor/main.go:66-95`, `python-sensor/sensor.py:23-52`).

### 3.1 Wizard recommendation heuristics (when `discover` suggests a sensor)

| Sensor | Process triggers | Port triggers | Logic |
|---|---|---|---|
| TCP Tarpit | mysqld, postgres, redis-server, mongod, mariadb, sshd, docker-proxy, memcached, rabbitmq, etcd | 3306, 5432, 6379, 27017, 22, 11211, 5672, 2379 | the **same** service must match a process AND a port |
| Web Router Decoy | nginx, apache2, httpd, lighttpd, docker-proxy, traefik, caddy, envoy, haproxy | 80, 443, 8080, 8443, 9000 | AND |
| File Canary | python3, node, java, nginx, apache2, httpd, php-fpm, docker-proxy, ruby, perl, go | none | process only |
| ICMP Canary, Scan Detector | none | none | "universal": always recommended |

Sources: manifests; `wizard/core/discovery/engine.go:40-160`. During template rendering the wizard sets `TS_IGNORE_PORTS` to **every port in use on the host** (`discover.go` `renderManifestTemplates`).

---

## 4. Detection coverage

There are **no SIEM detection rules, correlation searches, Sigma, KQL, LogScale or EQL queries** in the repo **[NOT IN PROJECT]**. The only "rules" are the trigger conditions inside each sensor. Notification routing (severity filter, arm state, silence, whitelist) is the only alert-routing logic.

| Rule (sensor logic) | Detects | Data source it needs | Latency (code-read) | ATT&CK |
|---|---|---|---|---|
| Tarpit `tcp_connection` | any completed TCP connection to a decoy port | the decoy port must be reachable; host netns | instant on connect; `tcp_session_payload` follows on close (client close, 50 KB read, or 3600s max) when data was captured (`TcpTarpit/main.go`) | [NOT IN PROJECT] |
| ICMP `icmp_scan_received` | ICMP echo/timestamp requests to the host | raw ICMP; host netns | instant for the first packet per source; then one event per `TS_ICMP_COOLDOWN` window carrying `suppressed_since_last` | [NOT IN PROJECT] |
| Scan `network_scan_detected` | horizontal/vertical SYN scan per source IP; stealth NULL/FIN/XMAS; Nmap T3 OS probe (flags 0x2B); tool guess from window size 1024/2048/4096 | AF_PACKET on the host, IPv4 only; outbound frames ignored | instant for stealth probes; threshold-based for SYN; 60s cooldown per source per scan type | [NOT IN PROJECT] |
| File `decoy_file_tampered` | modify, attribute change, delete, move of a lure file | inotify on a bind-mounted inode | instant. The sensor exits (`log.Fatalf`) after delete or move (`main.go:370-400`) | [NOT IN PROJECT] |
| File `decoy_file_accessed` | open/read of a lure file | inotify; `TS_ALERT_ON_OPEN` (default true) | instant; deduped per file for `TS_ALERT_COOLDOWN` | [NOT IN PROJECT] |
| Web `web_login_attempt` / `web_page_view` / `web_path_probe` | credential submission; page view; path probing of the fake router panel | HTTP reachability | instant (views/probes rate-limited per source); 1.5s tarpit delay on login | [NOT IN PROJECT] |
| Hub `sensor_stopped` / `sensor_heartbeat_lost` / `sensor_recovered` | decoy stopped gracefully; heartbeats missing >60s (or stopped >5 min without recovery, within 24h); back online | sensor heartbeats and `/offline` | ≤15s poll + 60s threshold | [NOT IN PROJECT] |

The repo contains **no ATT&CK mappings**. The only mention is the `sensor_idea` issue template asking contributors for one (`.github/ISSUE_TEMPLATE/sensor_idea.yml:37`). A proposed mapping is in KNOWLEDGE-GAPS §2.3 and is marked as inference.

### 4.1 Event fields available to downstream detection

| Field | Set by | Trust | Notes |
|---|---|---|---|
| `sensorId` | sensor body | node-key holder | must exist in `node_sensors` for that node, otherwise 500 (FK failure; code maps it to 404 only if the error contains "FOREIGN KEY") |
| `eventTrigger` | sensor | node-key holder | free string |
| `severity` | sensor `TS_SEVERITY` (UI can set it) | node-key holder | normalised by the Hub: unknown → `medium` (`models.NormalizeSeverity`) |
| `source` | sensor | node-key holder | IP string, or `"Local OS"` for File Canary (no actor attribution), or `"Wizard Firedrill"` for tests |
| `target` | sensor | node-key holder | `Port N`, `ICMP Listener`, `Multiple Ports`, file basename, `Web Interface` |
| `details` | sensor | node-key holder | always a JSON object (non-objects wrapped), ≤64KB. Web decoy stores a keyed `attempted_password_hmac` by default (`TS_CAPTURE_PASSWORDS`, `TS_CAPTURE_HASH_KEY`) |
| `nodeId` | Hub (from key) | Hub | the alias is used in syslog/webhook output |
| `timestamp` | Hub receive time (RFC3339, second precision) | Hub | not the sensor's observation time |
| `count` | DB default 1 | never incremented | no aggregation exists |
| `whitelisted` | Hub | Hub | true when `source` matched `whitelisted_sources`; the event is stored archived |
| `sensorId`, `source`, `target`, `eventTrigger` | sensor | node-key holder | clamped to 256 chars; `sensorId` must be registered on the calling node |

Sources: `Hub/internal/models/models.go`, `Hub/internal/api/events.go`, `Hub/internal/services/event/service.go`, `Hub/internal/store/events.go:11-25`.

### 4.2 Syslog wire format (the only SIEM integration)

`Hub/internal/services/siem/service.go` (`formatSyslog`, `formatAudit`, `structuredData`):
```
<PRI>1 <RFC3339 UTC> truesignal truesignalSensor - EVENT [truesignal@<PEN> event_id="…" trigger="…" severity="…" source="…" target="…" node="<alias>" node_id="…" sensor="…" whitelisted="true|false"] {json event}\n
<133>1 <RFC3339 UTC> truesignal truesignalSensor - AUDIT [truesignal-audit@<PEN> action="…" path="…" status="…" actor_ip="…"]\n
```
- PRI uses facility local0 (16): critical=130, high=131, medium=132, low=133, other=134. AUDIT is 133.
- PEN defaults to 32473 (the RFC 5612 documentation number); set `TS_SYSLOG_PEN` to your own.
- SD-PARAM values escape `"`, `\` and `]` per RFC 5424 §6.3.3. The JSON body repeats the full event, including `details`.
- Transport: TCP (newline-framed), UDP, or TLS (`siem_protocol=tls`, optional `TS_SIEM_CA_FILE`). No octet counting.
- The Hub has no Elastic, LogScale or CEF output **[NOT IN PROJECT]**; parse the JSON body.

### 4.3 Webhook payload
The webhook carries only title `Threat detected on <alias>`, trigger, sensorId, source, target, time and severity. **`details` are not sent** (`Hub/internal/services/notify/service.go:180-194,399-439`).

### 4.4 Test / synthetic events (filter these in the SIEM)
- `truesignal firedrill` sends SIGUSR1. Each sensor emits its `SetTestPayload`: the **same eventTrigger as real events**, `source="Wizard Firedrill"`, `details.test_message` present (`SDKs/go-truesignal/sdk.go:201-224`, each `main.go`).
- `TS_TEST_MODE=true` sends the same payload synchronously and exits (`sdk.go:226-259`).
- SDK default when no test payload is set: trigger `test_mode_synthetic_alert`.

---

## 5. Hub internals relevant to operations

### 5.1 Default runtime config (DB, first boot)
`Hub/internal/store/sqlite.go:64-75`:
- `is_armed=true`
- `webhook_type=ntfy`, `webhook_url=""`
- `webhook_events=critical,high,medium,low` (`info` excluded; ICMP Canary now defaults to `low`)
- `auto_archive_days=0`, `auto_purge_days=0` (keep forever)
- `siem_address=""` (SIEM off), `siem_protocol=tcp` (`udp`, `tls` also accepted); `webhook_type` also accepts `none`
- `registry_url=https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/registry-pages`

If the `is_armed` row is missing, both `main.go` and `config/service.go` fall back to `true`.

### 5.2 Auth
| Actor | Mechanism | Details | Source |
|---|---|---|---|
| Human | `ts_auth` cookie, HttpOnly, SameSite=Strict, Secure unless `TS_ENV=development`; 12h absolute (`TS_SESSION_TTL`) + 15m idle (`TS_SESSION_IDLE_TIMEOUT`) | sessions are in memory (lost on restart); 10 failures per IP → 15 min lockout; password ≥12 chars; single admin, no RBAC, no MFA | `api/auth.go`, `services/auth/service.go` |
| Node / sensor | `Authorization: Bearer` or `X-Api-Key` (query-string keys rejected) | DB stores `sha256:<hex>`; key shown once at creation/rotation; validation cache keyed by token hash, cleared on node delete, key rotation and factory reset | `api/middleware.go`, `services/auth/service.go`, `store/nodes.go` |
| Setup | `POST /api/v2/setup` needs the one-time token printed in the Hub log (`TS_SETUP_TOKEN` overrides) | locked after first completion, or if `TS_DASHBOARD_PASSWORD` is set | `api/config.go`, `services/config/service.go` `EnsureSetupToken` |
| WebSocket | cookie-protected; same-origin `Origin` required outside development (Hub endpoint host also allowed) | | `services/websocket/service.go` `SameOrigin` |

### 5.3 Background workers
| Worker | Interval | Source |
|---|---|---|
| StateMonitor (offline detection + liveness alerts) | 15s tick, 60s threshold, 5 min stopped escalation | `services/statemonitor/statemonitor.go` |
| Retention | hourly | `services/event/service.go:130-158`, `store/events.go:133-181` |
| WS chart sync | 30s | `services/websocket/service.go` |
| Auth sweeper | sessions hourly, lockouts 5 min | `services/auth/service.go` |
| SIEM forwarder | queue drain | `services/siem/service.go` |
| Notifier | 2/s | `services/notify/service.go:213` |
| Updater (GitHub releases + registry index) | default 24h, plus 1h retry on failure | `services/updater/updater.go` |

### 5.4 Data model (SQLite)
Tables: `nodes`, `node_sensors (PK node_id+sensor_id)`, `events`, `sensor_status_changes`, `config`, `schema_migrations` (`Hub/internal/store/migrations.go:19-91`).
- **FK `ON DELETE CASCADE`** remains on `node_sensors` and `sensor_status_changes` (deleting a node deletes its sensors and status history). Since migration v3, `events` has **no FK**: events survive sensor and node deletion (`migrations.go` migration 3).
- Migration v3 also re-stores node keys as `sha256:<hex>`.
- Only one instance of each sensor type per node, because the sensor ID is the catalog ID.

### 5.5 Compose compiler controls
- Main container: forced `read_only`, `cap_drop: ALL`, `no-new-privileges`, json-file logging 10m×3, `restart: unless-stopped`; user defaults to `65532:65532` if unset; cap_add filtered to `NET_RAW`, `NET_BIND_SERVICE`, `DAC_OVERRIDE` (`compose/builder.go`, `security.AllowedCaps`).
- Init container: forced `read_only`, `cap_drop: ALL` (+ allowlisted caps), `no-new-privileges`, `network_mode: none`; user from manifest; dynamic dir binds are read-write (needed to create lures).
- Validation (`compose/security/validate.go`): caps allowlist; `network_mode` ∈ host/bridge/none; mounts absolute, not `/`, outside the denylist; interpolation checks on image/network/volume/command; every image needs an `@sha256:` digest (`RequirePinnedImages`; `TS_ALLOW_UNPINNED_IMAGES` dev override); `$` in env values escaped to `$$`.
- Per-version manifests are size-limited (1MB) and decoded strictly with ID/version validation and identity checks (`services/compose/service.go`). A missing or invalid manifest fails the whole compose (HTTP 422) instead of dropping the sensor.
- The catalog starts empty and fills from the registry (`catalog/service.go`); the index is size-limited (4MB).

---

## 6. Operations

| Area | What exists | Status | Source |
|---|---|---|---|
| Sensor health | heartbeat 30s; >60s → `down`; graceful `/offline` on SIGTERM; uptime heatmap (≥99% = up) | IMPL; alerts `sensor_stopped`, `sensor_heartbeat_lost`, `sensor_recovered` to SIEM/webhook | `sdk.go`, `statemonitor.go`, `services/sensor/service.go` |
| Config drift | `rev_` hash; "Pending" vs "Deployed" in UI | IMPL | `Docs/architecture/hub/backend/provisioning.md`, `store/sensors.go:23-` |
| End-to-end test | `truesignal firedrill` | IMPL, manual | `wizard/internal/commands/firedrill.go:16-` |
| Hub health endpoint | `GET /api/v2/version` only; no `/healthz` | IMPL | `api/router.go:53` |
| Hub self-monitoring / alerting | none | [NOT IN PROJECT] |  |
| Hub backups | only automatic pre-migration `VACUUM INTO` snapshot | IMPL | `store/migrations.go:304-357` |
| Retention | archive/purge days (default 0 = forever) | IMPL | `store/sqlite.go:69-70` |
| Node key rotation | UI "Rotate key" / `POST /api/v2/nodes/{id}/rotate-key`; old key rejected immediately; relink the node with the new key | IMPL | `services/node/service.go` `RotateKey`, `store/nodes.go` `RotateNodeKey` |
| Admin password rotation | UI `PATCH /system/password` (clears all sessions) | IMPL | `services/config/service.go` `ChangePassword` |
| Lure rotation / refresh | none | [NOT IN PROJECT] |  |
| Sensor updates | UI "Update Available" → node `apply` | IMPL | `Docs/operations.md:34-39` |
| Maintenance mode | "System Armed" toggle (webhooks only; SIEM continues); per-sensor silence (webhooks only) | IMPL | `notify/service.go:167`, `event/service.go:94-103` |
| Scanner allow-listing | `whitelisted_sources` exact-match on `source`; event stored archived and forwarded to SIEM with `whitelisted=true`; no webhook/live feed | IMPL | `event/service.go` `isWhitelisted` |
| Audit logging | every state-changing dashboard call plus login/logout/setup: `[AUDIT]` log line and SIEM `MSGID AUDIT` (method, route, status, IP; no body) | IMPL | `api/middleware.go` `AuditMiddleware`, `cmd/hub/main.go` `auditLogger` |
| Incident-response runbook | none | [NOT IN PROJECT] |  |
| On-call / ownership | none. `SECURITY.md` points only to GitHub private vulnerability reporting | [NOT IN PROJECT] |  |

### 6.1 CI/CD

All `uses:` actions are pinned to commit SHAs (version in a trailing comment).

| Workflow | Trigger | Does | Gaps | Source |
|---|---|---|---|---|
| GH `security.yml` | push/PR main | CodeQL go/js/python (SARIF as artifact only); Trivy fs (`exit-code: 1`, HIGH/CRITICAL) | SARIF not uploaded to code scanning | `.github/workflows/security.yml` |
| GH `test.yml` | push/PR main | build UI, then `go vet` + `go test -race` for Hub, wizard, Go SDK and each sensor; Python byte-compile | no E2E in CI | `.github/workflows/test.yml` |
| GH `publish-hub.yml` | tag `hub/v*` | build + push `ghcr.io/<repo_owner>/truesignal-hub:{vX,latest}`; GH release | no tests; no signing/SBOM | `.github/workflows/publish-hub.yml` |
| GH `publish-wizard.yml` | tag `wizard/v*` | linux amd64/arm64 + sha256 checksums | no tests; no signing | `.github/workflows/publish-wizard.yml` |
| GH `publish-sensor-registry.yml` | tag `sensor/**/v*` | build + push to the manifest's `image_repository`, inject digest, write `registry-pages` | pushes to `ghcr.io/mahmoudahmed3132/truesignal-*` (nothing published yet) | `.github/workflows/publish-sensor-registry.yml` |
| GH `rollback-sensor-registry.yml` | manual | mark latest manifest `deprecated`, rebuild index | none | same dir |
| GH `cleanup-ghcr.yml` | manual | delete untagged images | uses `DELETE_PACKAGES_TOKEN` | same dir |
| Gitea `build-hub-dev.yml` | push main `Hub/**` | build UI, `go vet` + `go test`, image `:dev` | none | `.gitea/workflows/` |
| Gitea `build-sensor-dev.yml` | manual | `go test` per sensor, build, MockHub contract test (passes only on a valid event) | none | `.gitea/workflows/`, `scripts/mock_hub.py` |
| Gitea `publish-sensor-registry.yml` | tag | same as GH, plus `LOCAL_REGISTRY` rewrite | none | `.gitea/workflows/` |
| Gitea `security.yml` | push/PR | Semgrep + Trivy (exit-code 1) | `semgrep:latest`, `trivy:latest` containers unpinned | `.gitea/workflows/` |

---

## 7. Decisions and history (from the files)

| Date | Decision / event | Source |
|---|---|---|
| 2026-06-22 | v2.0.0: API moved to `/api/v2`; standalone sensors deprecated in favour of the Node/fleet model; registry moved to `registry-pages`; wizard introduced; whitelist added; DisallowUnknownFields, interpolation blocking, digest pinning, rate limiting, distroless | `CHANGELOG.md:34-62` |
| 2026-06-26 | v2.0.1: deployed sensor versions pinned until `apply`; Tarpit uses `availablePort`; JSON export | `CHANGELOG.md:20-31` |
| undated | Hub 2.1.0 (code constant), README badge v2.1.0 | `models.go:6`, `README.md:10` |
| undated | Heartbeats migrated to discrete status changes (migration v2) | `store/migrations.go` migration 2 |
| undated | Split distribution: sensors via a custom static registry, wizard via GitHub releases | `Docs/architecture/README.md:148-151` |
| undated | Major-version-only compatibility (semver) | `Docs/architecture/README.md:158-163` |
| undated | Wizard is ephemeral, not an agent | `Docs/architecture/wizard/README.md:15` |
| undated | Avoid DROP/RENAME migrations due to CASCADE | `store/migrations.go` |
| 2026-10-19 | Migration v3 rebuilds `events` without its FK (copy into `events_v3`, then swap) so evidence outlives sensors and nodes | `store/migrations.go` migration 3 |
| undated | Accepted risks: compose tampering, CLI key exposure | `THREATMODEL.md:100-110` |
| undated | Planned: manifest signing, provenance, signed deployment artifacts, init-command checking; v2.2.0, v3.0.0 IaC overhaul, SIEM benchmarks | `THREATMODEL.md:47-49,78,88`, upstream README roadmap (removed at rebrand) |
| 2026-10-19 (+0300) | Imported into TrueSignal; CodeQL SARIF kept as an artifact because code scanning isn't enabled on the private repo | `git log`, `.github/workflows/security.yml:36-37` |

---

## 8. Glossary

| Term | Meaning |
|---|---|
| Hub | Central Go server: API, DB, UI, alert routing |
| Node | A host running sensors; identified by `node-<8hex>`, authenticated by `ts_key_…` |
| Sensor | One decoy/tripwire container type, defined by a manifest |
| Manifest | JSON definition of a sensor: metadata, heuristics, deployment, env vars |
| Registry | Static `index.json` + `<name>-v<ver>.json` served from the `registry-pages` branch |
| Wizard | `truesignal` root CLI: link, discover, apply, firedrill, status, relink, uninstall |
| Desired state / pending config | Sensor set and config in the Hub not yet applied on the node |
| Config revision (`rev_…`) | Hash of the node's sensor set; sensors echo it in heartbeats to prove sync |
| Firedrill | SIGUSR1-triggered synthetic event through the real pipeline |
| Test mode | `TS_TEST_MODE=true`: send one event synchronously, then exit |
| Armed / Disarmed | Global webhook on/off switch (does not affect SIEM or storage) |
| Silence | Per-sensor webhook suppression (does not affect SIEM or storage) |
| Whitelisted sources | Exact `source` strings whose events are stored archived and flagged, but not notified |
| Init container / provisioner | One-shot container that runs before a sensor (File Canary uses it to create lure files) |
| `dynamic_file_bind` / `dynamic_dir_bind` | Mount types expanded from a comma-separated env var (`source_env`) |
| Universal trigger | A manifest with no heuristics, so it is always recommended |
| Projection | Backend-computed analytics DTO (severity, velocity, summary, uptime) |
| Tarpit modes | `hold` (read slowly, keepalive NULs), `echo`, `close` (immediate close) |

---

## 9. Files read / skipped

**Read in full**: all of `README.md`, `CHANGELOG.md`, `SECURITY.md`, `THREATMODEL.md`, `CONTRIBUTING.md`, `Makefile`, `install.sh`, `.gitignore`, `Docs/**` (frontend docs skimmed at heading level), all 5 sensor `main.go`/`Dockerfile`/manifest/`go.mod`, both SDKs, both templates, `scripts/*`, all 10 workflows, `Hub/cmd`, `Hub/internal/{api,services,store,compose,catalog,models}` non-test files, `Hub/Dockerfile`, `Hub/docker-compose.yml`, `Hub/go.mod`, wizard `cmd`, `internal/{app,commands/apply,discover,firedrill,teardown,commands}`, `internal/deploy/{apply,docker}`, `internal/util`, `core/{api/client (partial),discovery}`.

**Skimmed** (signatures or greps only): `Hub/internal/projections/**`, `Hub/ui/src/**` (only `NodeSensorModal.vue` template handling, `FleetDeployModal.vue`, `Header.vue`, `NodeDetails.vue` install command), wizard `internal/cli/*`, `internal/commands/{linking,onboarding,status}`, `internal/deploy/uninstall.go`, `internal/system/state.go`, `core/scanner/*`, `core/schema/manifest.go`, `.github/ISSUE_TEMPLATE/*`, all `*_test.go` (counted, not read), `LICENSE` (header).

**Skipped**: `Hub/ui/package-lock.json` (lockfile), `Hub/ui/public/favicon.svg` (image), all `go.sum`, embedded `icon_svg` strings in manifests. No binaries, VM disks, vendored deps or build output exist in the tree (`node_modules/`, `dist/` are gitignored and absent).
