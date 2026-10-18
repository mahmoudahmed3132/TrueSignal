# TrueSignal: Project Knowledge Reference

Built 2026-10-18 from a full read of commit `e2f83e9` on branch `claude/intelligent-albattani-dbxcqn`.
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
| Upstream | HoneyWire by andreicscs, AGPLv3 | `README.md:6-14`, `LICENSE` |
| Import | 3 commits on 2026-10-19 (+0300) by Mahmoud Halim: initial import, add `Hub/`, CodeQL v4 change | `git log` |
| Hub version | `2.1.0` | `Hub/internal/models/models.go:6` |
| Wizard version | `2.0.1` | `wizard/core/api/client.go:17` |
| Latest CHANGELOG entry | v2.0.1 (2026-06-26) | `CHANGELOG.md:1` |
| TrueSignal-specific code or config | none. The string "TrueSignal" appears only in the commit message | `grep -ri truesignal` |
| Stated purpose | the onboarding request literally contains `{{WHAT IT IS FOR}}` | onboarding request |

Upstream's own description: a "Distributed High-Signal Security Early-Warning System Builder" for internal networks. Its model is the high-fidelity tripwire: "If it trips, you have an intruder" (`README.md:39-46`).

---

## 2. Architecture

### 2.1 Components

| # | Component | Language / runtime | Status | Source |
|---|---|---|---|---|
| 1 | Hub API + store + workers | Go 1.25, chi v5, modernc SQLite (WAL, FK on), gorilla/websocket | IMPL | `Hub/cmd/hub/main.go`, `Hub/go.mod` |
| 2 | Hub UI | Vue 3 + Pinia + Tailwind + Chart.js, embedded via `go:embed` | IMPL | `Hub/ui/`, `Hub/ui/embed.go` |
| 3 | Wizard CLI (`honeywire`) | Go, must run as root | IMPL | `wizard/cmd/wizard/main.go:34-36` |
| 4 | Official sensors (5) | Go static binaries, distroless | IMPL | `Sensors/official/*` |
| 5 | Go SDK | Go | IMPL | `SDKs/go-honeywire/sdk.go` |
| 6 | Python SDK | Python + requests | IMPL, not used by any official sensor | `SDKs/python-honeywire/honeywire/__init__.py` |
| 7 | Sensor templates | Go / Python | IMPL (Python template bug, see GAPS) | `Sensors/templates/` |
| 8 | Registry (`registry-pages` branch) | static JSON | CFG-UNTESTED. The branch is not in this checkout | `.github/workflows/publish-sensor-registry.yml`, `scripts/build-registry-index.sh` |
| 9 | Installer | POSIX sh | IMPL, but fetches upstream binaries | `install.sh` |
| 10 | Mock Hub | Python http.server | IMPL (CI contract test) | `scripts/mock_hub.py` |
| 11 | Community sensors | none present | PLANNED | `Sensors/community/README.md` |

### 2.2 Data flow: decoy interaction to alert

```
 attacker / insider
   |  TCP connect | ICMP echo | SYN/FIN/NULL/XMAS | file write/open | HTTP POST /login
   v
 +------------------------- NODE (Docker, project "honeywire") --------------------------+
 | sensor container (host netns)                                                         |
 |   detection logic (main.go) -> sdk.ReportEvent() -> chan(1000) -> eventLoop          |
 |   heartbeatLoop every 30s ---------------------------------------------+              |
 +-----------------------------|-------------------------------------------|--------------+
                               | POST /api/v2/event                        | POST /api/v2/heartbeat
                               | Authorization: Bearer hw_key_... (node key)| (configRev)
                               v                                           v
 +------------------------------- HUB (:8080, HTTP) -------------------------------------+
 | AgentAuthMiddleware: key -> nodeID (cached), rate limit 100/min/node, burst 100       |
 | EventService.ProcessEvent                                                             |
 |   1. source in whitelisted_sources? ---- yes --> DROP (no DB, no SIEM, no UI)         |
 |   2. INSERT events (timestamp = Hub receive time, UTC)                                |
 |   3. silenced? no -> NotifyService.Dispatch                                           |
 |        armed && webhook_url && severity in webhook_events -> queue(1000) -> webhook  |
 |        (ntfy | gotify | discord | slack, 2/s, 10 retries)                            |
 |   4. SiemService.QueueEvent -> queue(5000) -> TCP|UDP syslog line (10 retries)        |
 |   5. WebSocket broadcast NEW_EVENT -> UI                                              |
 | StateMonitor (15s): sensor heartbeat > 60s old -> sensor_status_changes 'offline'     |
 |                     -> WebSocket only (NO SIEM, NO webhook)                           |
 +---------------------------------------------------------------------------------------+
                               |
                               v
              SIEM / log collector [NOT IN PROJECT: no parser, index, rule or owner]
```
Sources: `Hub/internal/api/router.go:111-119`, `Hub/internal/api/middleware.go:86-130`, `Hub/internal/services/event/service.go:59-107`, `Hub/internal/services/notify/service.go:155-261`, `Hub/internal/services/siem/service.go:129-264`, `Hub/internal/services/statemonitor/statemonitor.go:28,42-` .

### 2.3 Deployment (control-plane) flow

```
 UI: add sensor to node + env values --> node_sensors row, nodes.pending_config=1
 Node (root): honeywire apply
   GET /api/v2/nodes/compose (node key)
     Hub: resolve version (deployed_version or latest compatible) -> FetchSpecificManifest from registry_url
          -> ValidateManifest -> BuildEnv(defaults < user < system) -> BuildService (sandbox baseline)
          -> YAML (HW_HUB_KEY = node key, HW_CONFIG_REV = rev_xxxxxxxx)
   wizard: deep-diff vs /opt/honeywire/sensors/honeywire-compose.yml
          -> write -> docker compose pull (failure tolerated) -> up -d --remove-orphans
          -> after 3s, if any service is exited/restarting -> restore previous compose
 Sensors heartbeat with HW_CONFIG_REV; Hub marks the node synced when every sensor reports the desired rev
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
| `hw-sensor-tcp-tarpit` v2.0.2 | network tarpit / service decoy | node, `network_mode: host`, UID 0, +NET_BIND_SERVICE | listens on `HW_DECOY_PORTS` (default `{{ availablePort 2222 }},{{ availablePort 3306 }}`; code fallback 2222,3306); banner `SSH-2.0-OpenSSH_8.2p1\r\n` on **every** port; mode hold/echo/close | accepted TCP connection (full handshake) | `tcp_connection` | high | IMPL |
| `hw-sensor-icmp-canary` v2.1.2 | network canary | node, host netns, UID 0, +NET_RAW | none. Passive raw ICMP socket | ICMP Echo (type 8) and Timestamp (type 13) to the host | `icmp_scan_received` | info | IMPL |
| `hw-sensor-network-scan-detector` v2.1.2 | network IDS-lite | node, host netns, UID 0, +NET_RAW, AF_PACKET/SOCK_DGRAM IPv4 | none | TCP SYN to ≥`HW_SCAN_THRESHOLD`(5) unique non-ignored ports within `HW_SCAN_WINDOW`(5s), or any single NULL/FIN/XMAS/0x2B probe | `network_scan_detected` | high | IMPL |
| `hw-sensor-file-canary` v2.0.1 | file lure + FIM | node; init container (UID 0, +DAC_OVERRIDE, rw bind of parent dirs) creates files; main container UID 65532, ro file binds under `/canaries` | `HW_DECOY_FILES` default: web host `/var/www/html/.backup-config.php`; DB host `/var/lib/db/dump.sql.bak`; else `/opt/.env.backup`; plus `/home/admin/vpn_keys.txt` if >1 matched service. Files are created **empty** | inotify: MODIFY, CLOSE_WRITE, ATTRIB, DELETE_SELF, MOVE_SELF; OPEN/ACCESS only if `HW_ALERT_ON_OPEN=true` (default false) | `decoy_file_tampered`, `decoy_file_accessed` | critical | IMPL |
| `hw-sensor-web-router-decoy` v2.0.1 | web credential lure | node, host netns, UID 0, +NET_BIND_SERVICE, port `HW_BIND_PORT` (default `{{ availablePort 8080 }}`) | fake "<brand> Router Login" page; brand from `HW_ROUTER_BRAND` (manifest default Netgear, code default Enterprise); footer hard-coded "Model RV340 / FW 1.0.03.20" | HTTP POST `/login` (GET `/` is **not** alerted) | `web_login_attempt` | critical | IMPL |

Sources, in row order:
- `Sensors/official/TcpTarpit/{tcp-tarpit.json,main.go:18-26,109-174}`
- `Sensors/official/IcmpCanary/{icmp-canary.json,main.go:44,67-122}`
- `Sensors/official/NetworkScanDetector/{network-scan-detector.json,main.go:30-68,102-116,170-221,231-329}`
- `Sensors/official/FileCanary/{file-canary.json,main.go:16-157,217-246}`
- `Sensors/official/WebRouterDecoy/{web-router-decoy.json,main.go:221-236,264-265,324-370}`

**Honeytokens** (credentials, API keys, cloud keys, canary documents, DNS tokens, AD objects): **[NOT IN PROJECT]**. `README.md:65` mentions PDF canary tokens and DNS sinkholes only as examples of what a community sensor *could* be.
The wizard defines unused lure-name generators (`randWebFile` → `wp-config.old.php`, `.env.staging`, `config.bak.php`, `aws_s3_keys.txt`; `randDBFile` → `dump_2023.sql`, `db_backup_prod.sql`, `.pgpass.old`, `migration_rollback.sql`; `TrapPath`). No manifest references them (`wizard/internal/commands/discover.go` `renderManifestTemplates`).

**Templates** (not decoys): `hw-sensor-custom-template` (Go) and `hw-sensor-python-template` (Python) emit `custom_anomaly_detected` every 60s from a hard-coded source `192.168.1.100` (`Sensors/templates/go-sensor/main.go:66-95`, `python-sensor/sensor.py:23-52`).

### 3.1 Wizard recommendation heuristics (when `discover` suggests a sensor)

| Sensor | Process triggers | Port triggers | Logic |
|---|---|---|---|
| TCP Tarpit | mysqld, postgres, redis-server, mongod, mariadb, sshd, docker-proxy, memcached, rabbitmq, etcd | 3306, 5432, 6379, 27017, 22, 11211, 5672, 2379 | the **same** service must match a process AND a port |
| Web Router Decoy | nginx, apache2, httpd, lighttpd, docker-proxy, traefik, caddy, envoy, haproxy | 80, 443, 8080, 8443, 9000 | AND |
| File Canary | python3, node, java, nginx, apache2, httpd, php-fpm, docker-proxy, ruby, perl, go | none | process only |
| ICMP Canary, Scan Detector | none | none | "universal": always recommended |

Sources: manifests; `wizard/core/discovery/engine.go:40-160`. During template rendering the wizard sets `HW_IGNORE_PORTS` to **every port in use on the host** (`discover.go` `renderManifestTemplates`).

---

## 4. Detection coverage

There are **no SIEM detection rules, correlation searches, Sigma, KQL, LogScale or EQL queries** in the repo **[NOT IN PROJECT]**. The only "rules" are the trigger conditions inside each sensor. Notification routing (severity filter, arm state, silence, whitelist) is the only alert-routing logic.

| Rule (sensor logic) | Detects | Data source it needs | Latency (code-read) | ATT&CK |
|---|---|---|---|---|
| Tarpit `tcp_connection` | any completed TCP connection to a decoy port | the decoy port must be reachable; host netns | event sent **after the connection ends**: client close, 50 KB read, or 3600s max (`TcpTarpit/main.go:23-25,127-173`). A tool that holds the session delays the alert up to 1h | [NOT IN PROJECT] |
| ICMP `icmp_scan_received` | each ICMP echo/timestamp request to the host | raw ICMP; host netns | per packet; no dedup or rate limit at the sensor | [NOT IN PROJECT] |
| Scan `network_scan_detected` | horizontal/vertical SYN scan per source IP; stealth NULL/FIN/XMAS; Nmap T3 OS probe (flags 0x2B); tool guess from window size 1024/2048/4096 | AF_PACKET on the host, IPv4 only; inbound and outbound frames are not distinguished | instant for stealth probes; threshold-based for SYN; 60s cooldown per source per scan type (`main.go:35,292-301`) | [NOT IN PROJECT] |
| File `decoy_file_tampered` | modify, attribute change, delete, move of a lure file | inotify on a bind-mounted inode | instant. The sensor exits (`log.Fatalf`) after delete or move (`main.go:370-400`) | [NOT IN PROJECT] |
| File `decoy_file_accessed` | open/read of a lure file | inotify; `HW_ALERT_ON_OPEN=true` | instant; **disabled by default** | [NOT IN PROJECT] |
| Web `web_login_attempt` | credential submission to the fake router panel | HTTP reachability | instant; then a 1.5s tarpit delay to the client | [NOT IN PROJECT] |

The repo contains **no ATT&CK mappings**. The only mention is the `sensor_idea` issue template asking contributors for one (`.github/ISSUE_TEMPLATE/sensor_idea.yml:37`). A proposed mapping is in KNOWLEDGE-GAPS §2.3 and is marked as inference.

### 4.1 Event fields available to downstream detection

| Field | Set by | Trust | Notes |
|---|---|---|---|
| `sensorId` | sensor body | node-key holder | must exist in `node_sensors` for that node, otherwise 500 (FK failure; code maps it to 404 only if the error contains "FOREIGN KEY") |
| `eventTrigger` | sensor | node-key holder | free string |
| `severity` | sensor `HW_SEVERITY` (UI can set it) | node-key holder | **not validated** by the Hub |
| `source` | sensor | node-key holder | IP string, or `"Local OS"` for File Canary (no actor attribution), or `"Wizard Firedrill"` for tests |
| `target` | sensor | node-key holder | `Port N`, `ICMP Listener`, `Multiple Ports`, file basename, `Web Interface` |
| `details` | sensor | node-key holder | raw JSON; Web decoy puts `attempted_password` here in cleartext |
| `nodeId` | Hub (from key) | Hub | the alias is used in syslog/webhook output |
| `timestamp` | Hub receive time (RFC3339, second precision) | Hub | not the sensor's observation time |
| `count` | DB default 1 | never incremented | no aggregation exists |

Sources: `Hub/internal/models/models.go`, `Hub/internal/api/events.go`, `Hub/internal/services/event/service.go`, `Hub/internal/store/events.go:11-25`.

### 4.2 Syslog wire format (the only SIEM integration)

`Hub/internal/services/siem/service.go:303-359`:
```
<PRI>1 <RFC3339Nano UTC> honeywire honeywireSensor - - [honeywire trigger="…" source="…" target="…" node="<alias>" sensor="…" severity="…" details=<raw JSON>] <trigger>\n
```
- PRI uses facility local0 (16): critical=130, high=131, medium=132, low=133, other=134.
- Transport is TCP (persistent, newline-framed) or UDP. No TLS. No octet counting.
- **Not RFC5424-conformant**: the SD-ID lacks `@enterprise`; param values are unescaped; `details` is unquoted JSON. A `]` or `"` in attacker-controlled data breaks structured-data parsing (code-read, untested).
- The Hub has no Elastic, LogScale, CEF or JSON output **[NOT IN PROJECT]**.

### 4.3 Webhook payload
The webhook carries only title `Threat detected on <alias>`, trigger, sensorId, source, target, time and severity. **`details` are not sent** (`Hub/internal/services/notify/service.go:180-194,399-439`).

### 4.4 Test / synthetic events (filter these in the SIEM)
- `honeywire firedrill` sends SIGUSR1. Each sensor emits its `SetTestPayload`: the **same eventTrigger as real events**, `source="Wizard Firedrill"`, `details.test_message` present (`SDKs/go-honeywire/sdk.go:201-224`, each `main.go`).
- `HW_TEST_MODE=true` sends the same payload synchronously and exits (`sdk.go:226-259`).
- SDK default when no test payload is set: trigger `test_mode_synthetic_alert`.

---

## 5. Hub internals relevant to operations

### 5.1 Default runtime config (DB, first boot)
`Hub/internal/store/sqlite.go:64-75`:
- `is_armed=true`
- `webhook_type=ntfy`, `webhook_url=""`
- `webhook_events=critical,high,medium,low` (**info excluded, so ICMP Canary never pages by default**)
- `auto_archive_days=0`, `auto_purge_days=0` (keep forever)
- `siem_address=""` (SIEM off), `siem_protocol=tcp`
- `registry_url=https://raw.githubusercontent.com/andreicscs/HoneyWire/registry-pages`

Note: if the `is_armed` row is missing, `main.go:104` falls back to `false`, while `config/service.go:260` falls back to `true` on error.

### 5.2 Auth
| Actor | Mechanism | Details | Source |
|---|---|---|---|
| Human | `hw_auth` cookie, 30 days, HttpOnly, SameSite=Strict, Secure only if `HW_ENV=production` | sessions are in memory (lost on restart); 10 failures per IP → 15 min lockout; single admin, no RBAC, no MFA | `api/auth.go:26-60`, `services/auth/service.go:82-195` |
| Node / sensor | `Authorization: Bearer` or `X-Api-Key`; `?key=` also accepted on `/manifests*` | key stored **plaintext** in `nodes.api_key`; validated keys are cached in a `sync.Map` with **no eviction** | `api/middleware.go:86-170`, `services/auth/service.go:199-215`, `store/nodes.go:20-24` |
| Setup | `POST /api/v2/setup` is unauthenticated until the first completion | first caller sets the admin password; locked if `HW_DASHBOARD_PASSWORD` is set | `api/config.go:28-54`, `services/config/service.go` |
| WebSocket | cookie-protected; `CheckOrigin` always returns true | SameSite=Strict mitigates CSWSH | `services/websocket/service.go:13-17` |

### 5.3 Background workers
| Worker | Interval | Source |
|---|---|---|
| StateMonitor (offline detection) | 15s tick, 60s threshold | `services/statemonitor/statemonitor.go:28,42-` |
| Retention | hourly | `services/event/service.go:130-158`, `store/events.go:133-181` |
| WS chart sync | 30s | `services/websocket/service.go` |
| Auth sweeper | sessions hourly, lockouts 5 min | `services/auth/service.go` |
| SIEM forwarder | queue drain | `services/siem/service.go` |
| Notifier | 2/s | `services/notify/service.go:213` |
| Updater (GitHub releases + registry index) | default 24h, plus 1h retry on failure | `services/updater/updater.go` |

### 5.4 Data model (SQLite)
Tables: `nodes`, `node_sensors (PK node_id+sensor_id)`, `events`, `sensor_status_changes`, `config`, `schema_migrations` (`Hub/internal/store/migrations.go:19-91`).
- **FK `ON DELETE CASCADE`**: deleting a node deletes its sensors, and deleting a sensor deletes its events and status history (`migrations.go:49,66,76`).
- Only one instance of each sensor type per node, because the sensor ID is the catalog ID.

### 5.5 Compose compiler controls
- Main container (all IMPL): forced `read_only`, `cap_drop: ALL`, `no-new-privileges`, json-file logging 10m×3, `restart: unless-stopped`, user defaults to `1000:1000` if unset; cap_add filtered to the allowlist (`compose/builder.go:170-218`).
- Init container (IMPL, weaker): user from manifest; **no forced read_only / cap_drop / no-new-privileges**; dynamic dir binds are **read-write** (`compose/builder.go:48-160`).
- Validation: caps allowlist; mount denylist; interpolation checks on image/network/volume/command (`compose/security/validate.go`).
- Catalog manifests are decoded with `DisallowUnknownFields` (`compose/security/parse.go`). Per-version manifests used for **actual node deployment** use plain `json.Decode` (`services/compose/service.go:173`).
- The catalog boots with a hard-coded mock index advertising non-existent version `2.2.0` for all sensors until the first registry refresh (`catalog/service.go:41-56`).

---

## 6. Operations

| Area | What exists | Status | Source |
|---|---|---|---|
| Sensor health | heartbeat 30s; >60s → `down`; graceful `/offline` on SIGTERM; uptime heatmap (≥99% = up) | IMPL; UI-only, **no alert** | `sdk.go:373-409`, `statemonitor.go`, `Docs/architecture/hub/backend/projections.md` |
| Config drift | `rev_` hash; "Pending" vs "Deployed" in UI | IMPL | `Docs/architecture/hub/backend/provisioning.md`, `store/sensors.go:23-` |
| End-to-end test | `honeywire firedrill` | IMPL, manual | `wizard/internal/commands/firedrill.go:16-` |
| Hub health endpoint | `GET /api/v2/version` only; no `/healthz` | IMPL | `api/router.go:53` |
| Hub self-monitoring / alerting | none | [NOT IN PROJECT] |  |
| Hub backups | only automatic pre-migration `VACUUM INTO` snapshot | IMPL | `store/migrations.go:304-357` |
| Retention | archive/purge days (default 0 = forever) | IMPL | `store/sqlite.go:69-70` |
| Node key rotation | none. Workaround: delete and recreate the node (loses event history via CASCADE) | [NOT IN PROJECT] |  |
| Admin password rotation | UI `PATCH /system/password` (clears all sessions) | IMPL | `services/config/service.go` `ChangePassword` |
| Lure rotation / refresh | none | [NOT IN PROJECT] |  |
| Sensor updates | UI "Update Available" → node `apply` | IMPL | `Docs/operations.md:34-39` |
| Maintenance mode | "System Armed" toggle (webhooks only; SIEM continues); per-sensor silence (webhooks only) | IMPL | `notify/service.go:167`, `event/service.go:94-103` |
| Scanner allow-listing | `whitelisted_sources` exact-match on `source`; drops the event entirely | IMPL | `event/service.go:63-72` |
| Audit logging | `log.Printf` for lockouts, factory reset, event purge only; stdout | IMPL (minimal) | `auth/service.go:190`, `config/service.go`, `event/service.go:126` |
| Incident-response runbook | none | [NOT IN PROJECT] |  |
| On-call / ownership | none. Upstream `SECURITY.md` says "solo maintainer" | [NOT IN PROJECT] |  |

### 6.1 CI/CD

| Workflow | Trigger | Does | Gaps | Source |
|---|---|---|---|---|
| GH `security.yml` | push/PR main | CodeQL go/js/python (SARIF as artifact only); Trivy fs | Trivy has no `exit-code`, so it never fails; `trivy-action@master` unpinned | `.github/workflows/security.yml` |
| GH `publish-hub.yml` | tag `hub/v*` | build + push `ghcr.io/<repo_owner>/honeywire-hub:{vX,latest}`; GH release | no tests; no signing/SBOM | `.github/workflows/publish-hub.yml` |
| GH `publish-wizard.yml` | tag `wizard/v*` | linux amd64/arm64 + sha256 checksums | no tests; no signing | `.github/workflows/publish-wizard.yml` |
| GH `publish-sensor-registry.yml` | tag `sensor/**/v*` | build + push to the manifest's `image_repository`, inject digest, write `registry-pages` | pushes to `ghcr.io/andreicscs/*` (will fail without upstream rights) | `.github/workflows/publish-sensor-registry.yml` |
| GH `rollback-sensor-registry.yml` | manual | mark latest manifest `deprecated`, rebuild index | none | same dir |
| GH `cleanup-ghcr.yml` | manual | delete untagged images | uses `DELETE_PACKAGES_TOKEN` | same dir |
| Gitea `build-hub-dev.yml` | push main `Hub/**` | build UI, image `:dev` | `go test` commented out (line 69) | `.gitea/workflows/` |
| Gitea `build-sensor-dev.yml` | manual | `go test` per sensor (no tests exist), build, MockHub contract test | Go 1.21 vs go.mod 1.25; mock passes on any POST | `.gitea/workflows/`, `scripts/mock_hub.py:67-69` |
| Gitea `publish-sensor-registry.yml` | tag | same as GH, plus `LOCAL_REGISTRY` rewrite | none | `.gitea/workflows/` |
| Gitea `security.yml` | push/PR | Semgrep + Trivy (exit-code 1) | none | `.gitea/workflows/` |

---

## 7. Decisions and history (from the files)

| Date | Decision / event | Source |
|---|---|---|
| 2026-06-22 | v2.0.0: API moved to `/api/v2`; standalone sensors deprecated in favour of the Node/fleet model; registry moved to `registry-pages`; wizard introduced; whitelist added; DisallowUnknownFields, interpolation blocking, digest pinning, rate limiting, distroless | `CHANGELOG.md:15-43` |
| 2026-06-26 | v2.0.1: deployed sensor versions pinned until `apply`; Tarpit uses `availablePort`; JSON export | `CHANGELOG.md:1-12` |
| undated | Hub 2.1.0 (code constant), README badge v2.1.0 | `models.go:6`, `README.md:10` |
| undated | Heartbeats migrated to discrete status changes (migration v2) | `store/migrations.go` migration 2 |
| undated | Split distribution: sensors via a custom static registry, wizard via GitHub releases | `Docs/architecture/README.md:148-151` |
| undated | Major-version-only compatibility (semver) | `Docs/architecture/README.md:158-163` |
| undated | Wizard is ephemeral, not an agent | `Docs/architecture/wizard/README.md:15` |
| undated | Avoid DROP/RENAME migrations due to CASCADE | `store/migrations.go:93-103` |
| undated | Accepted risks: compose tampering, CLI key exposure | `THREATMODEL.md:100-110` |
| undated | Planned: manifest signing, provenance, signed deployment artifacts, init-command checking; v2.2.0, v3.0.0 IaC overhaul, SIEM benchmarks | `THREATMODEL.md:47-49,78,88`, `README.md:175-177` |
| 2026-10-19 (+0300) | Imported into TrueSignal; CodeQL SARIF kept as an artifact because code scanning isn't enabled on the private repo | `git log`, `.github/workflows/security.yml:36-37` |

---

## 8. Glossary

| Term | Meaning |
|---|---|
| Hub / Sentinel Hub | Central Go server: API, DB, UI, alert routing |
| Node | A host running sensors; identified by `node-<8hex>`, authenticated by `hw_key_…` |
| Sensor / HoneyWire | One decoy/tripwire container type, defined by a manifest |
| Manifest | JSON definition of a sensor: metadata, heuristics, deployment, env vars |
| Registry | Static `index.json` + `<name>-v<ver>.json` served from the `registry-pages` branch |
| Wizard | `honeywire` root CLI: link, discover, apply, firedrill, status, relink, uninstall |
| Desired state / pending config | Sensor set and config in the Hub not yet applied on the node |
| Config revision (`rev_…`) | Hash of the node's sensor set; sensors echo it in heartbeats to prove sync |
| Firedrill | SIGUSR1-triggered synthetic event through the real pipeline |
| Test mode | `HW_TEST_MODE=true`: send one event synchronously, then exit |
| Armed / Disarmed | Global webhook on/off switch (does not affect SIEM or storage) |
| Silence | Per-sensor webhook suppression (does not affect SIEM or storage) |
| Whitelisted sources | Exact `source` strings whose events are discarded entirely |
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
