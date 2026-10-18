# TrueSignal: Knowledge Gaps, Contradictions and Review Items

Built 2026-10-18 from a full read of commit `e2f83e9`. Nothing here was executed. "(code-read, untested)" marks behaviour inferred from source only.
Section 4 lists configuration that looks inconsistent with the stated safety constraints. **Nothing was changed.** These items are for owner review.

## 0. Top 5 (ranked by risk to a production PCI/CBE environment)

1. **Runtime trust is anchored upstream, and the validator permits root-equivalent sensors.**
   - The default `registry_url`, every sensor image, the Hub image, the installer (`get.honeywire.dev` → `AndReicscs/HoneyWire` releases) and the update check all resolve to upstream (`Hub/internal/store/sqlite.go:73`, `Sensors/official/*/*.json`, `Hub/docker-compose.yml`, `install.sh:92-108`, `Hub/internal/services/updater/updater.go:18`).
   - The compiler accepts `network_mode: host`, `user: 0:0`, `NET_ADMIN`, and rw binds outside a 5-entry denylist (§4).
   - Result: whoever controls upstream's registry branch can ship a manifest that a TrueSignal node runs as root in the host network namespace at the next `honeywire apply`.
2. **No detection content and a fragile SIEM feed.**
   - The repo has no rules for Elastic or LogScale. The only export is newline-framed, plaintext TCP/UDP "syslog" that is not RFC5424-valid and embeds attacker-controlled strings unescaped (`Hub/internal/services/siem/service.go:303-343`).
   - **Sensor-down / decoy-killed events never leave the Hub.** They are UI-only (`Hub/internal/services/statemonitor/statemonitor.go`). Killing a decoy container is therefore invisible to the SIEM.
3. **Blinding controls with no audit trail.**
   - A single admin account (no RBAC, no MFA, 30-day cookies, plain HTTP by default) can do all of the following, and none of it is logged beyond stdout:
     - whitelist a source, which drops its events before storage *and* before SIEM (`Hub/internal/services/event/service.go:63-72`);
     - remove a sensor, which CASCADE-deletes its event history (`Hub/internal/store/migrations.go:66,76`);
     - disarm, silence, or "Delete all events".
4. **Cleartext credential capture.**
   - The Web Router Decoy stores whatever username and password are typed (`Sensors/official/WebRouterDecoy/main.go:349-359`) in SQLite, the UI, JSON export and the SIEM line.
   - Retention defaults to forever (`sqlite.go:69-70`).
   - If staff ever type real credentials, PAN-adjacent or AD secrets land in the Hub and the SIEM. No data-handling rule exists.
5. **Detection-quality defects that cut fidelity or timeliness** (code-read, untested):
   - Tarpit alerts only at disconnect, up to 1h later (`TcpTarpit/main.go:25,127-173`).
   - File Canary read detection is off by default, lures are 0-byte files, and the source is always `"Local OS"`.
   - ICMP default severity `info` is excluded from paging.
   - The scan detector cannot drop privileges under `cap_drop: ALL`.
   - The SSH banner is served on the MySQL decoy port.
   - Firedrill events reuse production `eventTrigger` names.
   - Hub tests exist but no CI runs them.

---

## 1. Contradictions between files

| # | Claim | Where | Contradicted by | Verdict |
|---|---|---|---|---|
| C1 | "Strict typed schema enforcement (`DisallowUnknownFields`)" for manifests | `THREATMODEL.md:42`, `Docs/architecture/hub/backend/compose.md:21-22` | Per-version manifests used for node deployment are decoded with plain `json.Decode` (`Hub/internal/services/compose/service.go:173`). The registry index is also non-strict (`Hub/internal/catalog/service.go:88`) | DOC-ONLY for the deploy path |
| C2 | "Enforces cryptographic image digest pinning" | `CHANGELOG.md:37`, `THREATMODEL.md:46` | The builder appends a digest only if one is present (`Hub/internal/compose/builder.go:22-33`). Source manifests have `image_digest: ""`, `image_tag: "dev"` | Applied when present; not enforced |
| C3 | Forbidden mounts include the Docker socket | `THREATMODEL.md:68`, `compose.md:27` | Only `/var/run/docker.sock` is blocked. `/run/docker.sock`, `/run/containerd`, `/var/lib/docker`, `/dev`, `/boot`, `/home` are not (`Hub/internal/compose/security/validate.go:18-24`) | Partial |
| C4 | Interpolation rejected (`${`, `{{`, `$`) | `THREATMODEL.md:44` | Env var defaults are intentionally Go templates (`{{ availablePort 2222 }}`) and are not checked (`validate.go:56-80`) | Scoped to image, network, volume and command fields only |
| C5 | Hub backend uses standard `net/http`, no third-party framework | `Docs/architecture/hub/backend/README.md:11`, `README.md:167` | `github.com/go-chi/chi/v5` (`Hub/internal/api/router.go:11-12`, `Hub/go.mod`) | Doc stale |
| C6 | Health monitor lives in `services/sensor` and polls every 30s | `Docs/architecture/hub/backend/services.md:11` | `services/statemonitor/statemonitor.go:28` polls every 15s | Doc stale |
| C7 | Event service "verifies version compatibility"; events can return 426 | `services.md:32`, `API.md:620` | `ProcessEvent` has no version check. 426 exists only for the `X-Wizard-Version` header (`middleware.go:108-124`). The SDK sends no version | DOC-ONLY |
| C8 | SDK performs a `syncHubVersion` handshake and refuses to start on major mismatch; heartbeats carry agent/contract version | `Docs/architecture/sensors/README.md:36,82` | Not in `SDKs/go-honeywire/sdk.go` or the Python SDK. The heartbeat body is `{sensorId, configRev}` only | DOC-ONLY |
| C9 | Deleting a node "permanently revokes the Node's API Key, ensuring it can never authenticate again" | `Docs/operations.md:50` | Validated keys are cached in a `sync.Map` with no eviction (`Hub/internal/services/auth/service.go:199-215`). `DeleteNode` doesn't clear it (`Hub/internal/services/node/service.go:231-237`). Event writes then fail on the FK, so practical injection is blocked (code-read, untested) | Auth still succeeds until Hub restart |
| C10 | `POST /nodes/{id}/upgrade` "triggers a fleet-wide sync command over WebSockets to force the node to pull" | `Docs/architecture/hub/backend/API.md:205` | It only bumps `deployed_version`. Nodes have no daemon or WS listener; `apply` must be run manually (`node/service.go:198-221`, `Docs/operations.md:22`) | DOC-ONLY |
| C11 | `webhookType` accepts `none` | `API.md:268,296` | Store accepts only ntfy/gotify/discord/slack (`Hub/internal/store/config.go:67`). Unknown types default to ntfy at send time (`notify/service.go:299-311`) | Doc wrong. Disable by clearing the URL |
| C12 | Setup stores "hub API key" (`hubKey`) | `API.md:64-74` | `hubKey` is parsed but ignored (`Hub/internal/api/config.go:40`, `store/config.go` `CompleteSetup`) | Doc stale |
| C13 | Compiler defaults user to `1000:1000` | `Docs/architecture/dataContracts.md:137`, `.github/ISSUE_TEMPLATE/sensor_idea.yml:59` | CONTRIBUTING and templates say UID 65532. All official manifests set explicit users, four of them `0:0` | Inconsistent guidance; code uses 1000:1000 |
| C14 | Manifest example has `port_assignments[].auto_shift`, Tarpit modes `hold, echo, banner` | `dataContracts.md:100-125` | `PortAssignment` has no `auto_shift` (strict decode would reject the example) (`Hub/internal/models/models.go`). Tarpit modes are `hold, echo, close` (`TcpTarpit/main.go:122-160`) | Doc stale |
| C15 | Manifest authoring path `Sensors/official/tcp-tarpit/manifest.json` | `Docs/development/maintainer-workflow.md:102-105` | Actual: `Sensors/official/TcpTarpit/tcp-tarpit.json` | Doc stale |
| C16 | Hub "explicitly avoids background network polling" | `maintainer-workflow.md:132` | The updater polls GitHub releases and the registry every 24h by default (`updater.go:89-159`, `config/service.go` default 24) | Contradiction |
| C17 | Referenced files that don't exist: `core/api/models.go`, `core/discovery/evaluator.go`, `internal/deploy/generator.go`, Hub `internal/services/compiler.go`, `internal/api/handlers/`, `ui/src/services/api.ts`, `internal/projections/dtos.go`, `views/Fleet.vue`, template `docker-compose.yml` files | `Docs/development/{wizard,workflows,structure,sensors}.md` | Tree inventory | Doc stale |
| C18 | Wizard discovery is "passive only", no state-mutating probes | `Docs/development/wizard.md:29-30` | `availablePort` does `net.Listen` on candidate ports (`wizard/internal/commands/discover.go` funcMap) | Minor contradiction |
| C19 | File Canary "automatically generates realistic trap files", "uses ACLs", "Required Capabilities: DAC_OVERRIDE" | `Sensors/official/FileCanary/file-canary.json` docs | Init creates **empty** files with `O_CREAT\|O_EXCL`, 0644 (`FileCanary/main.go:110-145`). No ACL code. The main container has no added caps | DOC-ONLY |
| C20 | Web Router Decoy mimics Netgear/TP-Link/Cisco, does browser fingerprinting, root "to allow bridging network modes" | `web-router-decoy.json` docs | Only the brand string changes. The footer is hard-coded Cisco RV340 (`WebRouterDecoy/main.go:221-236`). Only User-Agent is logged. `network_mode: host`, default port 8080 doesn't need root | DOC-ONLY |
| C21 | Scan detector "Dropped root privileges" after opening the socket | `NetworkScanDetector/main.go:108-116` | Hub compose forces `cap_drop: ALL`, so `setuid` lacks CAP_SETUID and fails; the process stays UID 0 with a warning (code-read, untested) | Likely never drops |
| C22 | "No tuning, no noise" / "100% of their traffic is actionable" | `README.md:43-46` | The manifests themselves warn of false positives (ICMP: Uptime Kuma; scan detector: noisy environments) | Marketing vs reality |
| C23 | Hub tests: "Tests are currently pending implementation" | `.gitea/workflows/build-hub-dev.yml:69-70` | 20 `_test.go` files, 67 test funcs exist under `Hub/`, `SDKs/`, `wizard/` | CI skips existing tests |
| C24 | Mock Hub validates the "V1.0 contract" and passes only on a valid event | `Docs/development/sensors.md:71`, `scripts/mock_hub.py` | `/tmp/test_passed` is written on **any** successful POST incl. heartbeat/offline (`mock_hub.py:67-69`). `severity` is accessed without a presence check | Weak contract test |
| C25 | Python template calls `set_test_payload(event_trigger=...)` | `Sensors/templates/python-sensor/sensor.py:66-75` | SDK signature is `set_test_payload(trigger, ...)` (`honeywire/__init__.py:144`), so a TypeError on start (code-read, untested) | Template broken |
| C26 | Manifest versions 2.0.1/2.0.2/2.1.2 | `Sensors/official/*/*.json` | The catalog's boot-time mock index advertises 2.2.0 for every sensor (`Hub/internal/catalog/service.go:41-56`) | Phantom versions until the first registry refresh |
| C27 | `is_armed` default | `Hub/internal/store/sqlite.go:65` = true | `Hub/cmd/hub/main.go:104` falls back to false; `config/service.go:260` falls back to true | Inconsistent fallbacks |
| C28 | Gitea sensor build uses Go 1.21 | `.gitea/workflows/build-sensor-dev.yml:26` | All go.mod files declare `go 1.25.0` | Toolchain mismatch |

---

## 2. Coverage mismatches

### 2.1 Decoys/lures without a downstream detection rule
None of the five sensors has a SIEM rule, dashboard, or response action in the repo **[NOT IN PROJECT]**. Specific holes:
- **Sensor liveness**: heartbeats and offline transitions are not exported. No rule can detect "decoy stopped" from the SIEM.
- **File Canary read access**: off by default (`HW_ALERT_ON_OPEN=false`), yet reading a lure is the core deception signal.
- **Web Router GET `/`**: page views and directory brute-forcing are not alerted. Only `POST /login` is (`WebRouterDecoy/main.go:311-322`). The manifest's recommendation reason claims it catches directory brute-forcing.
- **ICMP Canary** at `info` never pages with the default `webhook_events` (`sqlite.go:68`).
- **Tarpit with SYN-only scans** (`nmap -sS`) produces no Tarpit event. The handshake never completes, so only the Scan Detector sees it, and only if deployed on the same host.
- **IPv6**: the scan detector is IPv4-only (ETH_P_IP). The ICMP canary listens on `ip4:icmp` only.

### 2.2 Rules without a matching decoy/lure
- `custom_anomaly_detected` exists only in templates.
- `test_mode_synthetic_alert` is an SDK default with no sensor.
- Wizard lure generators (`randWebFile`, `randDBFile`, `TrapPath`) are defined but unused by any manifest.

### 2.3 Proposed ATT&CK mapping (inference, NOT in the files; validate before use)
| eventTrigger | Candidate technique(s) |
|---|---|
| `network_scan_detected` | T1046 Network Service Discovery |
| `icmp_scan_received` | T1018 Remote System Discovery |
| `tcp_connection` | T1046; T1021.004 (SSH lateral movement attempt) when a payload is present |
| `web_login_attempt` | T1110 Brute Force / T1078 Valid Accounts (credential testing) |
| `decoy_file_accessed` | T1083 File and Directory Discovery, T1005 Data from Local System, T1552.001 Credentials in Files |
| `decoy_file_tampered` | T1565.001 Stored Data Manipulation, T1486 Data Encrypted for Impact, T1070.004 File Deletion |

---

## 3. Missing pieces

| Area | Gap |
|---|---|
| Purpose & scope | The onboarding request left `{{WHAT IT IS FOR}}` unfilled. No README section describes TrueSignal's intended use, environment or scope |
| Environment | No node inventory, hostnames, subnets/VLANs, placement plan, firewall rules (Fortinet/Palo Alto), or naming convention for nodes **[NOT IN PROJECT]** |
| Honeytokens | No credential, cloud-key, AD, DNS or document tokens. The File Canary is the only lure mechanism |
| SIEM | No Elastic ingest pipeline/ECS mapping, no LogScale parser, no rules, no index or repo naming, no collector config |
| Alert routing / ownership | No on-call, escalation, or SOAR integration. Destinations are only ntfy/gotify/discord/slack (consumer SaaS) and syslog |
| Runbooks | No IR runbook per eventTrigger; no Hub DR/restore runbook; no node key rotation; no lure rotation; no decommission checklist (uninstall leaves lure files: `wizard/cmd/wizard/main.go:59-63`) |
| Hub HA/backup | Single SQLite file; only pre-migration snapshots |
| TLS | Required by the docs, but no reverse-proxy config, cert handling or HSTS guidance exists in repo |
| Audit | No persisted audit log for config, whitelist, arm/silence, sensor removal or event deletion |
| Tests | Sensors have zero unit tests; CI runs no Go tests; no integration test of Hub→SIEM; no detection replay or ground-truth harness |
| Supply chain | No image signing (cosign), SBOM, or provenance. Third-party actions are not SHA-pinned (`trivy-action@master`, `softprops/action-gh-release@v2`, `semgrep:latest`, `aquasec/trivy:latest`, `alpine:latest`) |
| Owner-controlled release path | GH sensor publishing pushes to the manifest's `ghcr.io/andreicscs/*` and will fail or be wrong for this repo. The `registry-pages` branch doesn't exist here |
| Licence compliance | AGPLv3 §13 applies if the modified Hub is offered over a network. No NOTICE or attribution plan |
| Compliance mapping | No PCI DSS / SOC 2 / CBE control mapping, data-classification or retention policy for captured attacker data |

---

## 4. Configuration inconsistent with stated safety constraints (flagged for review; not changed)

| # | Observation | Why it conflicts | Source |
|---|---|---|---|
| S1 | Four of five official sensors run `user: "0:0"` with `network_mode: host`. The validator does not restrict `user` or `network_mode` | Docs: "unprivileged", "least privilege", templates use 65532 | `Sensors/official/*/*.json`, `Hub/internal/compose/security/validate.go` |
| S2 | `NET_ADMIN` is allow-listed. Combined with host netns, a manifest can alter host routes and firewall | "strict capability allowlists to prevent container privilege escalation" | `validate.go:11-16`, `builder.go:64-79,204-218` |
| S3 | Init containers get no forced `read_only`, `cap_drop`, or `no-new-privileges`; run as UID 0 with Docker default caps + DAC_OVERRIDE; parent dirs of `HW_DECOY_FILES` are bind-mounted **read-write**; network defaults to bridge with egress | THREATMODEL calls this "PARTIAL" but the extent is not documented | `builder.go:48-160`, `file-canary.json` |
| S4 | Mount denylist misses `/run/docker.sock` (target of the usual `/var/run` symlink), `/var/lib/docker`, `/run/containerd`, `/dev`, `/home`. `HW_DECOY_FILES=/run/docker.sock` would bind the Docker socket (read-only bind, but socket connect still works) into the File Canary (code-read, untested) | Docker socket is meant to be forbidden | `validate.go:18-24`, `builder.go:248-271` |
| S5 | Hub and nodes default to plain HTTP. README Quick Start sets `HW_ENV=development` (no Secure cookie). The node key is passed in the curl command line and stored plaintext in DB, compose env and `/etc/honeywire/config.json` | "Always serve over HTTPS" | `README.md:126`, `Hub/internal/store/nodes.go:24`, `wizard/internal/app/config.go:8` |
| S6 | `honeywire discover` prompts for the **Hub master password on the decoy host** (or reads `HW_DASHBOARD_PASSWORD` from env) | Decoy hosts are assumed compromisable (Wizard is "untrusted") | `wizard/internal/app/session.go:56-90` |
| S7 | Node bootstrap is `curl … \| bash` from `get.honeywire.dev` (upstream domain), installing to `/usr/local/bin` as root. Checksums come from the same origin as the binary | Supply-chain controls | `Hub/ui/src/components/fleetmanagement/FleetDeployModal.vue:102`, `install.sh` |
| S8 | Default `registry_url` and all `image_repository` values point to upstream | Hub as sole trust anchor is undermined if the anchor's inputs are third-party | `sqlite.go:73`, manifests |
| S9 | Hub egress: GitHub API (24h), raw.githubusercontent.com (registry), webhook SaaS. Init containers and sensors on host netns have unrestricted egress. No egress policy exists | No egress constraint is documented. Flagged because decoys in a CDE normally have none | `updater.go:18`, `catalog/service.go:65-90` |
| S10 | Web decoy stores and forwards cleartext passwords. Default retention is forever. JSON export includes them | No "no real data on decoys" rule exists; PCI DSS 3/10 data handling | `WebRouterDecoy/main.go:349-359`, `sqlite.go:69-70`, `api/events.go` `ExportEvents` |
| S11 | Whitelist match drops events before storage and SIEM; changes are not audited | Hub "single source of truth" / high-fidelity claims | `event/service.go:63-72` |
| S12 | Removing a sensor or node CASCADE-deletes all its events and uptime history | Evidence retention | `migrations.go:49,66,76` |
| S13 | `DualAuthMiddleware` accepts the node key in `?key=` query string (lands in proxy/access logs) | Credential hygiene | `Hub/internal/api/middleware.go:143-144` |
| S14 | Severity, source, target and sensorId are sensor-supplied and unvalidated. Any holder of one node's key can forge events for any sensor registered on that node | "All inputs are untrusted" | `api/events.go`, `event/service.go` |
| S15 | WebSocket `CheckOrigin` returns true (relies on SameSite=Strict) | Defense in depth | `services/websocket/service.go:13-17` |
| S16 | `POST /api/v2/setup` is unauthenticated until first completion; first network caller sets the admin password | Exposure window at install | `api/router.go`, `api/config.go:28-54` |
| S17 | Hub image in `Hub/docker-compose.yml` is `:latest` with a `permission-fixer` running `alpine:latest` as root | Version pinning | `Hub/docker-compose.yml` |

---

## 5. Open questions for the owner

1. What is TrueSignal for, concretely? Kashier internal deception in the CDE / corporate network, a product, or a lab? This decides whether §4 items are blockers.
2. Will TrueSignal run its own registry, images and installer (owner-controlled `ghcr.io/<owner>/*` + its own `registry-pages`), or consume upstream as-is?
3. Which SIEM is the system of record for these alerts: Elastic, LogScale, or both? Via which collector (Logstash/Elastic Agent/LogScale Collector/Vector)? Who owns triage?
4. Where will nodes sit (VDC segments, CDE vs non-CDE), and what egress is allowed from decoy hosts?
5. Is capturing cleartext passwords on the Web Router Decoy acceptable, or should it be hashed/redacted before storage and forwarding?
6. Are honeytokens (AD, cloud, DB credentials, documents) in scope? None exist today.
