# TrueSignal: Knowledge Gaps, Contradictions and Review Items

Built 2026-10-18 from a full read of commit `e2f83e9`. Updated 2026-10-19 after the security/correctness pass (`CHANGELOG.md` top entry): every item now carries a **Status**.
Status values: **Fixed** (code changed and tested), **Docs** (documentation corrected to match code), **Partial** (mitigated, residual risk stated), **Open** (needs an owner decision or infrastructure that isn't in the repo).

## 0. Top 5 residual risks (ranked for a production PCI/CBE environment)

1. **Unsigned supply chain: repo write access is still fleet root.**
   - Manifests and images are not signed. Digest pinning is now enforced (`Hub/internal/compose/security/validate.go` `RequirePinnedImages`) and the sandbox is tighter (no `NET_ADMIN`, larger mount denylist, hardened init containers). But the digest comes from the same registry an attacker would write to.
   - Anyone who can push a `sensor/*` tag or write `registry-pages` can still ship a manifest that every node runs as root in the host netns at its next `truesignal apply`.
   - Fix needs cosign/sigstore keys plus Hub-side verification. **Open**: owner decision.
2. **Distribution isn't operational.** Nothing is published (no `registry-pages`, ghcr images or wizard release), so nodes can't install yet. The repo is public (owner decision 2026-10-24); token auth for a private repo exists in commit `4013e0d` (reverted) if that changes.
3. **No detection content.** The SIEM feed is now RFC 5424-valid, escaped, optionally TLS, and carries liveness and audit records. But the repo still has no Elastic/LogScale parser or rules **[NOT IN PROJECT]**.
4. **Single admin, no MFA/RBAC; Hub serves plain HTTP.** Mitigations now in place: 12-character minimum password, 12h absolute + 15m idle sessions, setup token, and audit records to the SIEM. A TLS reverse proxy is still mandatory and not in the repo.
5. **Decoy hosts hold a node key and may hold the dashboard password.**
   - The node key is plaintext on the node (`/etc/truesignal/config.json`, compose env). It is needed to authenticate and is scoped to that node.
   - `truesignal discover` prompts for the dashboard password on the decoy host (`wizard/internal/app/session.go`). **Open**: accepted risk or redesign (node-scoped registration API).

---

## 1. Contradictions between files

| # | Claim | Where | Contradicted by | Verdict | Status |
|---|---|---|---|---|---|
| C1 | "Strict typed schema enforcement (`DisallowUnknownFields`)" for manifests | `THREATMODEL.md:42`, `Docs/architecture/hub/backend/compose.md:21-22` | Per-version manifests used for node deployment are decoded with plain `json.Decode` (`Hub/internal/services/compose/service.go:173`). The registry index is also non-strict (`Hub/internal/catalog/service.go:88`) | DOC-ONLY for the deploy path | **Fixed**: per-version manifests decode strictly with a size limit and identity checks (`services/compose/service.go`); the index is size-limited (`catalog/service.go`), not strict |
| C2 | "Enforces cryptographic image digest pinning" | `CHANGELOG.md:56`, `THREATMODEL.md:46` | The builder appends a digest only if one is present (`Hub/internal/compose/builder.go:22-33`). Source manifests have `image_digest: ""`, `image_tag: "dev"` | Applied when present; not enforced | **Fixed**: enforced for main and init images (`RequirePinnedImages`); `TS_ALLOW_UNPINNED_IMAGES` is a dev override |
| C3 | Forbidden mounts include the Docker socket | `THREATMODEL.md:68`, `compose.md:27` | Only `/var/run/docker.sock` is blocked. `/run/docker.sock`, `/run/containerd`, `/var/lib/docker`, `/dev`, `/boot`, `/home` are not (`Hub/internal/compose/security/validate.go:18-24`) | Partial | **Fixed**: denylist expanded, absolute paths only (`security/validate.go`) |
| C4 | Interpolation rejected (`${`, `{{`, `$`) | `THREATMODEL.md:44` | Env var defaults are intentionally Go templates (`{{ availablePort 2222 }}`) and are not checked (`validate.go:56-80`) | Scoped to image, network, volume and command fields only | By design; **Docs** scoped |
| C5 | Hub backend uses standard `net/http`, no third-party framework | `Docs/architecture/hub/backend/README.md:11`, `README.md:153` | `github.com/go-chi/chi/v5` (`Hub/internal/api/router.go:11-12`, `Hub/go.mod`) | Doc stale | **Docs** |
| C6 | Health monitor lives in `services/sensor` and polls every 30s | `Docs/architecture/hub/backend/services.md:11` | `services/statemonitor/statemonitor.go:28` polls every 15s | Doc stale | **Docs** |
| C7 | Event service "verifies version compatibility"; events can return 426 | `services.md:32`, `API.md:620` | `ProcessEvent` has no version check. 426 exists only for the `X-Wizard-Version` header (`middleware.go:108-124`). The SDK sends no version | DOC-ONLY | **Docs** |
| C8 | SDK performs a `syncHubVersion` handshake and refuses to start on major mismatch; heartbeats carry agent/contract version | `Docs/architecture/sensors/README.md:36,82` | Not in `SDKs/go-truesignal/sdk.go` or the Python SDK. The heartbeat body is `{sensorId, configRev}` only | DOC-ONLY | **Docs** |
| C9 | Deleting a node "permanently revokes the Node's API Key, ensuring it can never authenticate again" | `Docs/operations.md:50` | Validated keys are cached in a `sync.Map` with no eviction (`Hub/internal/services/auth/service.go:199-215`). `DeleteNode` doesn't clear it (`Hub/internal/services/node/service.go:231-237`). Event writes then fail on the FK, so practical injection is blocked (code-read, untested) | Auth still succeeds until Hub restart | **Fixed**: cache keyed by token hash, invalidated on delete/rotate/reset (`services/auth/service.go`); E2E verified |
| C10 | `POST /nodes/{id}/upgrade` "triggers a fleet-wide sync command over WebSockets to force the node to pull" | `Docs/architecture/hub/backend/API.md:205` | It only bumps `deployed_version`. Nodes have no daemon or WS listener; `apply` must be run manually (`node/service.go:198-221`, `Docs/operations.md:22`) | DOC-ONLY | **Docs** |
| C11 | `webhookType` accepts `none` | `API.md:268,296` | Store accepts only ntfy/gotify/discord/slack (`Hub/internal/store/config.go:67`). Unknown types default to ntfy at send time (`notify/service.go:299-311`) | Doc wrong. Disable by clearing the URL | **Fixed**: `none` accepted and honoured by dispatch |
| C12 | Setup stores "hub API key" (`hubKey`) | `API.md:64-74` | `hubKey` is parsed but ignored (`Hub/internal/api/config.go:40`, `store/config.go` `CompleteSetup`) | Doc stale | **Fixed**: replaced by `setupToken` |
| C13 | Compiler defaults user to `1000:1000` | `Docs/architecture/dataContracts.md:137`, `.github/ISSUE_TEMPLATE/sensor_idea.yml:59` | CONTRIBUTING and templates say UID 65532. All official manifests set explicit users, four of them `0:0` | Inconsistent guidance; code uses 1000:1000 | **Fixed**: default is now `65532:65532`; guidance aligned |
| C14 | Manifest example has `port_assignments[].auto_shift`, Tarpit modes `hold, echo, banner` | `dataContracts.md:100-125` | `PortAssignment` has no `auto_shift` (strict decode would reject the example) (`Hub/internal/models/models.go`). Tarpit modes are `hold, echo, close` (`TcpTarpit/main.go:122-160`) | Doc stale | **Docs** |
| C15 | Manifest authoring path `Sensors/official/tcp-tarpit/manifest.json` | `Docs/development/maintainer-workflow.md:102-105` | Actual: `Sensors/official/TcpTarpit/tcp-tarpit.json` | Doc stale | **Docs** |
| C16 | Hub "explicitly avoids background network polling" | `maintainer-workflow.md:132` | The updater polls GitHub releases and the registry every 24h by default (`updater.go:89-159`, `config/service.go` default 24) | Contradiction | **Docs** |
| C17 | Referenced files that don't exist: `core/api/models.go`, `core/discovery/evaluator.go`, `internal/deploy/generator.go`, Hub `internal/services/compiler.go`, `internal/api/handlers/`, `ui/src/services/api.ts`, `internal/projections/dtos.go`, `views/Fleet.vue`, template `docker-compose.yml` files | `Docs/development/{wizard,workflows,structure,sensors}.md` | Tree inventory | Doc stale | **Docs** |
| C18 | Wizard discovery is "passive only", no state-mutating probes | `Docs/development/wizard.md:29-30` | `availablePort` does `net.Listen` on candidate ports (`wizard/internal/commands/discover.go` funcMap) | Minor contradiction | **Docs**: `availablePort` is a local bind check, not a network probe |
| C19 | File Canary "automatically generates realistic trap files", "uses ACLs", "Required Capabilities: DAC_OVERRIDE" | `Sensors/official/FileCanary/file-canary.json` docs | Init creates **empty** files with `O_CREAT\|O_EXCL`, 0644 (`FileCanary/main.go:110-145`). No ACL code. The main container has no added caps | DOC-ONLY | **Fixed**: lures get content by filename (`FileCanary/lure.go`); manifest docs corrected |
| C20 | Web Router Decoy mimics Netgear/TP-Link/Cisco, does browser fingerprinting, root "to allow bridging network modes" | `web-router-decoy.json` docs | Only the brand string changes. The footer is hard-coded Cisco RV340 (`WebRouterDecoy/main.go:221-236`). Only User-Agent is logged. `network_mode: host`, default port 8080 doesn't need root | DOC-ONLY | **Fixed**: per-brand profiles incl. footer; manifest docs corrected |
| C21 | Scan detector "Dropped root privileges" after opening the socket | `NetworkScanDetector/main.go:108-116` | Hub compose forces `cap_drop: ALL`, so `setuid` lacks CAP_SETUID and fails; the process stays UID 0 with a warning (code-read, untested) | Likely never drops | **Fixed** (honest log): it stays UID 0; privilege drop is impossible under `cap_drop: ALL` |
| C22 | "No tuning, no noise" / "100% of their traffic is actionable" | `README.md:37-40` | The manifests themselves warn of false positives (ICMP: Uptime Kuma; scan detector: noisy environments) | Marketing vs reality | **Docs** |
| C23 | Hub tests: "Tests are currently pending implementation" | `.gitea/workflows/build-hub-dev.yml:69-70` | 20 `_test.go` files, 67 test funcs exist under `Hub/`, `SDKs/`, `wizard/` | CI skips existing tests | **Fixed**: Gitea runs `go test`; GitHub `test.yml` added |
| C24 | Mock Hub validates the "V1.0 contract" and passes only on a valid event | `Docs/development/sensors.md:71`, `scripts/mock_hub.py` | `/tmp/test_passed` is written on **any** successful POST incl. heartbeat/offline (`mock_hub.py:67-69`). `severity` is accessed without a presence check | Weak contract test | **Fixed**: mock passes only on a valid event |
| C25 | Python template calls `set_test_payload(event_trigger=...)` | `Sensors/templates/python-sensor/sensor.py:66-75` | SDK signature is `set_test_payload(trigger, ...)` (`truesignal/__init__.py:144`), so a TypeError on start (code-read, untested) | Template broken | **Fixed** |
| C26 | Manifest versions 2.0.1/2.0.2/2.1.2 | `Sensors/official/*/*.json` | The catalog's boot-time mock index advertises 2.2.0 for every sensor (`Hub/internal/catalog/service.go:41-56`) | Phantom versions until the first registry refresh | **Fixed**: mock index removed |
| C27 | `is_armed` default | `Hub/internal/store/sqlite.go:65` = true | `Hub/cmd/hub/main.go:104` falls back to false; `config/service.go:260` falls back to true | Inconsistent fallbacks | **Fixed**: fallbacks agree (`true`) |
| C28 | Gitea sensor build uses Go 1.21 | `.gitea/workflows/build-sensor-dev.yml:26` | All go.mod files declare `go 1.25.0` | Toolchain mismatch | **Fixed**: all modules and CI on Go 1.26 |

---

## 2. Coverage mismatches

### 2.1 Decoys/lures without a downstream detection rule
None of the five sensors has a SIEM rule, dashboard, or response action in the repo **[NOT IN PROJECT]**. Specific holes:
- ~~Sensor liveness~~ **Fixed**: `sensor_stopped`, `sensor_heartbeat_lost`, `sensor_recovered` reach SIEM and webhooks.
- ~~File Canary read access off by default~~ **Fixed**: `TS_ALERT_ON_OPEN=true` default, with dedupe.
- ~~Web Router GET `/` not alerted~~ **Fixed**: `web_page_view` and `web_path_probe` (rate-limited per source).
- ~~ICMP Canary at `info` never pages~~ **Fixed**: default `low`, throttled per source (`TS_ICMP_COOLDOWN`).
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
| SIEM | ECS output, the Elastic index template / API key and LogScale HEC setup are in `Docs/siem-integration.md` (2026-10-24). Still missing: detection rules, Kashier index/repository naming, collector config |
| Alert routing / ownership | No on-call, escalation, or SOAR integration. Destinations are only ntfy/gotify/discord/slack (consumer SaaS) and syslog |
| Runbooks | No IR runbook per eventTrigger; no Hub DR/restore runbook; no lure rotation. Node key rotation now exists (UI / `POST /api/v2/nodes/{id}/rotate-key`); uninstall now lists the lure files it leaves |
| Hub HA/backup | Single SQLite file; only pre-migration snapshots |
| TLS | Required by the docs, but no reverse-proxy config, cert handling or HSTS guidance exists in repo |
| Audit | **Partial**: every state-changing dashboard call is logged and sent to the SIEM as `MSGID AUDIT` (route, status, client IP). Not persisted in the Hub DB; no before/after diff |
| Tests | **Partial**: every Go module has tests and `test.yml` runs them with `-race`. A Hub→sensor→SIEM E2E was run manually for this pass; it is not in CI. No detection replay harness |
| Supply chain | No image signing (cosign), SBOM, or provenance. GitHub/Gitea actions are now SHA-pinned; the Gitea security job still runs `semgrep/semgrep:latest` and `aquasec/trivy:latest` containers |
| Owner-controlled release path | Endpoints retargeted to the owner (2026-10-19), but nothing is published: no `registry-pages` branch, no ghcr images, no wizard release. |
| Licence compliance | AGPLv3 §13 applies if the modified Hub is offered over a network. No NOTICE or attribution plan |
| Compliance mapping | No PCI DSS / SOC 2 / CBE control mapping, data-classification or retention policy for captured attacker data |

---

## 4. Configuration inconsistent with stated safety constraints

| # | Observation | Why it conflicts | Source | Status |
|---|---|---|---|---|
| S1 | Four of five official sensors run `user: "0:0"` with `network_mode: host`. The validator does not restrict `user` or `network_mode` | Docs: "unprivileged", "least privilege", templates use 65532 | `Sensors/official/*/*.json`, `Hub/internal/compose/security/validate.go` | **Open**: raw sockets and low ports need root + host netns; `network_mode` now limited to host/bridge/none |
| S2 | `NET_ADMIN` is allow-listed. Combined with host netns, a manifest can alter host routes and firewall | "strict capability allowlists to prevent container privilege escalation" | `validate.go:11-16`, `builder.go:64-79,204-218` | **Fixed**: `NET_ADMIN` removed |
| S3 | Init containers get no forced `read_only`, `cap_drop`, or `no-new-privileges`; run as UID 0 with Docker default caps + DAC_OVERRIDE; parent dirs of `TS_DECOY_FILES` are bind-mounted **read-write**; network defaults to bridge with egress | THREATMODEL calls this "PARTIAL" but the extent is not documented | `builder.go:48-160`, `file-canary.json` | **Fixed**: init forced `read_only`, `cap_drop: ALL` (+ allowlisted caps), `no-new-privileges`, `network_mode: none`. It still runs UID 0 with a rw bind to the lure parent dirs, which file creation requires |
| S4 | Mount denylist misses `/run/docker.sock` (target of the usual `/var/run` symlink), `/var/lib/docker`, `/run/containerd`, `/dev`, `/home`. `TS_DECOY_FILES=/run/docker.sock` would bind the Docker socket (read-only bind, but socket connect still works) into the File Canary (code-read, untested) | Docker socket is meant to be forbidden | `validate.go:18-24`, `builder.go:248-271` | **Fixed**: test cases for `/run/docker.sock`, containerd and `/var/lib/docker` |
| S5 | Hub and nodes default to plain HTTP. README Quick Start sets `TS_ENV=development` (no Secure cookie). The node key is passed in the curl command line and stored plaintext in DB, compose env and `/etc/truesignal/config.json` | "Always serve over HTTPS" | `README.md:112`, `Hub/internal/store/nodes.go:24`, `wizard/internal/app/config.go:8` | **Partial**: keys sha256-hashed in DB, rotation added, key passed via `TS_NODE_API_KEY` (not argv). Plain HTTP stays unless a proxy is added; the node copy is necessarily plaintext |
| S6 | `truesignal discover` prompts for the **Hub master password on the decoy host** (or reads `TS_DASHBOARD_PASSWORD` from env) | Decoy hosts are assumed compromisable (Wizard is "untrusted") | `wizard/internal/app/session.go:56-90` | **Open**: owner decision |
| S7 | Node bootstrap is `curl … \| bash` of `install.sh` from raw.githubusercontent (this repo), installing to `/usr/local/bin` as root. Checksums come from the same origin as the binary; no signatures | Supply-chain controls | `Hub/ui/src/components/fleetmanagement/FleetDeployModal.vue:102`, `install.sh` | **Partial**: `install.sh --sha256` pin, POSIX-portable, tag validation; still no signatures |
| S8 | Default `registry_url` and all `image_repository` values point to this repo. Without signing, repo/CI write access equals code execution on every node | Hub as sole trust anchor is undermined by unsigned inputs | `sqlite.go:73`, manifests | **Open**: needs signing |
| S9 | Hub egress: GitHub API (24h), raw.githubusercontent.com (registry), webhook SaaS. Init containers and sensors on host netns have unrestricted egress. No egress policy exists | No egress constraint is documented. Flagged because decoys in a CDE normally have none | `updater.go:18`, `catalog/service.go:65-90` | **Partial**: init containers have no network. Sensors on host netns and Hub egress are unrestricted; enforce at the firewall (Palo Alto) **[NOT IN PROJECT]** |
| S10 | Web decoy stores and forwards cleartext passwords. Default retention is forever. JSON export includes them | No "no real data on decoys" rule exists; PCI DSS 3/10 data handling | `WebRouterDecoy/main.go:349-359`, `sqlite.go:69-70`, `api/events.go` `ExportEvents` | **Fixed**: `TS_CAPTURE_PASSWORDS=hash` default (`plain`/`none` available) |
| S11 | Whitelist match drops events before storage and SIEM; changes are not audited | Hub "single source of truth" / high-fidelity claims | `event/service.go:63-72` | **Fixed**: whitelisted events stored archived and sent to SIEM with `whitelisted=true`; config changes audited (route, status, IP; no body diff) |
| S12 | Removing a sensor or node CASCADE-deletes all its events and uptime history | Evidence retention | `migrations.go:49,66,76` | **Fixed**: events FK dropped (migration v3); E2E verified |
| S13 | `DualAuthMiddleware` accepts the node key in `?key=` query string (lands in proxy/access logs) | Credential hygiene | `Hub/internal/api/middleware.go:143-144` | **Fixed**: removed |
| S14 | Severity, source, target and sensorId are sensor-supplied and unvalidated. Any holder of one node's key can forge events for any sensor registered on that node | "All inputs are untrusted" | `api/events.go`, `event/service.go` | **Partial**: `sensorId` must be registered on the calling node; fields clamped, severity normalised. One node key can still forge events for that node's own sensors (per-sensor keys not implemented) |
| S15 | WebSocket `CheckOrigin` returns true (relies on SameSite=Strict) | Defense in depth | `services/websocket/service.go:13-17` | **Fixed**: same-origin check outside development |
| S16 | `POST /api/v2/setup` is unauthenticated until first completion; first network caller sets the admin password | Exposure window at install | `api/router.go`, `api/config.go:28-54` | **Fixed**: one-time setup token required |
| S17 | Hub image in `Hub/docker-compose.yml` is `:latest` with a `permission-fixer` running `alpine:latest` as root | Version pinning | `Hub/docker-compose.yml` | **Fixed**: fixer pinned by digest and sandboxed; Hub tag via `TS_HUB_VERSION`; `:latest` remains the default |

---

## 5. Open questions for the owner

1. What is TrueSignal for, concretely? Kashier internal deception in the CDE / corporate network, a product, or a lab? This decides whether §4 items are blockers.
2. Repo stays public for now (2026-10-24). Revisit before production: public images and installer vs. private + tokens vs. an internal mirror (e.g. Harbor).
3. Which SIEM is the system of record for these alerts: Elastic, LogScale, or both? Via which collector (Logstash/Elastic Agent/LogScale Collector/Vector)? Who owns triage?
4. Where will nodes sit (VDC segments, CDE vs non-CDE), and what egress is allowed from decoy hosts?
5. Web Router Decoy now hashes captured passwords by default (`TS_CAPTURE_PASSWORDS=hash`). Is `plain` ever needed (for example, for credential-stuffing intel), and under what data-handling rule?
6. Are honeytokens (AD, cloud, DB credentials, documents) in scope? None exist today.
