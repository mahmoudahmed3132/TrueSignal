# [Unreleased] - Security & correctness pass (2026-10-19)

### ⚠️ Breaking / operator action required
* **Schema v3 migration (automatic, with `.bak` snapshot):** node API keys are re-stored as `sha256:<hex>`; existing keys keep working, but the Hub can no longer display them. Use **Rotate key** on the node page to issue a new one (shown once).
* **First-run setup needs a token.** The Hub prints a one-time setup token in its log (override with `TS_SETUP_TOKEN`); `POST /api/v2/setup` now takes `setupToken` instead of the ignored `hubKey`. Passwords must be at least 12 characters.
* **Image digests are mandatory.** The compose compiler refuses manifests whose main or init images lack an `@sha256:` digest (`TS_ALLOW_UNPINNED_IMAGES=true` is a dev-only override). A missing or unfetchable manifest now fails the compose with HTTP 422 instead of silently dropping that decoy.
* **`?key=` node authentication removed.** Use the `Authorization: Bearer` header.
* **Sessions:** 12h absolute lifetime plus 15-minute idle timeout (`TS_SESSION_TTL`, `TS_SESSION_IDLE_TIMEOUT`).
* **`NET_ADMIN` is no longer an allowed capability**; `network_mode` is limited to `host`, `bridge` or `none`.
* **Default container user is `65532:65532`** (distroless `nonroot`) when a manifest sets none; it was `1000:1000`, which is usually a real login user on the host.
* **SIEM line format** is now RFC 5424-valid: `<PRI>1 TS truesignal truesignalSensor - EVENT [truesignal@<PEN> …] {json}`. SD values are escaped. PEN via `TS_SYSLOG_PEN` (default 32473). Update parsers.

### Security
* Node key validation cache is invalidated on node deletion, key rotation and factory reset (deleted nodes previously authenticated until a Hub restart).
* Events from sensors not registered on the calling node are rejected (404); heartbeats too.
* Event fields are clamped (256 chars), `details` is always a JSON object (≤64KB), unknown severities become `medium`.
* Mount denylist expanded (`/run`, `/var/run`, `/dev`, `/boot`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`, …); relative paths and `/` are rejected (a relative `../../../etc` previously passed).
* Init containers are forced `read_only`, `cap_drop: [ALL]`, `no-new-privileges` and `network_mode: none`.
* `$` in user env values is escaped so Docker Compose can't interpolate host variables.
* Manifests are size-limited and strictly decoded, with ID/version validation and identity checks.
* WebSocket upgrades require a same-origin `Origin` (outside development).
* Request body limits (1MB UI, 256KB agent routes), `ReadHeaderTimeout`, `IdleTimeout` and `MaxHeaderBytes` on the Hub and the web decoy.
* Audit records (method, route, status, client IP) for login, logout, setup and every state-changing dashboard call are logged and sent to the SIEM (`MSGID AUDIT`). Request bodies are not recorded.
* SIEM over TLS (`siemProtocol: tls`, optional `TS_SIEM_CA_FILE`).
* `X-Forwarded-For` is read from the right-most hop when `TS_TRUST_PROXY` is set.
* Web Router Decoy records a keyed HMAC-SHA256 of captured passwords by default (`TS_CAPTURE_PASSWORDS=hash|plain|none`; key `TS_CAPTURE_HASH_KEY` or derived from the node key) and HTML-escapes reflected values.
* Installer: POSIX `printf` (the `#!/bin/sh` script printed `-e` under dash), optional `--sha256` pin, node key passed via `TS_NODE_API_KEY` instead of argv, tag validation, `install -m 0755 -o 0 -g 0`.
* CI actions pinned to commit SHAs; GitHub Trivy now fails the build on HIGH/CRITICAL.

### Evidence retention
* Whitelisted sources are no longer dropped: events are stored archived and forwarded to the SIEM with `whitelisted=true`; only notifications and the live feed are suppressed.
* Events no longer cascade-delete when a sensor or node is removed (FK dropped in migration v3).

### Detection
* New liveness events, sent to the SIEM and webhooks: `sensor_stopped` (low, graceful), `sensor_heartbeat_lost` (high, missed heartbeats or stopped >5 min without recovery), `sensor_recovered` (info).
* TCP Tarpit alerts on connect (`tcp_connection`) instead of on disconnect (up to 1h later); captured data is a separate `tcp_session_payload`. Per-port banners via `TS_TARPIT_BANNERS` (SSH banner no longer served on non-SSH ports).
* File Canary: lures get realistic content on creation, read alerts on by default (`TS_ALERT_ON_OPEN=true`), per-file dedupe (`TS_ALERT_COOLDOWN`).
* Web Router Decoy: `web_page_view` and `web_path_probe` events (rate-limited per source).
* ICMP Canary: per-source throttle (`TS_ICMP_COOLDOWN`, default 60s) with a `suppressed_since_last` count; default severity raised from `info` to `low` so it reaches webhooks.
* Network Scan Detector ignores outbound frames (the host's own connections were counted as scans).

### Bug fixes
* Fleet/node views never refreshed on sensor state changes (WebSocket payload used `id` instead of `nodeId`).
* Numeric and boolean env values set in the UI were dropped from the compose file.
* Catalog advertised phantom `2.2.0` versions from a hard-coded mock index at boot.
* Python sensor template crashed on start (`set_test_payload` keyword).
* Mock Hub passed the contract test on a heartbeat; it now requires a valid event.
* `is_armed` fallback mismatch; SQLite temp directory hard-coded to `/data`.
* `PATCH /api/v2/config` silently ignored invalid `webhookType`/`siemProtocol`; it now returns 400, and validates `webhookEvents` severities. Removed a dead 426 branch from the event handler.
* `Hub/docker-compose.yml`: a non-default `TS_PORT` broke the port mapping (container always listens on 8080); the image tag is now `${TS_HUB_VERSION:-latest}`; the `permission-fixer` is pinned (`alpine:3.22@sha256:…`) and runs with no network, read-only rootfs and only `CHOWN`/`DAC_OVERRIDE`/`FOWNER`.
* `truesignal uninstall` now lists the lure files it leaves on disk; `discover` skips lure paths it can't place.
* Wizard config/state directories created `0750`.

### Toolchain
* **Go 1.26** for every module, Dockerfile and CI job (was 1.25). Needed for `golang.org/x/net` v0.60.0 (CVE-2026-78669) in the wizard and ICMP canary; `golang.org/x/mod` v0.40.0 in the Hub (CVE-2026-56864/56865).

### UI: Ledger brand
* New Ledger identity for the Hub UI, light and dark: warm paper/ink neutrals with one deep-teal accent (`#0B7A75`, `#2BB3A9` in dark), kept out of the severity hues so chrome never reads as an alert. All text/background pairs meet WCAG AA.
* New mark (two rings and a tripped point) in `components/ui/branding/BrandMark.vue`, used by the header, login/setup and the favicon.
* Instrument Sans + IBM Plex Mono, bundled via `@fontsource` (no CDN request at runtime; works on offline SOC networks). Previously `Inter`/`JetBrains Mono` were named but never loaded.
* Severity badges and row bleeds now follow theme tokens instead of hard-coded hexes.
* Product name is "TrueSignal" everywhere (the "Sentinel" suffix is dropped).
* Decoys are deliberately left unbranded: a TrueSignal mark on a honeypot would tell the attacker it is one.

### Tests & CI
* New tests for the event, statemonitor, websocket, SIEM, auth, compose and migration paths, every official sensor, and the wizard.
* `.github/workflows/test.yml` runs `go vet` and `go test -race` for every Go module (UI built first); Gitea Hub dev build now runs tests; Gitea sensor build uses Go 1.25.

---

# [Unreleased] - TrueSignal rebrand (2026-10-19)

### ⚠️ Breaking Changes
Complete rename from HoneyWire to TrueSignal. Nothing from a HoneyWire deployment is wire-compatible with this build:
* **Environment variables:** `HW_*` → `TS_*` (e.g. `TS_HUB_ENDPOINT`, `TS_HUB_KEY`, `TS_SENSOR_ID`, `TS_DB_PATH`, `TS_DASHBOARD_PASSWORD`).
* **Identifiers:** sensor IDs `hw-sensor-*` → `ts-sensor-*`; node keys `hw_key_*` → `ts_key_*`; session cookie `hw_auth` → `ts_auth`; container prefix `hw-` → `ts-`.
* **Host layout:** CLI `honeywire` → `truesignal`; `/opt/honeywire` → `/opt/truesignal`; `/etc/honeywire` → `/etc/truesignal`; compose project/file `honeywire`/`honeywire-compose.yml` → `truesignal`/`truesignal-compose.yml`; Hub DB `honeywire.db` → `truesignal.db`.
* **SIEM:** syslog HOSTNAME/APP-NAME/SD-ID `honeywire`/`honeywireSensor`/`honeywire` → `truesignal`/`truesignalSensor`/`truesignal`. Update any parsers.
* **Distribution:** images `ghcr.io/mahmoudahmed3132/truesignal-*`; sensor registry `raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/registry-pages`; wizard releases and update checks from `mahmoudahmed3132/TrueSignal`; installer is `install.sh` from this repo.
* **Go modules:** `github.com/honeywire/*` → `github.com/truesignal/*`; SDK dirs `SDKs/go-truesignal`, `SDKs/python-truesignal` (Python package `truesignal`, class `TrueSignalSensor`).

### Other
* New logo and favicon.
* Added `NOTICE` with upstream attribution and modification record (AGPLv3 §5).

---

# Upstream history (HoneyWire, pre-fork)

# [v2.0.1] - Hotfix & Export Features (2026-06-26)

### Bug Fixes
* **Hub Auto-Updates:** Fixed a race condition where the Hub would instantly autoupdate sensors before a manual sync was triggered. Deployed sensor versions are now correctly pinned until the user runs `honeywire apply`.
* **TCP Tarpit Port Collision:** Fixed an issue where the TCP Tarpit sensor template didn't use `{{ availablePort }}`, which caused conflicts with the Hub's web server if deployed on the same Node via the Wizard.
* **UI Deletion Desync:** Deleting a Node now dynamically clears associated UI events via WebSocket without requiring a hard page refresh. Clarified deletion confirm prompts.
* **Modal UX:** The Fleet Deploy Modal now cleanly auto-closes the moment a newly linked node connects to the Hub.

### Features
* **Event Exporting:** Added a native "Export JSON" button to the Event Table to download forensic event data contextually (respects active vs archived views).

**To update the Hub run: `docker compose up -d --pull always hub`**


# [v2.0.0] - "The Security and UX Update" (2026-06-22)
## This is a massive, breaking architectural update that transitions HoneyWire from a passive event listener into a comprehensive, distributed fleet management platform.

### ⚠️ Breaking Changes
* **Global API Path Bump:** All internal and external routing endpoints have been migrated to `/api/v2/`.
* **Deprecation of Standalone Sensors:** Sensors are no longer deployed as floating, unmanaged containers. All sensors must now be attached to a Node and managed via the new Hub Fleet Architecture. Existing `v1.1.1` deployments will need to be re-provisioned using the new Node structure.
* **Registry Migration:** Official sensor images are now indexed in the `registry-pages` branch to allow for better sensor lifecycle management and strict manifest validation.

---

### Major Features
* **Introduced The Wizard CLI:** A brand new, cross-platform CLI tool built to automate the operator lifecycle. The Wizard handles environment discovery, automated node linking, sensor deployment, and synthetic firedrill testing. *The Wizard is not a background daemon agent; it is a point-in-time CLI tool designed to automate operator tasks and exit.*
* **Nodes & Fleet Management:** The Hub has been completely overhauled to support a Node-based architecture. You can now track, manage, and monitor the health of multiple host machines (Nodes) from a single centralized Fleet dashboard.
* **Sensor Catalog & Deployment Engine:** You no longer need to manually write `docker-compose` files for sensors. The Hub now features a built-in Fleet Management view and Sensor Catalog pulling from a live Registry, allowing users to select and configure sensors directly from the Hub. Operators can generate copy-pasteable deployment commands leveraging the Wizard.
* **State Synchronization:** Added a real-time sync engine between the Hub and deployed Nodes. The Hub now tracks `Pending` vs `Deployed` states and automatically resolves them when a Node checks in.
* **60-Second Cyber Canary Deployments:** Thanks to the improved UX of the new Wizard and Fleet architecture, you can now seamlessly turn any standard Linux box into a fully provisioned Cyber Canary in under 60 seconds.
* **Event Source Whitelisting:** Added native support for event source whitelisting via the Hub settings to effortlessly filter out noise from known internal security scanners.

---

### Security Enhancements
* **Threat Model Documentation:** We have formally published our [Threat Model](./THREATMODEL.md) detailing trust boundaries, attack surfaces, and mitigations.
* **Supply Chain & Manifest Hardening:** To mitigate supply chain attacks, the Hub now enforces strict typed schema decoding, blocks variable interpolation, and enforces cryptographic image digest pinning for immutable sensor pulls.
* **Rate Limiting & DoS Protection:** Implemented a strict token-bucket rate limiter (100 req/min) across all Node API endpoints to prevent telemetry flooding, alongside hardened UI login limits.
* **Runtime Sandboxing & Distroless Execution:** Enforced distroless base images (no shells or package managers) across all official Hub and Sensor containers. Added explicit validation for dangerous mounts and strict capability allowlists to prevent container privilege escalation.

---

*Changelog: v1.1.1 → v2.0.0 | 2026-06-22*
