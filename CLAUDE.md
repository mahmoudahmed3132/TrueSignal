# TrueSignal: project memory for Claude sessions

Full reference: `docs/PROJECT-KNOWLEDGE.md`. Open issues and contradictions: `docs/KNOWLEDGE-GAPS.md`.
This file was built from a full read of the repo on 2026-10-18 and updated after the 2026-10-19 security/correctness pass (`CHANGELOG.md` top entry). Where docs and code disagree, **trust the code**.

## 1. What it is and current state

- TrueSignal is a fork of **HoneyWire v2.1.0** (AGPLv3, Andrea Termine), a Docker-based deception platform. It was fully rebranded on 2026-10-19: names, UI/logo, Go modules, paths, `TS_`/`ts-` protocol prefixes, distribution endpoints. Attribution lives in `NOTICE` and the README "Credits & License". The same day a security/correctness pass diverged it from upstream v2.1.0 (key hashing, setup token, digest pinning, liveness alerts, evidence retention; see CHANGELOG).
- It has a Go Hub (API + SQLite + Vue UI), 6 containerized decoy "sensors", Go/Python SDKs, and a root CLI "Wizard" that deploys sensors on each node.
- Detection logic lives inside the sensors. The Hub routes alerts to UI/WebSocket, webhooks (ntfy/gotify/discord/slack) and syslog (TCP/UDP).
- **No SIEM rules, no honeytokens, no network/subnet layout and no node inventory** are in the repo. Kashier-specific config is [NOT IN PROJECT].
- Distribution points at the owner's GitHub (`mahmoudahmed3132/TrueSignal`, `ghcr.io/mahmoudahmed3132/truesignal-*`). Nothing is published there yet. The repo is **public** (owner decision 2026-10-24, until further note), so anonymous pulls work once artifacts are published. See §6.
- Project purpose was left as the literal placeholder `{{WHAT IT IS FOR}}` in the onboarding request. Ask the owner.

## 2. Component map

| Component | Code | Runs where | Emits | Goes to |
|---|---|---|---|---|
| Hub | `Hub/` (Go, chi router, modernc SQLite, embedded Vue UI) | Docker, distroless nonroot, port 8080 (`Hub/docker-compose.yml`) | stores events; RFC5424-style syslog; webhooks; WS | SQLite `/data/truesignal.db`, SIEM `siem_address`, webhook URL, browser |
| Wizard (`truesignal` CLI) | `wizard/` | each node, **as root**, run on demand (not a daemon) | none | pulls compose from Hub, runs `docker compose -p truesignal` |
| TCP Tarpit | `Sensors/official/TcpTarpit/` | node, host netns, UID 0, +NET_BIND_SERVICE | `tcp_connection` (on connect), `tcp_session_payload` (on close, only if data was sent) | Hub `POST /api/v2/event` |
| ICMP Canary | `Sensors/official/IcmpCanary/` | node, host netns, UID 0, +NET_RAW | `icmp_scan_received` (throttled per source, `TS_ICMP_COOLDOWN` 60s; default severity `low`) | Hub |
| Network Scan Detector | `Sensors/official/NetworkScanDetector/` | node, host netns, UID 0, +NET_RAW, AF_PACKET (inbound frames only) | `network_scan_detected` | Hub |
| File Canary (FIM) | `Sensors/official/FileCanary/` | node; hardened init container creates lure files with content, main container uses inotify | `decoy_file_tampered`, `decoy_file_accessed` (`TS_ALERT_ON_OPEN` default true; dedupe `TS_ALERT_COOLDOWN`) | Hub |
| Web Router Decoy | `Sensors/official/WebRouterDecoy/` | node, host netns, UID 0, HTTP on `TS_BIND_PORT` | `web_login_attempt` (password hashed by default, `TS_CAPTURE_PASSWORDS=hash\|plain\|none`), `web_page_view`, `web_path_probe` | Hub |
| Identity Decoy | `Sensors/official/IdentityDecoy/` | node, host netns, UID 0, +NET_BIND_SERVICE, ports via `TS_SERVICES` (default `ldap:389,ldaps:636,rdp:3389`) | `ldap_login`/`ldaps_login`/`rdp_login` (critical), `*_query` (medium), `*_connection` (low); RDP captures `mstshash` and NLA/NTLM identity; LDAP/LDAPS capture NTLM binds (Sicily + SASL GSS-SPNEGO, `ldapntlm.go`); both under `TS_CAPTURE_NTLM=identity\|hash\|off`; passwords keyed-HMAC (`TS_CAPTURE_PASSWORDS`); persona via `TS_PERSONA_HOSTNAME`/`TS_PERSONA_DOMAIN` | Hub |
| Liveness (Hub-generated) | `Hub/internal/services/{sensor,statemonitor}` | Hub | `sensor_stopped` (low), `sensor_heartbeat_lost` (high), `sensor_recovered` (info); source `truesignal-hub` | same pipeline as events |
| Go SDK | `SDKs/go-truesignal/sdk.go` | linked into every sensor | event queue (1000, 7 retries); heartbeat every 30s | Hub |
| Python SDK | `SDKs/python-truesignal/` | community/template sensors only | same contract | Hub |
| Registry | `registry-pages` branch (not in this checkout) + `scripts/build-registry-index.sh` | static host | `index.json`, `<sensor>-v<ver>.json` | Hub catalog |

Honeytokens/lures: only File Canary lure files (content by filename, `Sensors/official/FileCanary/lure.go`; paths in `TS_DECOY_FILES`), plus the Web Router login page and Tarpit banners (`TS_TARPIT_BANNERS` per port). There are no credential/cloud/document honeytokens.

Alert destinations (`Hub/internal/services/event/service.go` `ProcessEvent`):
- The Hub resets server-owned fields, clamps strings (256), forces `details` to a JSON object (≤64KB) and normalises severity (unknown → `medium`).
- A `sensorId` not registered on the calling node is rejected with 404.
- Whitelisted `source` (exact match): stored **archived**, sent to SIEM with `whitelisted=true`; no webhook, no WebSocket.
- Otherwise: SQLite, then webhook if armed, severity is in `webhook_events` (default excludes `info`), and the sensor is not silenced; SIEM when `siem_address` is set; WebSocket `NEW_EVENT`.
- Liveness events use the same path, so they reach SIEM and webhooks.

## 3. Deploy, change, roll back

**Hub** (`Docs/operations.md` §7, `Hub/docker-compose.yml`)
- Deploy: `docker compose up -d`, then complete setup in the UI with the **one-time setup token printed in the Hub log** (or `TS_SETUP_TOKEN`), a ≥12-char password and the Hub endpoint. Or set `TS_DASHBOARD_PASSWORD` to lock setup.
- Env vars (`Hub/internal/services/config/service.go`): `TS_PORT`, `TS_DB_PATH`, `TS_ENV` (only `development` drops the cookie Secure flag and the WS origin check), `TS_TRUST_PROXY`, `TS_DASHBOARD_PASSWORD`, `TS_SETUP_TOKEN`, `TS_SESSION_TTL` (12h), `TS_SESSION_IDLE_TIMEOUT` (15m), `TS_ALLOW_UNPINNED_IMAGES` (dev only), `TS_SIEM_CA_FILE`, `TS_SYSLOG_PEN` (32473).
- Update: `docker compose pull && docker compose up -d`. Schema migrations run on boot and take a `*.pre-vN-*.bak` VACUUM snapshot first (`Hub/internal/store/migrations.go:304-306`).
- Roll back: [NOT IN PROJECT]. No documented procedure. Restore the pre-migration `.bak` and pin the old image tag (inference).
- TLS: the Hub serves plain HTTP. A reverse proxy is required by the docs, but no proxy config is in the repo.

**Node / sensors** (`Docs/operations.md` §1-5)
- Link: `curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | TS_NODE_API_KEY=<key> bash -s -- --link <hub>` (UI `FleetDeployModal.vue`; installer = `install.sh`, optional `--sha256 <hash>` pin). `--api-key` still works but exposes the key in `ps`.
- Node key: shown once at creation; stored hashed. Lost or leaked → **Rotate key** in the UI (`POST /api/v2/nodes/{id}/rotate-key`), then relink the node.
- Change: edit sensors and their env in the Hub UI. That sets the node's desired state. Then run `truesignal apply` on the node, which fetches the compose, deep-diffs it, then pulls and runs `up -d --remove-orphans` (`wizard/internal/commands/apply.go`, `wizard/internal/deploy/apply.go`).
- Auto-suggest: `truesignal discover` scans `/proc`, matches manifest heuristics, renders `{{ }}` templates, registers sensors (prompts for the **Hub dashboard password on the node**) and applies.
- Test: `truesignal firedrill` sends SIGUSR1 to each sensor, which emits its test payload with `source="Wizard Firedrill"`.
- Local rollback: automatic. If `compose up` fails, or any service is exited/restarting 3s after up, the previous `truesignal-compose.yml` is restored (`wizard/internal/deploy/apply.go:16-50,112-134`).
- Version rollback: maintainers only. Run the `rollback-sensor-registry` workflow, which marks the latest manifest `deprecated`. The UI then shows "Update Available" for the older version; click Update, then `truesignal apply`.
- Teardown: `truesignal uninstall` removes containers, `/opt/truesignal/sensors`, `/etc/truesignal/config.json` and the binary. **It leaves lure files on disk** and prints their paths. Then delete the node in the UI (its events are kept).

**Sensor release** (`Docs/development/maintainer-workflow.md` §4, `.github|.gitea/workflows/publish-sensor-registry.yml`)
- Edit `Sensors/official/<Dir>/<name>.json`, then push tag `sensor/<name>/vX.Y.Z` (or `make tag-sensors VERSION=vX.Y.Z`). CI builds the image, injects `version`, tag and digest, and writes to `registry-pages`.
- Tags are immutable. Never re-push a tag; bump the version instead.
- Hub release: tag `hub/vX.Y.Z` (`publish-hub.yml`). Wizard release: tag `wizard/vX.Y.Z` (`publish-wizard.yml`, sha256 checksums).

## 4. Conventions

- IDs: sensor `ts-sensor-<kebab>`; container name = sensor ID (`ts-` prefixed if missing); node `node-<8hex>`; node key `ts_key_<64hex>` (DB stores `sha256:<hex>`); config revision `rev_<8hex>` (sha256 of sorted sensor ID+version+env, `Hub/internal/services/node/service.go:265-286`).
- Images: `ghcr.io/<owner>/truesignal-<lowercasefoldername>`. Source manifests use `image_tag: "dev"` and an empty digest; CI fills both.
- Git tags: `hub/v*`, `wizard/v*`, `sensor/<name>/v*` (`Docs/architecture/README.md` §Tagging).
- Compatibility: a sensor or wizard **major** version must equal the Hub major (`HubVersion = "2.1.0"`, `Hub/internal/models/models.go:6`). A wizard mismatch returns HTTP 426.
- Paths: node `/opt/truesignal/sensors/truesignal-compose.yml` (0600), `/etc/truesignal/config.json` (0600); Hub `/data/truesignal.db`.
- Env: all sensor config is `TS_*`. Reserved (user cannot override): `TS_HUB_ENDPOINT`, `TS_HUB_KEY`, `TS_SENSOR_ID`, `TS_CONFIG_REV`, `TS_TEST_MODE` (`Hub/internal/compose/env.go`).
- Severity enum: `info|low|medium|high|critical`. The sensor sets it from `TS_SEVERITY`; the Hub maps anything else to `medium` (`models.NormalizeSeverity`).
- Code style (`Docs/development/contributionRules.md`): snake_case on disk, camelCase in memory; no global state; handlers hold no business logic; pure Go 1.26, no CGO; Vue `<script setup>`; mutate Pinia state in place.
- Tags on nodes are free-form JSON strings. No taxonomy is in the repo.
- Rule naming: no SIEM rules exist. The de-facto detection keys are `eventTrigger` values (§2).

## 5. Hard rules and safety constraints (as stated in the docs)

1. The Hub is the only policy authority. Wizard, manifests and sensor telemetry are untrusted (`THREATMODEL.md` §2, §5).
2. Main and init containers always get `read_only: true`, `cap_drop: [ALL]` and `no-new-privileges`; init containers also `network_mode: none`. Added caps are limited to `NET_RAW`, `NET_BIND_SERVICE`, `DAC_OVERRIDE`; `network_mode` to host/bridge/none (`Hub/internal/compose/builder.go`, `security/validate.go`).
3. Mounts must be absolute, not `/`, and outside the denylist in `security/validate.go` (`/run`, `/var/run`, `/proc`, `/sys`, `/dev`, `/boot`, `/etc`, `/root`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/{docker,containerd,kubelet}`).
4. No interpolation (`$`, `{{`) in image, network_mode, volume or init-command fields; `$` in env values is escaped to `$$`.
4a. Every image (main and init) must carry an `@sha256:` digest; a missing/invalid manifest fails the compose (422) rather than dropping the decoy.
4b. A manifest may declare `listen_ports_env` (env vars holding its listen ports). The Hub rejects a node whose sensors bind the same host port (422 `port_conflict`). Tarpit, Web Router Decoy and Identity Decoy declare it.
5. Distroless images only. Non-root preferred; UID 65532 is the template default.
6. No sensor-to-sensor communication. Telemetry flows one way to the Hub.
7. Wizard discovery must be passive: no active probing (`Docs/development/wizard.md` §2).
8. Run the Hub on a separate host from sensors. Always put HTTPS in front of the Hub (`README.md` Security Notes).
9. Never overwrite a released tag (`maintainer-workflow.md`). Never rebuild-and-drop a table that has FK CASCADE; use `ALTER TABLE` (`Hub/internal/store/migrations.go`). Since migration v3 `events` has no FK, so evidence survives sensor/node deletion; keep it that way.
10. New sensors must support `TS_TEST_MODE=true`: send a synthetic alert, then exit 0.

Not stated anywhere in the repo, so treat as [NOT IN PROJECT]: decoy egress restrictions, a "no real data on decoys" rule, network segmentation of decoys, a data classification of captured credentials.
Residual gaps (unsigned manifests/images, root + host netns sensors, single admin without MFA) are in KNOWLEDGE-GAPS §4.

## 6. Distribution endpoints (owner GitHub; repo is public; nothing published yet)

- `registry_url` default is `https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/registry-pages` (`Hub/internal/store/sqlite.go:73`). The branch doesn't exist until the first `sensor/*` tag is published.
- Sensor images are `ghcr.io/mahmoudahmed3132/truesignal-*` (all `Sensors/official/*/*.json`). The Hub image is `ghcr.io/mahmoudahmed3132/truesignal-hub:latest` (`Hub/docker-compose.yml`, `README.md`). None are pushed yet.
- Installer: `curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | bash` (UI). The wizard comes from this repo's Releases (`install.sh:92-108`).
- The Hub update check polls `api.github.com/repos/mahmoudahmed3132/TrueSignal/releases` every 24h (`Hub/internal/services/updater/updater.go:18`). It returns no wizard/hub releases until one is published; that only logs and retries.
- The Python template pip-installs the SDK from this repo `@main` (`Sensors/templates/python-sensor/requirements.txt`).
- Going private is deferred. Token-authenticated pulls (Hub `TS_GITHUB_TOKEN`, wizard `registry-login`, installer via API assets) were built in commit `4013e0d` and reverted on 2026-10-24 at the owner's request; revert the revert if the repo goes private.
- Brand rule: never reintroduce `HoneyWire`, `HW_` or `hw-` identifiers. Upstream's name appears only in `NOTICE`, the README credits and the CHANGELOG "Upstream history" section.

## 7. Where things live / what to read

| Need | Read |
|---|---|
| Event / heartbeat / manifest schema | `Docs/architecture/dataContracts.md`, then verify in `Hub/internal/models/models.go` |
| Alert routing | `Hub/internal/services/event/service.go`, `notify/service.go`, `siem/service.go` |
| Syslog wire format | `Hub/internal/services/siem/service.go:303-359` |
| Auth (UI cookie, node keys, rate limit) | `Hub/internal/api/middleware.go`, `Hub/internal/services/auth/service.go` |
| Compose compiler / sandbox | `Hub/internal/compose/{builder.go,env.go,security/validate.go}`, `Hub/internal/services/compose/service.go` |
| DB schema / retention | `Hub/internal/store/migrations.go`, `events.go`, `sqlite.go` (defaults) |
| Sensor detection logic | `Sensors/official/<Dir>/main.go` + `<name>.json` |
| Node lifecycle | `Docs/operations.md`, `wizard/internal/commands/*.go`, `wizard/internal/deploy/*.go` |
| Threat model | `THREATMODEL.md` (check claims against code) |
| CI/CD | `.github/workflows/*` (actions SHA-pinned; `test.yml` runs all Go tests), `.gitea/workflows/*`, `Makefile`, `scripts/` |
| Local testing | `scripts/mock_hub.py`, `Docs/development/setup.md`. Hub tests need `Hub/ui` built first (`npm ci && npm run build`, go:embed) |

## 8. Working rules for future sessions

- This repo is the platform only. Never invent hostnames, IPs, subnets, node lists or SIEM rule logic. Ask, or mark [NOT IN PROJECT].
- Secrets are never in git. At runtime they live in: the Hub DB (bcrypt admin hash, sha256 node-key hashes, webhook URLs incl. tokens), the node `/etc/truesignal/config.json` and `TS_HUB_KEY` in the node compose file (plaintext node key), the `TS_DASHBOARD_PASSWORD`/`TS_SETUP_TOKEN` env vars, and the GitHub secret `DELETE_PACKAGES_TOKEN`. Reference them by location only.
- Tests: Hub, wizard, Go SDK and all six sensors have Go tests; `.github/workflows/test.yml` runs `go vet` + `go test -race` per module. No UI unit tests, no Python SDK tests.
- Changing the event shape, the syslog format (RFC 5424, `Hub/internal/services/siem/service.go` `formatSyslog`/`formatAudit`) or `eventTrigger` names breaks downstream SIEM parsing. Treat them as a contract.
- The licence is AGPLv3 (inherited from HoneyWire). Keep `LICENSE`, `NOTICE` and the README credits intact. Modified network-served versions must offer their source.
