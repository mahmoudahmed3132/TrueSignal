# TrueSignal: project memory for Claude sessions

Full reference: `docs/PROJECT-KNOWLEDGE.md`. Open issues and contradictions: `docs/KNOWLEDGE-GAPS.md`.
This file was built from a full read of the repo on 2026-10-18. Where docs and code disagree, **trust the code**.
Many docs reference files that don't exist (list in KNOWLEDGE-GAPS §1).

## 1. What it is and current state

- TrueSignal is a fork of **HoneyWire v2.1.0** (AGPLv3, Andrea Termine), a Docker-based deception platform. It was fully rebranded on 2026-10-19: names, UI/logo, Go modules, paths, `TS_`/`ts-` protocol prefixes, distribution endpoints. Functionally it is still upstream v2.1.0. Attribution lives in `NOTICE` and the README "Credits & License".
- It has a Go Hub (API + SQLite + Vue UI), 5 containerized decoy "sensors", Go/Python SDKs, and a root CLI "Wizard" that deploys sensors on each node.
- Detection logic lives inside the sensors. The Hub routes alerts to UI/WebSocket, webhooks (ntfy/gotify/discord/slack) and syslog (TCP/UDP).
- **No SIEM rules, no honeytokens, no network/subnet layout and no node inventory** are in the repo. Kashier-specific config is [NOT IN PROJECT].
- Distribution points at the owner's GitHub (`mahmoudahmed3132/TrueSignal`, `ghcr.io/mahmoudahmed3132/truesignal-*`). Nothing is published there yet, and the repo is **private**, so anonymous node pulls fail. See §6.
- Project purpose was left as the literal placeholder `{{WHAT IT IS FOR}}` in the onboarding request. Ask the owner.

## 2. Component map

| Component | Code | Runs where | Emits | Goes to |
|---|---|---|---|---|
| Hub | `Hub/` (Go, chi router, modernc SQLite, embedded Vue UI) | Docker, distroless nonroot, port 8080 (`Hub/docker-compose.yml`) | stores events; RFC5424-style syslog; webhooks; WS | SQLite `/data/truesignal.db`, SIEM `siem_address`, webhook URL, browser |
| Wizard (`truesignal` CLI) | `wizard/` | each node, **as root**, run on demand (not a daemon) | none | pulls compose from Hub, runs `docker compose -p truesignal` |
| TCP Tarpit | `Sensors/official/TcpTarpit/` | node, host netns, UID 0, +NET_BIND_SERVICE | `tcp_connection` (sent on **connection close**) | Hub `POST /api/v2/event` |
| ICMP Canary | `Sensors/official/IcmpCanary/` | node, host netns, UID 0, +NET_RAW | `icmp_scan_received` (one per echo/timestamp req) | Hub |
| Network Scan Detector | `Sensors/official/NetworkScanDetector/` | node, host netns, UID 0, +NET_RAW, AF_PACKET | `network_scan_detected` | Hub |
| File Canary (FIM) | `Sensors/official/FileCanary/` | node; root init container creates lure files, main container uses inotify | `decoy_file_tampered`, `decoy_file_accessed` (access only if `TS_ALERT_ON_OPEN=true`) | Hub |
| Web Router Decoy | `Sensors/official/WebRouterDecoy/` | node, host netns, UID 0, HTTP on `TS_BIND_PORT` | `web_login_attempt` (POST /login only; **logs cleartext password**) | Hub |
| Go SDK | `SDKs/go-truesignal/sdk.go` | linked into every sensor | event queue (1000, 7 retries); heartbeat every 30s | Hub |
| Python SDK | `SDKs/python-truesignal/` | community/template sensors only | same contract | Hub |
| Registry | `registry-pages` branch (not in this checkout) + `scripts/build-registry-index.sh` | static host | `index.json`, `<sensor>-v<ver>.json` | Hub catalog |

Honeytokens/lures: only File Canary lure files (empty files, default paths in `file-canary.json` `TS_DECOY_FILES`), plus the Web Router login page and Tarpit banners. There are no credential/cloud/document honeytokens.

Alert destinations (`Hub/internal/services/event/service.go:59-107`):
- Whitelisted `source` (exact string match): the event is **dropped completely**. No DB row, no SIEM, no UI.
- Otherwise it is written to SQLite, then: webhook if armed, severity is in `webhook_events`, and the sensor is not silenced; SIEM always (when `siem_address` is set); WebSocket `NEW_EVENT`.
- Sensor down/offline is **UI-only**. Nothing goes to SIEM or webhooks (`services/statemonitor/statemonitor.go`).

## 3. Deploy, change, roll back

**Hub** (`Docs/operations.md` §7, `Hub/docker-compose.yml`)
- Deploy: `docker compose up -d`, then open the UI and complete setup (master password, Hub endpoint). Or set `TS_DASHBOARD_PASSWORD` to lock setup.
- Env vars: `TS_PORT`, `TS_DB_PATH`, `TS_ENV` (anything except `production` drops the cookie Secure flag), `TS_TRUST_PROXY`, `TS_DASHBOARD_PASSWORD` (`Hub/internal/services/config/service.go:32-44`).
- Update: `docker compose pull && docker compose up -d`. Schema migrations run on boot and take a `*.pre-vN-*.bak` VACUUM snapshot first (`Hub/internal/store/migrations.go:304-306`).
- Roll back: [NOT IN PROJECT]. No documented procedure. Restore the pre-migration `.bak` and pin the old image tag (inference).
- TLS: the Hub serves plain HTTP. A reverse proxy is required by the docs, but no proxy config is in the repo.

**Node / sensors** (`Docs/operations.md` §1-5)
- Link: `curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | bash -s -- --link <hub> --api-key <key>` (UI `FleetDeployModal.vue:102`; installer = `install.sh`).
- Change: edit sensors and their env in the Hub UI. That sets the node's desired state. Then run `truesignal apply` on the node, which fetches the compose, deep-diffs it, then pulls and runs `up -d --remove-orphans` (`wizard/internal/commands/apply.go`, `wizard/internal/deploy/apply.go`).
- Auto-suggest: `truesignal discover` scans `/proc`, matches manifest heuristics, renders `{{ }}` templates, registers sensors (prompts for the **Hub dashboard password on the node**) and applies.
- Test: `truesignal firedrill` sends SIGUSR1 to each sensor, which emits its test payload with `source="Wizard Firedrill"`.
- Local rollback: automatic. If `compose up` fails, or any service is exited/restarting 3s after up, the previous `truesignal-compose.yml` is restored (`wizard/internal/deploy/apply.go:16-50,112-134`).
- Version rollback: maintainers only. Run the `rollback-sensor-registry` workflow, which marks the latest manifest `deprecated`. The UI then shows "Update Available" for the older version; click Update, then `truesignal apply`.
- Teardown: `truesignal uninstall` removes containers, `/opt/truesignal/sensors`, `/etc/truesignal/config.json` and the binary. **It leaves lure files on disk.** Then delete the node in the UI.

**Sensor release** (`Docs/development/maintainer-workflow.md` §4, `.github|.gitea/workflows/publish-sensor-registry.yml`)
- Edit `Sensors/official/<Dir>/<name>.json`, then push tag `sensor/<name>/vX.Y.Z` (or `make tag-sensors VERSION=vX.Y.Z`). CI builds the image, injects `version`, tag and digest, and writes to `registry-pages`.
- Tags are immutable. Never re-push a tag; bump the version instead.
- Hub release: tag `hub/vX.Y.Z` (`publish-hub.yml`). Wizard release: tag `wizard/vX.Y.Z` (`publish-wizard.yml`, sha256 checksums).

## 4. Conventions

- IDs: sensor `ts-sensor-<kebab>`; container name = sensor ID (`ts-` prefixed if missing); node `node-<8hex>`; node key `ts_key_<64hex>`; config revision `rev_<8hex>` (sha256 of sorted sensor ID+version+env, `Hub/internal/services/node/service.go:265-286`).
- Images: `ghcr.io/<owner>/truesignal-<lowercasefoldername>`. Source manifests use `image_tag: "dev"` and an empty digest; CI fills both.
- Git tags: `hub/v*`, `wizard/v*`, `sensor/<name>/v*` (`Docs/architecture/README.md` §Tagging).
- Compatibility: a sensor or wizard **major** version must equal the Hub major (`HubVersion = "2.1.0"`, `Hub/internal/models/models.go:6`). A wizard mismatch returns HTTP 426.
- Paths: node `/opt/truesignal/sensors/truesignal-compose.yml` (0600), `/etc/truesignal/config.json` (0600); Hub `/data/truesignal.db`.
- Env: all sensor config is `TS_*`. Reserved (user cannot override): `TS_HUB_ENDPOINT`, `TS_HUB_KEY`, `TS_SENSOR_ID`, `TS_CONFIG_REV`, `TS_TEST_MODE` (`Hub/internal/compose/env.go`).
- Severity enum: `info|low|medium|high|critical`. The sensor sets it from `TS_SEVERITY` and the Hub does **not** validate it.
- Code style (`Docs/development/contributionRules.md`): snake_case on disk, camelCase in memory; no global state; handlers hold no business logic; pure Go 1.25, no CGO; Vue `<script setup>`; mutate Pinia state in place.
- Tags on nodes are free-form JSON strings. No taxonomy is in the repo.
- Rule naming: no SIEM rules exist. The de-facto detection keys are `eventTrigger` values (§2).

## 5. Hard rules and safety constraints (as stated in the docs)

1. The Hub is the only policy authority. Wizard, manifests and sensor telemetry are untrusted (`THREATMODEL.md` §2, §5).
2. Main sensor containers always get `read_only: true`, `cap_drop: [ALL]` and `no-new-privileges`. Added caps are limited to `NET_RAW`, `NET_BIND_SERVICE`, `NET_ADMIN`, `DAC_OVERRIDE` (`Hub/internal/compose/builder.go:175-218`, `security/validate.go:11-16`).
3. Forbidden mount prefixes: `/var/run/docker.sock`, `/proc`, `/sys`, `/etc`, `/root` (`security/validate.go:18-24`).
4. No interpolation (`$`, `{{`) in image, network_mode, volume or init-command fields.
5. Distroless images only. Non-root preferred; UID 65532 is the template default.
6. No sensor-to-sensor communication. Telemetry flows one way to the Hub.
7. Wizard discovery must be passive: no active probing (`Docs/development/wizard.md` §2).
8. Run the Hub on a separate host from sensors. Always put HTTPS in front of the Hub (`README.md` Security Notes).
9. Never overwrite a released tag (`maintainer-workflow.md`). Never rebuild-and-drop a table that has FK CASCADE; use `ALTER TABLE` (`Hub/internal/store/migrations.go:93-103`). Dropping `node_sensors` deletes events.
10. New sensors must support `TS_TEST_MODE=true`: send a synthetic alert, then exit 0.

Not stated anywhere in the repo, so treat as [NOT IN PROJECT]: decoy egress restrictions, a "no real data on decoys" rule, network segmentation of decoys, a data classification of captured credentials.
Several items above are partially violated in code. See KNOWLEDGE-GAPS §4 before relying on them.

## 6. Distribution endpoints (owner GitHub; repo is private; nothing published yet)

- `registry_url` default is `https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/registry-pages` (`Hub/internal/store/sqlite.go:73`). The branch doesn't exist until the first `sensor/*` tag is published.
- Sensor images are `ghcr.io/mahmoudahmed3132/truesignal-*` (all `Sensors/official/*/*.json`). The Hub image is `ghcr.io/mahmoudahmed3132/truesignal-hub:latest` (`Hub/docker-compose.yml`, `README.md`). None are pushed yet.
- Installer: `curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | bash` (UI). The wizard comes from this repo's Releases (`install.sh:92-108`).
- The Hub update check polls `api.github.com/repos/mahmoudahmed3132/TrueSignal/releases` every 24h (`Hub/internal/services/updater/updater.go:18`). It returns 404 while the repo is private; that only logs and retries.
- The Python template pip-installs the SDK from this repo `@main` (`Sensors/templates/python-sensor/requirements.txt`).
- Private repo means raw, releases and ghcr pulls need a token or public visibility. This is unresolved and the owner must decide.
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
| CI/CD | `.github/workflows/*`, `.gitea/workflows/*`, `Makefile`, `scripts/` |
| Local testing | `scripts/mock_hub.py`, `Docs/development/setup.md` |

## 8. Working rules for future sessions

- This repo is the platform only. Never invent hostnames, IPs, subnets, node lists or SIEM rule logic. Ask, or mark [NOT IN PROJECT].
- Secrets are never in git. At runtime they live in: the Hub DB (bcrypt admin hash, **plaintext node keys**, webhook URLs incl. tokens), the node `/etc/truesignal/config.json`, `TS_HUB_KEY` in the node compose file, the `TS_DASHBOARD_PASSWORD` env var, and the GitHub secret `DELETE_PACKAGES_TOKEN`. Reference them by location only.
- Hub Go tests exist (67 test funcs) but are **not run by any CI**. Sensors have no unit tests. Don't claim test coverage.
- Changing the event shape, the syslog format or `eventTrigger` names breaks downstream SIEM parsing. Treat them as a contract.
- The licence is AGPLv3 (inherited from HoneyWire). Keep `LICENSE`, `NOTICE` and the README credits intact. Modified network-served versions must offer their source.
