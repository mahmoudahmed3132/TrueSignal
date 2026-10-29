# [Unreleased] - Beacons and the Token Receiver (phase 3, part 1) (2026-10-29)

* **Beacons page** (sidebar): create callback tokens to plant where only an intruder would use them. There are three types:
  * a DNS name;
  * a web bug (remote 1x1 image);
  * a kubeconfig whose API server name is the token.

  Each beacon carries a name (where it is planted) and a memo. You can copy the value or download the file. Use counts, last use and every trigger are shown per beacon.
  * API: `GET/POST /api/v2/beacons`, `DELETE /api/v2/beacons/{id}`, `GET /api/v2/beacons/{id}/download`. Schema migration v5 adds the `beacons` table (no foreign keys).
* **New sensor: Token Receiver** (`ts-sensor-token-receiver` 2.0.0, `Sensors/official/TokenReceiver`). It is the internet-facing callback end, deployed on its own DMZ node, and the Hub stays internal. It has two parts:
  * **DNS:** authoritative-only DNS for one delegated zone over UDP and TCP. Out-of-zone queries are REFUSED. Replies are rate-limited per source. It records the EDNS Client Subnet when present.
  * **HTTP:** fixed-response HTTP (the same 1x1 GIF for every request). `X-Forwarded-For` is believed only from `TS_TRUSTED_PROXIES`.

  It raises one `beacon_triggered` (critical) per token and channel per `TS_ALERT_COOLDOWN`.
* **Tokens are HMAC-tagged:** 24 base32 characters, a 40-bit tag under `TS_BEACON_KEY`. Receivers drop names a scanner invents without asking the Hub.
  * `TS_BEACON_KEY` is a new reserved env var, derived from the Hub's `beacon_master_key` (which never leaves the Hub) and the same for all receivers.
  * Beacons and the key survive a factory reset unless `purgeHoneytokens`.
* **The Hub resolves the token** and attaches `details.beacon` (`id`, `name`, `type`, `domain`). A known beacon ignores the whitelist and the known-scanner list, because the reporting resolver may be an allow-listed one. An unknown token is stored at `medium` with `beacon_known: false`.
* **SIEM contract (additive):** new trigger `beacon_triggered` (ECS category `network`). It is not ATT&CK-mapped.
* Not built yet: Office documents, AWS keys, shell/batch beacons, MySQL dumps, cloned-site beacons, GeoIP enrichment (DB-IP Lite, decided) and the map.

# [2.3.0] - Hub 2.3.0: analyst features (2026-10-29)

Hub only. Wizard stays 2.2.0 and sensors are unchanged; only the major version must match, so existing nodes and sensors keep working. Tag: `hub/v2.3.0`.

**Upgrade.** No schema migration (the asset inventory and the Known Scanners list live in the config table). Roll back by pinning `TS_HUB_VERSION=v2.2.0`; 2.2.0 ignores the `assets` and `known_scanners` keys, so a later return to 2.3.0 finds them intact. 2.2.0 matches whitelist entries exactly, so CIDR entries added under 2.3.0 stop applying after a rollback and those sources alert again.

**SIEM contract (additive, tell the SOC first).** The full notice, with field lists, samples and rule actions, is `Docs/siem/soc-notice-2.3.0.md`. In short:
* RFC 5424 structured data appends `known_scanner`, `mitre_technique`, `mitre_tactic`, `source_asset`, `source_asset_criticality` after `whitelisted`. All are always present (empty when n/a). The JSON body gains `known_scanner`, `attack` and `source_asset` (`null` when n/a).
* ECS gains `threat.*`, `truesignal.known_scanner`, `truesignal.attack`, `truesignal.source_asset` and the `known_scanner` tag; known-scanner sources are `event.kind: event`.
* **Rule action:** any rule or dashboard that excludes `whitelisted=true` must also exclude `known_scanner=true`, or scanner noise reaches it.

**Also in this release:**
* `make tag-release` skips a Hub or Wizard tag that is already on origin, so a Hub-only release no longer fails on the existing wizard tag. A local-only tag pointing elsewhere than `HEAD` is an error rather than "released".
* `github.com/go-jose/go-jose/v4` 4.1.4 → 4.1.6 (CVE-2026-116587, DoS via crafted RSA JWK parameters; an indirect dependency of the Sigstore verifier).

## Evidence reports

* **Reports page** (sidebar): an evidence report for the last 7, 30 or 90 days or a custom range.
  * Executive summary with plain-language findings (known-asset sources, honeytoken use, ATT&CK techniques, archived events).
  * Daily activity, and breakdowns by severity and by decoy type.
  * Top sources with their assets, observed ATT&CK techniques and honeytoken uses.
  * Decoy coverage per node.
  * Control configuration: SIEM forwarding, notifications, armed state, admin MFA, retention, list sizes, Hub version.
  * A scope statement (supporting evidence for PCI DSS v4.0 Requirement 11.5.1 and CBE reviews; it does not replace IDS/IPS) and a sign-off block.
* **Output:** prints to PDF from the browser, switching to the light theme for printing, with print-safe layout and page breaks. A JSON download is the machine-readable copy.
* New endpoint `GET /api/v2/report?from=&to=`.
* Fix (Codex review of #25): "Assets involved" and its finding come from a new `assets` aggregate over **all** sources in the range (one row per inventory asset, with addresses and events). Previously they were derived from the 25-row top-sources table, counting one CIDR asset once per attacking address and missing assets beyond the cap.

## Attack Path

* **Attack Path page** (sidebar): one source's route through the decoys.
  * Source picker, ranked known assets first, then by decoys touched.
  * Summary: asset, events, decoys and duration.
  * Tactic progression: each technique that brought new tactics, so Valid Accounts is one step and not four stages.
  * The path: decoys in order of first contact, with triggers, ATT&CK techniques and highest severity.
  * A full timeline.
* Every expanded event in the dashboard links to it ("Investigate in Attack Path").
* New endpoint `GET /api/v2/path?source=`, covering active and archived events and capped at the most recent 2,000.

## Asset inventory

* **Assets page** (sidebar): an inventory of real hosts and ranges, with criticality, owner and tags.
  * Add, edit and remove entries inline; CSV import (header detected, duplicates and invalid rows skipped) and export.
  * Per-asset decoy activity: events and addresses.
  * API: `GET/PUT /api/v2/assets`. `PUT` replaces the list atomically after validation; the inventory is stored in the config table, so there is no schema change.
* **A decoy touched from an inventoried address names the asset.**
  * Events carry `sourceAsset` (`{name, criticality}`, most specific range wins), resolved against the current inventory.
  * Source profiles carry `asset`, and an inventoried address counts as internal even in public space.
  * Event table: a "Known asset" label filter and an asset badge on the source.
  * Expanded event details show the ATT&CK mapping and the source asset. Triage badges moved to a second line in the Source cell, so the table fits a 1440 px screen again.
* **SIEM contract change (additive):**
  * ECS `truesignal.source_asset`;
  * RFC 5424 `source_asset` and `source_asset_criticality` (always present, empty when none);
  * `"source_asset"` in the JSON body.

## MITRE ATT&CK mapping and Attack Navigator

* **Every mapped event carries a MITRE ATT&CK technique and its tactics** (`Hub/internal/attack`, table in `Docs/siem/attack-mapping.md`).
  * One primary technique per trigger, plus optional secondary ones.
  * Derived when events are read or forwarded, never stored, so past events are covered too.
  * Unmapped on purpose: `web_page_view`, Hub liveness, community triggers.
  * A test fails if the doc table and the code disagree.
* **SIEM contract change (additive).**
  * ECS: `threat.framework`, `threat.technique.*` (sub-techniques under `threat.technique.subtechnique.*`), `threat.tactic.*`, `truesignal.attack`.
  * RFC 5424: structured data gains `mitre_technique` and `mitre_tactic`. Both are always present and empty when the trigger is unmapped, so parameter positions are stable. The JSON body gains `attack`.
* **Attack Navigator page** (sidebar).
  * An ATT&CK matrix of the 16 techniques TrueSignal decoys can evidence, shaded by event count.
  * A details panel per technique: events, sources, last seen, triggers, link to attack.mitre.org.
  * A 24H / 7D / 30D / All filter and an ATT&CK Navigator layer export (format 4.5).
  * New endpoints `GET /api/v2/attack` and `/api/v2/attack/layer`.
* **Dashboard and event table.** An "ATT&CK techniques" tile; a technique badge on every mapped event; an ATT&CK tactic filter; search also matches technique IDs and names.

## Dashboard: decoy coverage

* **Decoy coverage row on the dashboard**, with a 24H / 7D / 30D / All filter. It follows the node/sensor selection and the archive view.
  * Tiles: decoys touched out of deployed, unique attacker sources, critical interactions, honeytokens used.
  * Bar charts: interactions per decoy type, and unique attacker sources per decoy type.
  * Donut: deployed decoys touched vs untouched.
* **Whitelist takes CIDR ranges, and a new Known Scanners list.** Both lists accept IPs, CIDR ranges (IPv4/IPv6) and exact source names, one per line, and can import IPs from a text or CSV file in Settings. A source with a port (`10.0.0.5:4431`) matches its address. Known-scanner events are handled like whitelisted ones (stored archived, sent to the SIEM, never notified) but flagged separately.
  * **SIEM contract change (additive):** RFC 5424 structured data and the JSON body gain `known_scanner`; ECS gains `truesignal.known_scanner` and the `known_scanner` tag, with `event.kind: event`. Existing parsers keep working; rules that exclude `whitelisted=true` should also exclude `known_scanner=true`.
  * Lists are validated and normalised on save (`400` on a bad CIDR, over 10,000 entries or an entry over 256 characters). A list saved earlier with a non-CIDR entry containing "/" still matches it as a name.
* **Triage labels, filters and search in the event table.**
  * Each event's source carries labels from its activity across all stored events: multi-decoy (touched two or more decoys), repeat source / single touch, internal / external address, whitelisted, known scanner.
  * Label chips filter the table (combined with AND), next to a free-text search over trigger, source, target, sensor, node and details.
  * Rows show the source's event count and badges for multi-decoy, scanner and whitelisted sources.
  * Backed by the new `GET /api/v2/sources`.
* **Honeytokens page** (sidebar).
  * Every planted credential with its status, node and File Canary, creation date, use count and last use.
  * Expanding a token lists each use: time, source, the decoy it was used against, and what matched.
  * Search, a used/unused filter and CSV export for a SIEM lookup table.
* **Detected Scans page** (sidebar).
  * Port scans and ICMP probes from all stored events, with search and a type filter, and a "Most probed ports" chart.
  * Tiles: port scans, ICMP probes, scanning sources, and sources that scanned and then touched a decoy (recon followed by access), with those sources badged in the table.
  * Detection only: nothing scans the network.
* New endpoint `GET /api/v2/insights` (`Hub/internal/projections/insights`). Hub liveness events are excluded from attacker counts.

# [Unreleased] - Signed releases (Sigstore) (2026-10-24)

* **The Hub accepts only signed sensor manifests.**
  * Each manifest needs a Sigstore bundle (`<manifest>.sigstore.json`).
  * The Hub verifies it offline against the embedded public-good trusted root. It requires a CT-logged certificate, a Rekor entry and a verified timestamp.
  * The certificate must belong to this repository's `publish-sensor-registry.yml` at that sensor's exact release tag. A signed manifest therefore cannot be replayed under another sensor name or version.
  * The check runs on the exact downloaded bytes, before decoding, and the decoded manifest must name the sensor and version it was requested as.
  * Since the manifest pins its image digest, the signature also covers the image.
  * Settings: `TS_MANIFEST_SIGNER_REPO` and `TS_SIGSTORE_TRUSTED_ROOT`. `TS_ALLOW_UNSIGNED_MANIFESTS=true` disables the check for development and is logged as a warning.
* **CI signs every release with Sigstore keyless** (cosign v3.1.4 via a SHA-pinned `cosign-installer`). There is no private key.
  * Sensor manifests: the bundle is verified in CI and published next to the manifest.
  * Sensor and Hub images: signed by digest.
  * Wizard binaries and `checksums.txt`: `.sigstore.json` release assets.
* **All sensors re-released at their next patch version.** The first releases carry no signature, so a verifying Hub would refuse them.
* `scripts/publish-registry.sh` publishes the bundle with its manifest, and the index builder ignores bundles.
* Verification commands and the remaining trust boundary (who can push release tags) are in `Docs/operations.md` §13.

# [Unreleased] - Admin MFA (Hub 2.2.0, Wizard 2.2.0) (2026-10-24)

* **TOTP for the dashboard admin** (RFC 6238, works with any authenticator app). The QR code is rendered by the Hub, so the UI needs no QR library. There are 10 single-use recovery codes, stored as SHA-256 hashes.
* **Replay protection:** the last accepted time step is stored, so a code works once even within its 30 s window.
* **Brute-force limits:** wrong codes count toward the existing per-IP lockout. 10 wrong codes from any mix of IPs also lock MFA account-wide for 15 minutes.
* **Re-authentication:** enrolling needs the password again, and the new authenticator must prove itself with a code before it takes effect. Disabling MFA or issuing new recovery codes needs the password and a current code. A hijacked session therefore cannot add its own authenticator or switch MFA off.
* **`TS_REQUIRE_MFA=true`:** an admin without MFA can sign in only to enroll; every other endpoint returns `403 mfa_enrollment_required`. MFA can't be disabled while this is set.
* **Break-glass:** `truesignal-hub mfa-reset` removes MFA when the authenticator and recovery codes are lost. The reset is sent to the SIEM as an audit record on the next Hub start.
* **Wizard:** prompts for the code when the Hub has MFA (`TS_DASHBOARD_MFA_CODE` for scripted runs). It gives a clear error when the Hub demands enrollment first. Older wizards cannot sign in to a Hub with MFA enabled.
* Hub and Wizard bumped to 2.2.0. The guide is `Docs/operations.md` §12.

# [Unreleased] - Release process fixes (2026-10-24)

* **First release published:** Hub and Wizard 2.1.0, and all nine sensors at their manifest versions.
* **Don't `git push --tags` a release.** GitHub creates no push event when one push carries more than three tags, so the first push of the 11 release tags started no workflow. They were dispatched on their tag refs instead. The new `make push-tags` pushes each release tag on `HEAD` in its own push, and the maintainer guide now says so. It replaces the earlier, wrong claim that pushing all tags at once is safe.
* **Hub and Wizard releases are now immutable, like sensors.** `publish-hub` fails if `truesignal-hub:v<version>` already exists in GHCR, and `publish-wizard` fails if the release already has assets. A duplicate dispatch on 2026-10-24 rebuilt `hub:v2.1.0` (new digest) and replaced the wizard v2.1.0 binaries and checksums. The 18:35 UTC builds are the current ones.

# [Unreleased] - Release readiness, Hub rollback and TLS (2026-10-24)

### Release pipeline
* **Parallel sensor releases no longer race.** Each `publish-sensor-registry` job now publishes through `scripts/publish-registry.sh`, which re-fetches `registry-pages`, re-applies its manifest and retries a rejected push. Previously nine sensor tags pushed together would conflict on the branch (and on creating it). A GitHub concurrency group was not an option: it cancels all but the newest queued job.
* **Released versions are immutable.** A sensor version already in `registry-pages` fails the job before the image is rebuilt. A rebuild would have moved the image tag and orphaned the digest the published manifest pins, and the GHCR cleanup deletes untagged images.
* **Tags must match code.** Sensor tags must equal the manifest `version`, `hub/v*` must equal `HubVersion`, and `wizard/v*` must equal `WizardVersion` (bumped 2.0.1 → 2.1.0).
* `make tag-sensors` now tags each sensor at its manifest version. The new `make tag-release` tags the Hub and the Wizard.
* Wizard binaries are built static (`CGO_ENABLED=0`, `-trimpath`).
* Images carry `org.opencontainers.image.source`/`version` labels. The GHCR cleanup matrix now includes the four newer decoys.
* **Fixed: FileCanary and WebRouterDecoy images would not build.** Their Dockerfiles compiled `./main.go` only, so they missed `lure.go` and `skin.go`. All sensor Dockerfiles now build the package. A new CI job builds every image on each PR.

### Hub
* **`TS_TRUSTED_PROXIES`:** comma-separated IPs/CIDRs. With `TS_TRUST_PROXY=true`, `X-Real-IP`, `X-Forwarded-For` and `X-Forwarded-Host` are now believed only from those peers. Before, they were believed from any client that could reach the Hub, which could then forge its IP to dodge the 10-attempt login lockout and falsify the audit log. An empty list keeps the old behaviour with a startup warning; an invalid entry stops the Hub.
* `TS_BIND_ADDR` in `Hub/docker-compose.yml` limits which interface publishes port 8080.

### TLS and operations
* `Hub/docker-compose.tls.yml` adds a TLS proxy and unpublishes the Hub's plain-HTTP port. The proxy is a digest-pinned, read-only, capability-free nginx with TLS 1.2/1.3, HSTS and WebSocket support, on a fixed address that the overlay sets as `TS_TRUSTED_PROXIES`. Verified end to end: spoofed `X-Real-IP` through the proxy no longer escapes the lockout, the authenticated WebSocket upgrades, and a foreign Origin is refused.
* `Docs/operations.md` §11 covers TLS: the nginx overlay and F5 BIG-IP (an iRule that replaces forwarding headers, the WebSocket profile, the monitor, and WAF exemptions for sensor endpoints).
* `Docs/operations.md` §7 adds an upgrade and rollback runbook:
  * An off-host backup that is WAL-safe.
  * Pinning the image when there is no schema change.
  * Restoring the `.bak` after a migration, which requires moving the `-wal`/`-shm` files aside.
  * The consequences of a restore: lost data, revived node keys, untracked honeytokens.
* `CLAUDE.md` now states the project's purpose.

# [Unreleased] - Web Router Decoy skin engine (2026-10-24)

* **Skins.** `TS_SKIN` picks the login surface: `router` (default, unchanged look; `TS_ROUTER_BRAND` still drives the footer), `nas`, `vpn` (SSL VPN with a realm selector, `/remote/login`), `webmail` (email field, `/mail/login`), `admin` (`/admin/login`) or `basic` (HTTP Basic challenge on every path; the `Authorization` header is captured). `TS_SKIN_PRODUCT` renames the product. Each skin sets a plausible `Server` header.
* **Custom skins** via `TS_SKIN_JSON`, strictly validated (unknown keys, CSS/header injection, bad paths and field types are rejected at start). Guide: `Docs/sensors/web-skins.md`.
* **Login events are rate-limited** to 20 per source per minute (shared `decoy.Limiter`), with `suppressed_since_last` on the next emitted event, so a form or Basic-auth spray can no longer fill the SDK queue and push out other alerts. Every attempt still gets the tarpit delay and the error page.
* Pages are now rendered with `html/template` (context-aware escaping) instead of `fmt` with manual escaping.
* Events keep their triggers and `attempted_username` (honeytoken matching). New details: `skin`, `auth` (`form`|`basic`), `path`, and `form_<field>` for extra fields such as a VPN realm. The firedrill payload no longer carries a cleartext password.
* Handlers are testable with a fake reporter; new tests cover every skin, Basic auth, escaping and custom-skin validation. Manifest bumped to 2.1.0.
* Removed a compiled `webrouterdecoy` binary that had been committed by mistake (it stays in git history).

# [Unreleased] - Decoy hardening from review (2026-10-24)

Follow-up to the database, remote-access and network-service decoys (review findings on PR #13):
* **Limiter state is bounded.** At most 10,000 sources are tracked. Expired entries are swept at most once per window, so a flood of distinct spoofed UDP sources costs amortised O(1) instead of a full scan per new source. When the table is full, new sources share one overflow budget.
* **FTP command length is bounded.** Lines longer than 512 bytes get `500 Command too long.` and the connection is closed; previously a client could make the sensor buffer unbounded input.
* **Connection events are rate-limited** (`*_connection`, 20 per source per minute, separate from the login budget), so a connect/disconnect flood can no longer fill the SDK's event queue and push out login alerts.

# [Unreleased] - Database, Remote Access and Network Service decoys (2026-10-24)

### Three new sensors
* **Database Decoy** (`ts-sensor-database-decoy`): MySQL, PostgreSQL and SQL Server (TDS 7.x) up to the login, each refused with the server's real error (1045, 28P01, 18456). PostgreSQL asks for a cleartext password and SQL Server's LOGIN7 password is decoded; both go through the capture policy. MySQL yields user, database and client attributes (the password is challenge/response). Runs **non-root (65532) with no added capabilities**. Verified against `psql`, PyMySQL, python-tds and impacket (whose fixed-layout PRELOGIN parser forced a strict four-option response; impacket also turns out to spoof SSMS as its app name, which is now recorded).
* **Remote Access Decoy** (`ts-sensor-remote-access-decoy`): SSH (OpenSSH 8.9 banner, ed25519 host key derived from the node key so it is stable without disk), Telnet and FTP (vsftpd banner). Records passwords, keyboard-interactive answers and offered public keys (type and SHA256 fingerprint). SSH defaults to port 2222 to avoid the host's sshd. Verified against paramiko, `ftplib` and a raw telnet session. **No unit tests yet.**
* **Network Service Decoy** (`ts-sensor-network-service-decoy`): SNMP v1/v2c/v3 and log-only DNS over UDP. SNMP answers the system group only for `TS_SNMP_COMMUNITY` and stays silent otherwise, like a real agent; communities are HMAC'd; SET is high severity; v3 records the USM user. DNS answers REFUSED and never resolves or forwards (Trapster's forwarding is deliberately not reproduced). AXFR is high severity. Replies are rate-limited with events, so the decoy can't act as a reflector. Verified against dnspython and raw SNMP datagrams.
* All three use per-node capture keys (`TS_CAPTURE_HASH_KEY`), so their usernames and passwords feed honeytoken matching. They declare `listen_ports_env` and support `TS_TEST_MODE`.

### Shared and Hub
* New `SDKs/go-truesignal/decoy` package: `TS_SERVICES` parsing, capture policy, accept loop, sanitising, and a per-source limiter (20 events/min; the rest are counted as `suppressed_since_last`).
* New Hub test: every `Sensors/official/*/*.json` must pass the Hub's strict decode, sandbox validation and major-version check.
* CI matrix, `.gitignore` and NOTICE (Trapster concept attribution) updated.

# [Unreleased] - Honeytokens (2026-10-24)

### Credential honeytokens linked to the decoys
* The Hub creates one fabricated credential per File Canary instance (username like `svc_reports97ef` plus a random password; new `honeytokens` table, schema migration v4, no foreign keys so attribution survives node/sensor deletion). It injects it as the reserved `TS_HONEYTOKEN`, and the provisioner writes it into lures it creates (`.env`, PHP config, `.pgpass`, SQL dump restore line, VPN config, generic backups). Existing host files are never modified.
* Every incoming event is checked: attempted usernames (`DOMAIN\user`, UPN and bind DN forms) and password HMACs. A match raises a **critical `honeytoken_used`** naming the lure's node and sensor, the triggering event and what matched. It is not suppressed by the source whitelist; sensors that send it themselves get HTTP 400.
* **Per-node capture keys:** the Hub generates a master key (`capture_master_key`) that never leaves it, and injects `TS_CAPTURE_HASH_KEY = HMAC(master, node ID)` into decoys that declare it (Identity Decoy, Web Router Decoy). A UI value is now ignored. The Hub re-derives the reporting node's key to compare password HMACs against every honeytoken, so matching is fleet-wide. Root on one node exposes only that node's key: enough to test its own captures, nothing from other nodes.
* **SIEM watchlist for real systems:** every honeytoken (username and planting location, never the secret) is published to the SIEM output on creation, at start and every 24 h (RFC 5424 `MSGID HONEYTOKEN`, ECS `truesignal.honeytoken` as a `user-account` indicator). `GET /api/v2/honeytokens?format=csv` exports a lookup file. `Docs/siem/honeytoken-detection.md` ships an importable Elastic indicator-match rule (`Docs/siem/elastic/truesignal-honeytoken-authentication.json`), a LogScale/Falcon query, and the AD audit policy needed to see logins by non-existent accounts.
* **Factory reset keeps honeytokens** and the master key, because their lures stay on disk; `purgeHoneytokens: true` deletes them and rotates the key.
* `GET /api/v2/honeytokens` lists tokens, where they are planted and their use count. Secrets are never returned.
* ECS output maps `honeytoken_used` to `intrusion_detection`/`authentication` with `user.name` = the honeytoken username.
* Verified end to end with real binaries: File Canary planted the token on node A; ldap3 simple and NTLM binds with it against an Identity Decoy on node B raised `honeytoken_used` (`username+password`, then `username`).

# [Unreleased] - ECS SIEM output (2026-10-24)

### Hub: ECS and HTTP SIEM outputs
* New `siemFormat`: `rfc5424` (default, unchanged) or `ecs`, which sends one ECS 8.11 JSON document per line over the existing `tcp`/`udp`/`tls` streams (for Elastic Agent's TCP input, Logstash `json_lines`, the LogScale Collector).
* New `siemProtocol` values. `elastic` posts to the Bulk API (`<url>/<data-stream>/_bulk`, `create` actions, `ApiKey` auth). `logscale` posts to the HEC endpoint (`Bearer` ingest token). Both send ECS over HTTPS with certificate verification (`TS_SIEM_CA_FILE` honoured) and never follow redirects.
* New write-only `siemToken`: it is stored in the Hub DB and never returned (the API exposes `siemTokenSet` only). Omit it to keep the stored token; send `""` to clear it.
* ECS mapping: `event.kind/category/action/severity/outcome`, `source.ip`, `destination.port`, `user.name/domain` (split from `DOMAIN\user`), `file.path`/`url.path`, `host`/`observer`, with the full record under `truesignal.*`. Captured secrets stay under `truesignal.details`. Audit records map to `truesignal.audit`.
* Delivery: network errors, `5xx` and `429` retry with the existing backoff; other `4xx` and Elastic bulk item errors drop the record and log the reason.
* `siemAddress` is validated against the effective protocol (`host:port` vs. `https` URL; `elastic` must include the data stream).
* UI: Settings → SIEM Forwarding gains the output, format and token fields.
* Setup guide, Elastic index template (`truesignal.details` as `flattened`), least-privilege API key and LogScale steps: `Docs/siem-integration.md`.

# [Unreleased] - LDAP NTLM bind capture (2026-10-23)

### Identity Decoy: LDAP/LDAPS NTLM binds
* The LDAP decoy now captures NTLM binds, not just simple binds. Most AD tooling authenticates this way, so these attempts were previously answered "success" and lost.
  * **Sicily** (MS-ADTS 5.1.1.1.3; ldap3-based tools such as BloodHound.py, ldapdomaindump and NetExec's LDAP module): package discovery returns `NTLM`, the NEGOTIATE gets a persona CHALLENGE in `matchedDN`, and the AUTHENTICATE is recorded.
  * **SASL GSS-SPNEGO** (impacket raw NTLMSSP; Windows/.NET clients such as SharpHound, SPNEGO-framed): the CHALLENGE goes back in `serverSaslCreds` with `saslBindInProgress`, matching the client's framing. A client that opens with an optimistic Kerberos token is steered to NTLM. Other SASL mechanisms (GSSAPI, DIGEST-MD5, EXTERNAL) are recorded as `*_query` with `sasl_mechanism` and refused.
  * The AUTHENTICATE is reported as critical `ldap_login`/`ldaps_login` with `username` (`DOMAIN\user`), `workstation` and `auth` (`sicily_ntlm` | `sasl_ntlm`), then refused with the AD `data 52e` diagnostic. Anonymous NTLM is a medium `*_query`.
* `TS_CAPTURE_NTLM` now governs LDAP as well as RDP: `identity` (default) records who tried; `hash` adds the NetNTLMv2 (hashcat 5600) response, which is crackable credential material (keep out of PCI scope); `off` refuses NTLM binds with `authMethodNotSupported`.
* LDAP messages split across TCP reads are now reassembled; previously such a message closed the connection.
* NetNTLMv2 formatting skips 24-byte NTLMv1 responses instead of emitting an invalid mode-5600 line (affected RDP `hash` mode too).
* Verified against ldap3 (LDAP and LDAPS) and impacket. The captured mode-5600 lines verify against the client passwords.

# [Unreleased] - RDP NLA/NTLM capture (2026-10-24)

### Identity Decoy: RDP Network Level Authentication
* The RDP decoy now captures the account from an NLA (CredSSP/NTLM) login, not just the pre-auth `mstshash` cookie. When a client requests NLA, the decoy selects HYBRID, completes the TLS handshake with its in-memory certificate, runs the CredSSP/NTLM exchange, and records `DOMAIN\user` and the workstation as a critical `rdp_login` (`auth: nla_ntlm`), then answers with a logon-failure NTSTATUS like a real host.
* `TS_CAPTURE_NTLM` controls it: `identity` (default — record who tried, no crackable material), `hash` (also record the NetNTLMv2 response in hashcat mode-5600 format, for threat intel; keep out of PCI scope), `off` (no NLA; `mstshash` cookie only). The NTLM parsing/building is re-derived from MS-NLMP/MS-CSSP; no third-party code.
* The challenge presents a realistic TargetInfo built from the persona (`TS_PERSONA_HOSTNAME`/`TS_PERSONA_DOMAIN`), so NTLMv2-capable clients proceed to authenticate.

# [Unreleased] - Identity Decoy sensor (2026-10-23)

### New sensor: Identity Decoy (AD services trap)
* New `ts-sensor-identity-decoy` emulates Windows identity services so lateral movement trips a decoy. One container serves several ports via `TS_SERVICES` (default `ldap:389,ldaps:636,rdp:3389`).
  * **LDAP / LDAPS:** answers directory binds like a domain controller. A simple bind is recorded as `ldap_login` / `ldaps_login` (critical) and the bad-password reply uses an AD-style `data 52e` error; anonymous binds and searches are recorded as `*_query` (medium) and get an empty, non-erroring directory so scanners keep probing. LDAPS generates its TLS certificate in memory (read-only rootfs).
  * **RDP:** records the username from the X.224 `mstshash` cookie as `rdp_login` (critical) and answers with the connection-confirm bytes a real Windows host returns. (NLA/CredSSP hash capture is a later increment.)
  * Bare connections are `*_connection` (low). Captured passwords are a keyed HMAC by default (`TS_CAPTURE_PASSWORDS=hash|plain|none`, `TS_CAPTURE_HASH_KEY`), never cleartext.
  * Shared persona across all services via `TS_PERSONA_HOSTNAME` (default `DC01`) and `TS_PERSONA_DOMAIN` (`corp.local`).
  * Ported in concept from Trapster Community (0xBallpoint, AGPLv3+); Go code and capture policy are TrueSignal's. See `NOTICE`.

### Hub
* **Port-conflict check:** a manifest may declare `listen_ports_env` (the env vars holding its listening ports). The Hub now rejects a node whose sensors bind the same host port with HTTP 422 `port_conflict`, instead of letting the second container crash-loop and trigger a rollback. The TCP Tarpit (`TS_DECOY_PORTS`) and Web Router Decoy (`TS_BIND_PORT`) manifests now declare it.

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
