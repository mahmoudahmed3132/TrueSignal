# Session handoff (2026-10-30, updated after the SIEM rules)

Read this first, then `CLAUDE.md` (project memory, kept current) and `Docs/KNOWLEDGE-GAPS.md`. Where docs and code disagree, trust the code.

## 1. Who and how

- **Owner:** Mahmoud, Senior Security Engineer and Detection Engineering Lead at Kashier (Cairo fintech). Expert security audience: skip basics.
- **Style:** direct, short, technically precise, answer first. Give the rationale before the code. Flag risks plainly. Use tables and lists only when clearer. Match his language (English so far).
- **Stack:** CrowdStrike Falcon/LogScale, Elastic SIEM, Fortinet → Palo Alto, Barracuda → F5, on Vodafone Egypt VDC. **Compliance:** PCI DSS, SOC 2, CBE.
- **Repo:** `mahmoudahmed3132/TrueSignal`, **public** (owner decision, reconfirmed 2026-10-26). Default branch `main`.
  - TrueSignal will become a startup / accelerator PoC.
  - The private-source plan (PR #23, commit `370e69c`) is dropped. Reviving it first needs an org/plan decision (it changes image paths and the signer identity).
  - Flagged to the owner, unresolved: the AGPL licence (upstream HoneyWire) for a commercial product is a legal question.
- **Working pattern:**
  - Claude develops on the session branch and opens a PR when a piece is ready. The owner delegates design details ("do what you think is best") but decides product and business questions.
  - **He merges fast, often before CI or Codex finish.** After a merge, check CI on the merge commit and read the PR's Codex comments. They can arrive after the merge, and you are no longer subscribed. (#32's P2 arrived exactly like this.)
  - Codex (`chatgpt-codex-connector`) reviews every PR. Every P2 so far has been real: verify, fix, reply on the thread, resolve.
  - **GitHub writes outside the session branch** (tags, release edits, package visibility) are done by the owner, usually by pasting a prompt Claude writes into **Claude Code on his Mac**. That terminal session returns an md report. Verify its claims (e.g. `git ls-remote --tags origin`): on 2026-10-30 "tags pushed" was first reported when none were on origin.
  - Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` + `Claude-Session: <session URL>`. No model IDs in any artifact.
- **What a cloud session cannot do:**
  - **Pushing:** only to the session branch: no tags. **Force-push is blocked** by the auto-mode classifier. To restart a branch, fast-forward to `origin/main` or revert; don't reset.
  - **Network:** the GHCR blob host, the vuln DB and the Sigstore TUF CDN are blocked; Docker Hub is rate-limited (read base-image digests via `mirror.gcr.io`). `dockerd &` works when needed. pip inside `docker build` needs the proxy CA (`/root/.ccr/ca-bundle.crt`, BuildKit secret).
  - **Releases:** the owner pushes tags (`make tag-release && make push-tags`, `make tag-sensors && make push-tags`). Claude can dispatch publish workflows on an existing tag ref.

## 2. What TrueSignal is

A fork of HoneyWire v2.1.0 (AGPLv3), fully rebranded: a Go Hub (API, SQLite, embedded Vue UI), 10 containerised decoy sensors (incl. the internet-facing Token Receiver), Go/Python SDKs, and a root CLI wizard (`truesignal`) per node.

**Purpose:** early, high-fidelity detection of attackers inside production. Decoys mirror production naming in an isolated subnet; honeytokens and beacons cover the SaaS/document side. Any interaction is a SIEM alert (LogScale or Elastic). Secondary: PCI DSS / CBE evidence (supporting control) and detection-coverage validation.

Component map, env vars, conventions and hard rules: `CLAUDE.md` §2-§8.

## 3. State

### Released (2026-10-30, all Sigstore-signed and verified)

| Artifact | Version | Commit / digest |
|---|---|---|
| Hub | `v2.3.0` | tag at `4471d82` (#27 merge), `sha256:4fea016c…d7d8` |
| Hub | **`v2.4.0`** (schema v5) = `:latest` | tag at `31b3643` (#31 merge), `sha256:3ceb58a1…e3de` |
| Wizard | `v2.2.1` | `31b3643`; 6 assets, cosign + sha256 verified |
| Sensors (new versions) | token-receiver **2.0.0** (new), web-router-decoy 2.1.2, file-canary 2.0.3 | `31b3643` |
| Sensors (unchanged) | database-decoy 2.0.1, icmp-canary 2.1.3, identity-decoy 2.0.1, network-scan-detector 2.1.3, network-service-decoy 2.0.1, remote-access-decoy 2.0.1, tcp-tarpit 2.0.3 | |

- All 11 GHCR packages are public (anonymous pulls verified). The `release-tags` ruleset is active. GitHub "Latest" release = Hub v2.4.0. Release notes for Hub v2.4.0 / Wizard v2.2.1 were corrected by hand (originals on the owner's Mac, `~/work/truesignal-release/release-notes-fix/orig-*.md`).
- **The Hub image is linux/amd64 only.** On arm64 (the owner's Mac) use `DOCKER_DEFAULT_PLATFORM=linux/amd64`. Wizard binaries are amd64 + arm64; sensor images amd64 only; `install.sh` refuses arm64 nodes unless `TS_ALLOW_ARM64=1`.
- SOC notices `Docs/siem/soc-notice-2.3.0.md` and `-2.4.0.md` were **sent** (owner confirmed).

### On `main` after 2.4.0, not released (CI only / compose; no version bump needed)

- **#32** (owner, via his Claude Code): per-component release notes; `:latest` only from the highest Hub tag. CLAUDE.md release state refreshed.
- **#33**: `Hub/docker-compose.yml` has no `build:`. A failed pull now fails `up` instead of building local source under the release tag (finding F3 from the release run). Builds are opt-in via `Hub/docker-compose.build.yml`. A CI guard checks it.
- **This handoff PR**: fixes #32's Codex P2 (a stale run could still regress `:latest`). `:latest` moves in a separate `promote-latest` job, serialized across Hub tags (`concurrency: publish-hub-latest`). It points at the highest **published and cosign-verified** `hub/v*`, not its own tag. It is untested until the next Hub tag runs; check that run's `promote-latest` log.

CI (Tests + Security Scans) on `main` @ `6121925` (#35 merge): green. #34 and #35 Codex reviews: #34's only P2 was fixed in #35 and resolved; #35 had no findings.

- **#35** made `promote-latest` copy the signed manifest unchanged (`--prefer-index=false`) and fail unless `:latest` resolves to the cosign-verified digest. **Untested until the next `hub/v*` tag.** When it runs, its log must show `:latest -> vX.Y.Z (sha256:…)`, and `cosign verify ghcr.io/mahmoudahmed3132/truesignal-hub:latest` must pass.

### The owner's Mac lab (not production)

- **Hub:** `~/TrueSignal-latest/Hub`, compose project `hub`, port 8088, on **v2.4.0** (pinned in `.env`), schema 5. Migrated from 2.1.0. The pre-migration snapshot is `truesignal_data/truesignal.db.pre-v4-20261030220008.bak`, plus full backups in `~/work/truesignal-release/backup-*`.
- `TS_DASHBOARD_PASSWORD` override is set in `.env` (password in the macOS Keychain, service "TrueSignal Hub (localhost:8088)"). While set, the UI password change is disabled.
- `TS_GEOIP_AUTO_UPDATE=true`; DB-IP City Lite 2026-10 loaded.
- SIEM output: a toy catcher, `~/work/truesignal-release/siem-catcher.py`, on `127.0.0.1:9514` (ECS stream, `siem-capture.log`). It does not survive a reboot. **No real LogScale/Elastic is wired to any Hub yet.**
- `local-test-node` (2026-10-24) is orphaned: no `/opt/truesignal` or CLI on the Mac, plus an old `ts-sensor-web-router-decoy` 2.1.0 container. A 2.4.0 Hub gives it no compose (unsigned 2.1.0 manifests). Left as test history by owner decision. **A real node needs a Linux x86_64 VM.**
- `docker logout ghcr.io` was done; log in again only if needed (pulls are anonymous).

### Not yet done in the real world

- No node has run `install.sh --link` → `discover`/`apply` → `firedrill` end to end on Linux.
- No Token Receiver is deployed: it needs a DMZ host, a delegated zone (NS records) and `TS_ANSWER_IPV4`.
- MFA is not enabled on any real Hub. No Hub sits behind TLS/F5 yet.

## 4. Recent PRs (#27-#35 on branch `claude/vigilant-dirac-x3oppg`)

| PR | What |
|---|---|
| #27 | Hub 2.3.0 release prep; `tag-release` counts only origin tags |
| #28 | Phase 3 part 1: beacons (DNS, web bug, kubeconfig), Token Receiver, Beacons page, migration v5 |
| #29 | Phase 3 part 2: DB-IP Lite GeoIP enrichment, map page, ECS/syslog geo fields |
| #30 | Fixes F1-F19 from the local verification run (2.4.0, Wizard 2.2.1, two sensor bumps) |
| #31 | Late Codex fixes on #30 (preflight mounts, recovery detection) |
| #32 | (owner) release notes per component, `:latest` race, CLAUDE.md |
| #33 | Compose never builds from source |
| #34 | Handoff + #32 Codex fix |
| #35 | Keep the signed digest when promoting `:latest` |
| (branch `claude/loving-knuth-29rxvu`) | SIEM detection rules (Elastic + LogScale), sample corpus from the real pipeline, Kibana rule test + CI |

All Codex P2s on #27-#31 were fixed, replied and resolved. #33: no findings. #32's thread is answered by this PR.

## 5. Lessons learned (don't repeat)

- **Compose:** never put `build:` next to `image:` in a production compose: a failed pull silently builds source under the release tag. Upgrades: `pull` → check digest → `cosign verify` → `up -d --no-build --pull never` → `GET /api/v2/version`.
- **Release verification:** trust `git ls-remote --tags origin`, the publish run, the GHCR digest and `cosign verify`, not a report's summary line.
- **Parallel releases:** two Hub tags pushed together run in parallel. Anything "latest"-shaped must be serialized and idempotent (promote the highest published, not your own).
- **Builds:** Dockerfiles must `go build .` / `./cmd/hub`, never `./main.go`. Base images digest-pinned.
- **Tags:** never `git push --tags`; use `make push-tags`, one tag per push (GitHub fires nothing for >3 tags in one push). Never re-run a publish for a released version. To tag a non-HEAD commit (2.3.0), `git tag <tag> <sha>` by hand: `make tag-release` tags HEAD.
- **Guards:** fail-open guards are bugs. Use direct HTTP with explicit 200/404/else.
- **mmap:** never overwrite an mmapped file in place (GeoIP DB): open a private snapshot copy.
- **nginx / F5:** `Docs/operations.md` §11 (`Host` as `$http_host`; replace, don't append, `X-Real-IP`/XFF).
- **Trivy:** gates on fixable HIGH/CRITICAL; new deps can trip it (go-jose 4.1.4 → 4.1.6). Prefer no new deps.
- **Safety classifier:** it stopped work on `RemoteAccessDecoy/main_test.go` (SSH client test content): don't regenerate that file. It blocks force-push and `rm -rf "$VAR"` inside `bash -c`; use `mktemp -d`.
- **Processes:** kill only by exact `awk '$2=="./binary"'`; `pkill -f` killed the session shell.
- **Git:** `git mv -k` silently skips untracked files. The repo `.gitignore` ignores any `dist/`.
- **Hub store:** `UpdateConfigBatch` silently drops config keys not in its allowlist (`store/config.go`).
- **SIEM tests / parsers:** don't anchor on the last structured-data parameter (`…"]`); parameters get appended (2.4.0 appended `source_country`, `source_geo_basis`).
- **UI:** check the event table at 1440 px; two `:class` bindings on one element only fail in `vite build`; `.bg-grid` is unlayered CSS. The embedded UI needs a Hub rebuild before screenshots. Verify screenshot timestamps.
- **Sessions:** UI sessions do not survive a Hub restart; expect to log in again after any recreate.

## 6. Open work, prioritised

1. **SIEM detection content: follow-ups.** The rule set shipped 2026-10-30 (`Docs/siem/detection-rules.md`): 16 Elastic rules plus LogScale twins, tested by `Hub/internal/services/event/siem_samples_test.go` (samples from the real pipeline) and `scripts/siem-rules/run-elastic.sh` (real Kibana 8.19 detection engine, CI workflow `siem-rules.yml`). Open:
   - **Run the LogScale queries once on real LogScale.** They are field-checked only; syntax is unverified. Record the result in the doc.
   - **Owner input:** the expected-country list for `truesignal-beacon-unexpected-country` (`EG` placeholder, ships disabled); the corporate resolver/proxy egress addresses for the Assets page; Elastic data stream and LogScale repository names; alert routing.
   - **Hub heartbeat to the SIEM** (new record type, e.g. `truesignal.heartbeat` every 5 min). Without it a dead Hub or a broken output is invisible. This is a SIEM contract change (SOC notice).
   - Optional: a new-terms rule for admin logins from a never-seen IP; a "node blinded" rule (several sensors lost on one node within minutes).
2. **End to end on a Linux x86_64 VM** (the Mac can't host nodes). Hub behind TLS (`docker-compose.tls.yml` or F5), `TS_REQUIRE_MFA=true`, `TS_TRUSTED_PROXIES` set. Node: `install.sh --link` → `discover`/`apply` → `firedrill`. Confirm events reach a real LogScale/Elastic with ATT&CK, asset and geo fields. Then a Token Receiver on a DMZ host with a delegated zone. Roll Wizard 2.2.1 out before enabling MFA.
3. **Phase 3, next beacons:** Office documents (Word/Excel) and AWS keys (needs a real IAM user plus CloudTrail → SIEM alerting). Then `.bashrc`/batch, MySQL dump, cloned-site. Then SARAB-style monthly beacon-creation charts (B5/B6).
4. **Non-root sensors.** Six run as UID 0 in the host netns; most only need `NET_BIND_SERVICE`.
5. **Smaller items:**
   - `cosign verify` of the Token Receiver *image* was skipped in the release run. Do it once, from any machine with Sigstore access.
   - An arm64 Hub image (currently out of scope; the compose fails loudly instead).
   - The installer could verify the wizard's `.sigstore.json`.
   - The Gitea mirror workflows lack signing and release guards.
   - The Remote Access Decoy has no unit tests.
   - VNC/rsync/MSSQL-TLS decoys are not built.
   - "Internal" ranges could become configurable (owner to say whether Kashier uses public space internally).

## 7. Key references

- **Operations:** `Docs/operations.md`: §7 upgrade/rollback (amd64 note, no-build), §10 honeytokens, §11 TLS/F5, §12 MFA, §13 signing, §14 beacons/Token Receiver, §15 GeoIP.
- **SIEM:** `Docs/siem-integration.md`, `Docs/siem/attack-mapping.md`, `Docs/siem/honeytoken-detection.md`, `Docs/siem/soc-notice-2.{3,4}.0.md`, `Docs/architecture/dataContracts.md`.
- **API:** `Docs/architecture/hub/backend/API.md`.
- **Release:** `Docs/development/maintainer-workflow.md`, `Makefile`, `.github/workflows/publish-*.yml`.
- **Local verification:** `Docs/LOCAL-VERIFICATION-PROMPT.md`.
- **History:** `CHANGELOG.md` (newest first).
