# Session handoff (2026-10-26)

Read this first, then `CLAUDE.md` (project memory, kept current) and `Docs/KNOWLEDGE-GAPS.md`. Where docs and code disagree, trust the code.

## 1. Who and how

- **Owner:** Mahmoud, Senior Security Engineer and Detection Engineering Lead at Kashier (Cairo fintech). Expert security audience: skip basics.
- **Style:** direct, short, technically precise, answer first. Give the rationale before the code. Flag risks plainly. Use tables and lists only when clearer. Match his language (English so far).
- **Stack:** CrowdStrike Falcon/LogScale, Elastic SIEM, Fortinet → Palo Alto, Barracuda → F5, on Vodafone Egypt VDC.
- **Compliance:** PCI DSS, SOC 2, CBE.
- **Repo:** `mahmoudahmed3132/TrueSignal`, **public** (owner decision, reconfirmed 2026-10-26). Default branch `main`.
  - TrueSignal will become a startup / accelerator PoC.
  - A private-source plan (public `truesignal-dist` repo) was built and dropped: PR #23 closed, code in commit `370e69c`. Reviving it first needs the org/plan decision, because GitHub Team requires an organisation, which changes image paths and the signer identity.
  - Flagged to the owner, unresolved: the AGPL licence (upstream HoneyWire) for a commercial product is a legal question.
- **Working pattern:**
  - Claude develops on the session branch and opens a PR when the owner asks or has delegated ("do what you think is best", 2026-10-26: he trusts Claude's calls on design details; still ask on product or business decisions).
  - **He merges fast, often before CI or Codex finish.** After a merge:
    - check CI on the merge commit;
    - read the PR's Codex comments: they can arrive after the merge, and you are no longer subscribed.
  - Codex (chatgpt-codex-connector) reviews every PR. Every P2 so far has been real; verify, fix, reply on the thread, resolve.
  - Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` + `Claude-Session: <session URL>`.
- **What a cloud session cannot do:**
  - **Pushing:** git push is allowed only to the session branch, so no tags, and no GitHub MCP tool creates them. **Force-push is blocked by the auto-mode classifier.** To restart a branch, fast-forward to `origin/main` or revert; don't reset.
  - **Network:** the GHCR blob host, the vuln DB and the Sigstore TUF CDN are blocked; Docker Hub is rate-limited. `dockerd &` works when needed. pip inside `docker build` needs the proxy CA (`/root/.ccr/ca-bundle.crt`, BuildKit secret).
  - **Releases:** tags are pushed by the owner (`make tag-release && make push-tags`, `make tag-sensors && make push-tags`). Claude can dispatch publish workflows on an existing tag ref.

## 2. What TrueSignal is

A fork of HoneyWire v2.1.0 (AGPLv3), fully rebranded.
- A Go Hub (API, SQLite, embedded Vue UI) and 9 containerised decoy sensors.
- Go/Python SDKs.
- A root CLI wizard (`truesignal`) on each node.

**Purpose:** early, high-fidelity detection of attackers inside production. Decoys mirror production naming in an isolated subnet, and honeytokens cover the SaaS side. Any interaction is a SIEM alert (LogScale or Elastic). Secondary goals:
- PCI DSS / CBE evidence (a supporting control);
- detection-coverage validation.

Component map, env vars, conventions and hard rules are in `CLAUDE.md` §2-§8.

## 3. State

### Released (unchanged since 2026-10-25)

| Artifact | Version | Notes |
|---|---|---|
| Hub | `ghcr.io/mahmoudahmed3132/truesignal-hub:v2.2.0` (`sha256:fc36ddc5…fd88`) | Sigstore-signed |
| Wizard | `wizard/v2.2.0` | static amd64/arm64, signed, verified |
| Sensors | database-decoy 2.0.1, file-canary 2.0.2, icmp-canary 2.1.3, identity-decoy 2.0.1, network-scan-detector 2.1.3, network-service-decoy 2.0.1, remote-access-decoy 2.0.1, tcp-tarpit 2.0.3, web-router-decoy 2.1.1 | all signed; older unsigned versions are refused by a 2.2.0 Hub |
| Tag ruleset | `sensor/*/*`, `hub/*`, `wizard/*` | owner + repo admins only |

Not yet done in the real world:
- No node has run the installer end to end.
- MFA is not enabled on any real Hub.
- Wizard 2.2.0 is not on any node.

### On `main`, NOT released: the analyst features (phases 1-2, 2026-10-26)

Built from a SARAB-style feature list the owner supplied (screenshots of a deception product). Features and ideas only; no code or branding copied.

| Area | What | Where |
|---|---|---|
| Dashboard | Decoy coverage tiles (touched/deployed, attacker sources, critical, ATT&CK techniques, honeytokens used) with 24H/7D/30D/All; bar charts per decoy type; touched/untouched donut | `projections/insights`, `GET /api/v2/insights`, `components/dashboard/{InsightTiles,DecoyTypeChart,DecoyCoverageChart}.vue` |
| Source lists | Whitelist takes IPs/CIDRs/names; new **Known Scanners** list (archived, no notify, flagged `known_scanner`); file import in Settings | `services/sourcelist`, config keys `whitelisted_sources`, `known_scanners` |
| Triage | Per-source labels (multi-decoy, known asset, repeat, single touch, internal/external, whitelisted, scanner), label + tactic filters, search, badges | `projections/sources`, `GET /api/v2/sources`, `EventTable.vue` |
| Honeytokens page | Planted credentials, uses, CSV | `views/Honeytokens.vue` |
| Detected Scans page | Port scans and ICMP probes, most-probed ports, "scanned then touched a decoy" | `views/Scans.vue` |
| MITRE ATT&CK | Primary + secondary technique per trigger; 16 techniques; derived on read, never stored | `internal/attack`, table `Docs/siem/attack-mapping.md` (a test keeps them in sync), `projections/attackmap`, `GET /api/v2/attack[/layer]`, `views/Attack.vue` |
| Assets | Inventory (criticality, owner, tags; config key `assets`, JSON, no migration); events carry `sourceAsset` | `internal/assets`, `GET/PUT /api/v2/assets`, `views/Assets.vue` |
| Attack Path | Per-source route through the decoys: steps, tactic progression (multi-tactic technique = one step), timeline | `projections/path`, `GET /api/v2/path`, `views/AttackPath.vue` |
| Reports | Evidence report for a range, printed to PDF from the browser; JSON copy; PCI DSS 11.5.1 / CBE scope statement and sign-off | `projections/report`, `GET /api/v2/report`, `views/Report.vue` |

**SIEM contract changes since 2.2.0, all additive.** Tell the SOC before release.
- **RFC 5424 structured data:** gains `known_scanner`, `mitre_technique`, `mitre_tactic`, `source_asset` and `source_asset_criticality`. All are always present (empty when n/a), so parameter positions are stable.
- **RFC 5424 JSON body:** gains `known_scanner`, `attack` and `source_asset`.
- **ECS:**
  - `threat.*`, with sub-techniques under `threat.technique.subtechnique.*`;
  - `truesignal.known_scanner`, `truesignal.attack` and `truesignal.source_asset`;
  - the `known_scanner` tag;
  - `event.kind: event` for scanner sources.
- **Action for existing rules:** any rule that excludes `whitelisted=true` must also exclude `known_scanner=true`.

**Owner-approved / delegated decisions:**
- **Triage:** "Apply Mines" became labels and filters only; nothing suppresses notifications.
- **List labels:** whitelist/scanner labels reflect the lists as they are now.
- **Internal ranges:** fixed (RFC 1918, RFC 6598, loopback, link-local, ULA), plus any inventoried asset.
- **ATT&CK:**
  - `web_page_view` and liveness are unmapped;
  - T1078 keeps its four ATT&CK tactics (never Credential Access);
  - `web_path_probe` → T1595.003;
  - `decoy_file_tampered` → T1565.001, with T1486 secondary.

## 4. PRs this session

| PR | Outcome |
|---|---|
| #23 | Private source / public dist: **closed** (repo stays public). Commit `370e69c`. |
| #24 | Phase 1. Merged. One Codex P2 (IPv6 `::1` import regex) fixed before merge. |
| #25 | Phase 2. Merged before Codex finished. Its one P2 (report "assets involved" counted from the 25-row top list and per address) is fixed in the handoff PR (`assets` aggregate in `GET /api/v2/report`). |
| (this) | Session handoff + the #25 Codex fix. |

Session branch for this work: `claude/beautiful-ptolemy-t0uxdm`. A new session gets its own branch: start it from `origin/main`.

## 5. Lessons learned (don't repeat)

- **Builds:** Dockerfiles must `go build .` / `./cmd/hub`, never `./main.go`.
- **Tags:** never `git push --tags`; use `make push-tags`, one tag per push. Never re-run a publish for a released version.
- **Guards:** fail-open guards are bugs. Use direct HTTP with explicit 200/404/else.
- **nginx / F5:** see `Docs/operations.md` §11 (`Host` as `$http_host`; replace, don't append, `X-Real-IP`/XFF).
- **Trivy:** gates on fixable HIGH/CRITICAL; new deps can trip it. Prefer no new deps; the Reports PDF uses browser print for this reason.
- **Safety classifier:**
  - It stopped work on `RemoteAccessDecoy/main_test.go` (SSH client test content). Don't regenerate that file.
  - It also blocks force-push and `rm -rf "$VAR"` patterns inside `bash -c`. Use `mktemp -d` dirs instead.
- **Processes:** kill only by exact `awk '$2=="./binary"'`; `pkill -f` killed the session shell.
- **Git:** `git mv -k` silently skips untracked files; check that the move happened.
- **Repo `.gitignore`:** it ignores any `dist/` directory, so don't name a source folder `dist`.
- **Hub store:** `UpdateConfigBatch` silently drops config keys not in its allowlist (`store/config.go`). Add new keys there.
- **SIEM tests:** don't anchor syslog assertions on the last structured-data parameter (`…"]`); new parameters get appended.
- **UI:**
  - Check the event table at 1440 px. Badges pushed the Time column off-screen twice, so keep triage badges on the second line.
  - Two `:class` bindings on one element is a Vue compile error that `vue-tsc` doesn't catch; only `vite build` does.
  - `.bg-grid` is unlayered CSS, so Tailwind utilities can't override it; print styles are in `assets/style.css`.
- **Screenshot testing:** a seeded local Hub plus Playwright found most layout bugs. A failed step in a script can leave an old screenshot in place, so verify timestamps.

## 6. Open work, prioritised

1. **Release Hub 2.3.0, then 2.4.0** (owner decision 2026-10-30: tag 2.3.0 at the commit that matches its notes, then cut 2.4.0).
   - **2.3.0:** `git tag hub/v2.3.0 4471d82 && git push origin refs/tags/hub/v2.3.0` (not `make tag-release`, which tags HEAD). SOC notice: `Docs/siem/soc-notice-2.3.0.md`.
   - **2.4.0 + Wizard 2.2.1:** after the fixes PR merges, `make tag-release && make push-tags` on `main`, then `make tag-sensors && make push-tags` (token-receiver 2.0.0, web-router-decoy 2.1.2, file-canary 2.0.3). Set the new `truesignal-tokenreceiver` GHCR package Public. Send `Docs/siem/soc-notice-2.4.0.md` to the SOC **before** upgrading: it includes an ECS `user.domain` behaviour change.
   - **Verification:** done on 2026-10-30 on the owner's Mac (`Docs/LOCAL-VERIFICATION-PROMPT.md`). Its findings F1-F19 are fixed in 2.4.0, except the items left by decision: arm64 refused rather than built, and the community Python template image left unpinned.
2. **Phase 3: callback beacons and the GeoIP map.** **2026-10-29, part 1 built:** Token Receiver sensor + Beacons page (DNS, web bug, kubeconfig), `Docs/operations.md` §14. Owner decisions: GeoIP = **DB-IP Lite**; first beacons = DNS + web bug + kubeconfig. **2026-10-30, part 2 built:** DB-IP Lite enrichment + GeoIP Map (`Docs/operations.md` §15). Verified with the real DB-IP file and auto-update on the owner's Mac (2026-10-30). Next: Office docs and AWS keys. These are the SaaS/document honeytokens named in the purpose.
   - **Design (agreed in principle):**
     - A **separate hardened token receiver** (HTTP + DNS), never the Hub; the Hub must stay off the internet.
     - The receiver forwards to the Hub like a sensor does.
     - Beacon types: Word/Excel doc, web bug, DNS token, kubeconfig, `.bashrc`/Windows batch, MySQL dump, cloned-site, and AWS keys. AWS keys need a real IAM user and CloudTrail alerting.
     - Then GeoIP and the map. Internal sources are RFC 1918, so the map only fills from beacons opened outside.
   - **Ask the owner:**
     - **GeoIP source**: MaxMind GeoLite2 (free account, licence key) or DB-IP Lite (no account, CC-BY attribution). Still unanswered.
     - Which beacon types first.
   - **Also pending:** SARAB's monthly "beacon generation" charts (B5/B6) belong here, once beacons have creation dates.
3. **Installer end to end on the owner's test VM.**
   - **Hub:** behind TLS, `TS_REQUIRE_MFA=true`, `TS_TRUSTED_PROXIES` set.
   - **On the node:** `install.sh --link`, then `discover`/`apply`, then `firedrill`.
   - **Confirm:** events reach LogScale/Elastic, with the new ATT&CK and asset fields.
   - **Order:** roll Wizard 2.2.0 out before enabling MFA.
4. **SIEM detection content.** Still only the honeytoken rule ships. Now that events carry `threat.*` and `source_asset`, write Elastic rules and LogScale queries for:
   - critical logins;
   - scan-then-touch;
   - `source_asset.criticality` in (high, critical) → escalate;
   - lateral movement (`threat.tactic.id: TA0008`);
   - liveness;
   - MFA reset / audit.
   Test them against real samples.
5. **Non-root sensors.** Six run as UID 0 in the host netns; most only need `NET_BIND_SERVICE`.
6. **Smaller items:**
   - The installer could verify the wizard's `.sigstore.json`.
   - The Gitea mirror workflows lack signing and release guards.
   - The Remote Access Decoy has no unit tests.
   - VNC/rsync/MSSQL-TLS decoys are not built.
   - The port-conflict check is protocol-agnostic.
   - "Internal" ranges could become configurable (owner to say whether Kashier uses public space internally).

## 7. Key references

- **Operations:** `Docs/operations.md`
  - §7 upgrade/rollback
  - §10 honeytokens
  - §11 TLS/F5
  - §12 MFA
  - §13 signing
- **SIEM:** `Docs/siem-integration.md`, `Docs/siem/attack-mapping.md`, `Docs/siem/honeytoken-detection.md`, `Docs/architecture/dataContracts.md` (syslog example)
- **API:** `Docs/architecture/hub/backend/API.md`. All the new endpoints are documented.
- **Release:** `Docs/development/maintainer-workflow.md`, `Makefile`, `.github/workflows/publish-*.yml`
- **History:** `CHANGELOG.md` (newest first; `[Unreleased]` = phases 1-2)
