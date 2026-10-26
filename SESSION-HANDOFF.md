# Session handoff (2026-10-25)

Read this first, then `CLAUDE.md` (project memory, kept current) and `docs/KNOWLEDGE-GAPS.md`. Where docs and code disagree, trust the code.

## 1. Who and how

- **Owner:** Mahmoud, Senior Security Engineer and Detection Engineering Lead at Kashier (Cairo fintech). Expert security audience: skip basics.
- **Style:** direct, short, technically precise, answer first. Give the rationale before the code. Flag risks plainly. Use tables and lists only when clearer. Match his language (English so far).
- **Stack:** CrowdStrike Falcon/LogScale, Elastic SIEM, Fortinet → Palo Alto, Barracuda → F5, on Vodafone Egypt VDC.
- **Compliance:** PCI DSS, SOC 2, CBE.
- **Repo:** `mahmoudahmed3132/TrueSignal`, public by owner decision until further notice. Default branch `main`. He merges PRs quickly, often before CI finishes, so always check CI on the merge commit.
- **Working pattern:**
  - Claude develops on a session branch and opens a PR when he asks ("open the PR").
  - Codex (chatgpt-codex-connector) reviews every PR. Treat its findings as claims to verify; P2 findings so far have all been real and were fixed.
  - Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` + `Claude-Session: <session URL>`.
- **What a cloud session cannot do:**
  - git push is allowed only to the designated session branch, so it can't push tags.
  - None of the GitHub MCP tools creates tags.
  - The sandbox blocks the GHCR blob host (`pkg-containers.githubusercontent.com`), Docker Hub is rate-limited, the vuln DB (`vuln.go.dev`) is blocked, and the Sigstore TUF CDN is blocked.
  - Docker may not be running; `dockerd &` works when needed.
  - Release tags are pushed by the owner (`make tag-sensors && make push-tags`, `make tag-release && make push-tags`). Claude can **dispatch** publish workflows on an existing tag ref via `actions_run_trigger`.

## 2. What TrueSignal is

- A fork of HoneyWire v2.1.0 (AGPLv3), fully rebranded.
- **Components:**
  - Go Hub: API, SQLite and an embedded Vue UI.
  - 9 containerised decoy sensors.
  - Go/Python SDKs.
  - A root CLI wizard (`truesignal`) that deploys sensors on each node.
- **Owner's purpose:**
  - Early, high-fidelity detection of attackers inside production, cloud or on-prem.
  - Decoy VMs that mirror production naming sit in an isolated subnet; honeytokens cover the SaaS side.
  - Any interaction raises a SIEM alert (LogScale or Elastic) for SOC triage.
  - Secondary goals: PCI DSS/CBE evidence (a supporting control) and validating detection coverage.
- Component map, env vars, conventions and hard rules are in `CLAUDE.md` §2-§5. Do not duplicate them.

## 3. Current released state (verified 2026-10-25)

| Artifact | Version | State |
|---|---|---|
| Hub | `ghcr.io/mahmoudahmed3132/truesignal-hub:v2.2.0` (`sha256:fc36ddc57b8327295e94a959966645b5d3b7088060fcbee1d883208e5ed4fd88`) | Published, anonymous pull OK. Sigstore signature attached as an OCI referrer (fallback tag `sha256-<digest>`; cosign v3 format, not `.sig`). Contents not downloaded here (GHCR blob host blocked); owner can verify with `cosign verify` (`Docs/operations.md` §13). |
| Wizard | `wizard/v2.2.0` release | Static amd64/arm64 + `checksums.txt`, each with `.sigstore.json`. **Cryptographically verified** against `publish-wizard.yml@refs/tags/wizard/v2.2.0`. |
| Sensors | database-decoy 2.0.1, file-canary 2.0.2, icmp-canary 2.1.3, identity-decoy 2.0.1, network-scan-detector 2.1.3, network-service-decoy 2.0.1, remote-access-decoy 2.0.1, tcp-tarpit 2.0.3, web-router-decoy 2.1.1 | All 9 signed. Every bundle in `registry-pages` passes the Hub's production verifier (`signing.New`, pinned identity), and none verifies under another version. `index.json` `latest` = these versions. |
| Old sensor versions | 2.0.0/2.0.1/2.1.0/2.1.2 first releases | Unsigned; a 2.2.0 Hub rejects them, as intended. |
| Old Hub/Wizard | v2.1.0 | Each built twice on 2026-10-24 (duplicate dispatch, before the re-release guard); the 18:35 UTC builds are current. |
| Tag ruleset | `sensor/*/*`, `hub/*`, `wizard/*`: restrict create/update/delete, bypass = repo admin | **Done by owner** 2026-10-25. |

**Not yet done in the real world:**
- No node has run the installer end to end.
- MFA is not enabled on any real Hub.
- Wizard 2.2.0 is not rolled out to any nodes.

## 4. What this session built (PRs, all merged)

| PR | What |
|---|---|
| #9 | Identity Decoy: LDAP/LDAPS NTLM bind capture (Sicily + SASL GSS-SPNEGO) |
| #10 | Revert the private-repo token pulls (repo stays public; revert the revert if it goes private, commit `4013e0d`) |
| #11 | ECS SIEM output: Elastic bulk + LogScale HEC (`siem_format`, write-only `siemToken`) |
| #12 | Credential honeytokens: per-node capture keys, SIEM watchlist, survive factory reset |
| #13–#15 | Database, Remote Access, Network Service decoys; shared `SDKs/go-truesignal/decoy` (limiter, capture, `TS_SERVICES`); review fixes |
| #16 | Web Router Decoy HTTP skin engine (`TS_SKIN` router/nas/vpn/webmail/admin/basic, `TS_SKIN_JSON`) + per-source login rate limit; untracked a committed binary |
| #17 | Release readiness (parallel-safe `scripts/publish-registry.sh`, immutable releases, version guards, static wizard, Dockerfiles build the whole package, CI builds every image); `TS_TRUSTED_PROXIES` (fixed IP spoofing of the login lockout); TLS nginx overlay + F5 guide (`Docs/operations.md` §11); Hub rollback runbook (§7); CLAUDE.md purpose |
| #18 | `make push-tags` (GitHub fires no workflow for a push with >3 tags); Hub/Wizard re-release guards (fail-closed HTTP checks); per-ref publish concurrency |
| #19 | Admin MFA: TOTP + recovery codes, `TS_REQUIRE_MFA` enroll-only gate, `mfa-reset` break-glass, wizard code prompt; Hub/Wizard 2.2.0 (`Docs/operations.md` §12) |
| #20 | Sigstore keyless signing: CI signs manifests/images/wizard; the Hub verifies every manifest offline against the embedded trusted root, pinned to `publish-sensor-registry.yml@refs/tags/sensor/<name>/v<ver>`; grpc bumped for Trivy (`Docs/operations.md` §13) |
| #21 | (owner) portable `sed` in `make tag-release` |

Session branch: `claude/dreamy-cray-hh19ze`. Restart it from `origin/main` for new work, because merged PRs are not reused.

## 5. Lessons learned (don't repeat)

- **Builds:** Dockerfiles must `go build .` / `./cmd/hub`, never `./main.go`, because multi-file packages broke three images. CI's `docker build` job now catches this.
- **Tags:** never `git push --tags` a release. Use `make push-tags`, one tag per push.
- **Re-runs:** never re-run or dispatch a publish for a version that is already released. Guards now refuse it, but check existing runs first.
- **Fail-open guards:** both the `docker manifest inspect` and `gh release view` guards turned out fail-open; use direct HTTP with explicit 200/404/else handling.
- **nginx:** a `proxy_set_header` in a location block drops every server-level one. Keep `Host` as `$http_host`, or the WebSocket origin check fails on non-443 ports.
- **F5:** the HTTP profile's XFF insert lets a client-supplied `X-Real-IP` through. Use the iRule in §11.
- **Trivy:** CI's Trivy FS scan gates on HIGH/CRITICAL findings with fixes; new deps can trip it (grpc did).
- **Safety classifier:** it stopped work twice on `Sensors/official/RemoteAccessDecoy/main_test.go` (SSH client test content), even after owner approval. Do not regenerate that content, even reworded. That sensor has no unit tests, documented.
- **Killing processes:** kill only by exact `awk '$2=="./binary"'` matching. `pkill -f` killed the session shell.

## 6. Open work, prioritised

0. **Analyst feature roadmap (owner-approved 2026-10-26, from a SARAB-style feature list).**
   - **Phase 1** (decoy coverage dashboard, CIDR whitelist + Known Scanners, triage labels/search, Honeytokens and Detected Scans pages): merged as mahmoudahmed3132/TrueSignal#24.
   - **Phase 2** on `claude/beautiful-ptolemy-t0uxdm`:
     - MITRE ATT&CK mapping (`Hub/internal/attack`, `Docs/siem/attack-mapping.md`, SIEM `threat.*` / `mitre_*`) and the Attack Navigator page;
     - Assets inventory (`source_asset` in events/SIEM);
     - Attack Path page;
     - Reports page (print to PDF).
     - The owner delegated the mapping calls. `web_page_view` and liveness are unmapped, and T1078 keeps its four ATT&CK tactics.
   - **Phase 3 (next):**
     - callback beacons (Word/Excel, web bug, DNS, kubeconfig, AWS keys, ...) on a **separate hardened token receiver**, never the Hub;
     - then GeoIP plus the map.
     - **Ask the owner: MaxMind GeoLite2 (account needed) or DB-IP Lite (CC-BY).** AWS key beacons need a real IAM user and CloudTrail.
   - **Release:** none of phases 1-2 is released. The next Hub release should be **2.3.0**: bump `HubVersion` and `WizardVersion` together if the wizard changes, otherwise the Hub alone (only the major must match).
   - **SIEM contract (additive since 2.2.0):** `known_scanner`, `mitre_technique`, `mitre_tactic`, `source_asset`, `source_asset_criticality` in syslog SD; `threat.*` and `truesignal.{known_scanner,attack,source_asset}` in ECS. Rules excluding `whitelisted=true` should also exclude `known_scanner=true`.

1. **Installer end to end on a real test VM** (owner's VM; the sandbox can't pull GHCR images).
   - Setup: Hub 2.2.0 behind TLS (`docker-compose.tls.yml` or F5), `TS_REQUIRE_MFA=true`, `TS_TRUSTED_PROXIES` set.
   - Run on the node: `install.sh … --link`, then `truesignal discover`/`apply`, then `firedrill`.
   - Confirm events reach LogScale/Elastic.
   - Roll Wizard 2.2.0 to nodes **before** enabling MFA; older wizards can't log in.
2. **SIEM detection content.** Only the honeytoken rule ships; this is the biggest gap against the purpose. Proposed:
   - Elastic rules + LogScale queries for `*_login` / `web_login_attempt` (critical).
   - Scan-then-touch sequences: `network_scan_detected` followed by `*_connection` from the same source.
   - Liveness (`sensor_heartbeat_lost`).
   - `MFA RESET` and admin audit events.
   - ATT&CK-mapped, tested against real event samples (`Docs/siem/`, ECS mapping in `Hub/internal/services/siem/ecs.go`; event shape and trigger names are a contract).
3. **Non-root sensors.** Six sensors run as UID 0 in the host netns. Most need only `NET_BIND_SERVICE`, so move them to 65532 with that capability. ICMP Canary and the Network Scan Detector need raw sockets and closer analysis.
4. **SaaS honeytokens.** Named in the purpose, not built. **Ask the owner which SaaS first** (fake AWS/Azure keys, decoy M365 user, Confluence/GitHub tokens).
5. **Smaller items:**
   - The installer could verify the wizard's `.sigstore.json` when cosign is present.
   - The Gitea mirror workflows lack the signing and release guards.
   - The Remote Access Decoy has no unit tests (see §5 classifier note).
   - VNC/rsync/MSSQL-over-TLS decoys are not built.
   - The port-conflict check is protocol-agnostic.

The owner's last question was "what's next?". Claude recommended (1) on his VM in parallel with Claude starting (2). He has not chosen yet.

## 7. Key references

- Operations: `Docs/operations.md`
  - §7 upgrade/rollback
  - §10 honeytokens
  - §11 TLS/F5
  - §12 MFA
  - §13 signing and verification commands
- Release process: `Docs/development/maintainer-workflow.md`, `Makefile` (`tag-sensors`, `tag-release`, `push-tags`), `.github/workflows/publish-*.yml`, `scripts/publish-registry.sh`
- Signing code: `Hub/internal/signing/` (embedded `trusted_root.json` sha256 `6494e21e…`, verified via the TUF chain from sigstore/root-signing; refresh from there when Sigstore rotates)
- Threat model and gaps: `THREATMODEL.md` (Risk-03 updated), `docs/KNOWLEDGE-GAPS.md`
- History: `CHANGELOG.md` (newest first)
