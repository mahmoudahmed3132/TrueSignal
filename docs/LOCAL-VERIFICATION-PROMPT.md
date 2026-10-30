# TrueSignal: full local verification (prompt for Claude Code on macOS)

> Paste everything below the line into Claude Code in Terminal, started from an empty working folder (for example `~/work/ts-verify`). It produces `TrueSignal-verification-report.md` in that folder. Bring that file back to the cloud session.

---

You are verifying the TrueSignal repository end to end on my Mac, using Docker Desktop. Your job is to **test and report, not to fix**. Work through the phases below in order. Record evidence for every check, and finish by writing `TrueSignal-verification-report.md` in the current folder, in the format given at the end. Another Claude session will read that report and act on it, so be precise: exact commands, exact versions, trimmed but real output, and file:line references.

## Hard rules (do not break these)

1. **Never push anything** to GitHub. No `git push`, no tags pushed, no `gh` writes, no workflow dispatches, no repository or package setting changes. Running `make tag-release` is allowed only in a throwaway clone, and its tags must be deleted afterwards.
2. **Don't fix code.** If something fails, find the root cause, put a proposed patch (a diff) in the report, and keep going. The one exception: a trivial local workaround needed to keep testing, which you must list under "Workarounds I applied".
3. **No real secrets or infrastructure.** Use throwaway passwords, `example.com`/`*.test` domains and RFC 5737 / RFC 1918 addresses. Never put a real credential into the report. Mask node keys as `ts_key_…last4`.
4. **Contain everything.** Run everything under `./ts-verify-work/`, and every compose project under a name starting `tsv-`.
5. **Ask before anything that needs sudo or changes system settings.** That means `/etc/resolver` and Docker Desktop settings. If I don't answer, skip it and mark it SKIPPED.
6. **Clean up at the end:** `docker compose down -v` for every `tsv-*` project, stop the processes you started, and remove `/etc/resolver/*` entries you created. Leave the clone and the report in place.
7. **Don't trust your own memory over the repo.** Where these instructions and the code disagree, trust the code, and note the disagreement in the report.

## Phase 0: environment

Record each of these, and install what's missing with Homebrew if I agree:
- `sw_vers` and `uname -m` (Apple Silicon = arm64).
- Docker Desktop version, `docker info` (CPUs, memory, OS/arch), and whether **Settings → Resources → Network → "Enable host networking"** is on. It's needed for sensors with `network_mode: host`. Ask me to enable it if it's off; it needs Docker Desktop 4.34 or later.
- Docker Desktop's x86_64/amd64 emulation (Rosetta): the published images may be amd64-only.
- `git`, `go version` (the repo needs **Go 1.26**), `node -v` (20+), `npm`, `jq`, `python3`, `sqlite3`, `dig`, `curl`, `openssl`. Optional: `cosign` (2.4+), `kubectl`, `mysql`/`psql` clients, `ldapsearch`, `snmpget`, `nmap`.

## Phase 1: clone and orient

```bash
mkdir -p ts-verify-work && cd ts-verify-work
git clone https://github.com/mahmoudahmed3132/TrueSignal.git
cd TrueSignal && git log --oneline -8 && git rev-parse HEAD
```

Read these before testing anything else: `SESSION-HANDOFF.md`, `CLAUDE.md`, `docs/KNOWLEDGE-GAPS.md`, `CHANGELOG.md` (top entries), `Docs/operations.md`, `Docs/siem-integration.md`, `Docs/siem/soc-notice-2.3.0.md`, `Docs/architecture/hub/backend/API.md`, `THREATMODEL.md`.

Record:
- the HEAD commit;
- `HubVersion` in `Hub/internal/models/models.go`;
- `WizardVersion` in `wizard/core/api/client.go`;
- every sensor manifest's `id` and `version` (`Sensors/official/*/*.json`).

## Phase 2: static checks and unit tests

The CI matrix is in `.github/workflows/test.yml`.
1. **UI first** (Hub tests embed it): `cd Hub/ui && npm ci && npx vue-tsc --noEmit && npm run build`.
2. **Go modules:** for each one, run `go vet ./...` and `go test -race -count=1 ./...`:
   - `Hub`, `wizard`, `SDKs/go-truesignal`;
   - every `Sensors/official/*` directory.
3. **Linux-only modules:** if a module fails to build or test on darwin (inotify, raw sockets, AF_PACKET), re-run it in Linux and record both results. Darwin-only failures are expected and not bugs:
   `docker run --rm -v "$PWD":/src -w /src/<module> golang:1.26 sh -c 'go vet ./... && go test -race -count=1 ./...'`
4. **Formatting:** `gofmt -l .` must print nothing in each module.
5. **Python SDK smoke:** run the same steps as the "Python SDK / mock hub" job in `test.yml`.
6. **`make tag-release` behaviour:** in a throwaway clone (`git clone TrueSignal /tmp/ts-tagtest`), run `make tag-release`. Expected: it creates `hub/v<HubVersion>` and skips `wizard/v2.2.0` because that tag is on origin. Then delete the local tags and the clone. **Do not run `make push-tags`.**

## Phase 3: images

1. **Build locally:**
   - the Hub: `docker build -t tsv/hub:dev Hub/`;
   - every sensor: `docker build -t tsv/<lowercasedir>:dev -f Sensors/official/<Dir>/Dockerfile .`
2. **Record per image:** pass/fail, size, and that it runs as non-root by default (`docker inspect -f '{{.Config.User}}'`).
3. **Docker Hub rate limits:** if you hit one, say so and continue.
4. **Published images:** pull `ghcr.io/mahmoudahmed3132/truesignal-hub:v2.2.0` (add `--platform linux/amd64` if needed). Then check whether `:v2.3.0` exists and which architectures each has (`docker buildx imagetools inspect …`).

## Phase 4: supply chain (needs cosign; otherwise SKIPPED)

Follow `Docs/operations.md` §13 exactly. With `REPO=mahmoudahmed3132/TrueSignal`:
1. **Registry:** fetch `https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/registry-pages/index.json`. List each sensor's `latest`.
2. **Manifest signatures:** for every sensor's latest manifest, download `<sensor>-v<ver>.json` and `<sensor>-v<ver>.json.sigstore.json` and run `cosign verify-blob` with the pinned certificate identity from §13.
3. **Image signatures:** `cosign verify` the Hub image for each released `hub/v*` tag, and one sensor image by digest (the digest is in its manifest).
4. **Wizard:** verify one wizard release binary and its `.sigstore.json` from the latest `wizard/v*` release.
5. **Token Receiver:** check whether `token-receiver` is in `index.json`. It is expected to be **absent** until it's released.

## Phase 5: Hub end to end

Run the **locally built** image so you test current `main`.

```bash
mkdir -p ../../hub-run && cp -r Hub/docker-compose.yml Hub/docker-compose.tls.yml Hub/deploy ../../hub-run/
cd ../../hub-run
```

Then:
1. **Compose override:** create `docker-compose.override.yml` that sets the image to `tsv/hub:dev` and adds these environment values:
   - `TS_SETUP_TOKEN=tsv-setup-token-0001`
   - `TS_ENV=development` (plain-HTTP cookies for local testing; note this in the report)
   - `TS_ALLOW_UNSIGNED_MANIFESTS` must stay **unset**: signature verification is part of the test.
2. **Start it:** `docker compose -p tsv-hub up -d`.
3. **Startup log:** confirm the startup lines: version, Sigstore verifier, GeoIP status, setup token.
4. **Setup and login,** via the API (`Docs/architecture/hub/backend/API.md`):
   - `POST /api/v2/setup` with `{"password":"…12+ chars…","hubEndpoint":"http://host.docker.internal:8080","setupToken":"tsv-setup-token-0001"}`;
   - `POST /login`, keeping the cookie jar.
5. **Negative auth tests:** a wrong setup token, a short password, 11 bad logins (lockout), and an API call without a cookie (401).
6. **MFA** (`Hub/internal/api/mfa.go`, `Docs/operations.md` §12):
   - enroll with `POST /api/v2/auth/mfa/setup` and `/enable`, computing TOTP codes in Python (RFC 6238, SHA-1, 6 digits, 30 s);
   - check that login now needs a code, that a code can't be replayed, and that a recovery code works exactly once;
   - then disable MFA.
   - Separately, restart with `TS_REQUIRE_MFA=true` and confirm an unenrolled login gets `403 mfa_enrollment_required` on normal endpoints.
7. **Read endpoints:** call every one and record the HTTP status and response shape:
   - `/api/v2/insights`, `/api/v2/sources`, `/api/v2/attack`, `/api/v2/attack/layer`, `/api/v2/path?source=…`, `/api/v2/report`;
   - `/api/v2/assets` (PUT a CIDR asset), `/api/v2/honeytokens` (and `?format=csv`), `/api/v2/beacons`, `/api/v2/geo`;
   - `/api/v2/system/updates`, `/api/v2/version`.
8. **Source lists:** set `whitelisted_sources` and `known_scanners` (CIDR plus an exact name) through `PATCH /api/v2/config`. Confirm that a bad CIDR returns `400`.

## Phase 6: GeoIP with the real DB-IP database

This could not be tested in the cloud: `download.db-ip.com` was unreachable there.
1. **Manual file:** download this month's `dbip-city-lite-YYYY-MM.mmdb.gz` from https://db-ip.com/db/download/ip-to-city-lite, gunzip it to `hub-run/truesignal_data/geoip/dbip-city-lite.mmdb`, and restart the Hub.
   - Expect the log line `[GeoIP] Loaded … (DBIP-City-Lite …)`.
   - `GET /api/v2/geo` should report `geoip.enabled=true` and a `buildDate`.
2. **Auto-update:** delete the file, set `TS_GEOIP_AUTO_UPDATE=true`, restart, and confirm the Hub downloads and loads it. Record the time taken and the file size.
3. **Overwrite safety:** with the Hub running, overwrite the file in place (`cp` an older or the same file over it), then query events and `/api/v2/geo`. The Hub must not crash.
4. **Real lookups:** post sensor events (Phase 7 node key) from `8.8.8.8`, `1.1.1.1`, `81.2.69.160`, `2a00:1450:4001::1`, `10.20.4.17` and `100.64.1.1`.
   - Check that `sourceGeo` appears on `GET /api/v2/events` for public addresses only.
   - Check the counts in `/api/v2/geo`.
   - Open the GeoIP Map page (Phase 11).

## Phase 7: node, compose rendering and the sensors

This exercises real Sigstore verification against the live registry.
1. **Node:** create one with `POST /api/v2/nodes` and keep its `apiKey`.
2. **Sensors:** add all **nine released sensors** to the node with `POST /api/v2/nodes/{id}/sensors`, using ids from `index.json`. Give them non-conflicting ports, using the `TS_SERVICES` env defaults from each manifest. Expect a `port_conflict` 422 if two clash: test that on purpose once.
3. **Render the compose:** fetch it the way a node does: `GET /api/v2/nodes/compose` with `Authorization: Bearer <node key>`. Inspect it:
   - every image is `@sha256:`-pinned;
   - `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`;
   - the reserved env vars are injected: `TS_HUB_KEY`, `TS_CAPTURE_HASH_KEY`, and `TS_HONEYTOKEN` for File Canary;
   - user-supplied overrides of reserved vars are dropped.
4. **Unsigned manifest:** try a sensor version that is in the registry but unsigned (an older first release). The Hub should refuse it. Record the error.
5. **Run the compose** on Docker Desktop: `docker compose -p tsv-node -f <rendered>.yml up -d`.
   - The sensors need `TS_HUB_ENDPOINT` to reach the Hub: `host.docker.internal:8080`.
   - With host networking on, the sensor ports are reachable from macOS on localhost.
   - Record which sensors start, which crash, and why. Raw-socket sensors may not work in Docker Desktop's VM; that is environment, not necessarily a bug, so explain which it is.
6. **Firedrill:** `docker kill -s USR1 <container>` for each sensor, which is what `truesignal firedrill` does. Each should produce a `source="Wizard Firedrill"` event.
7. **Real interactions:** hit each sensor and record the event it raises (trigger, severity, details, ATT&CK fields):
   - nc/telnet to the tarpit ports;
   - `ssh -p 2222 test@localhost`;
   - FTP and telnet logins;
   - `mysql`/`psql` client logins;
   - `curl` the web router: `/`, `/.env`, and a login POST;
   - `ldapsearch` simple bind to `ldap://localhost:389`;
   - `snmpget -c public` and `dig @localhost -p 53` (Network Service Decoy);
   - `ping` (ICMP canary);
   - `nmap -sS` from a container (scan detector);
   - touch or read a lure file (File Canary).
8. **Honeytoken:** read the planted credential from a File Canary lure (`TS_HONEYTOKEN` in the compose shows it), then use it against the SSH or MySQL decoy. A critical `honeytoken_used` event must follow, even if the source is whitelisted.
9. **Liveness:** stop one sensor container, then check for `sensor_stopped`, then `sensor_heartbeat_lost` after about 60 s, then `sensor_recovered` once it's back.
10. **Optional wizard path:** run the Linux wizard (`install.sh --link`) inside a privileged `ubuntu:24.04` container with `/var/run/docker.sock` mounted. Then run `truesignal apply`, `firedrill`, `discover --help` and `uninstall`, and record how far it gets. Mark it SKIPPED if it's impractical, and say why.

## Phase 8: beacons and the Token Receiver (unreleased)

The receiver image isn't published yet, so run the **local binary**: `cd Sensors/official/TokenReceiver && go build -o /tmp/tsv-receiver .`.
1. **Register it:** add `ts-sensor-token-receiver` to the node with `TS_BEACON_DOMAIN=t.example.test` and `TS_ANSWER_IPV4=127.0.0.1`. Because it isn't in the registry, the compose render may refuse it. That is expected: record it.
2. **Create beacons:** one each of `dns`, `web_bug` and `kubeconfig` via `POST /api/v2/beacons`, plus the download endpoint.
3. **Receiver key:** derive it from the Hub DB exactly as `Hub/internal/services/beacon/service.go` `deriveReceiverKey` does: HMAC-SHA256 of `"truesignal-beacon-receiver"`, keyed by `beacon_master_key` from the `config` table, as hex. Read the DB with `sqlite3 hub-run/truesignal_data/truesignal.db`.
4. **Run it:** with `TS_HUB_ENDPOINT=http://localhost:8080 TS_HUB_KEY=<node key> TS_SENSOR_ID=ts-sensor-token-receiver TS_BEACON_KEY=<derived> TS_BEACON_DOMAIN=t.example.test TS_ANSWER_IPV4=127.0.0.1 TS_SERVICES=dns:15353,http:18081 TS_TRUSTED_PROXIES=127.0.0.1`.
5. **DNS:**
   - `dig @127.0.0.1 -p 15353 <token>.t.example.test A`, plus `+tcp`, plus `+subnet=81.2.69.0/24`;
   - `dig … AAAA` (cooldown: no second event), `dig … www.t.example.test` (no event), `dig … example.org` (REFUSED), `dig … t.example.test NS` and `SOA`.
6. **HTTP:** `curl -H 'Host: t.example.test' -H 'X-Forwarded-For: 8.8.8.8' http://127.0.0.1:18081/static/<token>.gif`, and one request with no token (no event).
7. **kubectl (optional, needs sudo):** with my OK, create `/etc/resolver/t.example.test` containing `nameserver 127.0.0.1` and `port 15353`. Then run `kubectl --kubeconfig <downloaded file> get pods` and confirm the DNS beacon fires. Remove the resolver file afterwards.
8. **Expected Hub results:**
   - exactly one critical `beacon_triggered` per token and channel, with `details.beacon` (name and type);
   - beacon use counts updated on the Beacons page;
   - an unknown valid-format token goes to medium with `beacon_known=false`;
   - a whitelisted resolver still alerts.
9. **Robustness (gently, against localhost only):** open 300 idle TCP connections to 15353 and 18081. The receiver must stay responsive to a normal `dig` and `curl`, because it caps connections at 128 and 256.

## Phase 9: SIEM output

1. **Listener:** run a TCP listener on the Mac, for example `python3 -c` with a socket server writing to `siem-rfc5424.log`. Configure the Hub with `PATCH /api/v2/config` (`siemAddress=host.docker.internal:<port>`, `siemProtocol=tcp`, `siemFormat=rfc5424`), then trigger events.
2. **RFC 5424:** verify every field in `Docs/siem/soc-notice-2.3.0.md`:
   - `known_scanner`, `mitre_technique`, `mitre_tactic`, `source_asset`, `source_asset_criticality`, plus the newer `source_country`;
   - their order, that they're always present, and that they're empty when n/a;
   - the JSON body keys.
3. **ECS:** switch to `siemFormat=ecs` and verify:
   - `threat.*`, `truesignal.known_scanner`, `truesignal.source_asset`;
   - `source.geo.*`, only for `basis=source`; `truesignal.source_geo` for client-subnet beacons;
   - `event.kind=event` for scanner and whitelisted sources.
4. **Optional:** run Elasticsearch 8.x single-node in Docker with TLS (self-signed, `TS_SIEM_CA_FILE`), apply the index template from `Docs/siem-integration.md`, use `siemProtocol=elastic`, and confirm the documents index without mapping errors (`source.geo.location` as `geo_point`). SKIPPED is acceptable.

## Phase 10: TLS overlay and proxy trust

1. **Certificate:** generate a self-signed cert into `hub-run/deploy/tls/hub.crt` and `hub.key`.
2. **Start it:** `docker compose -p tsv-hub -f docker-compose.yml -f docker-compose.tls.yml -f docker-compose.override.yml up -d`, with `TS_HTTPS_PORT=8443` and `TS_HTTP_PORT=8081` to avoid needing root ports.
3. **Verify:**
   - HTTPS works and HSTS is present;
   - plain 8080 is no longer published;
   - a spoofed `X-Real-IP` through the proxy does **not** escape the login lockout;
   - the WebSocket (`/api/v2/ws`) upgrades with the session cookie;
   - a foreign `Origin` is refused. Run this check without `TS_ENV=development`.

## Phase 11: UI walkthrough (Playwright)

1. **Setup:** `npx playwright install chromium` in a scratch folder. Log in, then screenshot every page at 1440×900 in light **and** dark themes: Dashboard, Fleet, a node page, Attack Navigator, Attack Path (for a real source), Honeytokens, Beacons, GeoIP Map, Detected Scans, Assets, Reports (also print to PDF), Settings.
2. **Look for:**
   - overflow at 1440 px, especially the event table's Time column;
   - broken charts and console errors;
   - the DB-IP credit on the map;
   - antimeridian artefacts on the map;
   - empty states, and dark-mode contrast.
3. **Save the screenshots** under `ts-verify-work/screenshots/` and reference them in the report.

## Phase 12: upgrade and rollback

Follow `Docs/operations.md` §7.
1. **Start from the release:** a fresh data dir with `ghcr.io/mahmoudahmed3132/truesignal-hub:v2.2.0`. Do setup, then create a node and an asset.
2. **Upgrade:** switch to `tsv/hub:dev`.
   - Expect migration log lines, ending at schema v5 (beacons), and a `truesignal.db.pre-vN-*.bak` file.
   - Data from before the upgrade must be intact.
3. **Roll back:** start v2.2.0 against the upgraded DB; it must refuse to start. Then follow the documented restore from `.bak` and confirm v2.2.0 runs again.

## Phase 13: cleanup

Bring down every `tsv-*` project, stop the receiver, listener and any other processes you started, and remove any `/etc/resolver` files. List what you removed.

## Report format: `TrueSignal-verification-report.md`

````markdown
# TrueSignal verification report

- Date/time (UTC), machine (model, macOS, arch), Docker Desktop version + host-networking setting
- Repo HEAD: <sha> (<subject>); HubVersion / WizardVersion; sensor versions
- Tool versions: go, node, cosign, …

## Summary
| Phase | Result (PASS / FAIL / PARTIAL / SKIPPED) | Notes |
|---|---|---|
…one row per phase…

## Findings (most severe first)
For each:
### F<n>. <one-line title>  — severity: critical | high | medium | low
- Where: file:line (or endpoint / image)
- Repro: exact commands
- Expected vs actual (trimmed real output)
- Root cause (or best hypothesis, marked as such)
- Proposed fix (diff if small)

## Environment limits (not bugs)
- e.g. raw-socket sensors under Docker Desktop's VM, amd64-only images under emulation

## Evidence by phase
### Phase N — <name>
- Commands run (fenced)
- Key output (trimmed, real)
- Checks: ✅ / ❌ / ⏭ per item from the instructions

## Workarounds I applied
## Not tested and why
## Open questions for the owner
````

Keep the report factual and complete. If a check can't run, say exactly why. When you finish, print the report path and the summary table.
