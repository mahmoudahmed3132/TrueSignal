# TrueSignal Operations Guide

This guide covers the day-to-day operations and lifecycle management of your TrueSignal ecosystem. The UI is designed to be intuitive, but the concepts below clarify exactly how state is managed across your distributed nodes.

## 0. First Run (Hub Setup)

On first start the Hub prints a one-time setup token:

```text
[SETUP] Hub is not initialised. One-time setup token: <token>
```

Read it with `docker compose logs truesignal-hub`, open the UI and enter it with the admin password (12+ characters) and the Hub endpoint. For automated installs, set `TS_SETUP_TOKEN` yourself, or set `TS_DASHBOARD_PASSWORD` to skip setup entirely. Until setup is completed, anyone who can reach the Hub *and* knows the token can claim it, so complete setup before exposing the Hub.

Run the Hub behind an HTTPS reverse proxy. Leave `TS_ENV` unset (`production`) so the session cookie keeps its `Secure` flag; `TS_ENV=development` also disables the WebSocket origin check and is for local testing only.

## 1. Node Creation & Provisioning

A **Node** is any physical or virtual machine where you want to deploy deceptive sensors. 

1. **Create the Node:** In the TrueSignal Hub UI, navigate to the **Nodes** page and click "New Node". Give it a descriptive name (e.g., `DMZ-Web-Server`).
2. **Provisioning:** Once created, the Hub will generate a unique Node API Key and a setup command. **The key is shown only once.** The Hub stores only its SHA-256 hash, so it cannot show it again; if you lose it, rotate it (see §8).
3. **Link the Node:** SSH into your target machine and run the provided command. This command is an all-in-one script that installs the Setup Wizard on the host and immediately links the node to the Hub, establishing trust for its first deployment and all future deployment updates:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | TS_NODE_API_KEY=<key> bash -s -- --link <hub-url>
   ```
   The key is passed in the environment (`TS_NODE_API_KEY`) rather than as `--api-key`, so it does not show up in the process list. It still lands in your shell history; clear it if that matters.
4. **Pin the binary (recommended):** `install.sh` verifies the download against the release's `checksums.txt`, which detects corruption but not a tampered release. Add `--sha256 <expected-hash>` to require a specific binary hash obtained out of band.

## 2. Sensor Deployment

TrueSignal uses a declarative deployment model. You tell the Hub what you *want* the node to run, and the Hub compiles that desired state.

* **Assigning Sensors:** From the Hub UI, select a Node and browse the Registry. Choose the sensors you want to deploy (e.g., *TCP Tarpit*, *File Canary*) and configure their environment variables (like ports or trigger thresholds).
* **Desired State:** Once you assign a sensor, the Hub updates the Node's "Desired State." The sensor is not actively running on the host yet it is merely queued for deployment.

## 3. Node Synchronization (`apply`)

Because the Setup Wizard is an ephemeral, on-demand CLI tool rather than a constant 24/7 background agent, changes made in the UI must be explicitly pushed to the host.

* **Reconciliation:** To sync a Node, SSH into the target host and run:
  ```bash
  truesignal apply
  ```
* The Wizard will pull the latest compiled desired state from the Hub, compare it against the currently running Docker containers, and automatically spin up, reconfigure, or tear down sensors to match the Hub.
* If the Hub cannot compile the node's compose (a manifest is unavailable, fails validation, or an image is not digest-pinned), `apply` fails with the reason from the Hub's `422` response and the running sensors are left untouched.

> [!IMPORTANT]
> **Strict State Enforcement:** The `truesignal apply` command strictly enforces the configuration defined in the Hub. It does **not** perform local conflict resolution or template evaluation. If you manually configure a sensor to use port 8080 in the Hub UI, the node will blindly attempt to bind to 8080 even if that port is already in use by another application, resulting in a crash. It is the operator's responsibility to ensure manually configured settings are valid.
> Conversely, running the automated `truesignal discover` command directly on the host allows the wizard to proactively scan the environment, resolve port conflicts, and dynamically calculate a safe configuration before uploading it to the Hub.
>
> `discover` registers sensors with the Hub's dashboard API and therefore asks for the **Hub admin password on the node** (or reads `TS_DASHBOARD_PASSWORD`). Nodes are decoy hosts; treat that as exposing the admin password to the host. Where that is not acceptable, configure sensors in the UI and run only `truesignal apply` on the node.

## 4. Sensor Updates and Rollbacks

When community maintainers or official developers push a new version of a sensor to the Registry, you can manage the upgrade lifecycle directly from the UI.

1. **Updates:** If a newer version of an installed sensor is available, an "Update Available" badge will appear next to it on the Node page. Click the update button to queue the new version in the desired state. Run `truesignal apply` on the Node to execute the upgrade.
2. **Rollbacks:** The operator cannot perform a rollback independently. Rollbacks are managed by the core maintainers when a published update goes wrong. If a rollback is issued by the developers, it appears in the UI identically to an upgrade: an "Update Available" badge will appear, and clicking "Update" will actually revert the sensor to the older, stable version. The next `truesignal apply` will then seamlessly roll the container back.

## 5. Node Teardown

To cleanly remove TrueSignal from a host:

1. **Uninstall Sensors:** On the target host, run the teardown command:
   ```bash
   truesignal uninstall
   ```
   This action strictly targets TrueSignal resources. It will cleanly stop and remove the isolated Docker containers, delete the `/opt/truesignal` configuration directory, remove the node identity file at `/etc/truesignal/config.json`, and delete the CLI binary itself. It will **not** blindly wipe files or perform wide-ranging host cleanups, ensuring no important host data is ever accidentally deleted.

   **Lure files are left in place.** File Canary lures may sit next to real host files, so `uninstall` does not delete them; it prints the configured `TS_DECOY_FILES` paths at the end. Review and remove them yourself.
2. **Delete from Hub:** Return to the Hub UI and delete the Node. This revokes the Node's API Key immediately; it can never authenticate again. The node's **events are kept** (as are a removed sensor's), so its alert history remains available for investigation. Clear them explicitly from the Events page if you need to.

## 6. Updating the Setup Wizard

The Setup Wizard itself is updated independently from the sensors. The same curl script provided by the Hub to install the wizard can also be used to safely update it in place:

```bash
curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal/main/install.sh | bash
```

This will download the latest binary for your architecture and replace the existing installation without affecting any running sensors or node configurations.

## 7. Updating the Hub

Because the Hub is deployed as a standard Docker container, updating it is incredibly straightforward. You just need to pull the latest image and restart your compose stack. On the server hosting the Hub, run:

```bash
docker compose pull
docker compose up -d
```

This will cleanly restart the Hub with the newest release while preserving all of your persistent data, node identities, and configurations (which are safely stored in the mapped volumes).

In production, pin the release instead of tracking `latest`: `Hub/docker-compose.yml` reads the image tag from `TS_HUB_VERSION` (e.g. `TS_HUB_VERSION=v2.1.0 docker compose up -d`). `TS_PORT` in the shell sets the host port only; the Hub always listens on 8080 inside the container.

Schema migrations run automatically on boot and first write a `*.pre-vN-*.bak` snapshot next to the database. Migration v3 hashes existing node API keys and rebuilds the events table so events no longer depend on their sensor or node row; existing node keys keep working.

### Before an upgrade

1. Pin the current version so you can return to it: note `TS_HUB_VERSION` (or the running image digest: `docker inspect truesignal-hub --format '{{.Image}}'`).
2. Take an off-host copy of the data directory. The automatic `*.pre-vN-*.bak` sits on the same volume, so it does not survive losing the host. The database runs in WAL mode, so stop the Hub first and copy all three files:
   ```bash
   docker compose stop truesignal-hub
   tar czf truesignal-$(date -u +%Y%m%dT%H%M%SZ).tgz truesignal_data/truesignal.db*
   docker compose start truesignal-hub
   ```
   Treat the archive as secret: it holds the node-key hashes, webhook URLs, the SIEM token, the capture master key and the honeytoken secrets.
3. Upgrade: `TS_HUB_VERSION=vX.Y.Z docker compose pull && TS_HUB_VERSION=vX.Y.Z docker compose up -d`. The log shows `[DB] Running schema migration A -> B` when the schema changed, and a new `.bak` appears in `truesignal_data/`.

### Rolling back the Hub

**Case 1: the new version did not migrate the schema** (no `Running schema migration` line, no new `.bak`). Pin the old image and restart. Nothing else changes:
```bash
TS_HUB_VERSION=<old> docker compose up -d
```

**Case 2: the schema was migrated.** An older Hub refuses to start on a newer schema (`database schema version N is newer than supported version M`), so you must restore the pre-migration snapshot. Everything written after the upgrade is lost from the Hub: events, node and sensor changes, settings, key rotations, new honeytokens. The SIEM still has the events if forwarding was on; keep the post-upgrade database for evidence.
```bash
docker compose stop truesignal-hub
cd truesignal_data
mkdir -p ../rollback-evidence && mv truesignal.db truesignal.db-wal truesignal.db-shm ../rollback-evidence/ 2>/dev/null
cp truesignal.db.pre-v<M>-<timestamp>.bak truesignal.db   # the snapshot taken by this upgrade
cd ..
TS_HUB_VERSION=<old> docker compose up -d
```
Moving the `-wal`/`-shm` files away is required: SQLite would otherwise replay the newer database's write-ahead log onto the restored file and corrupt it.

After a Case 2 restore:
- **Node keys rotated after the snapshot are valid again**, and keys issued after it are gone. Rotate every key that was rotated or issued since the upgrade (`Rotate key`, then relink those nodes). Nodes deleted after the snapshot reappear; delete them again.
- **Honeytokens created after the snapshot are unknown to the Hub** but their lures stay on disk. Re-render those nodes' compose and run `truesignal apply` so the File Canary gets a token the Hub knows; delete the orphaned lures or note them as untracked.
- **Admin password and settings** revert to their state at the snapshot.
- Run `truesignal apply` on every node whose sensors changed after the upgrade.
- If the upgrade ran several migrations, use the `.bak` with the version you are returning to (`pre-v<M>` is the schema the old Hub expects).

> [!WARNING]
> **Major Version Upgrades:** While minor and patch updates (e.g., `v2.0.1` to `v2.0.4`) are safe to pull automatically, **Major** version bumps (e.g., `v2.x` to `v3.0`) often contain breaking changes, database schema migrations, or new environment variables. Always read the [GitHub Release Notes](https://github.com/mahmoudahmed3132/TrueSignal/releases) before pulling a major version to ensure you do not corrupt your Hub instance.

## 8. Rotating a Node API Key

Rotate a node's key if it may have been exposed (shell history, a copied compose file, a decommissioned admin laptop) or on your regular credential-rotation schedule.

1. In the Hub UI open the node, open its API key dialog and choose **Rotate Key** (or `POST /api/v2/nodes/{nodeId}/rotate-key`). The new key is shown once. The old key stops working immediately, so the node's sensors start getting `401` until step 3.
2. On the node, run `sudo truesignal relink`, choose **Link to existing node**, and paste the new key.
3. Run `sudo truesignal apply`. This rewrites the compose file with the new `TS_HUB_KEY` and restarts the sensors.

## 9. Liveness Alerts

Sensor liveness is reported through the normal event pipeline, so it reaches the SIEM and (for severities listed in `webhookEvents`) webhooks:

| Event | Severity | When |
|---|---|---|
| `sensor_stopped` | `low` | A sensor shut down gracefully (container stop, `apply` replacing it). |
| `sensor_heartbeat_lost` | `high` | A sensor that was online sent no heartbeat for 60 s, or a stopped sensor did not come back within 5 minutes. |
| `sensor_recovered` | `info` | A sensor that was offline sent a heartbeat again. |

A killed or stopped decoy is therefore visible in the SIEM. Sensors that were added but never deployed do not alert. Build a SIEM rule on `sensor_heartbeat_lost` rather than on `sensor_stopped`, which also fires on routine redeploys.

## 10. Honeytokens

Every File Canary instance plants a credential the Hub fabricates for it. Any later use of that credential against a TrueSignal decoy raises a critical `honeytoken_used` event that names the lure's node and sensor. Lure access only shows that a file was read; this shows the stolen credential being used, and where it was stolen from.

- **Planting:** when the Hub first renders a node's compose, it creates one honeytoken per File Canary instance: a username such as `svc_reports97ef` and a random password. It passes them as `TS_HONEYTOKEN`. The provisioner writes them into lures it **creates** (`.env` `DB_USERNAME`/`DB_PASSWORD`, `wp-config`-style PHP, `.pgpass`, the restore line of an SQL dump, a VPN config comment, generic backups). Existing host files used as tripwires are never modified, so they carry no token. The token is stable: redeploying does not change it.
- **Detection:** the Hub matches every incoming event:
  - **Username**, case-insensitive, after reducing `DOMAIN\user`, `user@realm` and the `CN=`/`UID=` of a bind DN. This also covers RDP `mstshash` and LDAP/RDP NTLM captures, which carry no password.
  - **Password**, by keyed HMAC. The Hub owns a master key (`capture_master_key`, generated on first use) that never leaves it. Each node's password-hashing decoys (Identity Decoy, Web Router Decoy) get `TS_CAPTURE_HASH_KEY = HMAC(master, node ID)`, a key valid for that node only. A value set in the UI is ignored. For each event, the Hub re-derives the reporting node's key, checks `hmac_key_id`, and compares the HMAC of every honeytoken's secret under that key. A planted credential is therefore recognised on any node. `TS_CAPTURE_PASSWORDS=plain` captures are compared directly.
- **Inventory:** `GET /api/v2/honeytokens` lists each token with where it was planted, its use count and when it was last used. `?format=csv` returns a watchlist file.
- **Real systems (AD, VPN, endpoints, databases):** the Hub publishes every honeytoken (username and planting location, never the password) to the configured SIEM output: on creation, at start and every 24 h (`MSGID HONEYTOKEN` / ECS `truesignal.honeytoken`). `Docs/siem/honeytoken-detection.md` has an importable Elastic indicator-match rule, the LogScale/Falcon query, and the audit policy that makes the logins visible.
- **Key exposure:** root on a node yields only that node's derived key. It can be used to dictionary-test password HMACs that node itself captured, which an attacker with root there could already intercept, and nothing captured on other nodes. Only the Hub holds the master key, so the Hub database (which also holds the honeytoken secrets) is the asset to protect.
- **Lifecycle:** honeytokens and the master key survive node and sensor deletion and a factory reset, because the lures that carry them stay on disk (uninstall never deletes lures). Re-linked nodes keep being protected by the old lures. To retire them deliberately, delete the lure files first, then reset with `purgeHoneytokens: true`. That also rotates the master key.

## 11. TLS in front of the Hub

The Hub serves plain HTTP. In production put a TLS proxy in front of it and make the Hub trust forwarding headers from that proxy only:

| Variable | Set to |
|---|---|
| `TS_TRUST_PROXY` | `true` |
| `TS_TRUSTED_PROXIES` | the proxy's address(es) as seen by the Hub, comma-separated IPs/CIDRs (e.g. the F5 SNAT self-IPs of both HA units). Without it, any client that reaches the Hub directly can forge `X-Real-IP` to dodge the login lockout and poison the audit log; the Hub warns at startup. An invalid entry stops the Hub. |
| `TS_BIND_ADDR` | (external proxy only) the Hub host's address on the proxy-facing network, so port 8080 is not reachable elsewhere |

Set the Hub endpoint (Settings, and what nodes link to) to the `https://` URL. Nodes and sensors use the same endpoint, so they go through the proxy too.

### Bundled nginx (`Hub/docker-compose.tls.yml`)

```bash
cd Hub
mkdir -p deploy/tls && cp hub.crt deploy/tls/hub.crt && cp hub.key deploy/tls/hub.key
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d
```

The overlay runs a digest-pinned unprivileged nginx (`Hub/deploy/nginx/truesignal.conf`): read-only, no capabilities, TLS 1.2/1.3 with ECDHE AEAD suites, HSTS, HTTP→HTTPS redirect, WebSocket pass-through for `/api/v2/ws`. The Hub's own port is no longer published, the proxy and the Hub have fixed addresses (`TS_PROXY_IP`, default `172.30.80.2`, and `TS_HUB_IP`, default `172.30.80.3`, in `TS_PROXY_SUBNET` `172.30.80.0/29`; the Hub is pinned too, or it would take `.2` first and the proxy could not start), and `TS_TRUSTED_PROXIES` is set to it. The proxy overwrites `X-Real-IP`/`X-Forwarded-For` with the TCP peer, so client-supplied values never reach the Hub. Requires Docker Compose 2.24+.

If you edit the config: nginx drops every server-level `proxy_set_header` in a location that sets any of its own, which is why the forwarding headers are repeated in each `location`. Keep `Host` as `$http_host` (with port) or the WebSocket origin check rejects the dashboard on a non-443 port.

### F5 BIG-IP

- **Virtual server** on 443 with a client SSL profile (TLS 1.2+; set `No TLSv1` and `No TLSv1.1`), pool member `<hub>:8080` over HTTP, SNAT automap or a SNAT pool. Run the Hub with `TS_BIND_ADDR` set to the interface the pool member address is on.
- **WebSocket:** attach a WebSocket profile to the virtual server (with the HTTP profile). Keep the TCP idle timeout above 60 s; the Hub pings every 20 s.
- **Forwarding headers: use an iRule, not the HTTP profile's "Insert X-Forwarded-For".** The profile adds a second header and the client's own `X-Forwarded-For` and `X-Real-IP` still pass through; the Hub reads `X-Real-IP` first. Replace them:
  ```tcl
  when HTTP_REQUEST {
      # Strip any route-domain suffix (10.1.1.1%2), which the Hub cannot parse.
      set client [getfield [IP::client_addr] "%" 1]
      HTTP::header remove X-Real-IP
      HTTP::header remove X-Forwarded-For
      HTTP::header remove X-Forwarded-Host
      HTTP::header insert X-Real-IP $client
      HTTP::header insert X-Forwarded-For $client
      HTTP::header replace X-Forwarded-Proto https
  }
  ```
- **`TS_TRUSTED_PROXIES`** = the self-IPs the BIG-IP uses as SNAT source towards the Hub (both units of an HA pair, or the SNAT pool). The Host header is passed unchanged, which the WebSocket origin check needs.
- **Monitor:** HTTP `GET /api/v2/version`, receive string `"version"`. It needs no authentication.
- If a WAF policy (ASM/Advanced WAF) sits on the virtual server, exempt `/api/v2/event` and `/api/v2/heartbeat` from body-content signatures: sensor events carry attacker payloads by design and would otherwise be blocked, which silently drops alerts.

## 12. Admin MFA

The dashboard admin can add a time-based one-time code (TOTP, RFC 6238: 6 digits, 30 s) from any authenticator app to the sign-in. PCI DSS 8.4 expects MFA for administrative access to systems in or connected to the CDE.

- **Enable:** Settings → Security & Access → Two-Factor Authentication → *Enable MFA*. Re-enter the password, scan the QR code (or type the key), confirm with a code. Save the 10 recovery codes shown once; each signs in once. The Hub keeps only their hashes.
- **Sign-in:** password, then the code (or a recovery code). A code works once: a captured code cannot be replayed, even within its 30 s window.
- **Brute force:** wrong codes count towards the 10-attempt per-IP lockout, and 10 wrong codes from any mix of sources lock MFA for 15 minutes.
- **Changes:** disabling MFA and issuing new recovery codes need the password and a current code, so a stolen session cannot turn MFA off or replace the authenticator. Every change is in the audit trail (Hub log and SIEM).
- **Enforce:** `TS_REQUIRE_MFA=true`. An admin without MFA can sign in only to enroll; every other endpoint returns `403 mfa_enrollment_required` until enrollment completes. MFA cannot be disabled while this is set.
- **Wizard:** commands that use the dashboard password (`link` with provisioning, `discover`) ask for the code. For a scripted run, set `TS_DASHBOARD_MFA_CODE` to a current code just before. Wizard 2.2.0 or later is needed; older wizards fail to sign in to a Hub with MFA.
- **Lost authenticator and recovery codes:** from the Hub host,
  ```bash
  docker compose run --rm truesignal-hub /app/truesignal-hub mfa-reset
  docker compose restart truesignal-hub
  ```
  This removes MFA (the password still applies) and sends an `MFA RESET` audit record to the SIEM when the Hub starts. Anyone who can run it already controls the Hub database; alert on that audit record.
- A factory reset clears MFA together with the admin account.

## 13. Signed releases (Sigstore)

Every release artifact is signed in CI with Sigstore keyless signing. A short-lived certificate is bound to this repository's publish workflow at the release tag, and every signature is recorded in the public Rekor transparency log. There is no private key to store or leak.

**What the Hub enforces.** Before using any registry manifest, the Hub downloads `<sensor>-v<version>.json.sigstore.json` next to it and verifies it offline against the Sigstore trusted root built into the Hub. It pins the signer to exactly:

```
https://github.com/mahmoudahmed3132/TrueSignal/.github/workflows/publish-sensor-registry.yml@refs/tags/sensor/<sensor>/v<version>
issuer https://token.actions.githubusercontent.com
```

It also requires a CT-logged certificate, a Rekor entry and a verified timestamp. A manifest that is unsigned, modified, signed by another repository or workflow, signed from a branch, or replayed under another sensor name or version is skipped and logged. A node that uses it then gets no compose. The manifest pins its image by `@sha256` digest, so the signature also covers the image the node runs. Docker on the nodes needs no extra tooling.

| Variable | Effect |
|---|---|
| `TS_MANIFEST_SIGNER_REPO` | `owner/name` whose publish workflow must have signed (default `mahmoudahmed3132/TrueSignal`). Set it if you fork and publish your own registry. |
| `TS_SIGSTORE_TRUSTED_ROOT` | Path to a newer Sigstore `trusted_root.json`, when Sigstore rotates keys before a Hub release ships the new root. |
| `TS_ALLOW_UNSIGNED_MANIFESTS=true` | Turns verification off (logged as a warning). Development, or a mirror you sign yourself, only. |

Manifests published before 2026-10-24's signing release (sensor 2.0.x/2.1.x as first released) carry no bundle. A Hub with verification on only uses the re-released signed versions. Publish those before upgrading the Hub; this release bumps every sensor's patch version for that.

**Verify by hand** (`cosign` 2.4+; `REPO=mahmoudahmed3132/TrueSignal`):

```bash
# A sensor manifest from the registry
cosign verify-blob --bundle tcp-tarpit-v2.0.3.json.sigstore.json \
  --certificate-identity "https://github.com/$REPO/.github/workflows/publish-sensor-registry.yml@refs/tags/sensor/tcp-tarpit/v2.0.3" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com tcp-tarpit-v2.0.3.json

# A sensor or Hub image, by digest
cosign verify ghcr.io/mahmoudahmed3132/truesignal-tcptarpit@sha256:<digest> \
  --certificate-identity-regexp "^https://github.com/$REPO/.github/workflows/publish-sensor-registry.yml@refs/tags/sensor/" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify ghcr.io/mahmoudahmed3132/truesignal-hub@sha256:<digest> \
  --certificate-identity "https://github.com/$REPO/.github/workflows/publish-hub.yml@refs/tags/hub/v2.3.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# The wizard binary (release assets include <file>.sigstore.json)
cosign verify-blob --bundle truesignal-linux-amd64.sigstore.json \
  --certificate-identity "https://github.com/$REPO/.github/workflows/publish-wizard.yml@refs/tags/wizard/v2.2.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com truesignal-linux-amd64
```

**What it does not cover.** Anyone who can push a `sensor/*` tag to this repository can still get a release signed, because the publish workflow runs on any such tag. Close that gap in GitHub: add a tag ruleset restricting who may create `sensor/*`, `hub/*` and `wizard/*` tags, and require reviews on `main` and on `.github/workflows/`. Alert on unexpected signatures under this identity in the Rekor log; the Sigstore `rekor-monitor` can do this.


## 14. Beacons (callback tokens)

Beacons are artifacts the Hub generates for you to plant where only an intruder would use them. Using one makes a DNS lookup or HTTP request to a **Token Receiver**, which raises a critical `beacon_triggered` event. Unlike the decoys, a beacon fires wherever the artifact is opened, including outside the network, so the receiver faces the internet. The Hub never does.

| Type | What you plant | What fires it |
|---|---|---|
| DNS name | `<token>.<zone>` in SSH configs, `.env` files, inventories, scripts | any resolution of the name, through any resolver |
| Web bug | `<img src="http://<zone>/static/<token>.gif">` in an HTML page, e-mail or document | loading the image (clients that block remote images don't fire) |
| Kubeconfig | a kubeconfig whose API server is `https://<token>.<zone>:6443` | `kubectl` resolving the server name (it then fails to connect) |

**Deploy the receiver** (once):
1. Create a node in a DMZ for the receiver alone. Link it as usual. It needs outbound HTTPS to the Hub's sensor API (`/api/v2/event`, `/api/v2/heartbeat`) and nothing else outbound. **[NOT IN PROJECT]**: the DMZ, the address and the Palo Alto/Fortinet rule.
2. Choose a zone that does not name TrueSignal or the company's security tooling, e.g. `cdn-assets.example.com`. In the parent zone, delegate it to the receiver: `cdn-assets  NS  ns1.cdn-assets.example.com.` plus a glue A record `ns1.cdn-assets.example.com  A  <receiver public IP>`.
3. Allow udp/53, tcp/53 and tcp/80 inbound from the internet to that node only.
4. In the Hub, add the **Token Receiver** sensor to the node with `TS_BEACON_DOMAIN=cdn-assets.example.com` and `TS_ANSWER_IPV4=<receiver public IP>` (needed for web bugs), then `truesignal apply`. The Hub injects `TS_BEACON_KEY`.
5. Check the delegation from outside: `dig +trace anything.cdn-assets.example.com` ends at the receiver with an authoritative answer.
6. For HTTPS web bugs, terminate TLS on a front end (F5) with a certificate for the zone, forward to tcp/80, and set `TS_TRUSTED_PROXIES` to the front end so the client address comes from `X-Forwarded-For`.

**Create and plant:** Hub → **Beacons** → type, a name saying where it will be planted (that name is what the alert shows), optional memo → **Create**, then copy the value or download the file. Plant it, and record the location in your change process.

**What an alert means:**
- DNS: `source` is the **resolver**, often a public or ISP resolver, not the attacker. `details.client_subnet` is the client's network when the resolver sends EDNS Client Subnet. Expect it rarely: Cloudflare never sends it, and Google sends it only to name servers that echo ECS back, which the receiver does not do yet. An internal resolver as the source means the lookup came from inside.
- HTTP: `source` is the client, `details.user_agent` names the application (Office, Outlook, a browser).
- Mail and security gateways, link scanners and sandboxes also resolve names and fetch images. A web bug in an e-mail can fire on delivery, not only on opening. Plant web bugs in documents at rest rather than in mail that crosses a gateway, and expect `user_agent` to tell scanners from people.
- One event per token and channel per `TS_ALERT_COOLDOWN` (60 s); repeats are counted in `repeats_since_last`.
- `beacon_known: false` (severity `medium`) is a valid token the Hub no longer has: a deleted beacon that was not removed from where it was planted, or an event forged by someone holding the receiver's keys.

**Lifecycle:** beacons and their master key (`beacon_master_key`) survive receiver redeploys, node deletion and a factory reset. Every receiver gets the same derived key, so a second receiver (a second NS for redundancy) needs no change to existing beacons. `purgeHoneytokens: true` on a factory reset deletes beacons and rotates the key, so every planted beacon goes silent. Remove the artifacts first.

**Not built yet:** Word/Excel documents, AWS keys, `.bashrc`/batch beacons, MySQL dumps, cloned-site beacons, GeoIP enrichment and the map (DB-IP Lite, next).

## 15. GeoIP enrichment and the map

The Hub can place public source addresses on a map and in the SIEM feed, using DB-IP's free **IP to City Lite** database (MMDB, monthly, CC BY 4.0).

**What gets located:**
- Only public addresses. Private, CGNAT (100.64/10), loopback, link-local and ULA sources are never looked up. The decoys live in internal space, so most decoy hits stay unmapped. The map fills from beacons opened outside and from any decoy reachable from public addresses.
- A DNS beacon carrying an EDNS Client Subnet is placed by that subnet (`basis: client_subnet`), not by the resolver that reported it.
- Lookups happen when events are read or forwarded. Nothing is stored, so a database update re-places past events too.

**Enable it.** Choose one:
- **Operator-supplied file (no Hub egress):** download `dbip-city-lite-YYYY-MM.mmdb.gz` from db-ip.com, unzip it to `truesignal_data/geoip/dbip-city-lite.mmdb` (the Hub's `/data/geoip/`), or point `TS_GEOIP_DB` at it. The Hub loads it at start and re-checks the file hourly. Replacing it in place is safe, because the Hub reads a private copy.
- **Hub auto-update:** set `TS_GEOIP_AUTO_UPDATE=true`.
  - The Hub fetches the current month's file from `https://download.db-ip.com/free/` at start and daily until it has that month's file. With no database at all, it falls back to the previous month's file.
  - This needs outbound HTTPS to `download.db-ip.com` (about 60 MB a month). DB-IP publishes no signature, so the file is trusted to TLS. It must still open as a City database before it replaces the current one, and a bad download leaves the old one in use.
  - Failures show on the map page and in the log.

**Where it appears:**
- **Map page** (sidebar): points per place, coloured by the highest severity there, with countries shaded by event count. Selecting a point lists its sources, each linking to Attack Path.
- **Event details:** the source's location.
- **SIEM:** ECS `source.geo.*` and `truesignal.source_geo`; syslog `source_country` and `"source_geo"` (`Docs/siem-integration.md`).

**Accuracy:** GeoIP is approximate. City-level placement of consumer and mobile ranges is often wrong, and VPN, Tor and cloud egress addresses show the provider's location. Treat the map as triage context, not attribution.

**Licence:** CC BY 4.0 requires crediting DB-IP wherever the data is shown. The map page does this ("IP Geolocation by DB-IP"). Keep the credit in screenshots and reports you share. MaxMind GeoLite2 files share the MMDB format and also load, but their EULA has its own terms (account, 30-day refresh, no redistribution), and the Hub's auto-update only fetches DB-IP.
