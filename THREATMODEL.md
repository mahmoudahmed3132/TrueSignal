# THREAT MODEL - TrueSignal

## 1. System Overview

TrueSignal is a decentralized sensor deployment system. For a deep dive into the architecture and data flows, see the [Architecture Overview](Docs/architecture/README.md). From a security perspective, the system is composed of:

- **Hub:** The central orchestrator, policy engine, and trust anchor.
- **Wizard:** An untrusted local CLI tool that discovers host services and requests deployment intents.
- **Manifests:** Untrusted, external JSON definitions that describe sensor behaviors.
- **Sensors:** Untrusted runtime containers executing within a sandboxed Docker environment.

---

## 2. Trust Boundaries & Assumptions

### 2.1 Hub (Trust Anchor & Root Authority)
The Hub is the ONLY enforcement point for deployment safety. It is responsible for rejecting unsafe manifests, enforcing deterministic compilation, and producing the final deployment artifacts.
* **Assumption:** The Hub is secure at the time of operation, runs in a controlled environment, and is protected by OS controls and reverse proxies. If compromised, future generated deployments may be malicious, though existing runtime executions are not directly affected.

### 2.2 Wizard (Untrusted Local Component)
The Wizard operates on the target host to observe state and generate deployment intents (modified manifests bindings).
* **Assumption:** The Wizard is fundamentally untrusted and may be locally compromised. It may leak environment metadata or submit altered deployment requests. Therefore, all Wizard outputs are treated as attacker-controllable input by the Hub.

### 2.3 Manifests (High-Risk Input DSL)
External sensor definitions dictate container images, capabilities, and mounts.
* **Assumption:** Manifests are fully attacker-controllable. Schema validity does *not* imply safety. Every field must be explicitly validated by the Hub.

### 2.4 Execution Boundary (Docker Runtime)
Sensors execute as isolated containers.
* **Assumption:** Docker isolation is not absolute security. Host systems may be compromised, and containers are treated as potentially hostile execution units requiring least-privilege configurations. To minimize post-compromise attacker capabilities, official components and sensors use minimal, shell-less "Distroless" base images.

---

## 3. Threat Analysis

### T1: Manifest & Supply Chain Compromise
**Attacker Capability:** Modifies sensor manifests at the registry, supplies malicious definitions, or alters container images in the registry.

**Impact:** Unsafe privilege requests, malicious configurations, or execution of compromised binaries within the sensor runtime.

* **Mitigations (IMPLEMENTED):**
  * Strict typed schema enforcement: per-version manifests are decoded with `DisallowUnknownFields` and a 1 MB size cap, and the manifest's `id`/`version` must match what was requested (`Hub/internal/services/compose/service.go`, `Hub/internal/compose/security`). The registry index is size-capped (4 MB) but not strictly decoded (`Hub/internal/catalog/service.go`).
  * Sensor IDs and versions are validated against strict patterns before they are used to build registry URLs.
  * Hub-side normalization prior to compilation.
  * Interpolation rejection (`$`, `{{`) in image, network, volume and init-command fields. Env var *defaults* are intentionally Go templates rendered by the Wizard, and `$` in env values is escaped to `$$` in the generated compose so Docker never interpolates it (`Hub/internal/compose/builder.go`).
  * Strict version pinning for historical manifests (prevents tag-overwriting and cache poisoning).
  * **Image digest pinning is enforced.** Every main and init image must carry a `sha256:` digest or compose generation fails with `422 invalid_manifest` (`security.RequirePinnedImages`). `TS_ALLOW_UNPINNED_IMAGES=true` disables this for local development only; the Hub logs a warning at startup.
  * **Fail closed.** If any installed sensor's manifest is unavailable or invalid, no compose is produced (rather than a compose silently missing that decoy).
* **Gaps (NOT IMPLEMENTED):**
  * Cryptographic manifest and image signature verification (e.g. cosign). Digest pinning proves the node runs the image the manifest names; it does not prove who published the manifest. Anyone who can write the registry branch or push a `sensor/*` tag controls what nodes run.
  * Provenance tracking / SBOM.

### T2: Wizard Misdirection & Deployment Intent Manipulation
**Attacker Capability:** Compromises the local Wizard to alter deployment requests, inject unsafe environment variables, or submit misleading local infrastructure state.

**Impact:** Leakage of local metadata, incorrect sensor recommendations, or subtle privilege escalation via configuration injection.

* **Mitigations (IMPLEMENTED):**
  * Hub treats *all* Wizard-generated deployment intents as fully untrusted.
  * Full re-validation of all manifests and overrides at the Hub compile stage.
  * Port range validation prevents local DoS from malformed `/proc` state.
* **Known weakness:** `truesignal discover` registers sensors through the dashboard API and therefore prompts for the **Hub admin password on the node** (or reads `TS_DASHBOARD_PASSWORD`). A node is a decoy host and should be assumed compromisable; typing the admin password there exposes it. Prefer configuring sensors in the dashboard and running only `truesignal apply` on nodes.

### T3: Privilege Escalation via Sensor Specification Abuse
**Attacker Capability:** Attempts unsafe container configurations via manifest injection (e.g., requesting dangerous capabilities, exploiting host network namespaces, defining unsafe mounts, or misusing init containers).

**Impact:** Host compromise via container escape paths, unauthorized filesystem access, or lateral network movement.

* **Mitigations (IMPLEMENTED):**
  * Capability allowlist: only `NET_RAW`, `NET_BIND_SERVICE` and `DAC_OVERRIDE`; everything else is dropped (`cap_drop: [ALL]`). `NET_ADMIN` is not allowed: combined with the host network namespace it would grant control of host routing and firewall rules (`Hub/internal/compose/security/validate.go`).
  * `network_mode` limited to `host`, `bridge` or `none` (no `container:`/`service:` namespace joining).
  * Mount validation: paths must be absolute, free of control characters, and not `/`. Forbidden prefixes: `/var/run`, `/run` (Docker/containerd sockets), `/proc`, `/sys`, `/dev`, `/boot`, `/etc`, `/root`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`. Paths are cleaned before matching, so `..` traversal is caught.
  * Read-only root filesystem enforcement for main sensor containers.
  * Security-opt enforcement (`no-new-privileges`).
  * **Init containers get the same baseline:** `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, and `network_mode: none` (provisioning never needs egress) (`Hub/internal/compose/builder.go`).
  * Distroless execution environments (no shell, package manager, or standard utilities) for all official Hub and Sensor images.
  * Dynamic volume path validation during Compose generation (each file and its parent directory).

* **Mitigations (PARTIAL):**
  * Init containers may still run as `0:0` with `DAC_OVERRIDE`, and dynamic lure binds mount each lure's **parent directory read-write** so the provisioner can create the file. A lure under, say, `/home/<user>/` gives the provisioner write access to that whole directory.
  * `user` is not restricted: four of the five official sensors run as `0:0` in the host network namespace because they need raw sockets or low ports on the host's real interfaces. The capability set is minimal, but a sensor compromise is a root process in the host netns.
* **Gaps (NOT IMPLEMENTED):**
  * Strict command checking for `init-provisioner` containers.
  * Mount allowlisting (the control is a denylist; `/home`, `/opt`, `/srv`, `/var/lib/*` outside the listed runtimes are allowed).

### T4: Hub Compromise (Root Trust Failure)
**Attacker Capability:** Modifies the central validation logic, Compose compiler behavior, or signing policies, or takes over the admin account.

**Impact:** Malicious generation of future deployment artifacts and systemic bypass of validation rules.

* **Mitigations (IMPLEMENTED):**
  * Hub runs in a least-privilege, distroless Docker container (sandboxed execution).
  * **First-run claim protection:** `POST /api/v2/setup` requires a one-time setup token printed in the Hub log (or set via `TS_SETUP_TOKEN`), so the first network caller cannot claim an uninitialised Hub (`Hub/internal/services/config/service.go`).
  * Admin password: bcrypt, minimum 12 characters; login is rate limited with lockout.
  * Sessions: 12h absolute lifetime and 15-minute idle timeout (`TS_SESSION_TTL`, `TS_SESSION_IDLE_TIMEOUT`); `HttpOnly`, `SameSite=Strict`, `Secure` in production.
  * WebSocket handshakes must come from the Hub's own origin in production (`Hub/internal/services/websocket/service.go`).
  * HTTP server timeouts and body limits (1 MB UI, 256 KB agent) against slow-read and oversized-body abuse.
  * **Audit trail:** every state-changing dashboard request, login, logout and setup call is logged and, when a SIEM is configured, forwarded as an RFC 5424 `AUDIT` record with action, route, status and client IP (`Hub/internal/api/middleware.go`, `Hub/internal/services/siem/service.go`).
  * **Blinding is visible:** whitelisted sources are no longer dropped; their events are stored (archived) and still forwarded to the SIEM flagged `whitelisted=true`. Removing a sensor or deleting a node keeps its events (the events table has no foreign key cascade) (`Hub/internal/services/event/service.go`, `Hub/internal/store/migrations.go` v3).
* **Gaps (NOT IMPLEMENTED):**
  * Signed deployment artifact enforcement (planned).
  * Single admin account: no RBAC, no MFA. Disarm, silence, whitelist and "delete all events" are available to that one account (they are audited, not prevented).
  * The Hub serves plain HTTP. TLS must be terminated by a reverse proxy in front of it; no proxy configuration ships with the repo.
  * Audit records are not persisted in the Hub database; without a SIEM they exist only in the container log.

### T5: Node Authentication Compromise
**Attacker Capability:** Steals node identity API keys to deploy unapproved sensors on compromised nodes or flood the Hub with fake telemetry.

**Impact:** Audit log confusion, false positive alerts, or Hub Denial of Service (DoS).

* **Mitigations (IMPLEMENTED):**
  * Node API Key Rate Limiting: Token bucket rate limit (100 req/min) enforced on all API endpoints to prevent high-volume DoS. UI login rate limiting is also active.
  * **Keys hashed at rest:** node keys are stored as `sha256:<hex>`; the plaintext is shown once at creation or rotation and is never returned by the API afterwards (`Hub/internal/store/nodes.go`). Migration v3 hashed existing keys.
  * **Rotation and revocation:** `POST /api/v2/nodes/{id}/rotate-key` issues a new key; rotation, node deletion and factory reset evict the Hub's auth cache immediately (`Hub/internal/services/auth/service.go`).
  * Keys are accepted only in headers, never in the query string.
  * Events and heartbeats are accepted only for sensors registered on the authenticated node. Server-side fields (`nodeId`, `timestamp`, read/archive state) are set by the Hub; severity is normalised; string fields and `details` are size-capped.
  * The installer and Wizard accept the key via `TS_NODE_API_KEY` so it does not appear in the process list.
  * SIEM output escapes RFC 5424 SD-PARAM values and strips control characters, so attacker-controlled `source`/`target` strings cannot forge syslog fields or records. `siemProtocol: tls` encrypts the feed. The `elastic`/`logscale` HTTP outputs require HTTPS with certificate verification, never follow redirects (the token cannot be bounced to another host), and the token is write-only through the API.
* **Residual risk:** keys are per node, not per sensor. Anyone holding a node's key (it is in `/etc/truesignal/config.json` and in every sensor container's environment on that node) can forge events for any sensor registered on that node.

### T6: Sensitive Data Captured by Decoys
**Attacker Capability:** An attacker, or a staff member by mistake, types real credentials into a decoy login page.

**Impact:** Real secrets stored in the Hub database, UI, JSON export and SIEM.

* **Mitigations (IMPLEMENTED):**
  * The Web Router Decoy defaults to `TS_CAPTURE_PASSWORDS=hash`: it records a keyed HMAC-SHA256 (`attempted_password_hmac`, plus `attempted_password_length` and `hmac_key_id`), not the password. The key is `TS_CAPTURE_HASH_KEY` if set, otherwise derived from the node key, which the Hub stores only as a hash (`Sensors/official/WebRouterDecoy/main.go` `passwordHashKey`). `none` records only whether one was submitted; `plain` restores cleartext capture and should only be used where that data handling is approved.
* **Residual risk:** anyone holding the HMAC key (the decoy host, or the Hub if `TS_CAPTURE_HASH_KEY` is set through the UI) can dictionary-test captured values. Treat the field as sensitive. Default event retention is unlimited; set `autoPurgeDays`.

---

## 4. Risk Register (Accepted Risks)

The following risks represent known architectural trade-offs or constraints that are explicitly formally accepted:

### Risk-01: Post-Delivery Compose Tampering
A compromised local Wizard could bypass Hub validation entirely by ignoring the `truesignal-compose.yml` returned by the Hub, instead executing a locally crafted, malicious compose file.
* **Why it is accepted:** Hub validation guarantees the safety of what it *generates*, not what the host *chooses to run*. Exploiting this requires write access to the filesystem and access to the Docker socket. An attacker with these privileges already possesses equivalent root-level control of the host. Thus, TrueSignal-specific controls are no longer the relevant security boundary; it is a general host-security failure.

### Risk-02: Bootstrap Credential Exposure
During the initial host provisioning link, the operator supplies the node API key. Passing it with `--api-key` exposes it in `ps` output and shell history; passing it via `TS_NODE_API_KEY` (what the dashboard's install command does) keeps it out of the process list, but it still lands in the operator's shell history.
* **Why it is accepted:** This is a one-time bootstrap operation, standard for unattended deployments, and assumed to occur within a controlled environment prior to active hostile presence. After initialization, credentials are read from root-only (0600) configuration files. If exposure is suspected, rotate the key.

### Risk-03: Unsigned Distribution Channel
The installer is fetched with `curl | sh`, and wizard binaries are verified only against a `checksums.txt` from the same release. Manifests and images are digest-pinned but unsigned.
* **Why it is accepted (for now):** signing needs key infrastructure the project does not yet have. Operators can pin the wizard binary with `install.sh --sha256 <hash>`, and should mirror images and the registry to infrastructure they control.

### Risk-04: Decoy Host Trust
Sensors run as root in the host network namespace on decoy hosts, and inotify-based file monitoring cannot attribute which process touched a lure. A fully compromised decoy host can stop or spoof its own sensors.
* **Why it is accepted:** raw-socket and host-interface visibility are the product. Liveness events (`sensor_stopped`, `sensor_heartbeat_lost`) are forwarded to the SIEM so a silenced decoy is itself a signal.

---

## 5. Core Security Principles

TrueSignal security is not based on trust. It is predicated on strict verification and boundary enforcement:

1. **Hub is the ONLY Authority:** No security or policy logic resides in the Wizard.
2. **All Inputs are Untrusted:** External manifests, local Wizard requests and deployed sensors telemetry are treated as hostile input.
3. **Compile-Time Security:** Security policies (capabilities, mounts, read-only constraints) are structurally enforced during Compose generation, before runtime execution begins.
4. **Deterministic Generation:** The compiler must produce predictable, auditable artifacts.
5. **Least Privilege:** Containers are assumed to be potentially hostile units, defaulting to read-only environments with explicitly allowed capabilities, and executed via Distroless base images to eliminate secondary payload tooling.