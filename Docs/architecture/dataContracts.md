# TrueSignal Data Contracts

This document serves as the **single source of truth** for all cross-component data shapes in the TrueSignal platform. To prevent documentation drift, these contracts are defined here and referenced by other subsystems (Hub, Wizard, Sensors, SDKs).

---

## 1. The Universal Event Standard

This is the standard telemetry payload that all sensors (official or community) must POST to the Hub when an intrusion is detected. The Hub's frontend dynamically parses, syntax-highlights, and renders this JSON.

**Endpoint:** `POST /api/v2/event`
**Authentication:** `Authorization: Bearer <TS_NODE_KEY>`

```json
{
  "sensorId": "core-dpi-engine",
  "eventTrigger": "malformed_jwt_detected",
  "severity": "critical",
  "source": "104.28.19.12",
  "target": "Auth Gateway",
  "details": {
    "protocol": "TCP",
    "headers_stripped": true,
    "payload_sample": [
      "Authorization: Bearer eyJhbG... [TRUNCATED]",
      "User-Agent: curl/7.64.1"
    ]
  }
}
```

### Field Definitions
- `sensorId` (string, required): The unique identifier of the sensor emitting the event.
- `eventTrigger` (string, required): A brief, machine-readable reason for the event.
- `sensorId` must be registered on the node that owns the API key; otherwise the Hub answers `404` and stores nothing.
- `severity` (string, required): One of `info`, `low`, `medium`, `high`, `critical` (case-insensitive). Any other value is stored as `medium`.
- `source` (string, required): The attacker's IP, hostname, or identifier.
- `target` (string, required): The decoy service or port that was attacked.
- `details` (object, optional): A flexible JSON object containing forensic artifacts. Primitive values are rendered as tags; arrays are rendered as syntax-highlighted code blocks in the UI. Non-object values are wrapped as `{"value": ...}`; payloads over 64 KB are replaced with `{"truncated": true, "original_bytes": N}`.

`sensorId`, `eventTrigger`, `source` and `target` are truncated to 256 characters.

*(Note: When querying the Hub's API or viewing the SQLite DB, the backend automatically enriches this payload with `id`, `nodeId`, `timestamp`, `isRead`, `isArchived`, and `count`. These are always set by the Hub; values sent by a sensor are ignored. Events from whitelisted sources additionally carry `"whitelisted": true`, events from known-scanner sources `"knownScanner": true`; both are stored archived and read and never notify.)*

### Event triggers

`eventTrigger` values are a contract: SIEM parsers and rules key on them. Do not rename them.

| Trigger | Emitted by | Severity | Meaning |
|---|---|---|---|
| `tcp_connection` | TCP Tarpit | `TS_SEVERITY` | A client connected to a decoy port (sent immediately on connect, `details.phase = "connect"`). |
| `tcp_session_payload` | TCP Tarpit | `TS_SEVERITY` | Sent when the session closes, only if the client sent data (`payload`, `bytes_received`, `duration_sec`). |
| `icmp_scan_received` | ICMP Canary | `TS_SEVERITY` (default `low`) | Echo/timestamp request. At most one event per source per `TS_ICMP_COOLDOWN` seconds (default 60); `details.suppressed_since_last` counts the rest. |
| `network_scan_detected` | Network Scan Detector | `TS_SEVERITY` | Port-scan pattern from one source (inbound frames only). |
| `decoy_file_tampered` | File Canary | `TS_SEVERITY` | A lure was modified, had attributes changed, was moved or deleted. |
| `decoy_file_accessed` | File Canary | `TS_SEVERITY` | A lure was opened or read (`TS_ALERT_ON_OPEN`, default `true`). Repeats within `TS_ALERT_COOLDOWN` seconds are suppressed. |
| `web_login_attempt` | Web Router Decoy | `TS_SEVERITY` | Form `POST` to the skin's login path, or a Basic `Authorization` header (`basic` skin). `attempted_username`, `auth` (`form`\|`basic`), `skin`, `path`, `form_<field>` for extra fields (`Docs/sensors/web-skins.md`). At most 20 per source per minute; the rest are counted in `suppressed_since_last`. The password is recorded per `TS_CAPTURE_PASSWORDS`: `hash` (default: `attempted_password_hmac` (HMAC-SHA256 keyed by `TS_CAPTURE_HASH_KEY`, else derived from the node key), `attempted_password_length`, `hmac_key_id`), `none` (`password_submitted`), or `plain` (`attempted_password`). |
| `web_page_view` | Web Router Decoy | `medium` | `GET /` (`details.skin`). At most one recon event per source per 60 s. |
| `web_path_probe` | Web Router Decoy | `medium` | Request for any other path (`/.env`, `/admin`, ...). Shares the per-source 60 s limit with `web_page_view`. |
| `sensor_stopped` | Hub | `low` | The sensor reported a graceful shutdown (`POST /api/v2/offline`). `details.reason`. |
| `sensor_recovered` | Hub | `info` | First heartbeat after an `offline` state. |
| `mysql_login`, `postgres_login`, `mssql_login` | Database Decoy | `critical` | A database login attempt, always refused with the server's real error. `details`: `username`, `database`, `client_app`, `client_host` (MSSQL), `auth`. PostgreSQL and MSSQL yield the password, recorded per `TS_CAPTURE_PASSWORDS`; MySQL only `password_submitted`, plus `client_os`/`client_library` from connection attributes. `*_connection` (`low`) on every connect. |
| `ssh_login`, `telnet_login`, `ftp_login` | Remote Access Decoy | `critical` | A remote-access login attempt, always refused. `details`: `username`, `auth` (`password`, `keyboard-interactive`, `publickey`, `anonymous`), the password per `TS_CAPTURE_PASSWORDS`; SSH adds `client_version`, and for keys `key_type` and `key_fingerprint` (SHA256). `*_connection` (`low`) on every connect. |
| `snmp_query` | Network Service Decoy | `medium` (`high` for SET) | `snmp_version`, `pdu`, `oids`, `community_valid`, the community string per `TS_CAPTURE_PASSWORDS` (`community_hmac`…); v3: `username`. |
| `dns_query` | Network Service Decoy | `medium` (`high` for AXFR) | `query_name`, `query_type`. Answered REFUSED, never resolved or forwarded. |
| `honeytoken_used` | Hub | `critical` | A credential the Hub planted in a File Canary lure was used against a decoy (see `Docs/operations.md` §10). `node_id`/`sensor_id`/`source` are where and by whom it was used. `details`: `honeytoken_id`, `honeytoken_username`, `matched_on` (`username`, `password` or `username+password`), `planted_node_id`, `planted_sensor_id`, `triggering_event_id`, `triggering_trigger`, `protocol`, `dst_port`. Never suppressed by the source whitelist. Sensors cannot send it (HTTP 400). |
| `beacon_triggered` | Token Receiver | `critical` (`medium` for an unknown token) | A beacon the Hub created was resolved (DNS) or fetched (HTTP) (`Docs/operations.md` §14). `source` is the resolver for DNS and the client (or, behind a `TS_TRUSTED_PROXIES` front end, the forwarded client) for HTTP. `details`: `token`, `channel` (`dns`\|`http`), `repeats_since_last`; DNS: `query_name`, `query_type`, `transport`, `resolver`, `client_subnet` (EDNS Client Subnet, when the resolver sends it); HTTP: `method`, `host`, `path`, `user_agent`, `referer`, `proxy`. The Hub adds `beacon` (`id`, `name`, `type`, `domain`) for a known token and ignores the source lists; an unknown token (deleted beacon) is stored at `medium` with `beacon_known: false`. One event per token and channel per `TS_ALERT_COOLDOWN`. Not ATT&CK-mapped. |
| `sensor_heartbeat_lost` | Hub | `high` | No heartbeat for 60 s from a sensor that was online (`details.reason = "heartbeat_timeout"`), or a stopped sensor that has not come back within 5 minutes (`"not_restarted_after_stop"`). |

The interactive decoys (Database, Remote Access, Network Service) report at most 20 login/query events and, separately, 20 `*_connection` events per source per minute; further ones are counted and the next reported event carries `suppressed_since_last`. At most 10,000 sources are tracked individually per window; beyond that, new sources share one overflow budget.

Hub-raised liveness events use `source = "truesignal-hub"`; `honeytoken_used` keeps the attacker's `source` from the triggering event. Firedrill and `TS_TEST_MODE` events use the sensor's normal trigger with `source = "Wizard Firedrill"`; filter on `source` to exclude them.

---

## 2. Heartbeat Payload

This payload is emitted continuously (every 30 seconds, with backoff when the Hub is unhealthy) by sensors to prove they are alive and running the expected configuration. It carries no version information. The Hub marks a sensor offline after 60 seconds without one.

**Endpoint:** `POST /api/v2/heartbeat`
**Authentication:** `Authorization: Bearer <TS_NODE_KEY>`

```json
{
  "sensorId": "alpha-node-01",
  "configRev": "rev_abc123"
}
```

### Field Definitions
- `sensorId` (string, required): The unique identifier of the sensor.
- `configRev` (string, required): The current configuration revision the sensor is running. Used by the Hub to determine if the node has synchronized its desired state.

On SIGTERM the SDK also sends `POST /api/v2/offline` with `{"sensorId": "...", "reason": "graceful_shutdown"}`.

---

## 3. Sensor Manifest

The Sensor Manifest is the declarative JSON schema used to describe a decoy. It is consumed by the Wizard to evaluate host heuristics and generate Docker Compose deployments, and by the Hub to render UI metadata.

```json
{
  "id": "ts-sensor-tcp-tarpit",
  "version": "2.1.0",
  "name": "TCP Tarpit",
  "category": "network",
  "osi_layer": "L4",
  "icon_svg": "<svg>...</svg>",
  "description": "Slows down automated network scanners by holding TCP connections open indefinitely.",
  "documentation": {
    "summary": "Deploy this on unused ports to trap automated scanners.",
    "sections": [
      {
        "title": "Operation",
        "type": "markdown",
        "content": ["Holds connections open until timeout."]
      }
    ]
  },
  "heuristics": {
    "triggers": {
      "ports": [22, 23, 3389, 5900]
    },
    "recommendation_reason": "High-value administrative ports are exposed."
  },
  "deployment": {
    "image_repository": "ghcr.io/mahmoudahmed3132/truesignal-tcptarpit",
    "image_tag": "v2.1.0",
    "image_digest": "sha256:<64 hex, filled in by CI>",
    "network_mode": "host",
    "user": "65532:65532",
    "cap_add": ["NET_BIND_SERVICE"],
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "port_assignments": [
      {
        "env_var_name": "TS_DECOY_PORTS",
        "default": 2222
      }
    ],
    "volume_mounts": [
      {
        "source": "/var/log/tarpit",
        "target": "/logs",
        "type": "bind",
        "read_only": true
      }
    ],
    "init_containers": [],
    "env_vars": [
      {
        "name": "TS_TARPIT_MODE",
        "description": "Behavior mode: hold, echo, or close",
        "default": "hold",
        "type": "string",
        "required": true
      }
    ]
  }
}
```

### Key Subsystems
- `heuristics.triggers`: Used by the Wizard Discovery Engine. If the Wizard observes matching `processes`, `ports`, or `file_patterns` on the host, it will recommend this sensor.
- `deployment`: Used by the Wizard Deployment Engine to generate the Intermediate Representation (IR) and final `docker-compose.yml`.
- `deployment.env_vars`: Rendered in the Hub UI so users can configure the sensor dynamically. Defaults may be Wizard templates such as `{{ availablePort 2222 }}`.
- `deployment.image_digest`: **Required** in published manifests (main and init images). The Hub refuses to compile a manifest without a `sha256:` digest unless `TS_ALLOW_UNPINNED_IMAGES=true` (development only). Source manifests in the repo leave it empty; the publish workflow fills it in.

Manifests are decoded strictly: unknown fields (for example the old `port_assignments[].auto_shift`) make the manifest invalid. Other rules enforced by the compiler (`Hub/internal/compose/security/validate.go`):
- `cap_add` may only contain `NET_RAW`, `NET_BIND_SERVICE`, `DAC_OVERRIDE`.
- `network_mode` may only be empty, `host`, `bridge` or `none`.
- Volume sources must be absolute paths outside the forbidden prefixes (`/run`, `/var/run`, `/proc`, `/sys`, `/dev`, `/boot`, `/etc`, `/root`, `/usr`, `/bin`, `/sbin`, `/lib*`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/kubelet`) and not `/`.
- Main-container volume mounts are always mounted read-only, whatever `read_only` says.

> [!TIP]
> **Automatic Sandbox Enforcement:** You do not need to manually specify `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]`, or `read_only: true` in your manifest for the primary sensor container. The Hub's **Compose Compiler** unconditionally injects these fields into the final deployment plan to guarantee a strict security baseline. It will also default `user` to `65532:65532` (distroless `nonroot`) if omitted to prevent root execution as a baseline. Init containers get the same baseline plus `network_mode: none`.

---

## 4. SIEM Syslog Format

When `siemAddress` is set, the Hub forwards every stored event (including whitelisted and Hub-raised ones) and every audit record as one RFC 5424 message per line (newline-terminated over `tcp`/`tls`; one message per datagram over `udp`). Source: `Hub/internal/services/siem/service.go`.

```text
<PRI>1 TIMESTAMP truesignal truesignalSensor - EVENT [truesignal@PEN event_id="42" trigger="tcp_connection" severity="high" source="203.0.113.7" target="Port 2222" node="db-node-01" node_id="node-1a2b3c4d" sensor="ts-sensor-tcp-tarpit" whitelisted="false" known_scanner="false" mitre_technique="T1046" mitre_tactic="TA0007" source_asset="" source_asset_criticality=""] {"event_id":42,"timestamp":"...","node_id":"...","node":"...","sensor_id":"...","trigger":"...","severity":"...","source":"...","target":"...","whitelisted":false,"known_scanner":false,"attack":{"primary":{"id":"T1046","name":"Network Service Discovery","tactics":[{"id":"TA0007","name":"Discovery"}]}},"source_asset":null,"details":{...}}
```

- **PRI:** facility `local0` (16). Severity `critical`→2, `high`→3, `medium`→4, `low`→5, `info`→6.
- **HOSTNAME / APP-NAME / PROCID:** fixed `truesignal`, `truesignalSensor`, `-`. The node is in the structured data, not the HOSTNAME.
- **MSGID:** `EVENT` for detections, `AUDIT` for admin actions.
- **Structured data:** SD-ID `truesignal@<PEN>`. Values are escaped per RFC 5424 §6.3.3 (`"`, `\`, `]`), control characters become spaces, and each value is capped at 1024 bytes, so attacker-supplied strings cannot inject fields or records.
- **MSG:** the full event as single-line JSON (for an Elastic `json` processor or LogScale `parseJson()`).
- **PEN:** `TS_SYSLOG_PEN`, default `32473` (the RFC 5612 documentation number). Set your organisation's IANA Private Enterprise Number.

Honeytoken inventory records (`Docs/siem/honeytoken-detection.md`) use PRI `<134>` (local0.info) and MSGID `HONEYTOKEN`. They are sent when a token is created, at Hub start and every 24 h, and never include the secret:

```text
<134>1 TIMESTAMP truesignal truesignalSensor - HONEYTOKEN [truesignal-honeytoken@PEN honeytoken_id="ht_956c6041" username="svc_reports97ef" planted_node_id="node-d41340e4" planted_sensor_id="ts-sensor-file-canary" status="active"] {"honeytoken_id":"ht_956c6041","username":"svc_reports97ef",...}
```

Audit records use PRI `<133>` (local0.notice):

```text
<133>1 TIMESTAMP truesignal truesignalSensor - AUDIT [truesignal-audit@PEN action="PATCH /api/v2/config" path="/api/v2/config" status="200" actor_ip="10.0.0.5"] {"timestamp":"...","action":"PATCH /api/v2/config","path":"/api/v2/config","status":200,"actor_ip":"10.0.0.5"}
```

**Transport:** `siemProtocol` is `tcp`, `udp` or `tls`. With `siemFormat: ecs` (or the `elastic`/`logscale` HTTP outputs), records are ECS JSON instead of RFC 5424; that mapping is in `Docs/siem-integration.md` and is also a contract. The RFC 5424 format above is unchanged and stays the default. With `tls`, the Hub requires TLS 1.2+ and verifies the receiver against the system roots or the PEM bundle in `TS_SIEM_CA_FILE`. Sensor liveness (`sensor_stopped`, `sensor_heartbeat_lost`, `sensor_recovered`) arrives as ordinary `EVENT` records.
