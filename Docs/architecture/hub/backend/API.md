# TrueSignal Hub — API Reference

All Hub routes are prefixed with `/api/v2` unless otherwise noted.

## Authentication

TrueSignal uses two separate authentication methods.

### Dashboard (UI) routes

Dashboard endpoints are protected by an HTTP-only, `SameSite=Strict` session cookie named `ts_auth` (`Secure` unless `TS_ENV` is not `production`).
The cookie is issued by `POST /login`. Sessions expire after an absolute lifetime of 12 hours (`TS_SESSION_TTL`) or 15 minutes without a request (`TS_SESSION_IDLE_TIMEOUT`), whichever comes first. Both take Go durations (e.g. `8h`, `10m`). `TS_SESSION_IDLE_TIMEOUT=0` disables the idle timeout; the absolute lifetime cannot be disabled.

### Agent (sensor) routes

Sensor/agent endpoints are authenticated with a node API key using the Authorization header:

```http
Authorization: Bearer <TS_NODE_KEY>
```

`X-Api-Key: <TS_NODE_KEY>` is also accepted. Keys in the query string (`?key=`) are **not** accepted: they end up in proxy and access logs.

Node keys are stored as SHA-256 hashes (`sha256:<hex>`). The plaintext key is shown only when a node is created or its key is rotated.

### Request limits

Request bodies are capped at 1 MB on dashboard routes and 256 KB on agent routes. Larger bodies fail JSON decoding with `400 Bad Request`.

### Audit trail

Every non-GET request to `/login`, `/logout`, `/api/v2/setup` and the dashboard routes is logged as `[AUDIT] <METHOD> <route> status=<code> ip=<addr>`. When a SIEM is configured it is also forwarded as an RFC 5424 `AUDIT` record (see [Data Contracts](/Docs/architecture/dataContracts.md)). Audit records are not stored in the database.
## Public Endpoints

### GET /api/v2/version

Returns the running Hub version.

**Response:**
```json
{ "version": "2.1.0" }
```

### POST /login

Authenticates a dashboard user and sets the `ts_auth` cookie.

**Request:**
```json
{ "password": "your_password" }
```

**Response:** `200 OK` with cookie on success.

**Errors:** `401 Unauthorized` for invalid credentials, `429 Too Many Requests` after repeated failures.

### POST /logout

Invalidates the current dashboard session, clears the cookie and redirects the client to `/`.

**Response:** `303 See Other`

### GET /api/v2/setup/status

Returns whether the Hub requires initial setup.
When `TS_DASHBOARD_PASSWORD` is set, setup is considered locked and this endpoint returns `requiresSetup: false`.

**Response:**
```json
{ "requiresSetup": true }
```

### POST /api/v2/setup

Completes first-time hub setup and stores the bcrypt-hashed admin password and the hub endpoint.
If `TS_DASHBOARD_PASSWORD` is set, setup is blocked.

The caller must present the one-time **setup token**. While setup is pending, the Hub prints it on startup:

```text
[SETUP] Hub is not initialised. One-time setup token: <token>
```

Set `TS_SETUP_TOKEN` to choose the token yourself (for automated installs). Without the token, whoever reaches the Hub first could claim it.

**Request:**
```json
{
  "password": "at-least-12-characters",
  "hubEndpoint": "https://truesignal.my-domain.com",
  "setupToken": "<token from the Hub log>"
}
```

**Response:** `200 OK`

**Errors:**
- `400 Bad Request` if a field is missing, or the password is shorter than 12 characters.
- `403 Forbidden` if the setup token is wrong, setup is locked by `TS_DASHBOARD_PASSWORD`, or setup is already complete.

## Dashboard Endpoints (UI Cookie Required)

These endpoints require a valid `ts_auth` session cookie.

### GET /api/v2/ws

Upgrades the connection to a WebSocket for realtime dashboard updates.

In production the handshake `Origin` must match the request `Host`, the configured `hubEndpoint` host, or (with `TS_TRUST_PROXY=true`) `X-Forwarded-Host`. Requests without an `Origin` header (non-browser clients) are allowed, since they still need the session cookie. When `TS_ENV` is not `production`, any origin is accepted.

All messages use the envelope:

```json
{ "type": "<MESSAGE_TYPE>", "payload": { ... } }
```

Common message types:

- `NEW_EVENT` — a sensor reported an event.
- `NEW_SENSOR` — a new sensor was discovered.
- `SENSOR_HEARTBEAT` — a sensor heartbeat was received.
- `NODE_SYNCED` — a node reported that pending config was applied.
- `SILENCE_SENSOR` — a sensor silence state changed.
- `SYNC_CHARTS` — instructs UIs to refresh chart data.

### GET /api/v2/manifests

Fetches the sensor manifest catalog from `RegistryURL` or the default public manifest registry.

### GET /api/v2/manifests/{sensorId}/versions

Fetches a specific historical version schema of a sensor manifest from the registry.

**Query parameters:**
- `version` — The exact version string to fetch (e.g. `2.0.6`).

### POST /api/v2/compose/generate

Generates a `docker-compose.yml` preview from the selected sensor manifests and UI-provided environment values.

**Request:**
```json
{
  "hubEndpoint": "https://truesignal.my-domain.com",
  "hubKey": "hub_key_abc",
  "sensors": [
    {
      "sensorId": "alpha-node-01",
      "envValues": {
        "TS_SEVERITY": "medium"
      },
      "manifest": { ... }
    }
  ]
}
```

**Response:** `application/x-yaml` compose payload.

### Nodes and Sensors

#### POST /api/v2/nodes

Creates a new node entry and returns the generated node credentials. The plaintext `apiKey` is returned **only here** (and by `rotate-key`); the Hub keeps just its hash.

**Request:**
```json
{
  "alias": "production-db-node",
  "tags": ["database", "prod"]
}
```

**Response:**
`201 Created`
```json
{
  "nodeId": "node-1a2b3c4d",
  "apiKey": "ts_key_abcd1234...",
  "alias": "production-db-node"
}
```

#### GET /api/v2/nodes

Returns all registered nodes and their installed sensors. Each node includes current status and pending config state.

**Response:**
```json
[
  {
    "nodeId": "node-alpha",
    "alias": "Production Web Server",
    "activeRevision": "rev_e4f2a1",
    "desiredRevision": "rev_b7c9d0",
    "hasPendingConfig": true,
    "hasUpdateAvailable": true,
    "status": "online",
    "installedSensors": [
      {
        "sensorId": "ts-tcp-tarpit",
        "customName": "SSH Decoy",
        "updateAvailable": true
      }
    ]
  }
]
```

#### GET /api/v2/nodes/{nodeId}

Returns details for a single node, including installed sensors and per-sensor event counts. Neither this endpoint nor `GET /api/v2/nodes` returns the node API key.

#### PATCH /api/v2/nodes/{nodeId}

Updates a node's alias, tags, public IP, or private IP.

**Request:**
```json
{
  "alias": "prod-db-node",
  "tags": ["database","primary"],
  "publicIp": "198.51.100.12",
  "privateIp": "10.0.0.12"
}
```

#### POST /api/v2/nodes/{nodeId}/upgrade

Bumps every installed sensor on the node to the latest compatible manifest version in the catalog and marks the node pending sync. Nothing is pushed to the node: nodes have no listener, so the change takes effect the next time `truesignal apply` runs on the node.

#### POST /api/v2/nodes/{nodeId}/rotate-key

Issues a new node API key and invalidates the previous one immediately (including the Hub's auth cache). The new key is returned once.

**Response:**
```json
{
  "nodeId": "node-1a2b3c4d",
  "apiKey": "ts_key_..."
}
```

**Errors:** `404 Not Found` if the node does not exist.

After rotating, run `sudo truesignal relink` on the node, choose "Link to existing node" and paste the new key, then run `sudo truesignal apply` so the sensors' `TS_HUB_KEY` is updated. Until then the node's sensors are rejected with `401`.

#### GET /api/v2/nodes/{nodeId}/compose

Returns the node's generated `docker-compose.yml` for review in the dashboard (`application/x-yaml`). `TS_HUB_KEY` is replaced with the placeholder `__REPLACE_WITH_NODE_API_KEY__`, because the Hub no longer holds the plaintext key.

**Errors:** `404 Not Found` for an unknown node; `422 Unprocessable Entity` for the compose failures listed under [Node Compose](#node-compose).

#### DELETE /api/v2/nodes/{nodeId}

Deletes a node, its sensor assignments and heartbeat/status records, and revokes its API key immediately. **Events are retained** (the events table has no foreign key to nodes or sensors), so evidence survives decommissioning.

#### POST /api/v2/nodes/{nodeId}/sensors

Adds a sensor to a node and flags the node as pending configuration sync.

**Request:**
```json
{
  "sensorId": "ts-tcp-tarpit",
  "customName": "TCP Tarpit",
  "configValues": {
    "TS_SEVERITY": "high"
  }
}
```

#### PUT /api/v2/nodes/{nodeId}/sensors/{sensorId}

Updates a sensor's custom name and config values and marks the parent node pending sync.

#### DELETE /api/v2/nodes/{nodeId}/sensors/{sensorId}

Removes a sensor from the node and marks the node pending sync. The sensor's past events are retained.

#### POST /api/v2/nodes/{nodeId}/sensors/{sensorId}/upgrade

Upgrades a specific sensor to the latest available manifest version listed in the registry, and marks the node pending sync.

#### PATCH /api/v2/nodes/{nodeId}/sensors/{sensorId}/silence

Toggles a sensor's silence state. Silenced sensors still log events and still forward to the SIEM, but suppress webhook notifications.

**Request:**
```json
{ "isSilenced": true }
```

**Response:**
```json
{
  "status": "success",
  "sensorId": "ts-tcp-tarpit",
  "isSilenced": true
}
```

### Configuration and System Settings

#### GET /api/v2/config

Returns runtime configuration loaded from SQLite. 

**Response Schema:**
| Field | Type | Description |
|-------|------|-------------|
| `hubEndpoint` | `string` | The fully qualified URL of the Hub (e.g., `https://hub.example.com`). |
| `autoArchiveDays` | `integer` | Days before active events are moved to the archive. `0` = Keep forever. |
| `autoPurgeDays` | `integer` | Days before archived events are permanently deleted. `0` = Keep forever. |
| `webhookType` | `string` | The active push notification provider (`ntfy`, `gotify`, `discord`, `slack`, `none`). |
| `webhookUrl` | `string` | The target URL for the selected webhook provider. |
| `webhookEvents` | `string[]` | Array of severity levels that trigger a notification (e.g., `["critical", "high"]`). |
| `siemAddress` | `string` | `host:port` for `tcp`/`udp`/`tls`; an `https` URL for `elastic` (including the data stream) and `logscale` (HEC endpoint). Empty if disabled. |
| `siemProtocol` | `string` | SIEM output (`tcp`, `udp`, `tls`, `elastic`, `logscale`). See `Docs/siem-integration.md`. |
| `siemFormat` | `string` | Line format for `tcp`/`udp`/`tls`: `rfc5424` (default) or `ecs`. The HTTP outputs always send ECS. |
| `siemTokenSet` | `boolean` | Whether an HTTP output token is stored. The token itself is never returned. |
| `registryUrl` | `string` | Base URL of the sensor registry (`index.json` and `<sensor>-v<version>.json`). |
| `whitelistedSources` | `string` | Comma-separated exact `source` values. Matching events are stored archived and forwarded to the SIEM with `whitelisted=true`, but raise no webhook or UI alert. |
| `autoPurgeHeartbeatsDays` | `integer` | Days to keep heartbeat/status history. |
| `updateCheckIntervalHours` | `integer` | Hours between Hub/Wizard release checks. |

**Response:**
```json
{
  "hubEndpoint": "https://truesignal.my-domain.com",
  "autoArchiveDays": 90,
  "autoPurgeDays": 180,
  "webhookType": "none",
  "webhookUrl": "",
  "webhookEvents": [],
  "siemAddress": "",
  "siemProtocol": "tcp",
  "siemFormat": "rfc5424",
  "siemTokenSet": false
}
```

#### PATCH /api/v2/config

Updates runtime settings. Only supported fields are applied. This endpoint also hot-reloads webhook and SIEM configuration.

`webhookType: "none"` disables webhook delivery.

**Accepted Fields:**
- `hubEndpoint`
- `autoArchiveDays`
- `autoPurgeDays`
- `webhookType` (`ntfy`, `gotify`, `discord`, `slack`, `none`)
- `webhookUrl`
- `webhookEvents` (list of `info`, `low`, `medium`, `high`, `critical`)
- `siemAddress`
- `siemProtocol` (`tcp`, `udp`, `tls`, `elastic`, `logscale`). For `tls` and the HTTP outputs, the Hub verifies the receiver certificate against the system roots, or against the PEM bundle in `TS_SIEM_CA_FILE` if set (TLS 1.2+).
- `siemFormat` (`rfc5424`, `ecs`)
- `siemToken`: write-only. The encoded Elasticsearch API key or the LogScale ingest token. Omit it to keep the stored token; `""` clears it.
- `registryUrl`
- `whitelistedSources`
- `autoPurgeHeartbeatsDays`
- `updateCheckIntervalHours`

**Errors:** `400 Bad Request` if `hubEndpoint`, `webhookUrl` or `registryUrl` is not an `http(s)` URL, `siemAddress` does not fit the effective `siemProtocol` (`host:port` for streams; an `https` URL without credentials, query or fragment for HTTP outputs, with a data stream path for `elastic`), `siemToken` spans lines, `siemFormat` is unknown, `webhookType` / `siemProtocol` is not one of the listed values (case-insensitive), `webhookEvents` contains an unknown severity, or a day/hour field is not a non-negative integer. A rejected request changes nothing.

**Request example:**
```json
{
  "autoArchiveDays": 14,
  "webhookType": "discord",
  "webhookUrl": "https://discord.com/api/webhooks/...",
  "webhookEvents": ["critical", "high"]
}
```

#### GET /api/v2/system/state

Returns whether the Hub is armed.

**Response:**
```json
{ "isArmed": true }
```

#### PATCH /api/v2/system/state

Sets the armed/disarmed state.

**Request:**
```json
{ "isArmed": false }
```

#### PATCH /api/v2/system/password

Changes the dashboard admin password. When `TS_DASHBOARD_PASSWORD` is set, this operation is forbidden (`403`).

**Errors:** `401 Unauthorized` if `currentPassword` is wrong; `400 Bad Request` if `newPassword` is shorter than 12 characters.

**Request:**
```json
{
  "currentPassword": "oldPassword",
  "newPassword": "newPassword"
}
```

#### POST /api/v2/system/reset

Performs a full factory reset of the runtime database, clearing events, sensors, heartbeats, and config.
Requires the current admin password. Honeytokens, beacons and their master keys are **kept** by default, because their lures are still on disk. `purgeHoneytokens: true` deletes them and rotates both keys (planted beacons then go silent); delete the lure files first, or they become credentials the Hub no longer recognises. `?dryrun=true` with the same body returns row counts (it includes `honeytokens` and `beacons` only when purging).

**Request:**
```json
{ "password": "your_master_password", "purgeHoneytokens": false }
```

**Response:** `200 OK`

#### GET /api/v2/system/updates

Returns release update states for both the Hub and the TrueSignal Wizard.

**Response:**
```json
{
  "update_available": false,
  "latest_version": "v2.1.0",
  "release_notes_url": "",
  "wizard_update_available": true,
  "latest_wizard_version": "v2.1.0",
  "wizard_release_notes_url": "https://github.com/mahmoudahmed3132/TrueSignal/releases/tag/wizard/v2.1.0",
  "acknowledged_wizard_release": ""
}
```

#### POST /api/v2/system/wizard/acknowledge

Acknowledges/dismisses a Wizard update announcement so the UI indicator is not shown until a newer release is published.

**Request:**
```json
{ "version": "v2.1.0" }
```

**Response:**
```json
{ "status": "success" }
```

## Fleet and Events

### GET /api/v2/events/unread

Returns the count of active, unread events.

**Response:**
```json
{ "count": 12 }
```

### GET /api/v2/events

Returns a list of events, newest first.

**Query parameters:**
- `archived` — `true` or `false` (default: `false`)
- `nodeId` — filter by node ID
- `sensorId` — filter by sensor ID

### GET /api/v2/insights

Decoy coverage for the dashboard: deployed vs touched decoys, attacker sources and per-decoy-type activity. Hub liveness events (`sensor_stopped`, `sensor_heartbeat_lost`, `sensor_recovered`) are not attacker activity and are excluded. Honeytoken counts are all-time (the Hub keeps a use counter, not per-use rows).

**Query parameters:**
- `timeframe` — `24H`, `7D`, `30D` or `alltime` (default and any other value: `alltime`)
- `archived` — `true` or `false` (default: `false`), as for `/api/v2/events`
- `nodeId`, `sensorId` — narrow events, deployed decoys and honeytokens

```json
{"timeframe":"alltime","events":47,"criticalEvents":26,"uniqueSources":5,"decoysDeployed":10,"decoysTouched":6,"decoyTypesDeployed":9,"honeytokensTotal":1,"honeytokensUsed":1,
 "byType":[{"sensorId":"ts-sensor-tcp-tarpit","events":17,"uniqueSources":5,"deployed":2,"touched":2}]}
```

`byType` lists every deployed type (zero activity included) and every type with events, busiest first. A decoy counts as touched when it has at least one event in the timeframe; `uniqueSources` per type counts a source once per type, the top-level `uniqueSources` once overall.

### GET /api/v2/report

Decoy activity for the evidence report in a date range. `from` / `to` are RFC 3339 times or `YYYY-MM-DD` dates (`to` exclusive); default: the last 30 days; the range must be positive and at most 366 days (`400` otherwise). Figures use active events (Hub liveness excluded); `archivedEvents` counts in-range archived events (whitelisted, known scanners, analyst triage), which are not in the figures.

Returns `summary` (the `/api/v2/insights` shape for the range), `severity`, `daily` (one entry per UTC day), `topSources` (25, known assets first, then by critical events; each with its `asset`), `sourcesTotal`, `assets` (one row per inventory asset over **all** in-range sources: `name`, `criticality`, `sources`, `events`), `techniques` (observed ATT&CK techniques), `honeytokenUses`. The Reports page adds fleet and configuration state from the other endpoints and prints to PDF from the browser.

### GET /api/v2/path

One source's route through the decoys, from all its events (active and archived, Hub liveness excluded, the most recent 2,000 at most; `truncated` says when more exist). `source` is required (≤256 characters).

- `steps`: one per decoy (node + sensor), in order of first contact, with first/last seen, event count, highest severity, triggers and primary ATT&CK techniques.
- `progression`: each technique that brought new tactics into the path, in order; a technique filed under several tactics (T1078) is one step listing them.
- `timeline`: the events, oldest first, each with its `attack` mapping.
- `asset`: the inventory asset the source belongs to, if any.

```json
{"source":"10.20.4.101","asset":{"name":"jump-host-01","criticality":"critical"},"events":17,"truncated":false,"firstSeen":"...","lastSeen":"...",
 "steps":[{"nodeId":"node-a1b2c3d4","sensorId":"ts-sensor-tcp-tarpit","firstSeen":"...","lastSeen":"...","events":4,"maxSeverity":"low","triggers":["tcp_connection"],"techniques":["T1046"]}],
 "progression":[{"firstSeen":"...","technique":"T1046","name":"Network Service Discovery","tactics":[{"id":"TA0007","name":"Discovery"}]}],"timeline":[...]}
```

### GET /api/v2/assets · PUT /api/v2/assets

The asset inventory: real hosts and ranges with criticality (`low`, `medium` (default), `high`, `critical`), owner and tags. `PUT` replaces the whole list atomically (`{"assets":[...]}`, unknown fields rejected) after validation: a name is required, `address` must be an IP or CIDR range, no two entries may cover the same range, at most 5,000 entries, fields up to 256 characters. A rejected `PUT` changes nothing. Stored in the config table (no schema change), so a factory reset clears it; export it first (Assets page, CSV).

Events (`sourceAsset`), source profiles (`asset`) and the SIEM (`truesignal.source_asset`) carry the asset the source address belongs to, the most specific range winning. It is resolved against the current inventory when read or forwarded. An inventoried address counts as internal even in public space.

```json
{"assets":[{"name":"jump-host-01","address":"10.20.4.101","criticality":"critical","owner":"IT Ops","tags":["pci","bastion"]}]}
```

### GET /api/v2/attack

Activity per MITRE ATT&CK technique over every technique TrueSignal can evidence (zero counts included), with the tactics in matrix order. Same query parameters as `/api/v2/insights`. `primaryEvents` counts events whose primary technique it is; `secondaryEvents` those that list it as secondary. Mapping: `Docs/siem/attack-mapping.md`. Every event returned by `/api/v2/events` (and WebSocket `NEW_EVENT`) carries its mapping as `attack` (`{"primary":{id,name,tactics},"secondary":[...]}`), absent for unmapped triggers.

```json
{"timeframe":"alltime","mappedEvents":57,"techniquesObserved":7,"techniquesCovered":16,"tactics":[{"id":"TA0043","name":"Reconnaissance"}],
 "techniques":[{"id":"T1021.004","name":"Remote Services: SSH","tactics":["TA0008"],"primaryEvents":11,"secondaryEvents":0,"sources":4,"lastSeen":"2026-10-24T06:18:37Z","triggers":["ssh_login"]}]}
```

### GET /api/v2/attack/layer

The same data as an ATT&CK Navigator layer file (format 4.5, `enterprise-attack`), served as an attachment. Score = primary events; covered techniques without events are included with score 0. Load it at the ATT&CK Navigator with "Open Existing Layer".

### GET /api/v2/sources

One activity profile per event source across all events (active and archived), Hub liveness excluded, busiest first. `whitelisted` and `knownScanner` reflect the lists as they are now, not when the events arrived. `internal` covers RFC 1918, RFC 6598, loopback, link-local and IPv6 unique-local addresses; both flags are `false` for a non-IP source (`isIp: false`). The dashboard derives its triage labels (multi-decoy, repeat, single touch, internal, external, whitelisted, known scanner) from it.

```json
{"sources":[{"source":"10.20.4.101","events":15,"decoys":5,"firstSeen":"2026-10-06T03:18:37Z","lastSeen":"2026-10-24T06:18:37Z","isIp":true,"internal":true,"whitelisted":false,"knownScanner":false}]}
```

### GET /api/v2/honeytokens

Lists the honeytokens the Hub has planted (one per File Canary instance, created on its first compose render). The secret is never returned; it is in the lure files. `?format=csv` returns `username,honeytoken_id,planted_node_id,planted_sensor_id,created_at` for SIEM lookup files.

```json
[{"id":"ht_956c6041","username":"svc_reports97ef","nodeId":"node-d41340e4","sensorId":"ts-sensor-file-canary","createdAt":"2026-10-24T02:19:11Z","lastUsedAt":"2026-10-24T02:19:40Z","useCount":2}]
```

### GET /api/v2/beacons · POST /api/v2/beacons · DELETE /api/v2/beacons/{id} · GET /api/v2/beacons/{id}/download

Callback beacons (`Docs/operations.md` §14). `GET` returns every beacon with its rendered artifact, plus `domains`: the zones deployed Token Receivers serve (`TS_BEACON_DOMAIN`).

```json
{"beacons":[{"id":"bc_03d9b960","token":"cx7iy6ni6nvrfbg4uzj7qcf2","type":"kubeconfig","name":"jump-01 ~/.kube/config","memo":"","domain":"t.example.com","createdAt":"2026-10-29T22:20:14Z","lastUsedAt":"","useCount":0,
  "artifact":{"filename":"kubeconfig-jump-01-kube-config.yaml","contentType":"application/yaml","value":"cx7iy6ni6nvrfbg4uzj7qcf2.t.example.com","content":"apiVersion: v1\n..."}}],
 "domains":["t.example.com"]}
```

`POST` body: `{"type":"dns|web_bug|kubeconfig","name":"where it is planted (≤128)","memo":"optional (≤512)","domain":"optional"}`. `domain` defaults to the receivers' zone when exactly one is deployed. Returns `201` with the beacon, `400` on validation errors. `DELETE` returns `204`; past events are kept and a later use is reported as an unknown token. `download` returns the artifact as a file.

### GET /api/v2/events/export

Exports events as a downloadable JSON file (`truesignal_events.json`).

**Query parameters:**
- `archived` — `true` or `false` (default: `false`)
- `nodeId` — filter by node ID
- `sensorId` — filter by sensor ID

### PATCH /api/v2/events/read

Marks all active events as read.

### PATCH /api/v2/events/{eventId}/read

Marks a single event as read.

### PATCH /api/v2/events/{eventId}/archive

Archives a single event and marks it as read.

### PATCH /api/v2/events/archive-all

Archives all active events.

### DELETE /api/v2/events

Deletes all events permanently.

**Query parameters:**
- `dryrun=true` — return the count of deletable events without deleting them.

**Response (dryrun):**
```json
{
  "status": "success",
  "dryrun": true,
  "would_delete": 4512
}
```

**Response:**
```json
{ "status": "success", "dryrun": false }
```

### GET /api/v2/events/severity

Returns severity distribution analytics for the fleet.

**Query parameters:**
- `timeframe` — timeframe filter (e.g. `alltime`, `24H`) (default: `alltime`)
- `node` — filter by node ID (optional)
- `sensor` — filter by sensor ID (optional)
- `viewingArchive` — `true`, `1`, `false`, or `0` (default: `false`)

**Example Response:**
```json
{
  "timeframe": "24H",
  "total": 80,
  "critical": 5,
  "high": 12,
  "medium": 25,
  "low": 8,
  "info": 30
}
```

### GET /api/v2/events/velocity

Returns time-bucketed velocity analytics for the fleet.

**Query parameters:**
- `timeframe` — timeframe filter (`1H`, `24H`, `7D`, `30D`) (default: `24H`)
- `nodeId` — filter by node ID (optional)
- `sensorId` — filter by sensor ID (optional)
- `archived` — include archived events (`true` or `false`) (default: `false`)

**Example Response:**
```json
{
  "timeframe": "24H", 
  "bucketSizeMs": 3600000,
  "generatedAt": 1716552000000,
  "bucketTimestamps": [1716465600000, 1716469200000],
  "labels": ["-23h", "-22h", "Now"],
  "exactTimes": ["May 23, 08:00 AM", "May 23, 09:00 AM"],
  "series": {
    "critical": [0, 1, 0],
    "high": [2, 0, 5],
    "medium": [0, 0, 0],
    "low": [0, 0, 0],
    "info": [1, 3, 2]
  },
  "recentEventCount": 14
}
```

## Uptime and Health

### GET /api/v2/uptime

Returns uptime blocks for fleet health charts.

**Query parameters:**
- `timeframe` — `1H`, `24H`, `7D`, `30D` (default: `24H`)

**Example Response:**
```json
{
  "timeframe": "24H", 
  "generatedAt": "2024-05-24T10:00:00Z",
  "summary": {
    "overallUptime": 98.5
  },
  "groups": [
    {
      "nodeId": "node-alpha",
      "nodeAlias": "Production Web Server",
      "worstStatus": "degraded",
      "sensors": [
        {
          "sensorId": "ts-tcp-tarpit",
          "displayName": "TCP Tarpit",
          "status": "up",
          "isSilenced": false,
          "blocks": [
            { "status": "up", "label": "Online", "timeLabel": "-23h" },
            { "status": "up", "label": "Online", "timeLabel": "-22h" },
            { "status": "up", "label": "Online", "timeLabel": "Current" }
          ]
        },
        {
          "sensorId": "ts-file-canary",
          "displayName": "File Integrity Monitor",
          "status": "degraded",
          "isSilenced": false,
          "blocks": [
            { "status": "up", "label": "Online", "timeLabel": "-23h" },
            { "status": "degraded", "label": "Degraded (50/60 pings)", "timeLabel": "-22h" },
            { "status": "up", "label": "Online", "timeLabel": "Current" }
          ]
        }
      ]
    },
    {
      "nodeId": "node-beta",
      "nodeAlias": "Dev Database",
      "worstStatus": "down",
      "sensors": [
        {
          "sensorId": "ts-network-scan",
          "displayName": "Network Scan Detector",
          "status": "down",
          "isSilenced": true,
          "blocks": [
            { "status": "down", "label": "Offline", "timeLabel": "-23h" },
            { "status": "down", "label": "Offline", "timeLabel": "-22h" },
            { "status": "down", "label": "Offline", "timeLabel": "Current" }
          ]
        }
      ]
    }
  ]
}
```

## Node Compose

### GET /api/v2/nodes/compose

Returns a generated `docker-compose.yml` for a node based on the node's current installed sensors.

**Authentication:** `Authorization: Bearer <TS_NODE_KEY>`

This endpoint is read-only for node deployment: it returns the current or requested `TS_CONFIG_REV` without marking the node as synced. The node is marked synced only when its heartbeat reports the expected revision.

The compiler **fails closed**: if any installed sensor's manifest cannot be fetched or validated, no compose is returned (rather than a compose missing that decoy, which `apply --remove-orphans` would then tear down).

**Errors:**
- `401 Unauthorized` for an unknown or revoked key.
- `422 Unprocessable Entity` with a reason prefix in the error message:
  - `manifest_unavailable` — the manifest for an installed sensor/version could not be fetched, failed strict decoding, or its `id`/`version` did not match the request.
  - `invalid_manifest` — the manifest failed the security validator (e.g. forbidden mount, capability or network mode) or an image is not digest-pinned.
  - `incompatible_sensor` — the sensor's major version does not match the Hub.
  - `build_failed` — compose rendering failed.

### GET /api/v2/nodes/me

Returns the node record for the presented node key (used by the Wizard to verify linking).

## Agent Endpoints

These endpoints are used by sensor agents and require the node API key bearer token.

### POST /api/v2/heartbeat

Reports a sensor heartbeat and updates its versioning state. A heartbeat that follows an `offline` state raises a `sensor_recovered` event.

**Request:**
```json
{
  "sensorId": "alpha-node-01",
  "configRev": "rev_abc123"
}
```

**Response:**
```json
{ "status": "alive" }
```

**Errors:** `404 Not Found` if `sensorId` is not registered on the authenticated node.

### POST /api/v2/offline

Reports a graceful sensor shutdown (sent by the SDK on SIGTERM). The Hub records the offline state and raises a `sensor_stopped` event (severity `low`). If the sensor does not come back within 5 minutes, the state monitor escalates with `sensor_heartbeat_lost` (`high`).

**Request:**
```json
{ "sensorId": "ts-sensor-tcp-tarpit", "reason": "graceful_shutdown" }
```

**Response:**
```json
{ "status": "offline_acknowledged" }
```

### POST /api/v2/event

Reports an intrusion event to the Hub.

**Request:**
> 📖 **[View the Universal Event Standard Contract](/Docs/architecture/dataContracts.md#1-the-universal-event-standard)**

**Severity values:** `info`, `low`, `medium`, `high`, `critical`. Matching is case-insensitive; any other value is stored as `medium` and logged.

The Hub sets `nodeId` (from the key), `timestamp`, `id`, `isRead` and `isArchived` itself and ignores any values sent for them. `sensorId`, `eventTrigger`, `source` and `target` are truncated to 256 characters. `details` must be a JSON object up to 64 KB; anything else is wrapped or replaced so the stored value is always an object.

**Response:**
```json
{ "status": "success" }
```

**Errors:**
- `400 Bad Request` for invalid JSON or a missing `sensorId`.
- `401 Unauthorized` for an unknown or revoked node key.
- `404 Not Found` if `sensorId` is not registered on the authenticated node.

There is no version check on events; the only `426 Upgrade Required` in the API comes from the `X-Wizard-Version` header check on Wizard requests.
