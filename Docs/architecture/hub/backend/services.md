# Domain Services & Orchestration

The `internal/services` layer is the brain of the TrueSignal Hub. It contains the actual "verbs" of the system and is strictly framework-agnostic. Services define their own dependencies via narrow interfaces, ensuring high testability and clear boundaries.

## Background Workers

Workers are decoupled from the HTTP transport layer and managed exclusively via the `context.Context` instantiated in `main.go`.

| Worker | Location | Purpose |
|---|---|---|
| **State Monitor** | `services/statemonitor` | Polls every 15s. If a sensor that was online misses heartbeats for > 60s, records it `offline`, broadcasts a WS update and raises a `sensor_heartbeat_lost` (high) event. A gracefully stopped sensor that has not come back within 5 minutes is escalated the same way (once per outage; outages older than 24h are not re-alerted after a Hub restart). |
| **Event Retention** | `services/event` | Wakes hourly to delete/archive events older than configured thresholds to prevent DB bloat. |
| **Chart Sync** | `services/websocket` | Emits an empty payload every 30s telling the UI to tick its time-series charts forward smoothly. |
| **Auth Sweeper** | `services/auth` | Cleans up expired sessions and brute-force IP lockout maps to prevent memory leaks. |
| **SIEM Forwarder** | `services/siem` | Drains the in-memory event and audit channel as RFC 5424 syslog over TCP, UDP or TLS to external log aggregators. |
| **Updater** | `services/updater` | Checks GitHub releases and refreshes the registry catalog every `updateCheckIntervalHours` (default 24). |
| **Node Sync** | `services/node` | Re-evaluates every node's pending-config state when the catalog changes. |
| **Notifier** | `services/notify` | Drains the webhook channel to Slack/Discord/Gotify, preventing external API latency from blocking TrueSignal HTTP responses. |

## Data Flow Example (Event Processing)

To understand how the layers interact, consider the lifecycle of an intrusion event when a sensor POSTs to `/api/v2/event`:

1. **Router (`internal/api/router.go`):** Matches the route and invokes `AgentAuthMiddleware`.
2. **Middleware:** 
   - Reads the `X-Api-Key` or `Bearer` token.
   - Calls `authService.AuthenticateNodeRequest()`.
   - Injects the authenticated `NodeID` into the request `Context`.
3. **API Handler (`internal/api/events.go`):**
   - Parses the JSON body into a `models.Event`.
   - Extracts `NodeID` from the context.
   - Calls `eventService.ProcessEvent(event, nodeID)`.
4. **Event Service (`internal/services/event/service.go`):**
   - Resets server-owned fields (`id`, `nodeId`, read/archive state), normalises severity, truncates string fields and normalises `details` to a JSON object (max 64 KB).
   - Rejects the event (`ErrSensorNotRegistered` → `404`) if the sensor is not registered on the node.
   - Marks the event archived/read and `whitelisted` if its `source` is in `whitelisted_sources`.
   - Calls `store.InsertEvent()`.
   - Calls `store.UpdateNodeLastHeartbeat()` (not for Hub-raised events).
   - Sends the event to the SIEM via `siemService.QueueEvent()` (whitelisted events included).
   - For non-whitelisted events: checks `store.IsSensorSilenced()` and, if false, triggers `notifyService.Dispatch()`; then broadcasts the update to the UI via `broadcaster.Broadcast("NEW_EVENT")`.
5. **API Handler:** Returns a clean `HTTP 200 OK`.

There is no version check on events. Hub-raised events (`sensor_stopped`, `sensor_recovered`, `sensor_heartbeat_lost`) enter the same pipeline through `EmitSystemEvent` with `source = "truesignal-hub"`.

## Developer Guide: Adding a New Feature

When extending the backend, strict adherence to the established flow is required:

1. **Models:** Define your data structures in `models/`.
2. **Store:** Write the SQL queries in `store/`. Update the interface definition at the top of your target Service.
3. **Service:** Write the business logic in `services/<domain>/service.go`. Handle all errors, business validation, and side effects here.
4. **API Handler:** Write a thin HTTP wrapper in `api/<domain>.go`. Use `api.RespondError` and `api.SendJSON`.
5. **Router & Main:** Register the route in `api/router.go` and wire the dependencies in `cmd/hub/main.go`.
