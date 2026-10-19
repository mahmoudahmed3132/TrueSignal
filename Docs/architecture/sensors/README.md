# Sensor Architecture Overview

## Purpose

Sensors are the decentralized execution layer of the TrueSignal platform. They are individual, containerized decoy applications placed throughout a network. 

Their core responsibilities are:
- Detecting malicious activity (generating telemetry and alerts)
- Emitting continuous health heartbeats
- Operating with total independence (no sensor-to-sensor communication)

To ensure consistency, resilience, and strict adherence to the [**TrueSignal Event Standard**](/Docs/architecture/dataContracts.md#1-the-universal-event-standard), all official sensors are built using TrueSignal's Language SDKs (available in Go and Python). This document outlines the architectural contract and behavior enforced by these SDKs.

---

## High-Level Architecture

The sensor architecture is built on a concurrent, multi-pipeline design that strictly separates domain rules (Policy) from network transport (Pipelines).

```mermaid
graph TD
    Init[Initialization & Sync]
    Init --> Classify[Shared Classifier]
    Classify --> Policy[Policy Interpreters]
    Policy --> Event[Event Worker Pipeline]
    Policy --> Heartbeat[Heartbeat Worker Pipeline]
```

---

## 1. Initialization & Sync

Before a sensor begins monitoring, it validates its configuration.

1. **Environment Validation:** The sensor strictly requires `TS_HUB_ENDPOINT`, `TS_HUB_KEY`, and `TS_SENSOR_ID` to be present, and refuses to start otherwise.
2. **Pipeline Boot:** The SDK spins up the Event Loop and Heartbeat Loop as isolated background workers (Goroutines in Go, Daemon Threads in Python).

There is no version handshake between sensor and Hub. Version compatibility is enforced at deploy time instead: the Hub refuses to compile a manifest whose major version differs from its own (`incompatible_sensor`).

---

## 2. Shared Classifier (The Truth Layer)

The SDK utilizes a pure functional `classify` method. This layer evaluates raw HTTP results (or network errors) and returns a factual `ResponseFact` object. It contains **no behavioral logic**.

**Determines:**
- `IsError`: Was the request successful?
- `IsTransient`: Is this a network timeout, a 429 Rate Limit, or a 5xx error (meaning we should retry)? Or is it a 400/401/403/404 (meaning it's a fatal failure)? The Hub answers `404` when the sensor is not registered on the node, and `401` after the node key was rotated or the node deleted.
- `RetryAfter`: Did the Hub explicitly request a backoff duration via HTTP headers?

---

## 3. Policy Interpreters (Domain Rules)

The Policy Engine interprets the `ResponseFact` and dictates the exact behavior the pipelines must follow.

### Event Policy
Governs the strict, ordered, retry-bounded queue for intrusion events.
- **SUCCESS:** The event was received.
- **RETRY:** A transient error occurred. The policy calculates a Jittered Exponential Backoff delay (or uses the Hub's `Retry-After` header).
- **DROP:** A terminal error occurred (e.g., Auth failure). The event is discarded to prevent infinite looping.

### Heartbeat Policy
Governs the stateless, lossy, continuous signal for node health.
- **OK State:** Wait the `BaseHeartbeatInterval` (30 seconds).
- **Degraded State (Transient):** Maintain the steady lossy pulse, unless the Hub explicitly provided a `Retry-After` header, in which case the sensor respects the Hub's requested breathing room.
- **Terminal State:** Enter a massive `TerminalSleepInterval` (1 hour) to prevent hammering a Hub that has actively rejected the sensor's credentials.

---

## 4. Runtime Pipelines

### Pipeline A: Event Worker
The Event Worker handles intrusion alerts. It prioritizes guaranteed delivery without blocking the main monitoring thread.

1. **Buffering:** When the sensor logic detects an intrusion, it calls `ReportEvent`. This pushes the payload into a bounded, non-blocking channel/queue (capacity: 1000). If the buffer is full, the event is immediately dropped to prevent out-of-memory crashes on the host.
2. **Execution:** The worker pulls events from the queue one by one.
3. **Retries:** It attempts delivery up to `MaxRetriesPerEvent` (7 times). If transient errors occur, it pauses processing using the delay calculated by the Event Policy. If the limit is reached, the event is dropped.

### Pipeline B: Heartbeat Worker
The Heartbeat Worker proves the sensor is alive.

1. **Stateless Pulse:** Every 30 seconds, it POSTs to `/api/v2/heartbeat` with `{"sensorId": "...", "configRev": "..."}` (see [Data Contracts](/Docs/architecture/dataContracts.md#2-heartbeat-payload)). No version information is sent.
2. **Lossy:** Unlike events, heartbeats are not queued or retried. If a heartbeat fails, the worker simply sleeps and tries again on the next tick.

---

## 5. Graceful Shutdown & Offline Signaling

When a sensor container receives a termination signal (SIGTERM):

1. **Stop Signal:** The SDK stops accepting new events into the buffer.
2. **Drain Queue:** The Event Worker attempts a best-effort, rapid flush of any remaining events in its buffer directly to the Hub.
3. **Offline Notification (`GoOffline`):** The sensor fires a final, fast-timeout POST to `/api/v2/offline` with the reason `graceful_shutdown`. This allows the Hub to immediately mark the sensor as "Offline" rather than waiting 60 seconds for the heartbeat monitor to declare it "Down". The Hub records a `sensor_stopped` event (low) and, if the sensor has not come back within 5 minutes, escalates with `sensor_heartbeat_lost` (high).