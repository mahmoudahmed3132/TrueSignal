# Sensor Development Guide

TrueSignal's architecture separates the central Hub from the deceptive traps (Sensors). This guide explains how to build a custom sensor from scratch, ensuring it complies with TrueSignal's Universal Event Standard and strict security model.

## 1. Anatomy of a Sensor

Every sensor in TrueSignal consists of three core components:
1. **The Application Logic:** Typically a pure Go binary utilizing the TrueSignal SDK.
2. **The Security Sandbox:** A highly restricted `Dockerfile`.
3. **The Deployment Manifest:** A JSON manifest (`<sensor-name>.json`, e.g. `Sensors/official/TcpTarpit/tcp-tarpit.json`) that tells the Hub and Wizard how to deploy and configure it.

---

## 2. Using the Go SDK

While you can technically write a sensor in any language using HTTP POST requests, the **TrueSignal Go SDK** (`SDKs/go-truesignal`) is the official standard. It handles authentication, backoff retries, heartbeats, and strict adherence to the data contract.

### Basic Implementation

Instead of starting from scratch, always use the official templates located at [`Sensors/templates/`](/Sensors/templates/). 
See the [Templates README](/Sensors/templates/README.md) and the [Community Sensors README](/Sensors/community/README.md) for more details. These directories contain pre-configured `main.go` and `sensor.py` files with detailed comments, hardened `Dockerfile`s, and example manifests (`manifest.example.json`) that declare the required security capabilities.

---

## 3. The Deployment Manifest

The manifest is the single source of truth for your sensor. It defines how the Hub renders its UI card, how the Wizard deploys it, and what heuristics trigger a recommendation.

Instead of starting from scratch, base your manifest on the templates provided at [`Sensors/templates/go-sensor/manifest.example.json`](/Sensors/templates/go-sensor/manifest.example.json) or [`Sensors/templates/python-sensor/manifest.example.json`](/Sensors/templates/python-sensor/manifest.example.json).

### Key Sections
*   **`heuristics`:** Instructs the Wizard when to recommend this sensor. For example, if you build an Nginx honeypot, you would set `"processes": ["nginx"]` and `"ports": [80, 443]`.
*   **`deployment.env_vars`:** Defines configurable parameters that the Hub UI will generate forms for. If your sensor needs a custom configurable port, define it here.
*   **`deployment.image_repository` / `image_tag` / `image_digest`:** The Docker image to pull. Leave `image_digest` empty in source; the publish workflow fills it in, and the Hub refuses to deploy an image without one.

*(See [`Docs/architecture/dataContracts.md`](/Docs/architecture/dataContracts.md) for the full manifest schema and required fields).*

---

## 4. The Security Sandbox

TrueSignal treats sensors as untrusted, potentially hostile execution units. **If a sensor is compromised, the blast radius must be minimal.**

To ensure compliance, **always use the `Dockerfile` and manifest deployment configuration provided in the templates (e.g., [`Sensors/templates/go-sensor/`](/Sensors/templates/go-sensor/))**. It is pre-configured to enforce the following baseline rules:

1.  **Distroless Base:** The Dockerfile must use a minimal base image like `gcr.io/distroless/static-debian12`. No shells (`/bin/sh`), no package managers, no utilities.
2.  **Prefer unprivileged Execution:** It is better for the container to run as a non-root user (e.g., `USER 65532:65532`). If the manifest sets no `user`, the Hub defaults it to `65532:65532`.
3.  **Capability Stripping:** The deployment must drop all Linux capabilities. The Hub will automatically append `cap_drop: ["ALL"]` to the Compose output. If your sensor strictly requires a capability, it must be explicitly requested in the manifest and be one of the Hub's allowed capabilities: `NET_RAW`, `NET_BIND_SERVICE`, `DAC_OVERRIDE`.
4.  **No New Privileges:** The Hub enforces `security_opt: ["no-new-privileges:true"]` automatically.

---

## 5. Local Testing

Do not boot the entire Hub to test a sensor's data payload. Use the Mock Hub script:

1.  Start the Mock Hub:
    ```bash
    python3 scripts/mock_hub.py
    ```
2.  Run your sensor container locally:
    ```bash
    docker run --rm \
      -e TS_HUB_ENDPOINT=http://<YOUR_LOCAL_IP>:8080 \
      -e TS_HUB_KEY=test_key \
      -e TS_SENSOR_ID=test_sensor \
      -e TS_TEST_MODE=true \
      your-sensor-image:latest
    ```

The Mock Hub validates your event against the [Universal Event Standard](/Docs/architecture/dataContracts.md#1-the-universal-event-standard) (all six keys present, a valid severity, `details` a JSON object) and prints `[EVENT] OK` or the specific failure reason. Only a valid event writes the CI success flag `/tmp/test_passed`; heartbeats and offline notices do not. It does not check node keys or sensor registration, so also run against a real Hub before release.

## 5.1. Testing Methodologies (CI/CD vs Live)

TrueSignal distinguishes between two distinct ways of testing a sensor payload. Because of the strict security model (no exposed APIs, no shell access), testing relies on process state rather than direct interaction:

1. **Boot-Time CI/CD Testing (`TS_TEST_MODE=true`):**
   When a sensor container boots with this flag, it acts as a short-lived execution check. It synchronously sends a test payload directly to the Hub wire (bypassing internal queues) and immediately shuts down with exit code `0`. This guarantees payload delivery before the container exits. It is strictly used for automated CI pipelines.

2. **Live In-Flight Testing (`SIGUSR1`):**
   When a sensor is actively running in production, it can be tested on-demand via the Wizard CLI (`wizard firedrill`). The Wizard sends a `SIGUSR1` Unix signal to the target Docker container.
   Unlike the CI test, the signal handler routes the synthetic event into the sensor's asynchronous event queue (`ReportEvent()`). This ensures the test payload traverses the exact same real-world code paths (including exponential backoff, rate limits, and network retries) as a genuine intrusion event, all without interrupting the sensor's active uptime.