<p align="center">
  <a href="https://github.com/mahmoudahmed3132/TrueSignal" target="_blank" rel="noopener noreferrer">
    <img src="Hub/ui/public/favicon.svg" alt="TrueSignal Logo" width="150" />
  </a>
</p>
<h1 align="center">TrueSignal</h1>

<p align="center">
  <a href="https://github.com/mahmoudahmed3132/TrueSignal/releases">
    <img src="https://img.shields.io/badge/release-v2.1.0-blue.svg?style=flat-square" alt="Latest Release" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-AGPLv3-blue.svg?style=flat-square" alt="License: AGPLv3" />
  </a>
  <a href="Hub/docker-compose.yml">
    <img src="https://img.shields.io/badge/Docker-Native-2496ED.svg?style=flat-square&logo=docker&logoColor=white" alt="Docker Native" />
  </a>
</p>

## 📋 Table of Contents
- [Overview](#overview)
- [The Universal Event Standard](#-the-universal-event-standard-bring-your-own-sensor)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start Guide](#-quick-start-guide)
- [Security Notes](#security-notes)
- [Tech Stack](#tech-stack)
- [Roadmap & Development](#roadmap-development)
- [Versioning and API Reference](#versioning-and-api-reference)
- [Credits & License](#credits--license)

## Overview
**TrueSignal** is a lightweight, Distributed High-Signal Security Early-Warning System Builder, designed for internal networks. It leverages its architecture and UX to make it incredibly easy to build a new Cyber Canary server or deploy TrueSignal sensors on existing ones. Using deception technology, it replaces the "magnifying glass" approach of traditional SIEMs which often drown analysts in false positives by surveilling legitimate traffic with a High-Fidelity Tripwire model. 

Place a sensor exactly where you want it. If it trips, you have an intruder.
  - **Production Tripwires**: Sound the alarm when active services are being poked in ways they shouldn't be. By placing a sensor on a sensitive file that should never be read or a service port that should never be accessed, you identify intruders by their deviation from the "authorized path."
  - **Synthetic Deception**: Deploy lures like the [ICMP Canary](./Sensors/official/IcmpCanary/) or [Network Scan Detector](./Sensors/official/NetworkScanDetector/) to act as decoys. Since these sensors provide no legitimate business value, nearly all of their traffic deserves a look; the exceptions are known infrastructure such as monitoring probes and authorised scanners, which you whitelist.

Set up multiple and you start to have a pretty clear idea of the lateral movement of an intruder. Expect little tuning and little noise compared with log-based detection, but not zero: uptime monitors ping, vulnerability scanners scan, and backup or indexing jobs can touch lure files.
If you have legitimate automated security scanners tripping TrueSignal sensors, whitelist them from the Hub's settings. Whitelisted events are still stored (archived) and still forwarded to your SIEM, flagged `whitelisted=true`, so a whitelist cannot silently hide activity.

## 🔌 The Universal Event Standard (Bring Your Own Sensor)

[**Community Sensors**](./Sensors/community/)
> Note: If you build your sensor using the official TrueSignal SDKs, this JSON formatting and delivery is handled for you automatically.

The true power of TrueSignal is that the Hub and Wizard are **completely sensor-agnostic**. You are not limited to the included official sensors. 

By adhering to the **TrueSignal Event Standard V2.0**, you can write a script in *any* language (Bash, Go, Rust, Python) to monitor *anything*, and the Sentinel UI will dynamically parse, syntax-highlight, and render your forensic data. 

Whether it is a **Deep Packet Inspection (DPI)** engine, a **DNS sinkhole**, a **Canary Token** embedded in a PDF, an **Email Honeypot**, or a simple **TCP Port Tripwire**, just POST the **Universal Event Standard** JSON payload to the Hub. 

> **[View the full Event Data Contract here](./Docs/architecture/dataContracts.md#1-the-universal-event-standard)** 

## Features

- **The Sentinel Hub UI:** A fully responsive, Vue 3-powered dashboard featuring dynamic forensic payload inspection, Nodes and Sensors deployment and management, including sensor updates, directly from the UI.
  - **Universal Push Notifications:** Native, zero-dependency integration for routing critical alerts to **Discord, Slack, Ntfy, and Gotify**.
  - **Enterprise SIEM Integration:** Native RFC5424 Syslog forwarding (TCP/UDP) for seamlessly pushing structured telemetry to Splunk, Elastic, Wazuh, or Vector.
- **The Setup Wizard:** A deployment and testing automation tool, developed explicitly to not be a 24/7 running agent. It is simply a TUI CLI tool that automates operator tasks like applying and reconciling the Hub's desired state for a given Node, automatically handling configuration, deployment, and rollbacks on failed deployments.
- **Suite of Official TrueSignal sensors:** Includes native [TCP Tarpit](./Sensors/official/TcpTarpit/), [Web Router Decoy](./Sensors/official/WebRouterDecoy/), [File Canary (FIM)](./Sensors/official/FileCanary/), [ICMP Canary](./Sensors/official/IcmpCanary/), and [Network Scan Detector](./Sensors/official/NetworkScanDetector/).

## Architecture

TrueSignal is split into four independent microservices:

1. `/Hub`: The central brain. A pure Go binary running an embedded SQLite database and the Vue.js dashboard. It runs as a non-root user inside a Distroless container, safely mounting data to a dedicated volume.
2. `/Sensors`: The decoy nodes. Statically-linked Go binaries that listen on vulnerable ports, trap attackers, and securely POST intrusion data back to the Hub.
3. `/SDKs`: Official libraries (like `sdk-go`) that handle secure Hub communication so community developers can easily build new sensors.
4. `/wizard`: Setup wizard cli tool to automate operator tasks such as discovery, deployment and testing of TrueSignal sensors.

> **[Check out the full architecture docs](./Docs/architecture/README.md)**
> **[Read the User Operations Guide](./Docs/operations.md)**

## 🚀 Quick Start Guide

Deploying the TrueSignal Hub takes less than 60 seconds using our pre-built GitHub Container images.

### 1. Deploy the Hub
Create a new directory on your server, create a `docker-compose.yml` file, and paste the following:

```yaml
services:
  # 1. THE PERMISSION FIXER: Runs once to ensure the Hub can write to the data volume
  permission-fixer:
    image: alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
    container_name: truesignal-permission-fixer
    command: sh -c "chown -R 65532:65532 /data"
    network_mode: none
    read_only: true
    cap_drop: ["ALL"]
    cap_add: ["CHOWN", "DAC_OVERRIDE", "FOWNER"]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - ./truesignal_data:/data

  # 2. THE HUB: The central Go-based dashboard and API
  hub:
    # Pin a release in production, e.g. TS_HUB_VERSION=v2.1.0
    image: ghcr.io/mahmoudahmed3132/truesignal-hub:${TS_HUB_VERSION:-latest}
    container_name: truesignal-hub
    restart: unless-stopped
    ports:
      # Host port is configurable; the Hub always listens on 8080 inside.
      # Bind to 127.0.0.1 instead when a reverse proxy runs on the same host.
      - "${TS_PORT:-8080}:8080"
    volumes:
      - ./truesignal_data:/data
    depends_on:
      permission-fixer:
        condition: service_completed_successfully
        
    # Strict Security Sandbox
    user: "65532:65532"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    
    environment:
      - TS_PORT=8080
      - TS_DB_PATH=/data/truesignal.db
      # Set to true only when a reverse proxy sets X-Forwarded-For / X-Real-IP
      # - TS_TRUST_PROXY=true
      # Optional: choose the one-time setup token instead of reading it from the log
      # - TS_SETUP_TOKEN=<random string>
      # Optional: Hardcode the dashboard password (disables the UI password reset feature)
      # - TS_DASHBOARD_PASSWORD=<at least 12 characters>
      # Local HTTP testing only: drops the cookie Secure flag and the WebSocket origin check
      # - TS_ENV=development
```

The Hub runs in production mode by default, which marks the session cookie `Secure`: browsers will only send it over HTTPS. Put a TLS reverse proxy (Nginx, Caddy, Traefik, F5, ...) in front of it. For a quick local trial over plain HTTP, uncomment `TS_ENV=development`, and never leave it set in production.

Start the Hub:
```bash
docker compose up -d
```

### 2. Initialize the System
Get the one-time setup token from the Hub log:
```bash
docker compose logs hub | grep SETUP
```
Navigate to your Hub's URL (through the reverse proxy, or `http://<your-server-ip>:<TS_PORT>` for a local trial) in your browser. You will be greeted by the **TrueSignal Sentinel** setup screen.
1. Paste the setup token. It stops anyone else who can reach the Hub from claiming it first.
2. Create your Master Password (at least 12 characters).
3. Verify your Hub Endpoint URL (the IP/URL where sensors will reach the Hub).
4. Click "Initialize Hub".

### 3. Deploy Sensors
1. Create a new Node and paste the provided command to install and link the Setup Wizard to the hub
2. Install sensors directly from the Hub and then run `truesignal apply` on the node to reconcile desired state or run `truesignal discover` to let the Setup wizard automatically scan and suggest TrueSignal sensors based on environment.

### 4. Testing the TrueSignal sensors

Once your containers are up, the Tarpit sensor should appear as `ONLINE` within 30 seconds.
Run `truesignal firedrill` to make the TrueSignal sensors send a mock event to the hub to test connectivity.

> **Note:** For a deeper dive into managing nodes, updating sensors, and handling rollbacks, see the **[User Operations Guide](./Docs/operations.md)**.

---

## Security Notes
* **Threat Model:** For a deep dive into trust boundaries, architecture risks, and sandboxing rules, see the **[THREATMODEL.md](./THREATMODEL.md)**.
* **Node Keys:** Ensure your sensors use their unique `Node Key` to communicate with the Hub. The Hub will reject any payloads with mismatched or invalid keys, and events for sensors not registered on that node. Keys are stored hashed, shown once, and can be rotated from the node page (see the [Operations Guide](./Docs/operations.md#8-rotating-a-node-api-key)).
* **SIEM Forwarding:** Events, sensor liveness changes and admin actions can be forwarded as RFC 5424 syslog over TCP, UDP or TLS. See [Data Contracts](./Docs/architecture/dataContracts.md#4-siem-syslog-format).
* **System Arming:** You can toggle the "System Armed" button in the Hub UI to temporarily disable push notifications while doing internal network maintenance or vulnerability scanning. Events are still stored and forwarded to the SIEM while disarmed.
* **Container Hardening:** TrueSignal utilizes `gcr.io/distroless/static-debian12:nonroot`. We follow the principle of least privilege to make sure that if a container is compromised, the blast is contained.
* **Distributed Deployment:** It is highly recommended to run the Hub and its Sensors on separate physical or virtual machines. If an attacker compromises a sensor node, they should not have immediate local access to the centralized Hub.
* ⚠️ **Encryption (HTTPS):** Always serve the Hub Web UI and API over HTTPS using a reverse proxy (like Nginx, Caddy, or Traefik) in production. Failure to do so exposes your Dashboard password and Node Keys to network sniffing.


## Tech Stack
* **Backend:** Go 1.25, `net/http` with the `go-chi/chi` router, SQLite (ModernC Pure Go Driver)
* **Frontend:** Vue 3 (Composition API), TailwindCSS, Chart.js
* **Infrastructure:** Docker, Docker Compose v5.0.0+


<a id="roadmap-development"></a>
## Roadmap & Development

Planned work and known gaps are tracked in [`docs/KNOWLEDGE-GAPS.md`](./docs/KNOWLEDGE-GAPS.md). Development guides live in [`Docs/development/`](./Docs/development/README.md).


## Versioning and API Reference

- TrueSignal versions are managed via Git Tags.
- `Hub` endpoint:
  - `GET /api/v2/version` → returns `{ "version": "v2.x.x" }`
- API docs file: [API.md](./Docs/architecture/hub/backend/API.md) with full backend route reference and sample payloads.

## Credits & License

TrueSignal is a fork of [HoneyWire](https://github.com/andreicscs/HoneyWire) by Andrea Termine, rebranded and maintained independently. Upstream copyright is retained. See [`NOTICE`](./NOTICE).

Licensed under the GNU Affero General Public License v3.0 ([`LICENSE`](./LICENSE)). If you run a modified TrueSignal Hub as a network service, AGPLv3 §13 requires offering its source to users of that service.
