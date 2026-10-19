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
