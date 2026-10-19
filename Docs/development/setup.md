# Local Environment Setup

This guide covers how to set up TrueSignal for local development. 

For advanced CI/CD simulation (e.g., local Gitea and private Docker registries), see [maintainer-workflow.md](/Docs/development/maintainer-workflow.md).

## Prerequisites

Ensure the following are installed on your development machine:
- **Go** 1.26+
- **Node.js** (v20+) and **npm**
- **Docker** v5.0+

---

## 1. Quick Start (Minimal Setup)

This is the fastest way to get the Hub and Wizard running locally for standard UI/API development.

### A. Running the Hub (Backend + Frontend)

The Hub requires both the Go backend and the Vue frontend to run simultaneously.

1. **Start the Frontend Dev Server:**
   Navigate to the UI directory and start Vite:
   ```bash
   cd Hub/ui
   npm install
   npm run dev
   ```
   *Note: Vite runs on port 5173 by default, but it is configured to proxy API requests to the Go backend.*

2. **Start the Backend Server:**
   Open a new terminal, navigate to the Hub directory, and run the Go binary:
   ```bash
   cd Hub
   TS_ENV=development TS_PORT=8080 go run cmd/hub/main.go
   ```
   *Note: `TS_ENV=development` is crucial; it disables the `Secure` flag on the authentication cookie so you can log in over `http://localhost`, and relaxes the WebSocket origin check for the Vite dev server. Never use it in production.*

   *Note: the Go binary embeds `Hub/ui/dist` (`go:embed`). Run `npm run build` in `Hub/ui` once before `go run`/`go test` if `dist/` does not exist.*

   On first start the Hub logs a one-time setup token (`[SETUP] ... One-time setup token: ...`). Enter it on the setup page, or start the Hub with `TS_SETUP_TOKEN=<your-token>` to choose it. The admin password must be at least 12 characters.

   Locally built sensor images have no registry digest. Add `TS_ALLOW_UNPINNED_IMAGES=true` to let the Hub compile them (development only).

3. **Access the Application:**
   Open your browser and navigate to `http://localhost:5173`. Complete the initial setup (with the setup token from the Hub log), then create a node to get its key.

### B. Running the Wizard

To test the Wizard against your local Hub:

1. Copy the Node API Key shown when you create the node (it is shown once; rotate it if lost).
2. Run the Wizard from the repository root, passing the key in the environment so it stays out of the process list:
   ```bash
   TS_NODE_API_KEY=<YOUR_NODE_KEY> go run wizard/cmd/wizard/main.go --link http://localhost:8080
   ```
   The Wizard refuses to run unless it is root, so run this from a root shell.
   (`--api-key <YOUR_NODE_KEY>` still works.)

### C. Running the Tests

CI (`.github/workflows/test.yml`) runs `go vet ./...` and `go test -race ./...` for the Hub, the Wizard, the Go SDK and each official sensor, and byte-compiles the Python SDK, template and scripts. Run the same locally before pushing:

```bash
(cd Hub/ui && npm ci && npm run build)   # the Hub tests need the embedded UI
for m in Hub wizard SDKs/go-truesignal Sensors/official/*/; do (cd "$m" && go vet ./... && go test ./...); done
```

---

## 2. Standard Dev Setup (Testing Sensors)

When developing or modifying sensors, you need to verify their interaction with the network.

### Mocking the Hub for Sensor Testing

If you are building a sensor and only want to test its telemetry output without running the full TrueSignal Hub, use the provided Python Mock Hub script.

1. Start the Mock Hub:
   ```bash
   python3 scripts/mock_hub.py
   ```
2. Start your sensor via Docker, passing the Mock Hub's address and enabling test mode:
   ```bash
   docker run --rm \
     -e TS_HUB_ENDPOINT=http://<YOUR_LOCAL_IP>:8080 \
     -e TS_HUB_KEY=test_key \
     -e TS_SENSOR_ID=test_sensor \
     -e TS_TEST_MODE=true \
     your-sensor-image:latest
   ```

If successful, the Mock Hub will print `[EVENT] OK` to the console, proving your sensor's JSON payload adheres to the required [Data Contracts](/Docs/architecture/dataContracts.md).