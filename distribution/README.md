# TrueSignal distribution

Public release channel for TrueSignal, a deception platform: a Hub (API, UI,
SIEM output) and containerised decoy sensors deployed on each node by the
`truesignal` wizard. This repository holds only what Hubs and nodes download.
It is maintained by CI; do not edit it by hand.

| What | Where |
|---|---|
| Node installer | `install.sh` on `main` |
| Wizard binaries | Releases `wizard/vX.Y.Z` (static linux amd64/arm64, `checksums.txt`, Sigstore bundles) |
| Hub image | `ghcr.io/mahmoudahmed3132/truesignal-hub` (release notes `hub/vX.Y.Z` carry the digest) |
| Sensor registry | `registry-pages` branch: `index.json`, `<sensor>-v<ver>.json` + `.sigstore.json` |
| Sensor images | `ghcr.io/mahmoudahmed3132/truesignal-*`, pinned by digest in each manifest |

## Install a node

Create the node in the Hub UI and copy its command, or:

```sh
curl -fsSL https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-dist/main/install.sh \
  | TS_NODE_API_KEY=<key> bash -s -- --link https://<hub>
```

Add `--sha256 <hash>` (from the release's `checksums.txt`) to pin the wizard binary.

## Verify

Sensor manifests, images, the Hub image and the wizard binaries are signed with
Sigstore keyless signing by the release workflows of the TrueSignal source
repository. The Hub verifies every sensor manifest before using it. Each
release's notes give the `cosign` command and the expected certificate
identity.

## Licence and source

TrueSignal is a modified version of HoneyWire by Andrea Termine and is
licensed under the GNU Affero General Public License v3.0 (`LICENSE`). See
`NOTICE` for attribution and the list of modifications.

If you received or use TrueSignal, you are entitled to its Corresponding
Source under the AGPLv3. To request it, open an issue in this repository.
