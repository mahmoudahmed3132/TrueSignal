# SIEM Integration

The Hub forwards every event (including whitelisted evidence and Hub-generated liveness) and every audited admin action to one SIEM destination. Configure it under **Settings → SIEM Forwarding** or with `PATCH /api/v2/config`.

## Outputs

| `siemProtocol` | `siemAddress` | Payload | Auth |
|---|---|---|---|
| `tcp`, `udp`, `tls` | `host:port` | One line per record. `siemFormat` picks `rfc5424` (default; see `Docs/architecture/dataContracts.md`) or `ecs` (one ECS JSON document per line) | none (`tls` verifies the receiver) |
| `elastic` | Cluster URL **plus data stream**, e.g. `https://es.example:9200/logs-truesignal-default` | ECS, via `POST <address>/_bulk` with a `create` action per document | `siemToken` = encoded API key, sent as `Authorization: ApiKey …` |
| `logscale` | HEC endpoint, e.g. `https://cloud.us.humio.com/api/v1/ingest/hec` | ECS document in the HEC `event` field (`sourcetype: truesignal`) | `siemToken` = ingest token, sent as `Authorization: Bearer …` |

- HTTP outputs require `https://`. Certificates are verified against the system roots, or against `TS_SIEM_CA_FILE` when it is set. Redirects are not followed, so the token is never sent to a host other than `siemAddress`.
- `siemToken` is write-only. `GET /api/v2/config` returns only `siemTokenSet`. Leave the token out of a `PATCH` to keep the stored one, or send `""` to clear it. It is stored in the Hub database alongside the webhook URLs, so protect the Hub's `/data` volume accordingly.
- Delivery: records go one per request. Network errors, `5xx` and `429` are retried with backoff (10 attempts). Any other `4xx`, or an Elastic bulk item error such as a mapping conflict, drops that record and logs the reason. The queue holds 5000 records in memory.
- Changing the output takes effect immediately; no restart is needed.

## ECS mapping (ECS 8.11)

| ECS field | Value |
|---|---|
| `@timestamp` | Event time from the sensor |
| `event.kind` | `alert`. `event` for whitelisted sources, Hub liveness (`sensor_*`) and audit records |
| `event.category` | `intrusion_detection` plus `authentication` (`*_login`, `web_login_attempt`), `file` (`decoy_file_*`), `web` (`web_*`) or `network`. Liveness is `host` |
| `event.type` | `info` (audit changes: `change`) |
| `event.action` | The `eventTrigger` (e.g. `ldap_login`) or the audited `METHOD /route` |
| `event.severity` | `critical` 99, `high` 73, `medium` 47, `low` 21, `info` 1 |
| `event.outcome` | `failure` for authentication attempts (decoys never grant access); audit: by HTTP status |
| `event.dataset` / `event.module` | `truesignal.alert` or `truesignal.audit` / `truesignal` |
| `event.provider`, `event.id` | Sensor ID, Hub event ID |
| `log.level` | TrueSignal severity string |
| `source.ip` | Event `source` when it is an IP address; otherwise `source.address` |
| `destination.port` | `details.dst_port` |
| `user.name`, `user.domain` | `details.username` (`DOMAIN\user` is split), `attempted_username` or `bind_dn` |
| `file.path` / `url.path` | `details.path` for file canaries / web decoys |
| `user_agent.original`, `http.request.method` | Web decoy details |
| `host.name`, `host.id`, `observer.hostname` | Node alias, node ID |
| `observer.type` / `vendor` / `product` | `honeypot` / `TrueSignal` / `TrueSignal` |
| `tags` | `truesignal`, `deception` (plus `whitelisted`; audit: `audit`) |
| `truesignal.*` | The complete TrueSignal record, including `truesignal.details` |

Captured secrets (`password_hmac`, `netntlmv2` and similar) appear only under `truesignal.details`, never in ECS `user.*`. If `TS_CAPTURE_NTLM=hash` or `TS_CAPTURE_PASSWORDS=plain` is enabled on any sensor, the destination index or repository holds credential material: keep it out of PCI scope and restrict who can read it.

## Elastic setup

`truesignal.details` differs per sensor, so map it as `flattened` to avoid mapping conflicts. The template below assumes Elastic 8.13+ (for the `ecs@mappings` component). Create it once:

```json
PUT _index_template/logs-truesignal
{
  "index_patterns": ["logs-truesignal-*"],
  "data_stream": {},
  "priority": 200,
  "composed_of": ["logs@mappings", "logs@settings", "ecs@mappings"],
  "template": {
    "mappings": {
      "properties": {
        "truesignal": { "properties": { "details": { "type": "flattened" } } }
      }
    }
  }
}
```

API key for the Hub, limited to writing its own data stream:

```json
POST /_security/api_key
{
  "name": "truesignal-hub",
  "role_descriptors": {
    "truesignal_writer": {
      "indices": [{ "names": ["logs-truesignal-*"], "privileges": ["create_doc", "auto_configure"] }]
    }
  }
}
```

Put the response's `encoded` value in `siemToken`, and set `siemAddress` to `https://<es-host>:9200/logs-truesignal-default`. To check ingest, search `event.module:truesignal` in Discover.

## LogScale setup

1. Create (or choose) a repository and an **ingest token** for it. Assign a parser that parses JSON (for example the built-in `json` parser) so the ECS fields are extracted.
2. Set `siemProtocol: logscale`, `siemAddress: https://<your-logscale>/api/v1/ingest/hec` and `siemToken: <ingest token>`.
3. To check ingest, search the repository for `event.module = "truesignal"`.

As an alternative, `tcp`/`tls` with `siemFormat: ecs` works with the LogScale Collector or Elastic Agent's TCP input.
