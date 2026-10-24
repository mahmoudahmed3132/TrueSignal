# Web Router Decoy skins

The Web Router Decoy (`ts-sensor-web-router-decoy`) serves one login surface per instance. A skin is data (product name, colours, form fields, footer, `Server` header, login path), rendered by one `html/template`, so every value is HTML-escaped. Code: `Sensors/official/WebRouterDecoy/skin.go`.

## Choosing a skin

| `TS_SKIN` | Surface | Login path | User field | Extra fields | `Server` |
|---|---|---|---|---|---|
| `router` (default) | "<brand> Router Login"; footer model/firmware match `TS_ROUTER_BRAND` | `/login` | `username` | | `httpd` |
| `nas` | NAS storage manager | `/login` | `username` | | `nginx` |
| `vpn` | SSL VPN portal | `/remote/login` | `username` | `realm` select | `xxxxxxxx-xxxxx` |
| `webmail` | Webmail sign-in | `/mail/login` | `email` | | `Apache` |
| `admin` | Generic application admin console | `/admin/login` | `username` | | `Apache-Coyote/1.1` |
| `basic` | HTTP Basic auth challenge on every path | any | `Authorization` header | | `GoAhead-Webs` |

`TS_SKIN_PRODUCT` replaces the product name in the header and `<title>` (the realm for `basic`). Pick a name that fits the network segment the decoy sits in; a "VPN portal" on a database VLAN is a tell.

## Custom skin (`TS_SKIN_JSON`)

Set `TS_SKIN_JSON` to a JSON object; it overrides `TS_SKIN`. Unknown keys are rejected and the sensor exits at start on any validation error.

```json
{
  "name": "sso",
  "product": "Corp SSO",
  "panel_title": "Sign in",
  "intro": "Use your corporate account.",
  "error_text": "Incorrect user ID or password.",
  "button": "Sign in",
  "accent": "#0b5394",
  "login_path": "/sso/login",
  "fields": [
    {"name": "user", "label": "User ID", "type": "text", "autocomplete": "username"},
    {"name": "pass", "label": "Password", "type": "password"},
    {"name": "domain", "label": "Domain", "type": "select", "options": ["CORP", "OPS"]}
  ],
  "user_field": "user",
  "pass_field": "pass",
  "footer": [["Version", "3.4.1"]],
  "server_header": "nginx"
}
```

Rules: at most 16 KiB; `product` required; `accent` is `#rrggbb`; `login_path` is a simple absolute path other than `/`; 1-8 fields named `[a-z][a-z0-9_]*`, type `text|password|email|select`; `user_field` and `pass_field` must name fields; text values single-line, at most 256 bytes; at most 8 footer rows. `"basic": true` with an optional `realm` makes a Basic-auth skin (no fields needed).

## Events

Triggers are unchanged (`web_login_attempt`, `web_page_view`, `web_path_probe`). Every event adds `skin`. Login events add:

* `attempted_username`: the skin's user field (or the Basic-auth user). The Hub matches honeytokens on it.
* The password per `TS_CAPTURE_PASSWORDS` (`attempted_password_hmac` by default).
* `auth`: `form` or `basic`; `path`: the request path.
* `form_<name>` for each extra form field (e.g. `form_realm`), at most 256 bytes.

Login events are limited to 20 per source per minute; the rest are dropped and counted, and the next event from that source carries `suppressed_since_last`. The attacker sees no difference (same delay and error page). A honeytoken submitted inside a suppressed burst is not reported for that attempt; it is caught when it is submitted again after the window.

Severity is `TS_SEVERITY` (critical by default) for logins and medium for views and probes. The target is `Web Interface (<product>)`.
