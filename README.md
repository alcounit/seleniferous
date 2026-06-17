# seleniferous

**Per-pod sidecar proxy for the [Selenosis](https://github.com/alcounit/selenosis) browser platform.**
It lives inside every browser pod, fronts the browser for Selenium, Playwright, and MCP
traffic, gives the session a stable identity, and tears the pod down when the session
ends or goes idle.

[![GitHub release](https://img.shields.io/github/v/release/alcounit/seleniferous)](https://github.com/alcounit/seleniferous/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/alcounit/seleniferous.svg)](https://pkg.go.dev/github.com/alcounit/seleniferous/v2)
[![Docker Pulls](https://img.shields.io/docker/pulls/alcounit/seleniferous.svg)](https://hub.docker.com/r/alcounit/seleniferous)
[![codecov](https://codecov.io/gh/alcounit/seleniferous/branch/main/graph/badge.svg)](https://codecov.io/gh/alcounit/seleniferous)
[![Go Report Card](https://goreportcard.com/badge/github.com/alcounit/seleniferous/v2)](https://goreportcard.com/report/github.com/alcounit/seleniferous/v2)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

---

## What it does

seleniferous is not something you run by hand — it ships **inside the browser pod** as a
sidecar and is driven by the selenosis hub. In that pod it:

- **Fronts the browser.** Proxies WebDriver (incl. BiDi), Chrome DevTools Protocol,
  Playwright (WebSocket), and MCP traffic to the local browser process on `BROWSER_PORT`.
- **Gives the session a stable identity.** Rewrites the browser-provided `sessionId` to a
  deterministic, pod-derived UUID, so routing stays stateless across the whole stack.
- **Owns the session lifecycle.** Tracks create and idle timeouts and tears the pod down
  when the session ends or goes idle — no orphaned browsers.
- **Exposes per-session helper routes.** Internal HTTP routing to custom sidecars and a
  VNC proxy endpoint, both used by selenosis and browser-ui.

---

## How it fits

A request travels **client → selenosis (hub) → seleniferous (this sidecar) → browser**.
The hub resolves which pod a session belongs to and proxies traffic to that pod's
seleniferous; seleniferous forwards it to the browser next to it and manages everything
session-scoped. See the [selenosis architecture](https://github.com/alcounit/selenosis#how-it-works)
for the full picture.

| Component | Role |
| --- | --- |
| **[selenosis](https://github.com/alcounit/selenosis)** | Stateless Selenium / Playwright / MCP hub. Creates browser sessions and proxies traffic to the right pod. |
| **[seleniferous](https://github.com/alcounit/seleniferous)** (this repo) | Sidecar proxy inside each browser pod. Session lifecycle, id rewriting, idle timeouts, internal routing. |
| **[browser-controller](https://github.com/alcounit/browser-controller)** | Kubernetes operator that reconciles `Browser` / `BrowserConfig` CRDs into pods, with deterministic cleanup. |
| **[browser-service](https://github.com/alcounit/browser-service)** | REST + server-sent-events facade over `Browser` resources. |
| **[browser-ui](https://github.com/alcounit/browser-ui)** | Web dashboard with a live session list and an in-browser VNC viewer. |
| **[selenosis-deploy](https://github.com/alcounit/selenosis-deploy)** | Helm chart that deploys the whole stack. **Start here.** |

> You normally don't deploy seleniferous directly — it's attached to every browser pod
> through a `BrowserConfig` sidecar entry. The Helm chart and example `BrowserConfig`s in
> [selenosis-deploy](https://github.com/alcounit/selenosis-deploy) wire it up for you.

---

## Session identity

This is the mechanism that keeps the whole platform stateless — worth understanding
before touching any routing code.

A pod's IP maps to a **deterministic UUID** (`IPUUID`) and back. seleniferous rewrites the
real upstream session id (the browser's WebDriver session id, or the MCP session) to that
stable, pod-derived id on the way out, and maps it back on the way in. Because the id
*encodes the pod*, selenosis can route any later request straight to the right pod by
decoding it — there is no session registry anywhere. The same scheme carries the id in the
WebDriver `sessionId` for Selenium/Playwright and in the `Mcp-Session-Id` header for MCP.

---

## Configuration

seleniferous is configured via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:4445` | HTTP listen address. |
| `BROWSER_PORT` | `4444` | Local browser port inside the pod. |
| `SESSION_RETRY_COUNT` | `5` | Maximum retry attempts for session creation. |
| `SESSION_RETRY_DELAY` | `2s` | Delay between consecutive session-creation attempts. |
| `SESSION_CREATE_TIMEOUT` | `1m` | Maximum time to wait for a browser response. |
| `SESSION_IDLE_TIMEOUT` | `5m` | Max time to wait for the first request, then max idle time after session creation. |
| `ROUTING_RULES` | empty | Rules for the internal HTTP proxy (see below). |
| `POD_IP` | auto | Pod IP used to derive the stable `sessionId` (auto-detected if absent). |

---

## Endpoints

seleniferous exposes Selenium-compatible endpoints plus internal proxy routes for
selenosis.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/session` | Create a new WebDriver session (proxied to the local browser). |
| `*` | `/session/{sessionId}/*` | Proxy all session traffic (HTTP and WebSocket). |
| `WS` | `/playwright` | Proxy Playwright WebSocket traffic. |
| `POST` | `/mcp` | MCP Streamable HTTP — client requests (proxied to the local browser `/mcp`). |
| `GET` | `/mcp` | MCP Streamable HTTP — server-initiated stream. |
| `DELETE` | `/mcp` | Terminate the MCP session and schedule pod teardown. |
| `*` | `/selenosis/v1/sessions/{sessionId}/proxy/http/*` | Internal HTTP proxy into the pod (custom sidecars). |
| `GET` | `/selenosis/v1/vnc/{sessionId}` | Internal VNC proxy used by browser-ui. |

---

## Request flow

1. selenosis proxies `POST /wd/hub/session` to `POST /session` on the sidecar.
2. seleniferous forwards the request to the local browser on `BROWSER_PORT`.
3. The browser returns a `sessionId`; seleniferous rewrites it to the pod `IPUUID`.
4. All subsequent requests are proxied by seleniferous to the browser, and each one resets
   the idle timeout. When it expires (or the session is deleted), the pod is torn down.

<details>
<summary><b>Talking to seleniferous directly (curl)</b></summary>

You usually go through selenosis, but you can hit the sidecar directly inside the pod:

```bash
# Create a session
curl -sS -X POST http://{pod_ip}:4445/session \
  -H 'Content-Type: application/json' \
  -d '{ "capabilities": { "alwaysMatch": { "browserName": "chrome", "browserVersion": "120.0" } } }'

# Proxy a command on an existing session
curl -sS -X GET http://{pod_ip}:4445/session/<sessionId>/url
```

</details>

---

## Internal HTTP routing (`ROUTING_RULES`)

seleniferous can route HTTP requests arriving on
`/selenosis/v1/sessions/{sessionId}/proxy/http/*` to targets reachable **inside the browser
pod** — a file server, a recorder, a mock backend, any custom sidecar — so per-session
helpers are reachable through the hub at the same host and auth as the browser.

<details>
<summary><b>Rule schema and a file-server example</b></summary>

`ROUTING_RULES` is a JSON array. Rules are evaluated in order; the first match wins.

| Field | Required | Description |
| --- | --- | --- |
| `pathRegex` | yes | Regex matched against the full request path. Use named capture groups to extract segments for rewriting. |
| `target` | yes | Proxy destination in `host:port` form (inside the pod). |
| `rewritePath` | no | Path template; use `{groupName}` to substitute named capture group values. |

Example — expose a file server listening on `127.0.0.1:8080`:

```json
[
  {
    "pathRegex": "^/selenosis/v1/sessions/[^/]+/proxy/http/(?P<path>.*)$",
    "target": "127.0.0.1:8080",
    "rewritePath": "/{path}"
  }
]
```

Set it as an environment variable on the seleniferous container (via `BrowserConfig`):

```bash
ROUTING_RULES='[{"pathRegex":"^/selenosis/v1/sessions/[^/]+/proxy/http/(?P<path>.*)$","target":"127.0.0.1:8080","rewritePath":"/{path}"}]'
```

A request to `/selenosis/v1/sessions/<sessionId>/proxy/http/json?file=report.txt` is
rewritten to `/json?file=report.txt` and forwarded to `127.0.0.1:8080` inside the pod.

</details>

---

## MCP (experimental)

seleniferous proxies [Model Context Protocol](https://modelcontextprotocol.io/) **Streamable
HTTP** traffic to an MCP server running inside the browser container on `BROWSER_PORT`,
exposed on a single `/mcp` endpoint (`POST` / `GET` / `DELETE`). One MCP session per pod.

<details>
<summary><b>Lifecycle, header rewriting, and error responses</b></summary>

Sessions are identified by the `Mcp-Session-Id` header, which must equal the pod-derived
`IPUUID`.

- **Initialize** — `POST /mcp` *without* `Mcp-Session-Id` starts the upstream MCP session.
  seleniferous stores `IPUUID -> <browser session id>` and returns `IPUUID` to the client
  in the `Mcp-Session-Id` response header.
- **Proxied requests** — `POST` / `GET /mcp` with `Mcp-Session-Id: <IPUUID>` are forwarded
  to `/mcp` on the browser. seleniferous rewrites the header to the real browser session id
  on the way in, and back to `IPUUID` on the way out.
- **Terminate** — `DELETE /mcp` ends the session and schedules pod teardown.

Error responses follow JSON-RPC 2.0, so a spec-compliant client reacts correctly:

- a missing `Mcp-Session-Id` header → **`400`** (`InvalidParams`);
- a header that doesn't match the pod `IPUUID`, or whose session isn't in the store →
  **`404`** (`SessionNotFound`) so the client can `initialize` a fresh session.

Request and response **bodies** are forwarded unchanged; only the `Mcp-Session-Id` header
is rewritten. Each MCP request resets the idle timeout, exactly like Selenium and
Playwright traffic.

</details>

---

## Networking and headers

Behind a reverse proxy or ingress, set `X-Forwarded-Proto` and `X-Forwarded-Host` so
seleniferous can build correct external URLs.

---

## Build

The project builds and packages entirely via Docker — a local Go install is not required.

<details>
<summary><b>Makefile build variables</b></summary>

| Variable | Description |
| --- | --- |
| `BINARY_NAME` | Name of the produced binary (fixed: `seleniferous`). |
| `REGISTRY` | Docker registry prefix (default: `localhost:5000`). |
| `IMAGE_NAME` | Full image name, derived as `$(REGISTRY)/$(BINARY_NAME)`. |
| `VERSION` | Image version/tag (default: `develop`). |
| `EXTRA_TAGS` | Additional `-t` tags passed to `docker-push` (default: none). |
| `PLATFORM` | Target platform (default: `linux/amd64`). |
| `CONTAINER_TOOL` | Container build tool (default: `docker`). |

`REGISTRY` and `VERSION` are expected to be supplied externally so the same Makefile works
locally and in CI.

</details>

---

## License

[Apache-2.0](./LICENSE)
