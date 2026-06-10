[![GitHub release](https://img.shields.io/github/v/release/alcounit/seleniferous)](https://github.com/alcounit/seleniferous/releases) [![Go Reference](https://pkg.go.dev/badge/github.com/alcounit/seleniferous.svg)](https://pkg.go.dev/github.com/alcounit/seleniferous/v2) [![Docker Pulls](https://img.shields.io/docker/pulls/alcounit/seleniferous.svg)](https://hub.docker.com/r/alcounit/seleniferous)

# seleniferous
A sidecar proxy that runs inside the browser pod. It handles session creation and traffic routing, and shuts down the pod when a session expires or times out.

## What it does
- Accepts WebDriver traffic on `/session` and proxies it to the local browser service.
- Rewrites the browser-provided `sessionId` to a stable pod-derived UUID.
- Tracks idle and create timeouts.
- Exposes internal HTTP/VNC proxy routes used by Selenosis.

## Requirements
- Runs as a sidecar inside a browser pod.
- Local browser process reachable at `BROWSER_PORT`.
- Optional: `POD_IP` provided for stable session id generation (auto-detected if absent).

## Configuration
Seleniferous is configured via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:4445` | HTTP listen address. |
| `BROWSER_PORT` | `4444` | Local browser port inside the pod. |
| `SESSION_RETRY_COUNT` | `5` | Maximum number of retry attempts for session creation. |
| `SESSION_RETRY_DELAY` | `2s` | Delay between consecutive session creation attempts. |
| `SESSION_CREATE_TIMEOUT` | `1m` | Maximum duration to wait for a browser response. |
| `SESSION_IDLE_TIMEOUT` | `5m` | Max time to wait for first session request or max idle time after session creation. |
| `ROUTING_RULES` | empty | Additional routing rules for internal proxying. |
| `POD_IP` | auto | Pod IP used to derive stable `sessionId`. |

## Endpoints
Seleniferous exposes Selenium-compatible endpoints on `/session` and internal proxy endpoints for Selenosis.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/session` | Create a new WebDriver session (proxied to local browser). |
| `*` | `/session/{sessionId}/*` | Proxy all session traffic (HTTP and WebSocket). |
| `WS` | `/playwright` | Proxies WS traffic. |
| `POST` | `/mcp` | MCP Streamable HTTP transport — client requests (proxied to local browser `/mcp`). |
| `GET` | `/mcp` | MCP Streamable HTTP transport — server-initiated messages (proxied to local browser `/mcp`). |
| `DELETE` | `/mcp` | Terminate the MCP session; schedules browser teardown. |
| `*` | `/selenosis/v1/sessions/{sessionId}/proxy/http/*` | Internal HTTP proxy used by Selenosis. |
| `GET` | `/selenosis/v1/vnc/{sessionId}` | Internal VNC proxy used by Selenosis. |

## Request flow
1. Selenosis proxies `POST /wd/hub/session` to `POST /session` on the sidecar.
2. Seleniferous forwards the request to the local browser on `BROWSER_PORT`.
3. The browser returns a `sessionId`; Seleniferous rewrites it to the pod UUID.
4. All subsequent requests are proxied by Seleniferous to the browser.

## Example: create session
```bash
curl -sS -X POST http://{pod_ip}:4445/session \
  -H 'Content-Type: application/json' \
  -d '{
    "capabilities": {
      "alwaysMatch": {
        "browserName": "chrome",
        "browserVersion": "120.0"
      }
    }
  }'
```

## Example: proxy a command
```bash
curl -sS -X GET http://{pod_ip}:4445/session/<sessionId>/url
```

## Example: internal HTTP proxy

The `/selenosis/v1/sessions/{sessionId}/proxy/http/*` endpoint lets Selenosis route HTTP requests through the sidecar to a target reachable from within the browser pod. The target and path rewriting are controlled by `ROUTING_RULES`.

```bash
curl -sS http://{selenosis}:4444/selenosis/v1/sessions/<sessionId>/proxy/http/json
```

## Routing rules

`ROUTING_RULES` is a JSON array that controls how `/selenosis/v1/sessions/{sessionId}/proxy/http/*` requests are forwarded to targets inside the browser pod.

Each rule:

| Field | Required | Description |
| --- | --- | --- |
| `pathRegex` | yes | Regular expression matched against the full request path. Use named capture groups to extract path segments for rewriting. |
| `target` | yes | Proxy destination in `host:port` format. |
| `rewritePath` | no | Optional path template. Use `{groupName}` to substitute named capture group values. |

Example — expose the Fileserver:

```json
[
  {
    "pathRegex": "^/selenosis/v1/sessions/[^/]+/proxy/http/(?P<path>.*)$",
    "target": "127.0.0.1:8080",
    "rewritePath": "/{path}"
  }
]
```

Set as an environment variable:

```bash
ROUTING_RULES='[{"pathRegex":"^/selenosis/v1/sessions/[^/]+/proxy/http/(?P<path>.*)$","target":"127.0.0.1:8080","rewritePath":"/{path}"}]'
```

A request to `/selenosis/v1/sessions/<sessionId>/proxy/http/json?file=somefile.txt` is rewritten to `/json?file=somefile.txt` and forwarded to `127.0.0.1:8080`.

Multiple rules are evaluated in order; the first match is used.

## MCP (experimental)

Seleniferous proxies [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) **Streamable HTTP** traffic to an MCP server running inside the browser container on `BROWSER_PORT`. It is exposed on a single endpoint `/mcp` (`POST`, `GET`, `DELETE`).

Sessions are identified by the `Mcp-Session-Id` header, which must equal the pod-derived UUID (`IPUUID`).

- **Initialize** — `POST /mcp` without `Mcp-Session-Id` starts the upstream MCP session. Seleniferous stores the mapping `IPUUID -> <browser session id>` and returns `IPUUID` to the client in the `Mcp-Session-Id` response header. Only one MCP session per pod is allowed.
- **Proxied requests** — `POST`/`GET /mcp` with `Mcp-Session-Id: <IPUUID>` are forwarded to `/mcp` on the browser. Seleniferous rewrites the header to the real browser session id on the way in, and back to `IPUUID` on the way out.
- **Terminate** — `DELETE /mcp` ends the session and schedules teardown of the browser pod.

Error responses for non-initialize requests:

- a missing `Mcp-Session-Id` header returns **`400`**;
- a header that does not match the pod `IPUUID`, or whose MCP session is not in the store, returns **`404`** so the client can `initialize` a fresh session.

Request and response **bodies** are forwarded unchanged; only the `Mcp-Session-Id` header is rewritten. Each MCP request resets the session idle timeout, same as Selenium and Playwright traffic.

## Networking and headers
If you run behind a reverse proxy or ingress, set these headers so Seleniferous can build correct external URLs:
- `X-Forwarded-Proto`
- `X-Forwarded-Host`


## Build and image workflow

The project is built and packaged entirely via Docker. Local Go installation is not required for producing the final artifact.

## Build variables

The build process is controlled via the following Makefile variables:

| Variable         | Description                                                  |
|------------------|--------------------------------------------------------------|
| `BINARY_NAME`    | Name of the produced binary (fixed: `seleniferous`)         |
| `REGISTRY`       | Docker registry prefix (default: `localhost:5000`)           |
| `IMAGE_NAME`     | Full image name, derived as `$(REGISTRY)/$(BINARY_NAME)`     |
| `VERSION`        | Image version/tag (default: `develop`)                       |
| `EXTRA_TAGS`     | Additional `-t` tags passed to `docker-push` (default: none) |
| `PLATFORM`       | Target platform (default: `linux/amd64`)                     |
| `CONTAINER_TOOL` | Container build tool (default: `docker`)                     |

`REGISTRY` and `VERSION` are expected to be provided externally, which allows the same Makefile to be used locally and in CI.
