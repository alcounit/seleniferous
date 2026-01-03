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
| `SESSION_CREATE_TIMEOUT` | `5m` | Max time to wait for first session request. |
| `SESSION_IDLE_TIMEOUT` | `5m` | Max idle time after session creation. |
| `ROUTING_RULES` | empty | Additional routing rules for internal proxying. |
| `POD_IP` | auto | Pod IP used to derive stable `sessionId`. |

## Endpoints
Seleniferous exposes Selenium-compatible endpoints on `/session` and internal proxy endpoints for Selenosis.

| Method | Path | Description |
| --- | --- | --- |
| `POST` | `/session` | Create a new WebDriver session (proxied to local browser). |
| `*` | `/session/{sessionId}/*` | Proxy all session traffic (HTTP and WebSocket). |
| `*` | `/selenosis/v1/proxy/{sessionId}/proxy/*` | Internal HTTP proxy used by Selenosis. |
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

## Networking and headers
If you run behind a reverse proxy or ingress, set these headers so Seleniferous can build correct external URLs:
- `X-Forwarded-Proto`
- `X-Forwarded-Host`


## Build and image workflow

The project is built and packaged entirely via Docker. Local Go installation is not required for producing the final artifact.

## Build variables

The build process is controlled via the following Makefile variables:

Variable	Description
- BINARY_NAME	Name of the produced binary (seleniferous).
- DOCKER_REGISTRY	Docker registry prefix (passed via environment).
- IMAGE_NAME	Full image name (<registry>/seleniferous).
- VERSION	Image version/tag (default: v1.0.1).
- PLATFORM	Target platform (default: linux/amd64).

DOCKER_REGISTRY is expected to be provided externally, which allows the same Makefile to be used locally and in CI.

## Deployment

To be added....
