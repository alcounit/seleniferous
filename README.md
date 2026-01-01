![GitHub release (latest by date)](https://img.shields.io/github/v/release/alcounit/seleniferous)
![Docker Pulls](https://img.shields.io/docker/pulls/alcounit/seleniferous)
![GitHub](https://img.shields.io/github/license/alcounit/seleniferous)
# seleniferous
seleniferous proxies incoming connections to browser container. It is responsible for freeing resources when a session deleted or an idle timeout occurs.

## Overview
### Available flags
```
[user@host]$ ./seleniferous --help
seleniferous is a sidecar proxy for selenosis

Usage:
  seleniferous [flags]

Flags:
      --listhen-port string                  port to use for incomming requests (default "4445")
      --browser-port string                  browser port (default "4444")
      --proxy-default-path string            path used by handler (default "/session")
      --idle-timeout duration                time in seconds for idle session (default 2m0s)
      --namespace string                     kubernetes namespace (default "selenosis")
      --graceful-shutdown-timeout duration   time in seconds  gracefull shutdown timeout (default 15s)
  -h, --help                                 help for seleniferous
```

### Available endpoints
| Protocol | Endpoint                    |
|--------- |---------------------------- |
| HTTP    | /wd/hub/session              |
| HTTP    | /wd/hub/session/{sessionId}/ |
| HTTP    | /status                      |
