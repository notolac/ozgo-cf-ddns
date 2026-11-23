# ozgo-cf-ddns

[![CI](https://github.com/notolac/ozgo-cf-ddns/actions/workflows/ci.yml/badge.svg)](https://github.com/notolac/ozgo-cf-ddns/actions/workflows/ci.yml)
[![CodeQL](https://github.com/notolac/ozgo-cf-ddns/actions/workflows/codeql.yml/badge.svg)](https://github.com/notolac/ozgo-cf-ddns/actions/workflows/codeql.yml)

A Cloudflare dynamic DNS agent written in Go. It accepts the same environment
variables as [oznu/cloudflare-ddns](https://github.com/oznu/docker-cloudflare-ddns)
and keeps **many records in one container**. A small status page shows whether
each record is in sync and when it last changed.

## Why

`oznu/cloudflare-ddns` is archived and has a failure mode that never recovers
on its own. It resolves the zone and record IDs **once**, when the container
starts, and caches them. If the network is down at that moment, after a power
cut or while the router is still booting, the cached ID is empty and every
following update fails until someone restarts the container. Cloudflare keeps
serving the old IP in the meantime.

It also needs one container per record, so a few dozen hostnames means a few
dozen containers.

ozgo-cf-ddns looks the zone and record up again on every round, retries quickly
after failures and handles any number of records in a single process. It is
an original implementation and contains no code from oznu or other DDNS
clients.

## Features

- Uses the oznu variable names (`API_KEY`, `ZONE`, `SUBDOMAIN`, `PROXIED`,
  `RRTYPE`, `CUSTOM_LOOKUP_CMD`, `INTERFACE`, `DNS_SERVER`, `DELETE_ON_STOP`,
  `CRON`, `*_FILE`). An existing single-record service works unchanged.
- One container per account: add a suffix (`ZONE_BLOG`, `SUBDOMAIN_BLOG`, ...)
  for every extra record. Records may also use different tokens.
- Self-healing: nothing that failed is cached. After a failed round it retries
  after 30 s, then 1, 2 and 4 minutes, and at most every 5 minutes after that.
  It never retries later than the next `CRON` round.
- Public IP detected once per round and shared by all records.
- Fixed addresses with `STATIC_IP` (or the `CUSTOM_LOOKUP_CMD=echo <ip>` form).
- Proxy flag enforced: if someone flips the orange cloud by hand, the next
  round restores the configured value.
- Read-only status page, JSON API and health endpoint, with optional basic
  auth.
- Structured logs (text or JSON) that never contain credentials.
- Small image: static Go binary on Alpine, runs as a non-root user, multi-arch
  (amd64 and arm64).

## Quick start

```yaml
services:
  ddns:
    image: ghcr.io/notolac/ozgo-cf-ddns:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - API_KEY=$API_KEY        # Cloudflare API token
      - ZONE=example.com        # default zone
      - PROXIED=true            # default proxy flag
      - SUBDOMAIN_WWW=www       # www.example.com -> public IP, proxied
      - SUBDOMAIN_BLOG=blog     # blog.example.com -> public IP, proxied
      - ZONE_NAS=example.org    # nas.example.org -> fixed IP, DNS only
      - SUBDOMAIN_NAS=nas
      - PROXIED_NAS=false
      - STATIC_IP_NAS=192.0.2.10
```

Open `http://<host>:8080/` for the status page. See
[compose.example.yaml](compose.example.yaml) for a longer example.

Until the first stable release, `latest` does not exist yet. Use a version tag
(for example `0.1.0-rc.1`) or `edge`, which is built from `main`.

## Migrating from oznu

Each oznu service becomes a group of suffixed variables in one service. The
suffix is any name you like (letters, digits, `_`):

```yaml
# Before: one container per record
services:
  blog:
    image: oznu/cloudflare-ddns:latest
    environment:
      - API_KEY=$API_KEY
      - ZONE=example.com
      - SUBDOMAIN=blog
      - PROXIED=true
  nas:
    image: oznu/cloudflare-ddns:latest
    environment:
      - API_KEY=$API_KEY
      - ZONE=example.org
      - SUBDOMAIN=nas
      - PROXIED=false
      - CUSTOM_LOOKUP_CMD=echo 192.0.2.10

# After: one container
services:
  ddns:
    image: ghcr.io/notolac/ozgo-cf-ddns:0.1.0-rc.1
    environment:
      - API_KEY=$API_KEY
      - ZONE_BLOG=example.com
      - SUBDOMAIN_BLOG=blog
      - PROXIED_BLOG=true
      - ZONE_NAS=example.org
      - SUBDOMAIN_NAS=nas
      - PROXIED_NAS=false
      - CUSTOM_LOOKUP_CMD_NAS=echo 192.0.2.10   # or STATIC_IP_NAS=192.0.2.10
```

The agent only creates or updates the records it is configured for. Removing
a record from the configuration leaves its DNS entry in Cloudflare untouched.

## Configuration

### How records are declared

- **One record:** use the plain variables, exactly like oznu.
- **Several records:** each variable gets a `_<NAME>` suffix. A record exists
  when `ZONE_<NAME>` or `SUBDOMAIN_<NAME>` is set. Unsuffixed variables become
  defaults for every record. `SUBDOMAIN` is the exception: it cannot be shared,
  so it is not allowed without a suffix in this mode.
- `<NAME>` is case-sensitive and must not start with `FILE`. It is shown in
  lowercase in logs and on the status page.
- A suffixed variable that refers to a record that does not exist is rejected
  (it is usually a typo), and so is a record managed twice. The container exits
  with a clear error instead of running with a partial configuration.

### Record variables

All of these accept a `_<NAME>` suffix, and all except `SUBDOMAIN` fall back
to the unsuffixed value.

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | required | Cloudflare API token. With `EMAIL` set, the legacy global API key instead. |
| `API_KEY_FILE` | | Read `API_KEY` from a file (Docker secrets). Suffixed form: `API_KEY_FILE_<NAME>`. |
| `EMAIL` | | Account email, only for the legacy global API key. |
| `ZONE` / `ZONE_FILE` | required | Zone name, e.g. `example.com`. |
| `SUBDOMAIN` / `SUBDOMAIN_FILE` | apex | Record name inside the zone. Empty or `@` is the zone apex. |
| `PROXIED` | `false` | Proxy through Cloudflare (orange cloud). |
| `RRTYPE` | `A` | `A` (IPv4) or `AAAA` (IPv6). |
| `STATIC_IP` | | Fixed address instead of the detected public IP. |
| `CUSTOM_LOOKUP_CMD` | | Shell command that prints the address. `echo <ip>` is treated as `STATIC_IP` without starting a shell. |
| `INTERFACE` | | Use the first address of this network interface (needs `network_mode: host`). |
| `DNS_SERVER` | `1.1.1.1` / `2606:4700:4700::1111` | Resolver used for public IP detection. |
| `DELETE_ON_STOP` | `false` | Delete the record when the container stops. |

`STATIC_IP`, `CUSTOM_LOOKUP_CMD` and `INTERFACE` are mutually exclusive. When a
record sets any of them, the unsuffixed defaults for these three are ignored.

### Global variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CRON` | `*/5 * * * *` | Sync schedule (5-field cron, or `@hourly`, `@daily`, ...). The first round runs at start-up. |
| `WEB_ENABLED` | `true` | Serve the status page. |
| `WEB_PORT` | `8080` | Port of the status page. |
| `WEB_USER` / `WEB_PASSWORD` | | Enable HTTP basic auth for `/` and `/api/status`. Set both or neither. `WEB_PASSWORD_FILE` is also accepted. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `LOG_FORMAT` | `text` | `text` or `json`. |
| `TZ` | `UTC` | Time zone for the status page and logs. |

`PUID` and `PGID` from oznu are ignored with a warning. Use Docker's `user:`
option instead. The image runs as UID 10001 by default.

### Cloudflare token

Create an API token with **Zone → DNS → Edit** and **Zone → Zone → Read** for
the zones it manages. One token per container is the simplest setup. Records
can carry their own `API_KEY_<NAME>` when zones need separate credentials.

## How a round works

1. Work out the desired address of every record. The public IP is detected once
   per round: first a `whoami.cloudflare` TXT query (CHAOS class) to
   `DNS_SERVER`, then `https://1.1.1.1/cdn-cgi/trace` if that fails.
2. For each record, look up the zone ID (cached until a call with it fails) and
   the current record.
3. Create the record if it is missing, update it if the IP or the proxy flag
   differs, and leave it alone otherwise. Updates keep the TTL, comment and
   tags.
4. A failure only affects its record. The other records and zones carry on.

If several records share the same name and type, only the first is managed and
a warning is logged. Nothing is ever deleted unless `DELETE_ON_STOP` is set.

## Status page, API and health

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /` | optional | Status table: state, wanted vs. Cloudflare IP, proxy, last check, last change in Cloudflare, last error. Refreshes every 30 s. |
| `GET /api/status` | optional | The same data as JSON. |
| `GET /healthz` | none | `200` when every record is in sync, `503` otherwise. Only counts are returned, never names. |

The image defines a Docker `HEALTHCHECK` (`ozgo-cf-ddns healthcheck`), so
`docker ps` and Portainer show the container as *unhealthy* while any record
is failing.

## Logs

Logs go to stdout (`docker logs <container>`):

```text
level=INFO msg="record configured" name=www record=www.example.com type=A proxied=true source=public credentials="[redacted api-token]"
level=WARN msg="sync failed" record=www.example.com type=A error="public IP detection failed: ..." consecutive_failures=1
level=INFO msg="record recovered" record=www.example.com type=A after_failures=3
level=INFO msg="record updated" record=www.example.com type=A old_ip=203.0.113.50 ip=198.51.100.1 old_proxied=true proxied=true
level=INFO msg="round finished" records=12 ok=12 updated=1 failed=0 duration=1.2s
```

Use `LOG_LEVEL=debug` to also log records that are already in sync and the
detected public IP.

## Development

Requires Go 1.27 ([mise](https://mise.jdx.dev/) users: `mise install`).

```sh
go test -race ./...                       # unit and regression tests
go vet ./...
docker build -t ozgo-cf-ddns:dev .
scripts/smoke-test.sh ozgo-cf-ddns:dev    # container test without network
```

See [AGENTS.md](AGENTS.md) for the project rules, CI checks and release process.

## Releases and images

Releases follow [SemVer](https://semver.org/) tags: `vMAJOR.MINOR.PATCH`, with
optional pre-releases such as `v0.1.0-rc.1`. Images are published to
`ghcr.io/notolac/ozgo-cf-ddns`:

| Tag | Source |
|-----|--------|
| `0.1.0-rc.1`, `0.1.0`, ... | the matching git tag |
| `0.1`, `1` | latest stable release in that line (`MAJOR` tags start at 1.0.0) |
| `latest` | latest stable release (never a pre-release) |
| `edge`, `sha-<commit>` | every push to `main` |

Images carry an SBOM and a signed build provenance attestation:

```sh
gh attestation verify oci://ghcr.io/notolac/ozgo-cf-ddns:<tag> --repo notolac/ozgo-cf-ddns
```

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

[MIT](LICENSE)
