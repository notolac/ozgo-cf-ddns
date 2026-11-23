# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/notolac/ozgo-cf-ddns/security/advisories/new).
Do not open a public issue.

Include the affected version or image tag, how to reproduce the problem and its
impact. Never include real API tokens. Use a revoked token or a placeholder.

## Supported versions

Only the latest release, and `edge` built from `main`, receive fixes.

## Scope notes

- The status page is read-only and never shows credentials. Expose it only to
  trusted networks or set `WEB_USER`/`WEB_PASSWORD`.
- `CUSTOM_LOOKUP_CMD` runs a shell command by design (oznu compatibility). It is
  read from the container configuration only, never from the network.
