# AGENTS

Instructions for coding agents working on this repository. Keep this file short.

## Project

Cloudflare DDNS agent in Go. It accepts the oznu/cloudflare-ddns environment
variables and runs many records in one container, with a read-only status page.
Users read [README.md](README.md). This file covers how to work on the code.

```
cmd/ozgo-cf-ddns/   entry point: run, healthcheck, version
internal/config     env parsing (oznu names + _<NAME> suffix), validation
internal/cron       5-field cron parser
internal/ipdetect   public IP (DNS whoami + HTTPS trace), static, command, interface
internal/cloudflare minimal v4 API client
internal/agent      sync loop, retries, shared status
internal/hub        main/sidecar reports: HMAC signing, store, reporter
internal/web        status page, /api/status, /healthz, /api/sync route (html/template, embedded)
scripts/            smoke-test.sh (container test: no network, main + sidecar)
```

## Rules

- **The repository is public.** Never commit real domains, IPs, hostnames,
  tokens, account IDs, internal infrastructure names or links to private repos.
  Use only documentation values in examples and tests: `example.com`,
  `example.org`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and
  `2001:db8::/32`.
- **Secrets never reach logs, errors, the status page or the API.**
  `config.Credentials` and `config.Secret` (SYNC_KEY) redact themselves, so
  keep it that way. SYNC_KEY never goes over the wire: reports are signed. Every new output
  path needs a test that checks the token does not leak.
- **Configuration compatibility is a contract.** Do not rename or change the
  meaning of an oznu variable (`API_KEY`, `ZONE`, `SUBDOMAIN`, `PROXIED`,
  `RRTYPE`, `CUSTOM_LOOKUP_CMD`, `INTERFACE`, `DNS_SERVER`, `DELETE_ON_STOP`,
  `CRON`, `*_FILE`) or of the `_<NAME>` suffix rule. The same applies to
`SYNC_KEY`, `SYNC_URL`, `INSTANCE_NAME` and the `/api/sync` report format
from v0.2.0 on. New options get new names
  and safe defaults. Breaking changes need a MAJOR version bump.
- **Do not cache failures.** The reason this project exists is oznu caching an
  empty record ID at boot. Anything that failed must be looked up again in the
  next round, without a restart. `TestRecoversAfterStartingWithoutConnectivity`
  and `scripts/smoke-test.sh` guard this.
- **Do not delete what we do not own.** The agent only creates and updates
  configured records. Deleting is allowed only through `DELETE_ON_STOP`.
- Standard library only. Adding a third-party Go module needs a clear reason
  stated in the PR.
- Original code only. Do not copy code from oznu (GPL-3.0) or other DDNS
  clients. The project is MIT.
- Code, comments, docs and commit messages are in English. Use Conventional
  Commits (`feat:`, `fix:`, `docs:`, `ci:`, `test:`, `refactor:`, `chore:`).

## Before you finish a change

```sh
gofmt -l .                 # must print nothing
go vet ./...
go test -race ./...
docker build -t ozgo-cf-ddns:dev . && scripts/smoke-test.sh ozgo-cf-ddns:dev   # if Docker is available
```

- Every bug fix gets a regression test that fails without the fix.
- New config variables: update `internal/config`, its tests, the README tables
  and `compose.example.yaml`.
- Go version: `go.mod`, `mise.toml` and the `golang:` image in the `Dockerfile`
  move together.

## CI

| Workflow | Trigger | Checks |
|----------|---------|--------|
| `ci.yml` | push to `main`, PR | gofmt, vet, race tests, 30 s fuzz of the DNS parser; gitleaks (full history), govulncheck, gosec, hadolint, actionlint, zizmor; image build, smoke test, Trivy (HIGH/CRITICAL, fixable). On `main` it pushes `edge` and `sha-<commit>` to GHCR. |
| `codeql.yml` | push to `main`, PR, weekly | CodeQL `security-extended` for Go |
| `release.yml` | tag `v*` | tag validation, all verification steps, multi-arch image push with SBOM and provenance attestation, GitHub release |

- Pin every action to a full commit SHA with the version in a comment. Pin tool
  images by digest. Dependabot opens the update PRs.
- Workflows default to `permissions: contents: read`. Grant write scopes per job.
- Never use `${{ }}` expressions inside `run:`. Pass values through `env:`.
- Silence a gosec finding only with `// #nosec Gxxx -- reason`, never globally.

## Releases

- Tags are SemVer with a `v` prefix: `vMAJOR.MINOR.PATCH[-PRERELEASE]`.
  `release.yml` rejects anything else and any tag that is not on `main`.
- The series starts at **`v0.1.0-rc.1`**. Further candidates are `-rc.2`,
  `-rc.3`, and so on. The stable release drops the suffix (`v0.1.0`).
- While on `0.x`, a MINOR bump may break things and PATCH is for fixes only.
  From `1.0.0` on, a breaking change (see the compatibility rule) needs a MAJOR
  bump.
- Pre-releases are marked as such on GitHub and never move `latest`.
- Release only when the human asks for it:

  ```sh
  git switch main && git pull --ff-only
  git tag -a v0.1.0-rc.1 -m "v0.1.0-rc.1"
  git push origin v0.1.0-rc.1
  ```

- Release notes are generated from the commits, so write clear commit
  subjects. There is no CHANGELOG file.
