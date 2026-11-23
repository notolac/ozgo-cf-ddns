#!/usr/bin/env bash
# Container smoke test. Starts the image without network (the situation that
# broke oznu) and checks the process stays up, reports the failure, serves the
# status page and never prints the token.
#
# Usage: scripts/smoke-test.sh <image>
set -euo pipefail

IMAGE="${1:?usage: $0 <image>}"
TOKEN="smoke-test-token-$$"
NAME="ozgo-smoke-$$"

fail() { echo "FAIL: $*" >&2; docker logs "$NAME" >&2 || true; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== version"
docker run --rm "$IMAGE" version

echo "== invalid configuration exits with 1"
set +e
invalid_log=$(mktemp)
docker run --rm --network none -e API_KEY="$TOKEN" "$IMAGE" >"$invalid_log" 2>&1
rc=$?
set -e
[[ $rc -eq 1 ]] || fail "invalid config exit code $rc, want 1"
grep -q "no records configured" "$invalid_log" || fail "missing config error message"

echo "== runs without network"
docker run -d --name "$NAME" --network none \
  -e API_KEY="$TOKEN" -e ZONE=example.com \
  -e SUBDOMAIN_WWW=www -e PROXIED_WWW=true \
  -e SUBDOMAIN_LAN=lan -e STATIC_IP_LAN=192.0.2.10 \
  "$IMAGE" >/dev/null

status=""
for _ in $(seq 1 60); do
  status=$(docker exec "$NAME" wget -qO- http://127.0.0.1:8080/api/status 2>/dev/null || true)
  if grep -q '"last_round_end"' <<<"$status"; then break; fi
  sleep 1
done
grep -q '"last_round_end"' <<<"$status" || fail "first round did not finish"
grep -q '"state": "error"' <<<"$status" || fail "records should be in error without network"
grep -q '"healthy": false' <<<"$status" || fail "status should be unhealthy"

docker exec "$NAME" wget -qO- http://127.0.0.1:8080/ | grep -q "lan.example.com" || fail "status page"
if docker exec "$NAME" /usr/local/bin/ozgo-cf-ddns healthcheck >/dev/null; then
  fail "healthcheck should fail while records are failing"
fi
[[ "$(docker inspect -f '{{.State.Running}}' "$NAME")" == "true" ]] || fail "container stopped"
[[ "$(docker inspect -f '{{.Config.User}}' "$NAME")" == "10001:10001" ]] || fail "container must run as non-root"

logs=$(docker logs "$NAME" 2>&1)
grep -q "sync failed" <<<"$logs" || fail "failure not logged"
grep -q "$TOKEN" <<<"$logs$status" && fail "token leaked into logs or status"

echo "== graceful stop"
docker stop -t 10 "$NAME" >/dev/null
docker logs "$NAME" 2>&1 | grep -q "stopped" || fail "no clean shutdown"

echo "smoke test passed"
