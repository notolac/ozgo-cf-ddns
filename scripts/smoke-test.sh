#!/usr/bin/env bash
# Container smoke test. Starts the image without network (the situation that
# broke oznu) and checks the process stays up, reports the failure, serves the
# status page and never prints the token. Then runs a main container and a
# sidecar on an internal network (no internet) and checks the sidecar shows up
# on the main status page without SYNC_KEY ever reaching the logs.
#
# Usage: scripts/smoke-test.sh <image>
set -euo pipefail

IMAGE="${1:?usage: $0 <image>}"
TOKEN="smoke-test-token-$$"
NAME="ozgo-smoke-$$"
SYNC_KEY="smoke-sync-key-$$-0123456789abcdef0123456789"
NET="ozgo-smoke-net-$$"
MAIN="ozgo-smoke-main-$$"
SIDE="ozgo-smoke-side-$$"

fail() {
  echo "FAIL: $*" >&2
  for c in "$NAME" "$MAIN" "$SIDE"; do docker logs "$c" >&2 2>&1 || true; done
  exit 1
}
cleanup() {
  docker rm -f "$NAME" "$MAIN" "$SIDE" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
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

echo "== sidecar reports to the main container"
docker network create --internal "$NET" >/dev/null
docker run -d --name "$MAIN" --network "$NET" --network-alias ddns \
  -e API_KEY="$TOKEN" -e ZONE=example.com -e SUBDOMAIN=www \
  -e SYNC_KEY="$SYNC_KEY" -e INSTANCE_NAME=home \
  "$IMAGE" >/dev/null
docker run -d --name "$SIDE" --network "$NET" \
  -e API_KEY="$TOKEN" -e ZONE=example.org -e SUBDOMAIN=nas -e STATIC_IP=192.0.2.10 \
  -e SYNC_KEY="$SYNC_KEY" -e SYNC_URL=http://ddns:8080 -e INSTANCE_NAME=org \
  "$IMAGE" >/dev/null

status=""
for _ in $(seq 1 60); do
  status=$(docker exec "$MAIN" wget -qO- http://127.0.0.1:8080/api/status 2>/dev/null || true)
  if grep -q '"instance": "org"' <<<"$status"; then break; fi
  sleep 1
done
grep -q '"instance": "org"' <<<"$status" || fail "sidecar did not report"
grep -q '"fqdn": "nas.example.org"' <<<"$status" || fail "sidecar records missing"
docker exec "$MAIN" wget -qO- http://127.0.0.1:8080/ | grep -q 'id="instance-org"' || fail "sidecar not on the status page"
docker logs "$MAIN" 2>&1 | grep -q "sidecar connected" || fail "main did not log the sidecar"

if docker exec "$SIDE" wget -qO- --header "X-Ozgo-Timestamp: 1" --header "X-Ozgo-Signature: v1=00" \
  --post-data '{}' http://ddns:8080/api/sync >/dev/null 2>&1; then
  fail "unsigned report accepted"
fi

logs=$(docker logs "$MAIN" 2>&1; docker logs "$SIDE" 2>&1)
grep -q -- "$SYNC_KEY" <<<"$logs$status" && fail "SYNC_KEY leaked into logs or status"
grep -q -- "$TOKEN" <<<"$logs$status" && fail "token leaked into logs or status"

echo "smoke test passed"
