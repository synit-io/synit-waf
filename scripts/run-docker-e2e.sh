#!/bin/bash
set -euo pipefail

E2E_DIR="$(cd "$(dirname "$0")/../test/e2e" && pwd)"
DATA_DIR="$E2E_DIR/docker-test-data"
COMPOSE_FILE="$E2E_DIR/docker-compose.yml"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans
  rm -rf "$DATA_DIR"
}
trap cleanup EXIT

cleanup
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

cat <<'EOF' > "$DATA_DIR/config.yml"
global_settings:
  log_level: "DEBUG"

waf_rule_sets:
  "base-protection": |
    SecRuleEngine On
    SecRule ARGS:test "@contains blockme" "id:110002,phase:1,deny,status:403,msg:'blocked'"
  "advanced-protection": |
    SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:120004,phase:1,deny,status:403,msg:'blocked-ua'"

tenants:
  "e2e.test":
    upstreams:
      - url: "http://upstream:5678"
    security:
      waf_enabled: true
      paranoia_level: 1
      include_rule_sets:
        - "base-protection"
        - "advanced-protection"
EOF

docker compose -f "$COMPOSE_FILE" up -d --build

ready=0
for _ in {1..30}; do
  if curl -fsS http://localhost:8080/healthz | grep -q "ok"; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" != "1" ]; then
  docker compose -f "$COMPOSE_FILE" logs
  exit 1
fi

response=$(curl -fsS -H "Host: e2e.test" http://localhost:8080/)
test "$response" = "upstream-ok"

status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: e2e.test" "http://localhost:8080/?test=blockme")
test "$status" = "403"

status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: e2e.test" -H "User-Agent: sqlmap" http://localhost:8080/)
test "$status" = "403"

curl -fsS http://localhost:9090/readyz | grep -q '"ready":true'
curl -fsS http://localhost:9090/metrics | grep -q "synit_waf_http_requests_total"

cat <<'EOF' > "$DATA_DIR/config.yml"
global_settings:
  log_level: "DEBUG"
waf_rule_sets:
  "base-protection": |
    SecRuleEngine On
    SecRule ARGS:test "@contains blockme" "id:110002,phase:1,deny,status:403,msg:'blocked'"
tenants:
  "e2e.test":
    upstreams:
      - url: "http://upstream:5678"
    security:
      waf_enabled: true
      audit_mode: true
      paranoia_level: 1
      include_rule_sets: ["base-protection"]
EOF

# A single-file bind mount does not deliver inotify events into the container,
# so the container is restarted. Poll until the audit-mode policy answers.
docker compose -f "$COMPOSE_FILE" restart synit-waf
reloaded=0
for _ in {1..30}; do
  status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Host: e2e.test" "http://localhost:8080/?test=blockme" || true)
  if [ "$status" = "200" ]; then
    reloaded=1
    break
  fi
  sleep 1
done
if [ "$reloaded" != "1" ]; then
  echo "audit-mode policy was not applied within 30s (last status: $status)" >&2
  docker compose -f "$COMPOSE_FILE" logs synit-waf
  exit 1
fi
curl -fsS http://localhost:9090/metrics | grep -q 'synit_waf_audit_mode_events_total{tenant="e2e.test"} [1-9]'

echo "Docker E2E tests passed."
