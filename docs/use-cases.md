# Security use cases

These examples show where Synit WAF fits and which controls to combine. They are configuration fragments, not complete production policy. Define every referenced rule set, test representative traffic, and begin new enforcement in audit mode. Rule IDs `440000`-`440099` are reserved for the WAF's built-in directives; the fragments below use other ranges.

## 1. Gradual protection for a web application

Use Coraza rules in detection-only mode before blocking production traffic:

```yaml
waf_rule_sets:
  "web-baseline": |
    SecRule REQUEST_METHOD "@rx (?i:^(trace|track)$)" "id:110001,phase:1,deny,status:403,log,msg:'Unsafe method'"
    SecRule ARGS|REQUEST_URI "@rx (?i:(\.\./|%2e%2e%2f|/etc/passwd))" "id:110002,phase:2,deny,status:403,log,msg:'Traversal pattern'"

tenants:
  "www.example.com":
    upstreams:
      - url: "http://web-app:8080"
    security:
      waf_enabled: true
      audit_mode: true
      paranoia_level: 1
      include_rule_sets: ["web-baseline"]
```

In audit mode every matched rule with the `log` action is written to the application log as `WAF rule matched` with `rule_id`, `tenant`, `uri`, and `event_id`, and counted in `synit_waf_rule_matches_total{tenant,rule_id}`. A request that a blocking rule would have stopped also logs `WAF attack detected (Audit Mode)` and increments `synit_waf_audit_mode_events_total{tenant}`. Change `audit_mode` to `false` only after normal application traffic is clean.

Phase 2 rules such as `110002` run for every request, including GET requests without a body.

The repository contains small example WordPress and API rules under `assets/rules/profiles/`. They are not complete application protection, and no OWASP Core Rule Set is bundled; `paranoia_level` takes effect only when you add CRS under `global_settings.rules_dir`.

## 2. API authentication and throttling

Validate signed JWTs before requests reach an API and apply a per-client/per-tenant rate limit:

```yaml
tenants:
  "api.example.com":
    upstreams:
      - url: "http://api:8080"
    header_transform:
      strip_request: ["X-Authenticated-User"]
      inject_request:
        X-Gateway-Tenant: "{{TENANT}}"
        X-Gateway-Client-IP: "{{CLIENT_IP}}"
    security:
      waf_enabled: false
      jwt_validation:
        enabled: true
        jwks_endpoint: "https://identity.example.com/.well-known/jwks.json"
        issuer: "https://identity.example.com/"
        audience: "example-api"
      rate_limit:
        requests_per_minute: 600
        burst: 60
```

JWT validation accepts RSA (`RS*`, `PS*`), ECDSA (`ES*`), and EdDSA tokens whose `kid` is present in the JWKS; HMAC and `none` are rejected, the `exp` claim is required, and `iss` and `aud` must match. JWKS responses are cached for 15 minutes unless a positive `Cache-Control: max-age` is returned (one hour at most). A JWKS fetch failure returns `503`, an invalid token `401`. `jwt_validation` cannot be combined with `basic_auth` on the same tenant.

The rate limit key is the tenant plus the client address; IPv6 clients are grouped by `/64`. Limiters keep their state across configuration reloads as long as the policy is unchanged.

Header injection is not identity propagation: the runtime does not inject JWT claims. Strip any client-controlled trusted headers before adding gateway-owned values. The WAF itself sets `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` and drops client-sent values unless the peer is a trusted proxy.

## 3. Protect an internal administration service

Use bcrypt-backed Basic Auth and an IP allow list for a small internal service:

```yaml
global_settings:
  ip_sets:
    allow_list:
      - "10.0.0.0/8"
      - "192.168.1.0/24"

tenants:
  "admin.internal.example.com":
    upstreams:
      - url: "http://admin:8080"
    security:
      waf_enabled: true
      paranoia_level: 1
      basic_auth:
        - user: "operator"
          password: "$2a$12$REPLACE_WITH_A_REAL_BCRYPT_HASH"
```

Generate a bcrypt hash outside the configuration and keep the source password secret. Successful verifications are cached in memory for five minutes, so bcrypt does not run on every request; an unknown user name costs a bcrypt comparison as well, so response time does not reveal valid names. Global allow-listed IPs bypass rate limits, GeoIP, Coraza, GraphQL, and LLM checks, but they do not bypass tenant matching, JWT, Basic Auth, or CrowdSec.

## 4. Limit GraphQL request shape

Block introspection, deeply nested queries, and oversized JSON batches:

```yaml
tenants:
  "graphql.example.com":
    upstreams:
      - url: "http://graphql-api:8080"
    security:
      waf_enabled: true
      paranoia_level: 1
      graphql:
        enabled: true
        paths: ["/graphql"]
        block_introspection: true
        max_query_depth: 8
        max_batched_queries: 10
        max_query_bytes: 102400
```

Only requests under `paths` (default `["/graphql"]`, prefix match on a path boundary, also checked on the cleaned path) are treated as GraphQL; the rest of the tenant serves REST or static content untouched. GraphQL POST inspection accepts `application/json` (including parameters such as `charset`) and `application/graphql`; GET requests need a `query` parameter. A value of `0` disables the corresponding depth or batch limit; `max_query_bytes` defaults to 100 KiB. Encoded request bodies are rejected because they cannot be inspected safely.

## 5. Screen LLM request fields

Use the built-in static rule set without a classifier dependency:

```yaml
tenants:
  "ai.example.com":
    upstreams:
      - url: "http://llm-api:8080"
    security:
      waf_enabled: true
      audit_mode: true
      paranoia_level: 1
      include_rule_sets: ["llm-protection"]
      llm_protection:
        enabled: true
        mode: "rules"
        action: "audit"
        inspect_paths:
          - "/v1/chat/completions"
        inspect_json_fields:
          - "prompt"
          - "messages[].content"
```

The built-in `llm-protection` rules (IDs `440010`-`440013`) match instruction-override phrases such as "ignore all previous instructions", named jailbreak modes, and requests to reveal the system prompt. They run only for requests under `inspect_paths`; generic role play is not matched. They are a first filter, not complete coverage.

For `ml` or `hybrid` mode, add the classifier:

```yaml
      llm_protection:
        enabled: true
        mode: "hybrid"
        action: "audit"
        threshold: 0.85
        fail_mode: "open"
        timeout: "500ms"
        max_text_bytes: 8192
        sidecar_max_batch: 32
        sidecar_url: "http://127.0.0.1:5001/v1/detect"
        sidecar_token_env: "WAF_LLM_SIDECAR_TOKEN"
```

`sidecar_token_env` names the environment variable that holds the guard's `AUTH_TOKEN`; `WAF_LLM_SIDECAR_TOKEN_FILE` can point at a mounted secret instead. Texts longer than `max_text_bytes` are scored in overlapping chunks and sent in batches of at most `sidecar_max_batch`. Run `services/synit-llm-guard` or a compatible API; the bundled guard performs ONNX text classification with an operator-supplied model. Evaluate its model, labels, threshold, latency, and false-positive behavior against your traffic before switching `action` to `deny`.

## 6. Isolate many hostname policies

Keep shared settings in `config.yml` and place tenants in sibling shard files:

```text
/etc/waf/
├── config.yml
└── tenants.d/
    ├── customer-a.yml
    └── customer-b.yml
```

Each shard contains a `tenants` map:

```yaml
tenants:
  "customer-a.example.com":
    upstreams:
      - url: "http://customer-a:8080"
    security:
      waf_enabled: true
      paranoia_level: 1
```

Tenant hostnames must be unique across the base file and every shard; duplicates reject the whole candidate and leave the active configuration unchanged. The WAF watches the main file and `tenants.d` for create, write, rename, and remove events, then reloads changes transactionally. Tenants whose generated directives are identical share one Coraza instance, so many similar tenants cost little extra memory. A wildcard key such as `"*.customers.example.com"` serves any depth below the suffix.

## 7. Balance across upstream instances

List multiple upstreams for one hostname:

```yaml
tenants:
  "service.example.com":
    upstreams:
      - url: "http://service-a:8080"
      - url: "http://service-b:8080"
    health_check:
      interval: "10s"
      timeout: "5s"
      path: "/healthz"
    security:
      waf_enabled: false
      circuit_breaker:
        enabled: true
        threshold: 3
        cooldown: "30s"
        failure_status_codes: [502, 503, 504]
```

The runtime checks every upstream actively every `interval` (default `10s`): a TCP connect when `path` is empty, otherwise an HTTP GET where any status below `500` counts as healthy. Healthy upstreams are selected round-robin. The passive circuit breaker marks an upstream unavailable after `threshold` consecutive proxy failures or listed response status codes, then retries it after `cooldown`. On startup and on every reload all upstreams are probed before the configuration serves traffic.

## 8. Add CrowdSec decisions

Configure the CrowdSec Local API globally and opt in per tenant:

```yaml
crowdsec:
  api_url: "https://crowdsec.example.com:8080/"
  api_key: "" # set WAF_CROWDSEC_KEY or WAF_CROWDSEC_KEY_FILE instead
  cache_ttl: "30s"

tenants:
  "public.example.com":
    upstreams:
      - url: "http://public-app:8080"
    security:
      waf_enabled: false
      crowdsec_enabled: true
```

Supply the bouncer key through `WAF_CROWDSEC_KEY` or, for a mounted secret, `WAF_CROWDSEC_KEY_FILE`. A plain `http://` LAPI URL is accepted only for loopback or with `global_settings.allow_insecure_service_urls: true` on a trusted private network. Decisions are cached per client IP for `cache_ttl` (`0s` disables the cache), so a new ban takes up to that long to apply.

Set `global_settings.security_dependency_failure_mode` to `fail_open` or `fail_closed` deliberately. A CrowdSec initialization failure rejects startup or reload; the failure mode governs request-time lookup errors. In `fail_closed` mode a CrowdSec outage also makes `/readyz` report not ready.

## 9. Show a custom block page

Replace the default JSON `403` for Coraza blocks with a page of your own:

```yaml
tenants:
  "shop.example.com":
    upstreams:
      - url: "http://shop:8080"
    security:
      waf_enabled: true
      paranoia_level: 1
      include_rule_sets: ["web-baseline"]
      block_page_path: "/etc/waf/block-page.html"
```

The file must exist when the configuration is loaded; `-validate-config` checks that too. `{{HOST}}` and `{{EVENT_ID}}` are replaced with HTML-escaped values, and the event ID also appears in the `WAF blocked request` log entry so support staff can find the cause. `assets/examples/block-page.html` is a minimal template. `block_page_url` redirects with `302` instead when you prefer an external page.

## Choosing controls

Prefer the smallest policy that addresses a measured risk. Every additional body inspection, regular expression, network lookup, or response rewrite adds latency or failure modes. Benchmark with realistic payloads and monitor blocks by source (`synit_waf_blocked_requests_total{source}`) before broad rollout.
