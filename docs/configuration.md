# Synit WAF configuration reference

Synit WAF reads one YAML file plus optional sibling `tenants.d` shards. It watches both locations for create, write, rename, and remove events. The default path is `/etc/waf/config.yml`; use `-config PATH` or `EDGE_WAF_CONFIG` to select another file.

Validate a file without starting the proxy:

```bash
synit-waf -config ./config.yml -validate-config
```

`-validate-config` runs the same loader as startup: strict YAML decoding, shard merging, environment overrides, defaults, and every check in this document, including the existence of `block_page_path` files. Secrets referenced through the environment (`*_FILE` variables and `llm_protection.sidecar_token_env`) are resolved during validation, so an `ml` or `hybrid` tenant validates only when its token variable is set. It does not compile Coraza directives, open the GeoIP database, or contact CrowdSec. Those steps run at startup and on every reload, and a failure there rejects the configuration as well.

`assets/config.sample.yml` demonstrates every main section. Smaller examples live in `assets/examples/`.

## Minimal configuration

At least one tenant and one HTTP or HTTPS upstream are required:

```yaml
global_settings:
  log_level: "INFO"

tenants:
  "app.example.com":
    upstreams:
      - url: "http://app:8080"
        response_header_timeout: "30s"
    security:
      waf_enabled: false
```

Only configured host names are proxied. Host matching is case-insensitive and ignores a port, a trailing dot (`app.example.com.`), and the brackets of an IPv6 literal. A leading wildcard such as `*.example.com` matches any depth below the suffix: `a.example.com` and `a.b.example.com` both match, `example.com` does not. When exact and wildcard entries both match, the exact entry wins; among wildcards, the longest suffix wins. Two tenant keys that normalize to the same host reject the configuration.

Each upstream accepts an optional `response_header_timeout`. Zero uses `30s`; use a larger positive duration when an upstream legitimately needs more time before sending headers. Streaming remains unbounded after headers arrive.

## Global settings

```yaml
global_settings:
  log_level: "INFO"
  request_body_limit: 1048576
  response_masking_limit: 1048576
  request_body_oversize_action: "reject"
  security_dependency_failure_mode: "fail_open"
  allow_insecure_service_urls: false
  rules_dir: "/etc/waf/rules"
  read_timeout: "15s"
  write_timeout: "0s"
  idle_timeout: "60s"
  admin_address: "127.0.0.1:9090"
  upstream_transport:
    max_idle_conns_per_host: 64
    max_conns_per_host: 0
  global_rate_limit:
    requests_per_minute: 0
    burst: 0
  trust_forwarded_for: false
  trusted_proxy_cidrs: []
  ip_sets:
    allow_list: []
    block_list: []
  coordinator:
    enabled: false
    role: "leader"
    address: ":8089"
    secret: ""
    tls:
      ca_file: "/etc/waf/coordinator/ca.pem"
      cert_file: "/etc/waf/coordinator/server.pem"
      key_file: "/etc/waf/coordinator/server-key.pem"
      server_name: "waf-coordinator.internal"
  acme:
    enabled: false
    agree_tos: false
    email: "admin@example.com"
    storage_path: "/etc/waf/certs/acme"
    staging: true
    dns_provider: ""
    dns_token: ""
```

- `log_level` controls application logs. Logrus levels such as `trace`, `debug`, `info`, `warn`, `error`, and `fatal` are accepted case-insensitively. Empty or invalid values fall back to `info`.
- `request_body_limit` is the maximum request-body size, in bytes, read for Coraza, GraphQL, and LLM inspection. Values less than or equal to zero use `1048576` bytes. This key was called `response_buffer_limit` in earlier versions although it always limited the request body. The old key and `WAF_GLOBAL_RESPONSE_BUFFER_LIMIT` still work and log a deprecation warning. Setting both keys to different values rejects the configuration. When both environment variables are set, `WAF_GLOBAL_REQUEST_BODY_LIMIT` wins.
- `response_masking_limit` bounds upstream bodies that are buffered for response masking. Oversized mask-required responses fail closed with `502`; the default is `1048576` bytes.
- `request_body_oversize_action` must be `reject` (empty also defaults to `reject`). Oversized inspected bodies return `413`; they are never forwarded uninspected. No other value exists.
- `security_dependency_failure_mode` is `fail_open` or `fail_closed`. It controls CrowdSec and GeoIP dependency failures. Empty defaults to `fail_open`.
- `allow_insecure_service_urls` permits plain HTTP URLs for external JWKS, CrowdSec, log-forwarder, and LLM services. Loopback HTTP is always allowed. Keep this false unless transport security is provided by a trusted private network.
- `rules_dir` is the root directory for rule files that Coraza directives reference, for example `Include profiles/wordpress.conf`. It defaults to `/etc/waf/rules`. Coraza cannot read files outside this directory. See [Reusable WAF rule sets](#reusable-waf-rule-sets).
- `read_timeout`, `write_timeout`, and `idle_timeout` use Go duration syntax. Zero read/idle values use `15s`/`60s`. A zero write timeout remains disabled and is required for long-lived SSE; WebSocket upgrades are supported.
- `admin_address` is the dedicated listener for `/livez`, `/healthz`, `/readyz`, and `/metrics`; it defaults to `127.0.0.1:9090`. Keep it private and distinct from the public listener.
- `upstream_transport.max_idle_conns_per_host` is the number of idle keep-alive connections kept per upstream; zero uses `64`. `upstream_transport.max_conns_per_host` caps all connections per upstream, including those in use; `0` means unlimited. When the cap is reached, further requests wait for a free connection. Every upstream has its own transport, so both values apply per upstream URL. Negative values are rejected.
- `global_rate_limit.requests_per_minute` enables one process-wide token bucket when greater than zero. `burst` must then be greater than zero. Both fields must be non-negative; zero requests per minute disables this limit.
- `trust_forwarded_for` requires at least one `trusted_proxy_cidrs` entry. Forwarded hops are accepted only when the socket peer and intervening rightmost hops are trusted; otherwise the socket peer is the client. See [Headers sent to the upstream](#headers-sent-to-the-upstream).
- `ip_sets.allow_list`, `ip_sets.block_list`, and `trusted_proxy_cidrs` accept individual IPv4/IPv6 addresses or CIDRs. Invalid entries reject configuration. The block list is evaluated first. An allow-listed IP bypasses global and tenant rate limits, GeoIP, Coraza, GraphQL, and LLM inspection, but not host matching, JWT, Basic Auth, or CrowdSec.

Request bodies with a non-identity `Content-Encoding` are rejected with `415` whenever Coraza, GraphQL, or LLM body inspection applies. Decompress at a trusted ingress or send an uncompressed body; the WAF does not forward a compressed body past an enabled inspection control.

### ACME

When `global_settings.acme.enabled` is true, Synit WAF uses CertMagic instead of the configured plain HTTP listen address.

- `agree_tos` must be `true` when ACME is enabled. It records that you have read and accepted the subscriber agreement of the certificate authority (Let's Encrypt by default). Without it the configuration is rejected. It can be set with `WAF_GLOBAL_ACME_AGREE_TOS`.
- `email` is required when ACME is enabled.
- `storage_path` selects certificate storage. Empty uses CertMagic's default storage.
- `staging` selects Let's Encrypt staging.
- `dns_provider` is empty for HTTP-01 or `cloudflare` for DNS-01. Cloudflare requires `dns_token`; other provider names are rejected. Wildcard tenants require Cloudflare DNS-01.

Do not commit `dns_token`. Set it with `WAF_GLOBAL_ACME_DNS_TOKEN` or `WAF_GLOBAL_ACME_DNS_TOKEN_FILE`; `WAF_GLOBAL_ACME_DNS_PROVIDER` can select the provider.

Tenants added by a hot reload get their certificates in the background; a restart is not needed. Until the certificate is issued, TLS handshakes for the new host name fail. Changing `acme.enabled` itself is rejected on reload and needs a restart. The other ACME settings (`email`, `storage_path`, `staging`, DNS provider and token) are read once at startup.

### Rate-limit coordinator

The optional coordinator shares per-tenant, per-client rate-limit state across WAF processes using authenticated Go `net/rpc` over TLS 1.3.

- `enabled` starts coordinator use.
- `role` must be `leader` or `follower`.
- `secret` is mandatory and authenticates calls. Set it with `WAF_COORDINATOR_SECRET` or `WAF_COORDINATOR_SECRET_FILE`.
- Leaders require `tls.ca_file`, `tls.cert_file`, and `tls.key_file`; the CA verifies follower client certificates.
- Followers require `tls.ca_file`, `tls.cert_file`, `tls.key_file`, and `tls.server_name`.

Calls use a persistent reconnecting TLS 1.3 RPC connection with two-second operation deadlines and mutual certificate authentication. State and concurrent connections are bounded. If a runtime call fails, the node falls back to its local limiter. Restrict the RPC port and configure exactly one reachable leader.

## Logging

```yaml
logging:
  access_log:
    enabled: true
    path: "/var/log/waf/access-%yyyy-%MM-%dd.log"
    format: "json"
  error_log:
    enabled: true
    path: "/var/log/waf/error.log"
    format: "text"
  log_forwarder:
    enabled: false
    url: "http://ai-logs-receiver:8082/logs"
    token: ""
```

Access logs always go to stdout and application logs always go to stderr. Enabling a file section adds a file sink; it does not disable console output. `format` must be `json` or `text` when a file sink is enabled. Application logs on stderr are coloured only when stderr is a terminal, so container log collectors receive plain text.

The access log is written with `log/slog`. The stdout sink uses the slog text format (`key=value`); the file sink uses `json` or `text`. Each record has the message `request handled` and these fields: `time`, `level` (lower case), `client_ip`, `method`, `host`, `path`, `proto`, `status`, `size_bytes`, `duration_ms`, `referer`, `user_agent`, `tenant`, and `user` when Basic Auth succeeded. `tenant` is the matched tenant key or `unmatched`. Query strings are not logged. Long values are cut at 2048 bytes.

File paths support `%yyyy`, `%yy`, `%MM`, `%M`, `%dd`, `%d`, `%HH`, `%hh`, `%mm`, and `%ss`. The path is resolved again while the process runs, at most once per second. When the resolved path changes, for example at midnight for `%yyyy-%MM-%dd`, the WAF opens the new file and closes the old one. If the new file cannot be opened, it keeps writing to the current one. Old files are not deleted or compressed; use your own retention job. Log files are created with mode `0600`.

`log_forwarder` sends structured access and application log entries to an HTTP endpoint. Entries are collected into NDJSON batches: one JSON object per line, `Content-Type: application/x-ndjson`. A batch is sent after 250 ms, after 100 entries, or at 512 KiB, whichever comes first. The request carries `Authorization: Bearer <token>`. The token is required when forwarding is enabled; use `WAF_LOG_FORWARDER_TOKEN` or `WAF_LOG_FORWARDER_TOKEN_FILE` instead of committing it. The included AI Logs Receiver requires tokens of at least 32 characters. Delivery is asynchronous and best effort with no retry queue: single entries above 16 KiB, entries arriving while the queue of 1024 is full, and all entries of a batch that fails or gets a non-2xx answer are dropped and counted in `synit_waf_log_forward_dropped_total`. Each HTTP call has a two-second timeout.

### WAF rule logs

Coraza calls the WAF for every matched rule that carries the `log` action, in blocking mode and in audit mode. Each call writes one application log entry at level `warning`:

```text
msg="WAF rule matched" event_id=... client_ip=... uri=... rule_id=110002 severity=... message="Blocked SQL injection pattern" data=... tenant=app.example.com host=app.example.com audit_mode=true
```

The same event increments `synit_waf_rule_matches_total{tenant,rule_id}`. Rules without the `log` action (for example `nolog` rules) are not reported.

In blocking mode a blocked request also logs `WAF blocked request` with `client_ip`, `host`, `phase`, `rule_id`, and `event_id`. The `event_id` is the Coraza transaction ID and is the value shown on block pages.

In audit mode a request that matched at least one blocking rule (a rule with `deny`, `drop`, or `redirect`) logs `WAF attack detected (Audit Mode)` once, with `client_ip`, `host`, `tenant`, `rule_id`, and `event_id`, and increments `synit_waf_audit_mode_events_total{tenant}`.

## CrowdSec

```yaml
crowdsec:
  api_url: "http://crowdsec:8080/"
  api_key: ""
  cache_ttl: "30s"
```

`api_url` and `api_key` are required when any tenant sets `security.crowdsec_enabled: true`. The WAF initializes one live bouncer and checks the client IP for those tenants. CrowdSec is optional when no tenant enables it. Set the key with `WAF_CROWDSEC_KEY` or `WAF_CROWDSEC_KEY_FILE`.

`cache_ttl` is the time a LAPI answer for one client IP is reused, for both "banned" and "not banned". The default is `30s`. `0s` disables the cache, so LAPI is queried for every request. A new ban therefore takes up to `cache_ttl` to apply to a client that was seen shortly before, and a lifted ban takes equally long to clear. The cache holds up to 50,000 addresses and is emptied on every configuration reload. Negative values are rejected.

## GeoIP

```yaml
geoip:
  db_path: "/etc/waf/geoip/GeoLite2-Country.mmdb"
```

`db_path` is required when any tenant enables GeoIP. The WAF opens a MaxMind Country database and checks the validated client IP before tenant security controls. Missing or invalid databases fail startup/reload. Database acquisition and updates remain the operator's responsibility.

## Reusable WAF rule sets

`waf_rule_sets` maps names to Coraza/ModSecurity directives. A WAF-enabled tenant selects names with `security.include_rule_sets` and can add tenant-local `custom_rules`.

```yaml
waf_rule_sets:
  "base-protection": |
    SecRule REQUEST_METHOD "@rx (?i:^(trace|track)$)" "id:110001,phase:1,deny,status:403,log,msg:'Blocked unsafe HTTP method'"
```

Every referenced name must exist. Keep rule IDs unique across included and custom directives. Start new rules in `audit_mode`, test representative traffic, then enable blocking.

### No bundled OWASP Core Rule Set

Synit WAF does not bundle the OWASP Core Rule Set (CRS) or any other complete rule set. The repository and the container image contain only two small example profiles, `profiles/wordpress.conf` and `profiles/api-strict.conf`. If you want CRS, download a release yourself, put it under `rules_dir`, and include it from a rule set:

```yaml
waf_rule_sets:
  "crs": |
    Include crs/crs-setup.conf
    Include crs/rules/*.conf
```

Review the CRS license and update process yourself; see [third-party notices](./third_party.md#operator-supplied-artifacts).

### Rule files and `rules_dir`

Paths in `Include` and in operators such as `@pmFromFile` are resolved relative to `global_settings.rules_dir` (default `/etc/waf/rules`, environment `WAF_GLOBAL_RULES_DIR`). The container image installs the example profiles under `/etc/waf/rules/profiles/`; inspect and tune them before production use.

Rule files are not watched. They are read again when the configuration is reloaded, which happens when the main file or a `tenants.d` shard changes. On reload the WAF compares the size and modification time of every file under `rules_dir`; if nothing changed and the tenant's directives are the same, the existing Coraza instance is reused. To apply an edited rule file, change it and then touch the main configuration file.

### Reserved rule IDs

Rule IDs `440000`-`440099` are reserved for directives that Synit WAF generates. Do not use them in your own rules; a duplicate ID rejects the configuration at startup or reload.

| ID | Purpose |
|---|---|
| `440000` | `SecAction` that sets the paranoia variables from `paranoia_level` |
| `440001` | Denies a request with `403` when Coraza could not parse the request body (`REQBODY_ERROR`) |
| `440010` | Selects the JSON body processor for `application/json` requests (part of `llm-protection`) |
| `440011` | Skips the `llm-protection` detection rules for requests outside `inspect_paths` |
| `440012` | Instruction-override and known jailbreak phrases |
| `440013` | System-prompt extraction phrases |

### Built-in `llm-protection` rule set

Synit WAF provides a built-in `llm-protection` rule set unless that name is defined in `waf_rule_sets`. To run its static prompt-injection rules, include it in a WAF-enabled tenant:

```yaml
include_rule_sets:
  - "llm-protection"
```

The rule set is generated per tenant. Rules `440012` and `440013` run only for requests whose path is under the tenant's `llm_protection.inspect_paths` (the defaults apply when the list is empty); other endpoints of the same tenant are not affected. The patterns match instruction-override phrases such as "ignore all previous instructions", named jailbreak modes, and requests to reveal the system prompt. Generic role play such as "act as a translator" is not matched. The rules are a first filter, not a complete defence; combine them with the classifier for higher coverage.

If you define your own `llm-protection` entry in `waf_rule_sets`, it replaces the built-in set completely and is not scoped to `inspect_paths`.

### Instance sharing

Tenants whose generated directives are identical share one Coraza instance, which lowers memory use and reload time for many similar tenants. Instances are also kept across reloads when neither the directives nor the files under `rules_dir` changed.

## Tenants

```yaml
tenants:
  "app.example.com":
    upstreams:
      - url: "http://app-a:8080"
      - url: "http://app-b:8080"
    upstreamInsecure: false
    health_check:
      interval: "10s"
      timeout: "5s"
      path: ""
    header_transform:
      strip_request: ["X-Untrusted-Header"]
      inject_request:
        X-WAF-Tenant: "{{TENANT}}"
        X-Client-IP: "{{CLIENT_IP}}"
      strip_response: ["Server"]
      inject_response:
        X-Content-Type-Options: "nosniff"
    security:
      waf_enabled: true
      audit_mode: true
      paranoia_level: 1
      include_rule_sets: ["base-protection"]
```

- `upstreams` is required and must contain at least one absolute `http` or `https` URL with a host. Requests use round-robin selection among healthy upstreams.
- `upstreamInsecure` disables TLS certificate verification for HTTPS upstreams when true. It defaults to false. Use only for a controlled private endpoint.
- `header_transform.strip_request` removes named request headers before proxying.
- `header_transform.inject_request` sets request headers after stripping. `{{TENANT}}` expands to the matched tenant key and `{{CLIENT_IP}}` to the resolved client IP. Injected headers are set after hop-by-hop processing, so a client cannot remove them by naming them in a `Connection` header.
- `header_transform.strip_response` removes named upstream response headers.
- `header_transform.inject_response` sets literal response values; no placeholders are expanded.

### Upstream health checks

```yaml
health_check:
  interval: "10s"
  timeout: "5s"
  path: ""
```

Every upstream of a tenant is checked actively. `interval` defaults to `10s` and `timeout` to `5s`; negative values are rejected.

- With an empty `path` the check is a TCP connect to the upstream host and port.
- With a `path` the check is an HTTP `GET` of that path on the upstream URL. Any status below `500` counts as healthy, so `401` or `404` do not mark the upstream down. Redirects are not followed. The request uses the upstream transport, including `upstreamInsecure`, and the `User-Agent` `synit-waf-healthcheck`. The path must start with `/` and must not contain quotes, backslashes, whitespace, or control characters.

A tenant returns `503` when no upstream is healthy. On startup and on every reload all upstreams are probed once, in parallel, before the new configuration serves traffic. A reload therefore does not open a window in which upstream health is unknown; it takes at most one `timeout` longer.

### Headers sent to the upstream

The WAF sets these request headers itself:

| Header | Value |
|---|---|
| `X-Forwarded-For` | the resolved client IP (one address) |
| `X-Real-IP` | the resolved client IP |
| `X-Forwarded-Host` | the inbound `Host` |
| `X-Forwarded-Proto` | `https` when the WAF terminated TLS, otherwise `http` |

Client-supplied `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` values are dropped. The only exception: when `trust_forwarded_for` is true and the socket peer is inside `trusted_proxy_cidrs`, the client IP is taken from the proxy's `X-Forwarded-For` chain and the proxy's `X-Forwarded-Host` and `X-Forwarded-Proto` values are passed on.

The inbound `Host` header is preserved, so the upstream sees the tenant host name, not the host of the upstream URL. The `X-Synit-Dev-Bypass` header is never forwarded.

### Security policy

All security controls default to disabled unless stated otherwise.

#### Coraza WAF

- `waf_enabled` enables Coraza. When true, `paranoia_level` must be from `1` through `4`.
- `paranoia_level` sets `tx.paranoia_level` (read by CRS 3.x) and `tx.blocking_paranoia_level` plus `tx.detection_paranoia_level` (read by CRS 4.x). It has an effect only when you supply CRS or other rules that read these variables. With the example rules in this repository it changes nothing.
- `audit_mode` changes Coraza to `DetectionOnly`: matched rules are logged and counted but requests are not blocked. See [WAF rule logs](#waf-rule-logs).
- `include_rule_sets` selects reusable rule blocks.
- `custom_rules` appends raw Coraza directives for this tenant.
- `block_page_url` sends a `302` redirect for a Coraza block.
- `block_page_path` serves a local HTML file with status `403` when `block_page_url` is empty. The file must exist and be a regular file; it is read when the configuration is loaded or reloaded, not per request, and a missing file rejects the configuration (also with `-validate-config`). `{{EVENT_ID}}` and `{{HOST}}` are replaced; both values are HTML-escaped because `Host` is client controlled. Reload the configuration after editing the page. `assets/examples/block-page.html` is a minimal starting point.
- `dev_bypass_secret` lets a request with a matching `X-Synit-Dev-Bypass` header skip Coraza, GraphQL, and LLM checks. It does not bypass other controls. The secret must be at least 32 characters and is compared in constant time. The header is removed before the request is proxied. The WAF logs a warning at startup and on every reload for each tenant that sets it. Avoid this option in production and never commit its value.

Phase 2 rules run for every request, also when the request has no body.

#### CrowdSec and GeoIP

- `crowdsec_enabled` enables CrowdSec lookup and requires the global CrowdSec configuration.
- `geoip_enabled` enables MaxMind country lookup and requires `geoip.db_path`.
- `blocked_countries` contains two-letter ISO country codes. Matching requests return `403`.

#### JWT validation

```yaml
jwt_validation:
  enabled: true
  jwks_endpoint: "https://identity.example.com/.well-known/jwks.json"
  issuer: "https://identity.example.com/"
  audience: "my-api"
```

When enabled, endpoint, issuer, and audience are required. Requests need a bearer JWT that:

- has a `kid` header that exists in the JWKS;
- is signed with `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, or `EdDSA`; HMAC algorithms and `none` are rejected;
- carries an `exp` claim that lies in the future; tokens without `exp` are rejected;
- matches the configured `issuer` and `audience`.

Supported JWK types are `RSA`, `EC` (P-256, P-384, P-521), and `OKP` with curve `Ed25519`. The key type must fit the algorithm family in the token header. JWKS fetches have a five-second timeout, one MiB response limit, 100-key limit, coalesced refresh, and one-hour maximum cache TTL. JWT verification failures return `401`; JWKS fetch failures return `503`.

`jwt_validation` cannot be combined with `basic_auth` on the same tenant, because both read the `Authorization` header. The configuration is rejected.

#### Basic Auth

```yaml
basic_auth:
  - user: "operator"
    password: "$2y$05$..."
```

Each entry requires a non-empty user and bcrypt password hash. Plain-text passwords fail validation. Generate a hash with a trusted bcrypt/htpasswd tool and keep the hash out of public examples when it represents a real credential.

A successful verification is remembered in memory for five minutes, so bcrypt does not run for every request. The cache holds up to 4096 entries, its keys are HMACs (under a random per-process key) of the user name, the password, and the configured hash, and it is emptied on every configuration reload. Because the configured hash is part of the key, a removed or changed credential stops working immediately; the cache never outlives the configuration it was built from. An unknown user name costs the same bcrypt work as a known one, so response time does not reveal which users exist.

#### Per-tenant rate limit

```yaml
rate_limit:
  requests_per_minute: 600
  burst: 120
```

The token-bucket key is tenant plus client. IPv4 clients are keyed by address. IPv6 clients are grouped by their `/64` prefix, because a single subscriber normally controls a whole `/64`. Both fields must be non-negative. A positive request rate requires a positive burst; a positive burst requires a positive request rate. `requests_per_minute: 0` disables the limit. Buckets live in an in-memory cache of up to 10,000 tenant-client keys that expire after ten minutes without traffic. Limiters survive a configuration reload as long as `requests_per_minute` and `burst` of the tenant are unchanged; a changed policy starts with fresh buckets. When the coordinator is enabled, these checks are shared; coordinator failures fall back to the local cache.

#### Response masking

```yaml
response_masking:
  - pattern: '(?i)api[_-]?key=[^&[:space:]]+'
    replacement: "api_key=[REDACTED]"
```

Each `pattern` must be a non-empty valid Go regular expression. Rules modify `text/*`, JSON, and XML response bodies. Bodies are bounded by `global_settings.response_masking_limit`; an oversized mask-required response returns `502` instead of leaking an uninspected body. A modified response carries `X-Synit-Masked: true`.

A response without a `Content-Type` header, or with one that cannot be parsed, is buffered and its type is detected from the content. If the detected type is text, JSON, or XML it is masked; otherwise it is passed on unchanged. An upstream therefore cannot skip masking by omitting the header.

These responses still fail closed with `502` when the tenant has masking rules, because a complete plain body is required:

- `text/event-stream` (SSE);
- `206 Partial Content`;
- a non-identity `Content-Encoding` on a maskable or undeclared content type.

To reduce such cases the proxy removes `Accept-Encoding`, `Range`, and `If-Range` before forwarding a request whose tenant has masking rules. Do not combine response masking with SSE on one tenant. WebSocket upgrades remain supported because switching-protocol responses have no maskable body. `strip_response` and `inject_response` must not touch `Content-Type`, `Content-Encoding`, `Content-Length`, `Content-Range`, `Accept-Ranges`, `ETag`, or `Last-Modified` while masking is configured.

#### GraphQL protection

```yaml
graphql:
  enabled: true
  paths: ["/graphql"]
  block_introspection: true
  max_query_depth: 8
  max_batched_queries: 10
  max_query_bytes: 102400
```

- `paths` lists the GraphQL endpoints; the default is `["/graphql"]`. A path matches as a prefix on a path boundary: `/graphql` matches `/graphql` and `/graphql/v2` but not `/graphqlx`. The cleaned request path is checked as well, so `//graphql` or `/x/../graphql` cannot sidestep the control. Requests to any other path of the tenant are not treated as GraphQL and pass this control untouched. Each entry must start with `/`.
- `block_introspection` rejects `__schema` and `__type` fields, also inside fragments.
- `max_query_depth` limits selection depth; `0` disables the limit. Named fragments are expanded with cycle detection.
- `max_batched_queries` limits the number of operations in a JSON array body; `0` disables the limit.
- `max_query_bytes` limits one query string; the default is `102400` (100 KiB).

Before a query is parsed, a linear scan measures how deeply braces and brackets are nested. A query nested deeper than `max(64, 2 * max_query_depth + 16)` is rejected without parsing. This protects the recursive parser against pathological input.

Under the configured paths the policy accepts GET with a `query` parameter, POST `application/graphql`, and POST JSON objects or arrays containing `query`. Other methods return `405`, other content types `415`, malformed bodies `400`, and request bodies over `request_body_limit` `413`. Policy violations return `403` with a GraphQL-style error body.

#### LLM protection

```yaml
llm_protection:
  enabled: true
  mode: "hybrid"
  action: "audit"
  threshold: 0.85
  fail_mode: "open"
  timeout: "500ms"
  max_body_bytes: 0
  max_text_bytes: 8192
  sidecar_max_batch: 32
  sidecar_url: "http://synit-llm-guard:5001/v1/detect"
  sidecar_token_env: "WAF_LLM_SIDECAR_TOKEN"
  inspect_paths: ["/v1/chat/completions", "/v1/messages"]
  inspect_json_fields: ["prompt", "input", "query", "messages[].content"]
```

When enabled, omitted fields receive the values shown above, except `sidecar_url`, which defaults to `http://localhost:5001/v1/detect`. Important details:

- `mode` is `rules`, `ml`, or `hybrid`. `rules` and `hybrid` require `waf_enabled: true` and `llm-protection` in `include_rule_sets`. `rules` does not call a sidecar.
- `ml` and `hybrid` require `sidecar_url` and exactly one of `sidecar_token` or `sidecar_token_env`; calls use bearer authentication. `sidecar_token_env` names an environment variable. When that variable is unset, the file named by `<NAME>_FILE` is read instead. Prefer this indirection so the secret is not stored in YAML.
- `action` is `audit` or `deny`. It controls sidecar detections; Coraza blocking remains controlled by `audit_mode`.
- `threshold` is from `0.0` through `1.0`. Because zero is treated as omitted, the effective default is `0.85`.
- `fail_mode` is `open` or `closed`. Closed mode returns `403` when the body cannot be read or the sidecar is unreachable, times out, or answers with an unexpected status.
- `timeout` must be positive; the default is `500ms`. It is one deadline for all sidecar calls of a request, not per batch. The remaining time is passed to the guard as `max_latency_ms`.
- `max_body_bytes` limits the whole request body. `0` uses `global_settings.request_body_limit`. A larger body returns `413`; it is never truncated or forwarded uninspected. When Coraza is enabled for the tenant, `request_body_limit` applies first.
- `max_text_bytes` limits one extracted text, not the body; the default is `8192`. A longer text is split into overlapping chunks of at most this size (overlap up to 256 bytes, cut on UTF-8 boundaries). Every chunk is scored and the highest score counts. Keep the value at or below the guard's `MAX_TEXT_BYTES`.
- `sidecar_max_batch` is the number of texts sent in one sidecar call; the default is `32`. More texts are sent in several calls. It must not exceed the guard's `MAX_TEXTS`, otherwise the guard answers `400` and the request counts as uninspectable.
- `inspect_paths` use prefix matching on a path boundary, with the same cleaned-path check as `graphql.paths`. Entries must start with `/`. The list also scopes the built-in `llm-protection` rules, even when `enabled` is false.
- JSON fields use gjson-style paths; `messages[].content` is converted to array traversal. `text/plain` bodies are inspected directly. Other content types are skipped; a `Content-Type` header that cannot be parsed returns `415`, and an `application/json` body that is not valid JSON returns `400`.

A sidecar answer of `400`, `413`, or `422` means the input itself cannot be inspected, for example because a text is too large for the guard. This is not a dependency failure, so `fail_mode` does not apply: with `action: deny` the client receives `422`, with `action: audit` the event is logged, counted in `synit_waf_audit_mode_events_total`, and the request is allowed.

Scores are cached for ten minutes per sidecar URL, tenant, path, and text (up to 10,000 entries). The cache is emptied on reload.

The included `services/synit-llm-guard` performs text classification using an operator-mounted Hugging Face-compatible ONNX model. It refuses startup without `MODEL_PATH` and `AUTH_TOKEN`. The guard splits long texts again into chunks of `CHUNK_BYTES` (default `510`, the token window of a 512-token model minus its special tokens) with `CHUNK_OVERLAP_BYTES` (default `64`) overlap so that nothing falls outside the model's token window. It answers `504` when its inference deadline passes and `400` or `413` for input above its `MAX_TEXTS`, `MAX_TEXT_BYTES`, or `MAX_REQUEST_BYTES` limits. Model selection, label mapping, evaluation, monitoring, and updates are operator responsibilities; no model weights are bundled. See the [guard README](../services/synit-llm-guard/README.md).

#### Circuit breaker

```yaml
circuit_breaker:
  enabled: true
  threshold: 5
  cooldown: "30s"
  failure_status_codes: [502, 503, 504]
```

When enabled, proxy connection errors and selected upstream status codes count as failures. At `threshold`, the upstream is skipped for `cooldown`; zero cooldown uses `30s`. Active health checks continue independently. Use a positive threshold.

## Modular tenant files

If `tenants.d/` exists next to the main configuration, reload merges every top-level `.yml` and `.yaml` file containing a `tenants` map:

```yaml
tenants:
  "customer-a.example.com":
    upstreams:
      - url: "http://customer-a:8080"
    security:
      waf_enabled: true
      paranoia_level: 1
      include_rule_sets: ["base-protection"]
```

Tenant keys must be unique across the main file and every shard. Unknown YAML fields, duplicate tenants, unreadable shards, multiple YAML documents, or invalid values reject the entire candidate. Main-file and shard changes trigger a debounced transactional reload; the prior runtime stays active when a reload fails.

## Environment and command-line settings

Startup controls:

- `EDGE_WAF_CONFIG`: default path used by `-config`; the flag wins when both are supplied.
- `EDGE_WAF_ADDR`: plain HTTP listen address; default `:80`. ACME mode does not use it. It must differ from `admin_address`; the process refuses to start when both are the same.
- `-validate-config`: validate and exit.
- `-version`: print the build version and exit.

The following environment variables are parsed by `ApplyEnvOverrides`:

- `WAF_GLOBAL_LOG_LEVEL`
- `WAF_GLOBAL_REQUEST_BODY_LIMIT`
- `WAF_GLOBAL_RESPONSE_BUFFER_LIMIT` (deprecated alias of `WAF_GLOBAL_REQUEST_BODY_LIMIT`; logs a warning)
- `WAF_GLOBAL_RULES_DIR`
- `WAF_GLOBAL_RESPONSE_MASKING_LIMIT`
- `WAF_GLOBAL_REQUEST_BODY_OVERSIZE_ACTION`
- `WAF_GLOBAL_SECURITY_DEPENDENCY_FAILURE_MODE`
- `WAF_GLOBAL_ALLOW_INSECURE_SERVICE_URLS`
- `WAF_GLOBAL_READ_TIMEOUT`
- `WAF_GLOBAL_WRITE_TIMEOUT`
- `WAF_GLOBAL_IDLE_TIMEOUT`
- `WAF_GLOBAL_ADMIN_ADDRESS`
- `WAF_GLOBAL_ACME_ENABLED`
- `WAF_GLOBAL_ACME_AGREE_TOS`
- `WAF_GLOBAL_ACME_EMAIL`
- `WAF_GLOBAL_ACME_STORAGE_PATH`
- `WAF_GLOBAL_ACME_STAGING`
- `WAF_GLOBAL_ACME_DNS_PROVIDER`
- `WAF_GLOBAL_ACME_DNS_TOKEN` (or `WAF_GLOBAL_ACME_DNS_TOKEN_FILE`)
- `WAF_GLOBAL_TRUST_FORWARDED_FOR`
- `WAF_GLOBAL_TRUSTED_PROXY_CIDRS` (comma-separated)
- `WAF_COORDINATOR_ENABLED`
- `WAF_COORDINATOR_ROLE`
- `WAF_COORDINATOR_ADDRESS`
- `WAF_COORDINATOR_SECRET` (or `WAF_COORDINATOR_SECRET_FILE`)
- `WAF_COORDINATOR_TLS_CA_FILE`
- `WAF_COORDINATOR_TLS_CERT_FILE`
- `WAF_COORDINATOR_TLS_KEY_FILE`
- `WAF_COORDINATOR_TLS_SERVER_NAME`
- `WAF_CROWDSEC_URL`
- `WAF_CROWDSEC_KEY` (or `WAF_CROWDSEC_KEY_FILE`)
- `WAF_LOG_FORWARDER_TOKEN` (or `WAF_LOG_FORWARDER_TOKEN_FILE`)

`upstream_transport`, `crowdsec.cache_ttl`, and all tenant settings have no environment override.

Boolean overrides use Go boolean syntax. Invalid booleans, integers, or durations reject startup/reload. Overrides are reapplied on every reload.

### Secrets from files

Four secrets, plus the LLM sidecar token, can be read from a file, which fits Docker and Kubernetes secret mounts:

| Variable | File variant |
|---|---|
| `WAF_GLOBAL_ACME_DNS_TOKEN` | `WAF_GLOBAL_ACME_DNS_TOKEN_FILE` |
| `WAF_COORDINATOR_SECRET` | `WAF_COORDINATOR_SECRET_FILE` |
| `WAF_CROWDSEC_KEY` | `WAF_CROWDSEC_KEY_FILE` |
| `WAF_LOG_FORWARDER_TOKEN` | `WAF_LOG_FORWARDER_TOKEN_FILE` |
| the variable named by `llm_protection.sidecar_token_env` | the same name with `_FILE` appended |

The `_FILE` variable holds a path. The file content is used with leading and trailing whitespace removed. When both variants are set, the plain variable wins. An unreadable file rejects startup or reload. Files are read again on every reload, but a changed secret file alone does not trigger a reload.

## Reload and validation behavior

On startup, invalid main YAML, invalid configuration, a missing `block_page_path` file, a CrowdSec bouncer that cannot be initialized, or invalid Coraza directives stop initialization. Upstream health check failure does not invalidate configuration; it affects readiness and routing.

When watched configuration changes, Synit WAF constructs and validates replacement policy, upstream, CrowdSec, GeoIP, and coordinator state, probes every upstream once, and then publishes everything in one synchronized step. A failed reload is logged, counted in `synit_waf_config_reload_total{result="failure"}`, and the previous runtime stays active. Logging sinks, listener addresses, server timeouts, and the ACME account settings are startup-scoped and require restart.

What survives a reload: Coraza instances whose directives and rule files are unchanged, per-tenant rate limiters whose policy is unchanged, and the JWKS cache. What is emptied: the CrowdSec decision cache, the Basic Auth cache, and the LLM score cache.

With ACME enabled, tenants added by a reload get certificates in the background. Changing `acme.enabled` is rejected on reload.

### Operational endpoints

The dedicated admin listener serves `/livez`, `/healthz` (alias of `/livez`), `/readyz`, and `/metrics` for every `Host`.

The public listener answers `/livez` and `/healthz` itself only when the request's `Host` is not a configured tenant, for example a pod IP or `localhost`. A request for a tenant host is always proxied, so an application's own `/healthz` or `/livez` is never shadowed by the WAF. Point orchestrator and load-balancer probes at the admin listener, or make sure they send a `Host` that is not a tenant. A probe that sends a tenant `Host` to the public listener tests the upstream application, not the WAF.

`/readyz` requires every tenant to have a healthy upstream. When CrowdSec is used with fail-closed dependency policy, startup probes it and readiness tracks later probes/request checks; an outage makes readiness fail. Fail-open CrowdSec outages do not remove the instance from service.

### Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `synit_waf_http_requests_total` | `tenant`, `status_class` | Requests handled |
| `synit_waf_http_request_duration_seconds` | `tenant` | Histogram from request arrival to the end of the response, including upstream time |
| `synit_waf_blocked_requests_total` | `source`, `tenant` | Requests rejected by a control; see the source list below |
| `synit_waf_rule_matches_total` | `tenant`, `rule_id` | Matched Coraza rules that carry the `log` action |
| `synit_waf_audit_mode_events_total` | `tenant` | Requests that would have been blocked but were allowed by audit mode or `llm_protection.action: audit` |
| `synit_waf_upstream_requests_total` | `tenant`, `upstream`, `result` | Proxied requests by upstream; `result` is a status class or `error` |
| `synit_waf_upstream_healthy` | `tenant`, `upstream` | `1` healthy, `0` unhealthy |
| `synit_waf_config_reload_total` | `result` | Reload attempts (`success`, `failure`) |
| `synit_waf_log_forward_dropped_total` | none | Forwarded log entries that were dropped |
| `synit_waf_build_info` | `version`, `goversion` | Always `1` |

`tenant` is the configured tenant key, `unmatched` for unknown hosts, or `global` for process-wide controls. `rule_id` has one series per rule that matched at least once; with a large rule set such as CRS this can reach several hundred series per tenant.

`source` values of `synit_waf_blocked_requests_total`: `ip_blocklist` and `global_rate_limit` (tenant `global`), `unknown_host` (tenant `unmatched`), `geoip`, `rate_limit`, `basic_auth`, `crowdsec` (banned IP), `crowdsec_unavailable` and `crowdsec_error` (fail-closed dependency failures), `waf` (Coraza interruption), `request_body_oversize` and `request_content_encoding` (body rejected before Coraza inspection), `graphql_oversize` and `llm_protection_oversize` (body above the inspection limit), `llm_protection` (classifier deny), and `llm_protection_uninspectable` (sidecar rejected the input with `action: deny`). JWT failures and GraphQL policy violations return `401`/`403` but are not counted here; use `synit_waf_http_requests_total{status_class="4xx"}`.

## Optional dependencies

- CrowdSec LAPI: required only for tenants with `crowdsec_enabled: true`.
- GeoIP database: required for tenants with `geoip_enabled: true`.
- LLM classifier: required only for enabled `ml` or `hybrid` LLM policies.
- AI Logs Receiver: optional target for `logging.log_forwarder`.
- Cloudflare API: required only for ACME DNS-01 with `dns_provider: cloudflare`.
- Rate-limit coordinator: optional for multi-node per-client rate-limit sharing.
- OWASP CRS or other rule sets: not bundled; add them under `rules_dir` when needed.

## Examples

Every file below passes `synit-waf -validate-config` unchanged (`make validate-examples`).

- `assets/config.sample.yml`: every section with defaults or typical values.
- `assets/examples/basic-config.yml`: one tenant, audit-first WAF rollout, no external security service.
- `assets/examples/intermediate-config.yml`: multiple tenants, CrowdSec, and an HTTP health check.
- `assets/examples/advanced-config.yml`: trusted proxies, header transforms, JWT, GraphQL, response masking, GeoIP, and a wildcard tenant.
- `assets/examples/optimized-config.yml`: stricter reusable and business-specific rules plus a rules-only LLM tenant.
- `assets/examples/cluster/`: Docker Swarm scaling example.
- `assets/examples/block-page.html`: minimal `block_page_path` template with the `{{HOST}}` and `{{EVENT_ID}}` placeholders.

The intermediate, advanced, and optimized examples reference a CrowdSec LAPI and, for GeoIP, a MaxMind database. Validation passes without them; starting the WAF needs them.
