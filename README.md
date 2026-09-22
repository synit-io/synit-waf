# Synit WAF

Synit WAF is a tenant-aware reverse proxy and web application firewall written in Go. One process can protect several hostnames, apply a different security policy to each tenant, and route allowed traffic to healthy upstreams.

![CI](https://github.com/synit-io/synit-waf/actions/workflows/ci.yml/badge.svg)
![Release](https://github.com/synit-io/synit-waf/actions/workflows/release.yml/badge.svg)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)
[![Discord](https://img.shields.io/badge/community-Discord-5865F2.svg)](https://www.synit.io/discord)

Synit WAF is maintained by [synit.io](https://www.synit.io). Questions, ideas, and deployment stories are welcome in the [Discord community](https://www.synit.io/discord).

## What it does

Synit WAF sits between clients and application services. It selects a tenant from the HTTP `Host` header, applies that tenant's controls, and proxies an accepted request to a healthy upstream.

```text
                         public listener
Client / trusted proxy ───────┬──> /livez, /healthz   (only when Host is not a tenant)
                              │
                              v
  source IP -> IP lists -> GeoIP -> global rate limit -> tenant match
      -> tenant rate limit -> JWT / Basic Auth -> CrowdSec
      -> Coraza -> GraphQL / LLM controls
      -> healthy upstream -> response masking / header transforms

                         private admin listener
Operator / orchestrator ──────┬──> /livez, /healthz
                              ├──> /readyz
                              └──> /metrics
```

Only configured exact or wildcard hostnames are served. Unmatched hosts are rejected with `403`. Multiple upstreams use health-aware round-robin selection, active TCP or HTTP health checks, and an optional passive circuit breaker.

## Why use it?

Use Synit WAF when several applications need consistent edge controls without duplicating that logic in every service. Policy stays explicit in YAML, can vary by hostname, and can start in audit mode before enforcement.

Typical uses include:

- protecting websites and APIs with Coraza-compatible rules;
- enforcing JWT, Basic Auth, IP, country, and request-rate policies at the edge;
- constraining GraphQL introspection, depth, query size, and batched operations;
- screening configured LLM request fields with rules and an authenticated ONNX classifier;
- masking sensitive text in eligible upstream responses;
- centralizing access logs, readiness, upstream health, and Prometheus metrics.

Synit WAF is not a managed rules service, certificate authority, GeoIP feed, model provider, or distributed API gateway control plane. It does not bundle the OWASP Core Rule Set. Operators own configuration, rules, external data, secrets, deployment, monitoring, and policy evaluation.

## Capabilities

| Area | Support |
|---|---|
| Tenant routing | Exact and leading-wildcard hostnames (any depth), strict host allow-listing, multiple upstreams |
| WAF | Coraza rules, reusable rule sets, custom rules, rule files under `rules_dir`, audit mode, custom block pages |
| Identity | JWKS-backed JWT validation (RSA, ECDSA, EdDSA; `exp` required) or bcrypt-backed Basic Auth per tenant |
| Network policy | Trusted proxy chains, IP allow/block lists, global and per-tenant rate limits (IPv6 grouped by /64) |
| Threat intelligence | Optional CrowdSec decisions with a per-IP cache, and MaxMind country blocking |
| API controls | GraphQL introspection, depth, size, and batch limits on configured paths |
| LLM controls | Static prompt rules plus authenticated ONNX classification in `rules`, `ml`, or `hybrid` mode |
| Proxy behavior | WebSocket upgrades, SSE streaming, request/response header transforms, WAF-owned forwarding headers |
| Response controls | Regex-based masking for bounded, unencoded text, JSON, and XML responses |
| Resilience | Active TCP or HTTP health checks, passive circuit breakers, bounded upstream response-header timeouts, connection pool limits |
| TLS | External termination or automatic ACME; optional Cloudflare DNS-01 for wildcards |
| Operations | JSON/text logs with date-based file rotation, batched NDJSON log forwarding, liveness, readiness, Prometheus metrics |
| Configuration | Strict YAML, optional `tenants.d` shards, transactional file watching and reload, secrets from environment or files |
| Multi-node option | Authenticated mutual-TLS coordinator for per-tenant rate-limit state |

## Request path

Checks run in this order:

1. Global IP block list, then the allow list is evaluated.
2. Optional GeoIP country policy of the matched tenant.
3. Global process rate limit.
4. Exact or wildcard tenant match; unknown hosts receive `403`.
5. Per-tenant, per-client rate limit.
6. Optional JWT validation or Basic Auth.
7. Optional CrowdSec decision.
8. Optional Coraza, GraphQL, and LLM request inspection.
9. Round-robin selection among healthy upstreams.
10. Forwarding headers and request header transforms, proxying, passive failure tracking, response masking, and response header transforms.

An allow-listed IP skips GeoIP, both rate limits, and request inspection (step 8). It still passes host matching, authentication, and CrowdSec.

## Quick start

### Prerequisites

- Docker Engine with the Compose plugin
- Git
- `curl`

Go 1.27.0 or newer is required only when building or running from source.

### Run the verified example

The fastest evaluation is the self-cleaning Docker end-to-end scenario:

```bash
git clone https://github.com/synit-io/synit-waf.git
cd synit-waf
./scripts/run-docker-e2e.sh
```

The script builds the current WAF source, starts a local upstream, verifies allowed and blocked requests, checks readiness and metrics, switches the tenant to audit mode, and removes its containers afterward.

For a persistent hands-on deployment, follow the [onboarding guide](./docs/onboarding.md). It creates a local upstream, builds the image, installs a rule, and verifies each endpoint.

## Minimal configuration

At least one tenant and one HTTP or HTTPS upstream are required:

```yaml
global_settings:
  log_level: "INFO"
  admin_address: "127.0.0.1:9090"
  request_body_limit: 1048576
  write_timeout: "0s"

waf_rule_sets:
  starter: |
    SecRule REQUEST_METHOD "@rx (?i:^(trace|track)$)" "id:110001,phase:1,deny,status:403,log,msg:'Blocked unsafe method'"

tenants:
  "app.example.com":
    upstreams:
      - url: "http://app:8080"
        response_header_timeout: "30s"
    health_check:
      path: "/healthz" # omit for a TCP connect check
    security:
      waf_enabled: true
      audit_mode: true
      paranoia_level: 1
      include_rule_sets:
        - "starter"
```

`paranoia_level` is required when `waf_enabled` is true. It sets the paranoia variables that the OWASP Core Rule Set reads and has no other effect; no CRS is bundled. Rule IDs `440000`-`440099` are reserved for rules that Synit WAF generates.

Validate before starting:

```bash
go run ./cmd/synit-waf -config ./config.yml -validate-config
```

Validation checks the YAML schema and all policy invariants. Coraza directives are compiled when the process starts or reloads; a rule syntax error is reported then.

Run on unprivileged local ports:

```bash
EDGE_WAF_ADDR=127.0.0.1:8080 \
WAF_GLOBAL_ADMIN_ADDRESS=127.0.0.1:9090 \
  go run ./cmd/synit-waf -config ./config.yml
```

Send the configured hostname even when connecting to loopback:

```bash
curl -i -H 'Host: app.example.com' http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/livez
curl -i http://127.0.0.1:9090/readyz
curl -s http://127.0.0.1:9090/metrics | grep synit_waf
```

The upstream in the YAML must be reachable before `/readyz` reports ready. Start new rules with `audit_mode: true`, observe representative traffic, tune false positives, and then enable enforcement.

In audit mode every matched rule with the `log` action is written to the application log as `WAF rule matched` with its `rule_id`, `tenant`, `uri`, and `event_id`. A request that matched a blocking rule also logs `WAF attack detected (Audit Mode)` and increments `synit_waf_audit_mode_events_total`. `audit_mode` affects Coraza only. Authentication, rate limits, IP lists, CrowdSec, and GraphQL limits keep blocking; LLM classification has its own `action: audit`.

## Build and run

### Local binary

```bash
make build
./bin/synit-waf -version
./bin/synit-waf -config /absolute/path/config.yml -validate-config
EDGE_WAF_ADDR=127.0.0.1:8080 ./bin/synit-waf -config /absolute/path/config.yml
```

The default configuration path is `/etc/waf/config.yml`; `EDGE_WAF_CONFIG` changes it. The plain HTTP listener defaults to `:80`; `EDGE_WAF_ADDR` changes it. ACME mode owns the HTTP/HTTPS listeners and ignores `EDGE_WAF_ADDR`. Rule files referenced by `Include` are read from `global_settings.rules_dir`, default `/etc/waf/rules`.

### Container

```bash
docker build -t synit-waf:local .
docker run --rm \
  -p 8080:80 \
  -p 127.0.0.1:9090:9090 \
  -e WAF_GLOBAL_ADMIN_ADDRESS=0.0.0.0:9090 \
  -v /absolute/path/config.yml:/etc/waf/config.yml:ro \
  synit-waf:local
```

The runtime image is distroless and runs as a non-root user. The binary is `/usr/local/bin/synit-waf`; `LICENSE`, `NOTICE`, and third-party notices are under `/usr/share/doc/synit-waf/`. Mount individual configuration, tenant, certificate, and GeoIP paths instead of hiding all of `/etc/waf`; the image contains the example rule profiles under `/etc/waf/rules`.

Self-hosted Compose, Kubernetes, and Docker Swarm templates are available under [`deploy/`](./deploy/) and [`assets/examples/cluster/`](./assets/examples/cluster/). They are starting points: replace image versions, secrets, storage, networks, and upstreams before use.

## Container images

Release images are published to two registries:

| Registry | Images | Tags |
|---|---|---|
| Docker Hub | `synitio/synit-waf`, `synitio/ai-logs-receiver`, `synitio/synit-llm-guard` | `1.0.0`, `1.0`, `1`, `latest` (no `v` prefix) |
| GitHub Container Registry | `ghcr.io/synit-io/synit-waf`, `ghcr.io/synit-io/ai-logs-receiver`, `ghcr.io/synit-io/synit-llm-guard` | `latest` only |

Versioned tags exist only on Docker Hub. GHCR carries the `latest` tag of the newest stable release, and older GHCR versions are pruned. Use Docker Hub for anything that must be reproducible:

```bash
docker pull synitio/synit-waf:1.0.0
```

For production, pin the digest as well (`synitio/synit-waf:1.0.0@sha256:<digest>`), so a moved tag cannot change what runs. Images are built for `linux/amd64` and `linux/arm64`.

## Configuration

Synit WAF reads one strict YAML document. A sibling `tenants.d/` directory can add `.yml` or `.yaml` tenant shards. Host keys must be unique across every file.

The loader rejects:

- unknown YAML fields or multiple YAML documents;
- missing tenants or upstreams;
- duplicate or colliding normalized hostnames;
- invalid regular expressions, URLs, IP addresses, CIDRs, durations, and security invariants, for example a `dev_bypass_secret` shorter than 32 characters or `jwt_validation` together with `basic_auth`;
- a `block_page_path` that does not exist;
- ACME without `acme.agree_tos: true`.

Startup and reload additionally reject invalid Coraza rules, an unreadable GeoIP database, and unavailable dependencies required by a fail-closed policy.

The main file and `tenants.d` are watched. A reload builds and validates the complete candidate, probes every upstream, and then publishes it in one step; failure leaves the previous runtime active. Coraza instances and rate limiters that did not change are kept. With ACME enabled, tenants added by a reload get certificates in the background. Listener addresses, HTTP server timeouts, log sinks, and switching `acme.enabled` require a restart.

Secrets can come from YAML, from environment variables, or from files: `WAF_CROWDSEC_KEY_FILE`, `WAF_COORDINATOR_SECRET_FILE`, `WAF_LOG_FORWARDER_TOKEN_FILE`, `WAF_GLOBAL_ACME_DNS_TOKEN_FILE`, and `<NAME>_FILE` for the variable named by `llm_protection.sidecar_token_env`.

Use [`assets/config.sample.yml`](./assets/config.sample.yml) for a commented complete example and the [configuration guide](./docs/configuration.md) for every field and environment override.

## Request and response safety

- Inspected request bodies are bounded by `request_body_limit`. Oversized bodies return `413`; they are never forwarded uninspected.
- Compressed bodies requiring Coraza, GraphQL, or LLM inspection return `415`. Decompress at a trusted ingress or send an uncompressed request.
- Coraza phase 2 rules run for every request, including requests without a body.
- The WAF sets `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and `X-Forwarded-Proto` itself. Client-supplied values of these headers and `Forwarded` are dropped. Only a peer inside `trusted_proxy_cidrs`, with `trust_forwarded_for` enabled, can supply the client address chain and the forwarded host and protocol. The inbound `Host` is passed to the upstream unchanged.
- Headers from `inject_request` are set after hop-by-hop processing, so a client cannot strip them through a `Connection` header.
- GraphQL checks apply only under `graphql.paths` (default `/graphql`). Other paths of the tenant are not parsed as GraphQL. The cleaned path is matched too, so `//graphql` does not bypass the control.
- The built-in `llm-protection` rules apply only under `llm_protection.inspect_paths`. When the classifier cannot inspect an input (guard status `400`, `413`, or `422`), `action: deny` answers `422` regardless of `fail_mode`.
- `dev_bypass_secret` must be at least 32 characters, is compared in constant time, skips only Coraza, GraphQL, and LLM inspection, and its `X-Synit-Dev-Bypass` header is never forwarded. The WAF logs a warning for every tenant that sets it. Do not use it in production.
- Block pages loaded from `block_page_path` are read at load time, and the `{{HOST}}` and `{{EVENT_ID}}` values are HTML-escaped.
- Response masking buffers only eligible text, JSON, or XML representations. A response without `Content-Type` is buffered and its type is detected from the content. Encoded, partial, SSE, or oversized mask-required responses fail closed with `502`.
- WebSocket upgrades are supported. For long-lived SSE, keep `global_settings.write_timeout: 0s` and do not configure response masking for that tenant.
- Access logs omit query strings. `WAF rule matched` entries contain the full request URI and the matched data, and headers, bodies handled by optional services, and upstream applications can still contain sensitive data. Protect and retain logs accordingly.

## Optional components

### GeoIP

GeoIP policy uses an operator-supplied MaxMind country database. Set `geoip.db_path`, enable `security.geoip_enabled` for a tenant, and list ISO country codes under `blocked_countries`. Databases without country data, such as ASN databases, are rejected. No database or update mechanism is bundled.

### CrowdSec

CrowdSec-enabled tenants query an external CrowdSec LAPI. Calls are deadline-bounded, and decisions are cached per client IP for `crowdsec.cache_ttl` (default `30s`, `0s` disables the cache). Choose `security_dependency_failure_mode: fail_open` or `fail_closed` deliberately; fail-closed availability contributes to readiness.

### Synit LLM Guard

[`services/synit-llm-guard`](./services/synit-llm-guard/) is the classifier sidecar for `ml` and `hybrid` LLM policies. It requires:

- an operator-selected Hugging Face-compatible binary ONNX text-classification model;
- explicit safe and injection label mapping;
- bearer authentication shared with the WAF;
- private networking or TLS, resource limits, and workload-specific latency/quality evaluation.

The WAF sends at most `sidecar_max_batch` texts per call (default 32) and splits texts longer than `max_text_bytes` (default 8192) into overlapping chunks. The guard splits again into `CHUNK_BYTES` pieces for the model's token window and answers `504` when inference exceeds its deadline. The default WAF `timeout` is `500ms`. No model weights are bundled. Rules-only mode does not require the sidecar.

### AI Logs Receiver

[`services/ai-logs-receiver`](./services/ai-logs-receiver/) is an optional bearer-authenticated sink for WAF log forwarding. It accepts `application/x-ndjson` batches and single `application/json` events, stores bounded tenant-specific daily files, and applies request-rate, storage, and retention limits. Tokens must be at least 32 characters. It exposes `/healthz` and `/readyz`. It is a storage receiver, not an analysis service.

### Rate-limit coordinator

The optional coordinator shares per-tenant, per-client rate-limit checks across replicas. It requires a shared secret and mutual TLS 1.3. Global rate limits, health, circuit-breaker state, caches, and metrics remain process-local.

## Operational endpoints

| Listener | Endpoint | Meaning |
|---|---|---|
| Public | `GET /livez`, `GET /healthz` | Process liveness, answered only when `Host` is not a configured tenant |
| Admin | `GET /livez`, `GET /healthz` | Process liveness |
| Admin | `GET /readyz` | Tenant upstream and required dependency readiness (JSON report) |
| Admin | `GET /metrics` | Prometheus metrics |

On the public listener a request for a tenant host is always proxied, including `/livez` and `/healthz`, so an application's own health endpoint is not shadowed. Point probes at the admin listener, or send a `Host` that is not a tenant (a pod IP works).

The admin listener defaults to `127.0.0.1:9090`. Keep it on a private operations network.

Metrics:

- `synit_waf_http_requests_total{tenant,status_class}` and the histogram `synit_waf_http_request_duration_seconds{tenant}`;
- `synit_waf_blocked_requests_total{source,tenant}` for blocks by control;
- `synit_waf_rule_matches_total{tenant,rule_id}` for matched Coraza rules with the `log` action;
- `synit_waf_audit_mode_events_total{tenant}` for requests that audit mode let through;
- `synit_waf_upstream_requests_total{tenant,upstream,result}` and `synit_waf_upstream_healthy{tenant,upstream}`;
- `synit_waf_config_reload_total{result}`, `synit_waf_log_forward_dropped_total`, and `synit_waf_build_info{version,goversion}`.

## Deployment guidance

- Choose one TLS owner: an external ingress/load balancer or WAF-managed ACME. ACME requires `acme.agree_tos: true`, which records acceptance of the certificate authority's subscriber agreement.
- Preserve the real source address. Trust forwarded headers only from explicit proxy CIDRs.
- Keep configuration and rules read-only; provide separate writable persistent ACME storage when enabled.
- Mount and update the MaxMind database when GeoIP is enabled.
- Keep admin, CrowdSec, LLM guard, log receiver, and coordinator traffic private or encrypted.
- Supply secrets through environment variables or mounted secret files (`*_FILE` variables); never commit them.
- Probe the admin listener for liveness and readiness.
- Pin production images by immutable digest and record the matching configuration/rule revision.
- Aggregate per-process logs and metrics, define retention, and alert on readiness and reload failure.
- Load-test body inspection, response masking, GraphQL parsing, and model inference with representative traffic.
- Exercise fail-open/fail-closed behavior and rollback before production rollout.

See [deployment models](./docs/deployment_models.md) for binary, container, Kubernetes, Swarm, TLS, and multi-replica tradeoffs.

## Known limitations

- No OWASP Core Rule Set is bundled. The repository includes two small example rule profiles. `paranoia_level` only has an effect when you supply CRS. Supply and evaluate the rules your policy requires.
- Rule files under `rules_dir` are not watched. They are read again on the next configuration reload.
- Most state is process-local. The coordinator covers per-tenant rate limiting only.
- Configuration is file-based; there is no control-plane API or database.
- LLM guard accuracy and latency depend on the operator's model and traffic. Audit before using deny mode. The static `llm-protection` rules match a small set of known phrases.
- GeoIP accuracy depends on the operator's database and update cadence.
- Response masking cannot preserve streaming, compressed, ranged, or oversized representations and therefore fails closed when masking is required.
- CrowdSec decisions are cached per client IP for `crowdsec.cache_ttl` (30 seconds by default), so a new ban can take that long to apply. Successful Basic Auth checks are cached for 5 minutes, keyed by the password hash, so changing or removing a credential applies immediately.
- Listeners, server timeouts, logging sinks, ACME account settings, and switching ACME on or off require restart. A tenant added by a reload serves TLS only after its certificate is issued.
- Log forwarding is asynchronous and has no durable retry queue.

## Development

The project uses Go 1.27.0 and contains three Go modules: the WAF plus the two optional services.

```bash
make build            # bin/synit-waf
make vet              # go vet for all three modules
make test             # go test -race ./internal/... ./cmd/...
make test-services    # race tests of both service modules
make lint             # golangci-lint for all three modules
make notices-check    # go run ./tools/thirdparty -check
make validate-examples
make check-links      # relative links in Markdown files
```

Use `make test-e2e-host` for host-based end-to-end tests and `make test-e2e-docker` for the container scenario. See the [developer guide](./docs/developer.md) and [CONTRIBUTING.md](./CONTRIBUTING.md) for the full workflow, commit conventions, and the DCO sign-off.

## Repository layout

- [`cmd/synit-waf/`](./cmd/synit-waf/): runtime entry point
- [`internal/waf/`](./internal/waf/): configuration, policy, proxy, health, and observability
- [`services/synit-llm-guard/`](./services/synit-llm-guard/): authenticated ONNX classifier
- [`services/ai-logs-receiver/`](./services/ai-logs-receiver/): authenticated bounded log receiver
- [`assets/`](./assets/): sample configuration, example rule profiles, API description, and examples
- [`deploy/`](./deploy/): Compose and Kubernetes templates
- [`test/e2e/`](./test/e2e/): cross-component end-to-end tests
- [`tools/thirdparty/`](./tools/thirdparty/): deterministic dependency-notice generator
- [`third_party/`](./third_party/): generated dependency notices and manifest

## Documentation

- [Documentation index](./docs/README.md)
- [Onboarding and quick start](./docs/onboarding.md)
- [Configuration reference](./docs/configuration.md)
- [Use cases](./docs/use-cases.md)
- [Deployment models](./docs/deployment_models.md)
- [Developer guide](./docs/developer.md)
- [Third-party notices](./docs/third_party.md)
- [Releases](https://github.com/synit-io/synit-waf/releases): release notes are generated from the commit history
- [Security policy](./SECURITY.md)
- [Contributing](./CONTRIBUTING.md) and [Code of Conduct](./CODE_OF_CONDUCT.md)

## Community and support

- Discord: <https://www.synit.io/discord> for questions, configuration help, and discussion with maintainers and other operators.
- GitHub issues: defects and feature proposals, using the issue templates.
- GitHub releases: release notes generated from the commit history.

Vulnerabilities go through the private process in [`SECURITY.md`](./SECURITY.md), never through Discord or public issues.

## Maintainers

Synit WAF is developed and maintained by [synit.io](https://www.synit.io). The maintainer team is listed in [`.github/CODEOWNERS`](./.github/CODEOWNERS) and reviews every pull request. See [CONTRIBUTING.md](./CONTRIBUTING.md) if you want to help.

## Security

Report suspected vulnerabilities privately through the process in [`SECURITY.md`](./SECURITY.md). Do not include credentials, production traffic, models, or other sensitive data in public issues.

## License

Synit WAF is open source under the [Apache License, Version 2.0](./LICENSE).
See [NOTICE](./NOTICE) for attribution and
[`third_party/`](./third_party) for the licenses of bundled dependencies.
