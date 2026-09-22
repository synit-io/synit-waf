# Onboarding guide

This guide builds Synit WAF, places it in front of a local test service, verifies enforcement, and explains the first production decisions.

## Prerequisites

- Docker Engine with the Compose plugin
- Git
- `curl`
- Go 1.27.0 or newer only if running from source

## Fast verification

The repository includes a self-cleaning containerized end-to-end test:

```bash
git clone https://github.com/synit-io/synit-waf.git
cd synit-waf
./scripts/run-docker-e2e.sh
```

It builds the current source, starts a local upstream, verifies allowed and blocked traffic, checks readiness and Prometheus metrics, restarts the WAF with audit mode enabled, and removes the containers.

## Run a persistent local example

You can build the image from the repository or use a released image. Versioned tags exist only on Docker Hub (`synitio/synit-waf:1.0.0`); pin the digest in production (`synitio/synit-waf:1.0.0@sha256:<digest>`). The commands below build locally.

From the repository root, build the WAF image and create a network:

```bash
docker build -t synit-waf:local .
docker network create synit-waf-demo
docker run -d --name demo-upstream --network synit-waf-demo \
  hashicorp/http-echo:1.0.0 -listen=:5678 -text=upstream-ok
```

Create `config.yml` in the repository root:

```yaml
global_settings:
  log_level: "INFO"
  request_body_limit: 1048576
  write_timeout: "0s"
  admin_address: "0.0.0.0:9090"

waf_rule_sets:
  "starter": |
    SecRule ARGS:test "@contains blockme" "id:110001,phase:1,deny,status:403,log,msg:'Demo rule matched'"

tenants:
  "demo.example.com":
    upstreams:
      - url: "http://demo-upstream:5678"
    security:
      waf_enabled: true
      audit_mode: false
      paranoia_level: 1
      include_rule_sets:
        - "starter"
```

Rule IDs `440000`-`440099` are reserved for the WAF's own directives; use other IDs for your rules, as above.

Start the WAF:

```bash
docker run -d --name synit-waf-demo --network synit-waf-demo \
  -p 8080:80 -p 127.0.0.1:9090:9090 \
  -v "$PWD/config.yml:/etc/waf/config.yml:ro" \
  synit-waf:local
```

The container listens on port `80` for tenant traffic and on the admin address `9090` for liveness, readiness, and metrics. The admin listener is published on loopback only because it has no authentication.

Verify liveness, readiness, allowed traffic, and the demo rule:

```bash
curl -i http://127.0.0.1:9090/livez
curl -i http://127.0.0.1:9090/readyz
curl -i -H 'Host: demo.example.com' http://127.0.0.1:8080/
curl -i -H 'Host: demo.example.com' 'http://127.0.0.1:8080/?test=blockme'
```

Expected results:

- `/livez` on the admin listener returns `200` and `ok`.
- `/readyz` returns `200` with a JSON report once the upstream passed its TCP health check; before that it returns `503` and lists the reason.
- The tenant request returns `upstream-ok`.
- The request containing `test=blockme` returns `403` with a JSON body that carries an `event_id`.

The public listener also answers `/livez` and `/healthz`, but only when the `Host` header is not a configured tenant (`curl -i http://127.0.0.1:8080/livez` works because `127.0.0.1:8080` is not a tenant). With a tenant `Host` these paths are proxied to the upstream. Point orchestrator probes at the admin listener.

Inspect logs and metrics:

```bash
docker logs synit-waf-demo
curl -s http://127.0.0.1:9090/metrics | grep synit_waf
```

The blocked request appears in the application log as `WAF rule matched` (with `rule_id`, `tenant`, `uri`, and `event_id`) followed by `WAF blocked request`, and in the metrics as `synit_waf_blocked_requests_total{source="waf",tenant="demo.example.com"}` and `synit_waf_rule_matches_total{rule_id="110001",tenant="demo.example.com"}`.

Remove the demo resources when finished:

```bash
docker rm -f synit-waf-demo demo-upstream
docker network rm synit-waf-demo
```

## Run from source

Use the same `config.yml`, but change the upstream URL to an application reachable from the host, such as `http://127.0.0.1:5678`. Then run:

```bash
go mod download
go run ./cmd/synit-waf -config "$PWD/config.yml" -validate-config
EDGE_WAF_ADDR=127.0.0.1:8080 \
WAF_GLOBAL_ADMIN_ADDRESS=127.0.0.1:9090 \
  go run ./cmd/synit-waf -config "$PWD/config.yml"
```

`EDGE_WAF_CONFIG` can set the default configuration path. `EDGE_WAF_ADDR` changes the plain HTTP listener and defaults to `:80`. The public and admin addresses must differ.

## Configure your first real tenant

Replace the demo hostname, upstream, and rule set. DNS or the upstream load balancer must send the intended hostname in the HTTP `Host` header because unknown hosts are denied with `403`. Host matching ignores case, the port, a trailing dot, and IPv6 brackets; a `*.example.com` key matches any depth below `example.com`.

For a safe rollout:

1. Start with one low-risk tenant.
2. Set `audit_mode: true` and add only the rules you intend to evaluate.
3. Send representative normal and hostile traffic.
4. Review the `WAF rule matched` log entries, `synit_waf_rule_matches_total`, and `synit_waf_audit_mode_events_total`.
5. Tune false positives, then set `audit_mode: false`.
6. Add the admin listener's `/livez`, `/readyz`, and `/metrics` to monitoring.

The repository contains example configurations under `assets/examples/`; every file there passes `-validate-config`. Treat them as starting points and review every rule before production use. No OWASP Core Rule Set is bundled; `paranoia_level` only has an effect once you add CRS under `global_settings.rules_dir`.

## Secrets

Do not write bouncer keys, tokens, or the coordinator secret into `config.yml`. Set them through the environment, or point the `_FILE` variant at a mounted secret file:

| Setting | Environment variable | File variant |
|---|---|---|
| `crowdsec.api_key` | `WAF_CROWDSEC_KEY` | `WAF_CROWDSEC_KEY_FILE` |
| `logging.log_forwarder.token` | `WAF_LOG_FORWARDER_TOKEN` | `WAF_LOG_FORWARDER_TOKEN_FILE` |
| `global_settings.coordinator.secret` | `WAF_COORDINATOR_SECRET` | `WAF_COORDINATOR_SECRET_FILE` |
| `global_settings.acme.dns_token` | `WAF_GLOBAL_ACME_DNS_TOKEN` | `WAF_GLOBAL_ACME_DNS_TOKEN_FILE` |
| `llm_protection.sidecar_token` | the variable named by `sidecar_token_env` | the same name plus `_FILE` |

With Docker Compose or Swarm secrets, mount the secret and set for example `WAF_CROWDSEC_KEY_FILE=/run/secrets/crowdsec_key`. With Kubernetes, either inject the variable from a `Secret` or mount the `Secret` and use the `_FILE` variable.

## TLS choice

Choose one TLS owner:

- Terminate TLS at an ingress, load balancer, or CDN and send HTTP or HTTPS to the WAF.
- Enable `global_settings.acme` so CertMagic obtains certificates for the configured domains.

When ACME is enabled, set `acme.agree_tos: true` (you accept the certificate authority's subscriber agreement), provide an email, and mount persistent writable certificate storage at `storage_path`. Do not run several replicas against independent ephemeral ACME storage. Cloudflare DNS-01 is the only DNS provider wired into the runtime and is required for wildcard tenants. Tenants added later by a reload get their certificates in the background; switching `acme.enabled` on or off needs a restart.

## Production checks

- Enable `trust_forwarded_for` only with explicit `trusted_proxy_cidrs`; forwarded headers from other peers are dropped and the WAF sets `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` itself.
- Keep the default `write_timeout: 0s` for long-lived SSE, and do not enable response masking on an SSE tenant. WebSocket upgrades are supported.
- Send uncompressed bodies when Coraza, GraphQL, or LLM request inspection applies; encoded inspected bodies return `415`.
- Use bcrypt hashes for Basic Auth; never store plaintext passwords in configuration.
- Leave `dev_bypass_secret` empty in production. When set it must have at least 32 characters, and the WAF logs a warning on every start and reload.
- Decide whether CrowdSec, GeoIP, and LLM sidecar failures should fail open or fail closed.
- Keep the dedicated admin listener private and probe it from the orchestrator.
- Mount configuration read-only and certificate storage read-write.
- Pin container images by digest instead of mutable tags such as `latest`; versioned tags exist only on Docker Hub.
- Run rule changes in audit mode before enforcement.

Continue with the [configuration guide](./configuration.md), [use cases](./use-cases.md), and [deployment models](./deployment_models.md).
