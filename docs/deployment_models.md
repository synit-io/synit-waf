# Deployment models

Synit WAF is one runtime with file-based configuration. It can run as a local binary, a single container, or several replicas behind a load balancer.

## Common data path

In every model, clients connect to an edge listener. Synit WAF selects a tenant from the `Host` header, applies that tenant's policy, and proxies allowed traffic to a healthy upstream. Configuration, rule files, optional certificate state, logs, and metrics remain operator-owned.

The process has two listeners:

- the public listener (`EDGE_WAF_ADDR`, default `:80`; or the HTTP and HTTPS ports when ACME is enabled) serves tenant traffic. It answers `/livez` and `/healthz` itself only when the request `Host` is not a configured tenant; a tenant `Host` is proxied, including these two paths;
- the admin listener (`global_settings.admin_address`, default `127.0.0.1:9090`) serves `/livez`, `/healthz`, `/readyz`, and `/metrics` for every `Host` and has no authentication.

Point liveness, startup, and readiness probes at the admin listener. Keep it on a private network.

## Container images

Release images are published to Docker Hub as `synitio/synit-waf`, `synitio/ai-logs-receiver`, and `synitio/synit-llm-guard` with the tags `1.0.0`, `1.0`, `1`, and `latest` (no `v` prefix). Versioned tags exist only there. `ghcr.io/synit-io/<image>` carries only the `latest` tag of the newest stable release. Every template in this repository references `synitio/<image>:<version>`; before production, append the digest of the release you deploy (`synitio/synit-waf:1.0.0@sha256:<digest>`) so a moved tag cannot change what runs.

The WAF image is distroless and runs as UID `65532`. The binary is `/usr/local/bin/synit-waf`; `LICENSE`, `NOTICE`, and the third-party notices are under `/usr/share/doc/synit-waf/`. The image contains the example rule profiles under `/etc/waf/rules/profiles/` and empty `/etc/waf/certs/acme` and `/etc/waf/geoip` directories owned by the runtime user. It has no shell and no HTTP client, so container-level health checks must come from the platform (Kubernetes `httpGet` probes, a load balancer, or an external monitor), not from a command inside the container.

The container can run with a read-only root filesystem and without capabilities (binding port `80` as UID `65532` works with Docker's default unprivileged-port setting), but Coraza verifies at startup that it can create a temporary file, so `/tmp` must be writable: mount a `tmpfs` (Compose, Swarm) or an `emptyDir` (Kubernetes) there. All templates in this repository do this.

## 1. Local binary

Use a direct binary for development, evaluation, or a small host-managed installation.

```bash
go build -o bin/synit-waf ./cmd/synit-waf
EDGE_WAF_ADDR=127.0.0.1:8080 \
  ./bin/synit-waf -config /absolute/path/config.yml
```

Benefits:

- shortest edit/build/debug cycle;
- no container runtime dependency;
- direct access to host networking and files.

Tradeoffs:

- process supervision, filesystem permissions, upgrades, and rollback are your responsibility;
- the default listener is `:80`, so use `EDGE_WAF_ADDR` for an unprivileged development port;
- rule files referenced by `Include` are read from `global_settings.rules_dir` (default `/etc/waf/rules`, environment `WAF_GLOBAL_RULES_DIR`); point it at a directory the process can read.

## 2. Single container

Use the root `Dockerfile` or a released image for a small self-hosted edge or a workload managed by another container platform.

```bash
docker run -d --name synit-waf \
  -p 80:80 -p 443:443 -p 127.0.0.1:9090:9090 \
  -e WAF_GLOBAL_ADMIN_ADDRESS=0.0.0.0:9090 \
  -v /absolute/path/config.yml:/etc/waf/config.yml:ro \
  synitio/synit-waf:1.0.0   # pin the digest: synitio/synit-waf:1.0.0@sha256:<digest>
```

Mounting all of `/etc/waf` hides the packaged rule profiles, so mount individual configuration paths unless you provide your own complete directory. If the WAF manages ACME certificates, mount the configuration and rules read-only but provide a separate writable persistent mount for the configured ACME storage path.

The files under `deploy/self-hosted/` are Compose starting points. They expect `config/config.yml` and `config/tenants.d/` beside the Compose file and mount them individually so the image's bundled `/etc/waf/rules` remains visible. `docker-compose.yml` enables ACME and runs a CrowdSec LAPI; `docker-compose-llm.yml` adds the LLM guard. Both run the containers with a read-only root filesystem and without capabilities. Review their upstream networks, secrets, certificate mounts, and image references before use, and supply secrets through `*_FILE` variables that point at mounted secret files (see [Secrets](#secrets)).

`deploy/log-receiver/docker-compose.yml` runs the optional AI Logs Receiver on its own; the WAF's `logging.log_forwarder` points at it.

## 3. Multiple replicas

Run several WAF replicas behind an external load balancer when one process cannot meet availability or throughput requirements.

Required shared decisions:

- distribute the same base configuration, shard files, and rule revision to every replica;
- keep upstream DNS/service discovery consistent;
- aggregate per-process logs and Prometheus metrics;
- choose external TLS termination or shared ACME storage with safe locking semantics;
- expose the admin listener's `/livez` and `/readyz` to the orchestrator on a private network;
- use immutable image digests and rolling updates.

Most request processing is stateless, but caches, active health state, global rate limits, circuit-breaker state, and metrics are process-local. Per-tenant rate limiting is also local unless the optional native RPC coordinator is configured. That coordinator does not distribute the global rate limiter or other runtime state.

### Kubernetes

`deploy/kubernetes/` contains a WAF Deployment (`waf-deployment.yaml`) and a WAF-plus-LLM-guard Deployment (`waf-llm-deployment.yaml`), each with a `LoadBalancer` Service. They are operator-managed examples, not a required service dependency.

Both templates:

- reference `synitio/synit-waf:1.0.0` (and `synitio/synit-llm-guard:1.0.0`); append the digest before use;
- run every container with `runAsNonRoot`, UID `65532`, a read-only root filesystem, no privilege escalation, all capabilities dropped, and the `RuntimeDefault` seccomp profile;
- set CPU and memory requests and limits; adjust them after load testing;
- probe the admin listener (`/livez` for startup and liveness, `/readyz` for readiness) on port `9090`, and the guard's `/livez` and `/readyz` on port `5001`;
- disable the automatic mounting of a service account token.

Before applying them:

- create the referenced `synit-waf-config` ConfigMap with a valid `config.yml`;
- provide the referenced tenant, GeoIP database, and model PVCs plus the `llm-guard` Secret, and the ingress/load-balancer configuration;
- set coordinator roles and addresses consistently, or leave the coordinator disabled;
- add network policies that restrict access to the admin port.

The templates mount `config.yml` with `subPath`; Kubernetes does not update such mounts in place. Roll the Deployment after changing the base ConfigMap. Tenant shards on the referenced PVC remain watchable. Put `GeoLite2-Country.mmdb` on `waf-geoip-pvc` when GeoIP is enabled. The LLM guard shares the pod network, so configure `sidecar_url` with loopback (`http://127.0.0.1:5001/v1/detect`) rather than enabling insecure service URLs globally; the guard token is injected into both containers from one Secret and referenced by the WAF through `sidecar_token_env`.

The example LoadBalancer Services use `externalTrafficPolicy: Local` to preserve the direct client source address. Confirm that behavior with your load-balancer implementation; if another trusted proxy adds forwarded addresses, configure `trust_forwarded_for` and its exact CIDRs instead.

### Docker Swarm

`assets/examples/cluster/` demonstrates a replicated service and upstream. Its stack file is also a template: set the image version and digest, the host bind mounts, routing, and operational controls before production use. The WAF image contains no shell or HTTP client, so health checking belongs at the Swarm ingress or an external load balancer that probes `/livez` with a non-tenant `Host`, or at a monitor on the `operations` network that probes the admin listener.

## TLS ownership

Choose exactly one primary TLS termination model.

### External termination

Terminate TLS at a CDN, ingress, reverse proxy, or cloud load balancer. This is usually simpler for multiple replicas. Configure upstream encryption separately if traffic between the terminator and WAF must also use TLS.

Set `trust_forwarded_for: true` only with the proxy networks in `trusted_proxy_cidrs`. The runtime walks forwarded hops right-to-left and ignores the header when the socket peer is not trusted. The WAF always sets `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Real-IP` towards the upstream; values sent by untrusted peers are dropped.

### WAF-managed ACME

Enable `global_settings.acme` to let CertMagic serve HTTP/HTTPS and obtain certificates for configured tenant domains. Wildcards require the integrated Cloudflare DNS-01 provider. Provide:

- `acme.agree_tos: true`, which records that you accept the certificate authority's subscriber agreement;
- a registration email;
- durable, writable certificate storage;
- DNS and firewall reachability for the selected ACME challenge;
- coordination that prevents independent replicas from issuing against separate ephemeral stores.

Cloudflare DNS-01 is the only DNS provider explicitly integrated. `EDGE_WAF_ADDR` applies to the plain HTTP server path; CertMagic controls the listeners when ACME is enabled. Tenants added by a reload receive certificates in the background; toggling `acme.enabled` requires a restart.

## Configuration distribution

Each instance requires a base `config.yml`. A sibling `tenants.d/` directory can add tenant entries from `.yml` and `.yaml` files; duplicate keys reject the candidate.

The runtime watches the main file and sibling `tenants.d/`. Use an atomic, revisioned deployment process and verify admin `/readyz` after every rollout. Invalid YAML, unknown fields, duplicates, unreadable shards, or dependency construction failures leave the existing runtime active; invalid initial configuration fails startup. On a successful reload every upstream is probed before the new configuration serves traffic, so a reload does not open a window of unknown upstream health.

Hostname keys must be unique across the main file and every shard.

Environment overrides are applied at startup and on every reload. Logging sinks, listener addresses and timeouts, and the ACME account settings remain startup-scoped and require restart.

## Secrets

Keep secrets out of version-controlled YAML. Every secret the WAF needs can come from the environment or from a file named by the `_FILE` variant of the same variable:

- `WAF_CROWDSEC_KEY` / `WAF_CROWDSEC_KEY_FILE`
- `WAF_LOG_FORWARDER_TOKEN` / `WAF_LOG_FORWARDER_TOKEN_FILE`
- `WAF_COORDINATOR_SECRET` / `WAF_COORDINATOR_SECRET_FILE`
- `WAF_GLOBAL_ACME_DNS_TOKEN` / `WAF_GLOBAL_ACME_DNS_TOKEN_FILE`
- the variable named by `llm_protection.sidecar_token_env`, plus its `_FILE` variant

The file variant fits Docker and Swarm secrets (`/run/secrets/<name>`) and mounted Kubernetes Secrets. The plain variable wins when both are set; an unreadable file rejects startup or reload.

## Optional companion services

The WAF can run without either companion service.

- `services/ai-logs-receiver` accepts bearer-authenticated NDJSON or single-event JSON log payloads and stores daily append-only files per tenant ID. Configure tokens of at least 32 characters with `AI_LOG_TOKENS`. It exposes `/healthz` and `/readyz`.
- `services/synit-llm-guard` exposes authenticated `/v1/detect` for `ml` or `hybrid` LLM protection and requires an operator-mounted ONNX model. It exposes `/livez` and `/readyz`.

CrowdSec is an external security dependency rather than a repository service. Configure its LAPI only for tenants that enable CrowdSec.

## Production checklist

- Pin images by digest and record configuration/rule revisions.
- Validate configuration (`synit-waf -validate-config`) and run tests before rollout.
- Start rule changes in audit mode.
- Keep secrets outside version-controlled YAML; use `*_FILE` variables for mounted secrets.
- Restrict source IPs allowed to reach the WAF and the admin listener.
- Define log retention and protect forwarded log data.
- Monitor readiness, blocked requests, audit events, rule matches, reload failures, dropped forwarded logs, and upstream health.
- Test dependency failure modes and rollback.
- Benchmark response masking, body inspection, GraphQL parsing, and sidecar calls with representative payloads.
