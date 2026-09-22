# Cluster example (1 to N Synit WAF instances)

This folder shows how to run several Synit WAF replicas in Docker Swarm.

## What has to be shared

Request processing is local to each replica. You can scale from 1 to N replicas when shared inputs and optional dependencies are handled consistently:

- configuration distribution (`/etc/waf/config.yml`)
- CrowdSec LAPI, when enabled (`crowdsec.api_url`)
- centralized logging and metrics
- ACME certificate storage, when ACME is enabled

## Deploy

`swarm-stack.yml` references the Docker Hub image `synitio/synit-waf:1.0.0`. Set the version you want to run and append the image digest (`synitio/synit-waf:1.0.0@sha256:<digest>`) so every node runs the same image. The stack expects `/etc/waf/config.yml`, `/etc/waf/rules`, `/etc/waf/geoip` and `/etc/waf/certs` on every node that runs a replica. Then deploy:

```bash
docker stack deploy -c assets/examples/cluster/swarm-stack.yml synit-waf-cluster
```

## Scale up or down

```bash
# Scale to one instance
docker service scale synit-waf-cluster_synit-waf=1

# Scale to five instances
docker service scale synit-waf-cluster_synit-waf=5
```

## Validate

```bash
# Process liveness. Use a Host that is not a tenant, such as the node address.
curl -i http://<any-swarm-node>/livez

# A tenant request. Replace the host name with one of your tenants.
curl -i -H "Host: api.prod.example.com" http://<any-swarm-node>/
```

On the public listener `/livez` and `/healthz` answer only when the `Host` header is not a configured tenant. With a tenant `Host`, these paths are proxied to the tenant's upstream like any other path. Readiness (`/readyz`) and metrics are available only on the admin listener, port `9090` on the `operations` network.

## Production notes

- Use immutable image digests for deterministic rollouts.
- Keep rule and config updates controlled; all replicas should consume the same revision.
- The WAF watches the main config and `tenants.d/`. Distribute each revision atomically to every replica and check admin readiness after rollout.
- Use rolling updates with `start-first` to minimize downtime.
- Route traffic through an external load balancer/ingress with health checking.
- The published HTTP port uses Swarm host mode to preserve source addresses for GeoIP and IP limits. Run at most one published replica per node and let the external load balancer target those nodes.
- The admin listener is available only on the internal `operations` overlay at port `9090`; attach private monitoring there and never publish that port.
- Do not add shell-based container health checks: the distroless WAF image contains neither a shell nor `wget`/`curl`. Let the external load balancer probe `/livez` with a non-tenant `Host`, or probe the admin listener from the `operations` network.
- Per-tenant rate limits are node-local unless every follower is configured to use one reachable coordinator leader. Global rate limits are always per process.
- The stack mounts the host directory `/etc/waf/rules` over the rule profiles shipped in the image. Copy the profiles you need into that directory, or remove the mount.
- Secrets can be supplied as Swarm secrets: set `WAF_CROWDSEC_KEY_FILE`, `WAF_COORDINATOR_SECRET_FILE`, `WAF_LOG_FORWARDER_TOKEN_FILE` or `WAF_GLOBAL_ACME_DNS_TOKEN_FILE` to the path under `/run/secrets/`. The stack file contains a commented example for the CrowdSec key.
- The service runs with a read-only root filesystem and all capabilities dropped; the image runs as UID `65532`. Bind-mounted directories only need to be readable by that user.
- The included stack mounts `/etc/waf/certs` read-only. Keep ACME disabled for that example, terminate TLS at the ingress, or change the mount to writable shared storage before enabling ACME.
