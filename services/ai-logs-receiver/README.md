# AI Logs Receiver

AI Logs Receiver is an optional standalone HTTP service that accepts bearer-authenticated JSON log payloads from Synit WAF and appends them to tenant-specific daily files. It validates that every stored line is JSON but does not analyze logs or manage tokens.

## Configuration

The service uses these environment variables:

- `AI_LOG_TOKENS` is required. It is a JSON object mapping each tenant ID to one static bearer token of at least 32 characters.
- `LOGS_DIR` is the base output directory. Default: `./logs`; the published image sets `/data/ai-logs`.
- `PORT` is the TCP port bound on `0.0.0.0`. Default: `8082`.
- `MAX_REQUEST_BYTES` limits one body. Default: `10485760` (10 MiB).
- `MAX_TENANT_BYTES` caps regular files in one tenant directory. Default: `1073741824` (1 GiB).
- `REQUESTS_PER_MINUTE` is a fixed-window per-tenant request limit. Default: `600`.
- `RETENTION` removes `.log` files older than this Go duration at startup and every six hours. Default: `720h` (30 days).

Example:

```bash
export AI_LOG_TOKENS='{"tenant-a":"replace-with-a-long-random-token","tenant-b":"replace-with-another-long-random-token"}'
export LOGS_DIR='./logs'
export PORT='8082'
go run .
```

Each tenant ID must be a non-empty single path component. Use only a conservative set such as letters, numbers, `_`, and `-`; never use `.` or `..`. Tokens must be unique and at least 32 characters long, for example from `openssl rand -hex 32`; shorter or duplicate token values reject startup.

Changes to `AI_LOG_TOKENS` require a service restart. Keep tokens in a secret manager or protected environment file; do not commit them.

## Connect Synit WAF

The WAF token must match one value in `AI_LOG_TOKENS`:

```yaml
logging:
  log_forwarder:
    enabled: true
    url: "http://ai-logs-receiver:8082/logs"
    token: "replace-with-a-long-random-token"
```

Prefer `WAF_LOG_FORWARDER_TOKEN`, or `WAF_LOG_FORWARDER_TOKEN_FILE` for a mounted secret, over a token in the YAML file. The WAF accepts a plain `http://` receiver URL only for loopback or when `global_settings.allow_insecure_service_urls` is set for a trusted private network.

The WAF forwards its access log and error log as `application/x-ndjson` batches. A batch is sent after 250 ms, 100 events, or 512 KiB, whichever comes first, so normal traffic stays far below the default `REQUESTS_PER_MINUTE`. Forwarding never blocks request handling: the WAF queues at most 1024 events, drops events above 16 KiB, and counts every dropped or rejected event in `synit_waf_log_forward_dropped_total`.

Test directly:

```bash
curl -i http://127.0.0.1:8082/logs \
  -H 'Authorization: Bearer replace-with-a-long-random-token' \
  -H 'Content-Type: application/json' \
  --data '{"message":"receiver test"}'
```

A successful request returns `200 OK`. Missing or malformed authorization returns `401`; an unknown token returns `403`; methods other than `POST` return `405`; invalid bodies return `400`; oversize bodies return `413`; other content types return `415`; rate excess returns `429`; and exhausted tenant storage returns `507`.

## Request format

`POST /logs` accepts two content types; anything else, including a missing `Content-Type`, returns `415`:

- `application/x-ndjson`: a batch with one JSON value per line, lines separated by `\n`. Empty lines are skipped.
- `application/json`: a single JSON value on one line.

Every line must be valid JSON and must not contain raw control characters (bytes below `0x20`, including `\r` and tab); escape them inside JSON strings instead. One invalid line rejects the whole request with `400` and nothing is stored, so a tenant cannot forge additional log lines. A body without any JSON line is also rejected.

`REQUESTS_PER_MINUTE` counts requests, not lines. A request counts once its token, content type, and declared length are accepted and before its body is read, so invalid bodies and slow uploads count too.

## Failed authentication throttle

After 10 failed authentications (`401` or `403`) from one remote IP within one minute, every request from that IP returns `429` until the minute has passed, even with a valid token. The receiver tracks at most 4096 addresses and uses the TCP peer address; it does not read `X-Forwarded-For`, so clients behind one proxy or NAT share a budget.

## Storage layout

For a token assigned to `tenant-a`, the service appends each received JSON line plus a newline to:

```text
<LOGS_DIR>/tenant-a/YYYY-MM-DD.log
```

The date is UTC. Request bodies are read and validated before the tenant lock is taken; writes are then serialized per tenant within one process and synced before success. The per-tenant storage quota is enforced before every write from a usage counter that is read from disk on the tenant's first write and reconciled by each retention sweep. Expired files are removed only by the retention sweep, so a tenant at its quota regains space at the next sweep, not on its next request. The receiver does not encrypt files or coordinate several receiver processes sharing one directory; files changed by anything else are noticed at the next sweep. Use one receiver process per storage directory and still provide backup, disk monitoring, and access controls.

## Health checks

```bash
curl -i http://127.0.0.1:8082/healthz
curl -i http://127.0.0.1:8082/readyz
```

Both endpoints accept `GET` and `HEAD`; other methods return `405` with an `Allow` header.

- `/healthz` returns `200 ok`. It reports process liveness only.
- `/readyz` returns `200 ok` when the receiver can create and remove a file in `LOGS_DIR`, and `503` otherwise, for example when a bind mount is not writable by the image user. The result is cached for five seconds. A failed check is also logged at startup. It does not verify free space.

## Security and deployment notes

- Put the receiver behind TLS or on a private authenticated network. Bearer tokens are reusable credentials.
- Restrict write and read access to `LOGS_DIR`; WAF logs can contain sensitive request metadata.
- Avoid placing secrets in log payloads. The service stores validated JSON lines unchanged.
- Tune built-in request, rate, retention, and storage limits; an ingress limit can add defense in depth.
- Run the service as a non-root user and mount only the required writable log directory.
- The image runs as UID/GID `65532` and writes to `LOGS_DIR=/data/ai-logs`; mount a volume there and make bind-mounted log directories writable by that identity. Point readiness probes at `/readyz` to catch an unwritable directory. The Compose file in [`deploy/log-receiver/`](../../deploy/log-receiver/) uses a named volume with the correct image-owned directory.
- The server uses 10-second read and write timeouts and a 120-second idle timeout.
- SIGINT/SIGTERM trigger a bounded graceful shutdown.

## Container

Release images are published as `synitio/ai-logs-receiver:<version>` on Docker Hub. Pin production deployments by digest. To build from source:

```bash
docker build -t ai-logs-receiver:local .
docker run --rm -p 127.0.0.1:8082:8082 \
  -e AI_LOG_TOKENS='{"tenant-a":"replace-with-a-long-random-token"}' \
  -v ai-logs:/data/ai-logs \
  ai-logs-receiver:local
```

The image is distroless, has no shell, and contains only the static binary.

## Tests

```bash
go vet ./... && go test -race ./...
```
