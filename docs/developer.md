# Developer guide

This guide covers repository setup, local execution, verification, optional services, continuous integration, and releases.

For runtime setup and policy details, see the [onboarding guide](./onboarding.md) and [configuration guide](./configuration.md). Contribution rules (DCO sign-off, pull request conventions) are in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Prerequisites

- Go 1.27.0 or newer; all three modules declare `go 1.27.0`. CI and the container images use the newest 1.27.x patch release.
- Git
- Docker with the Compose plugin for the container image and the Docker end-to-end test
- `curl` for manual HTTP checks
- `golangci-lint` v2 for `make lint`. CI uses v2.13.2 compiled with the CI Go toolchain (`install-mode: goinstall`), because prebuilt golangci-lint binaries refuse a `go.mod` that targets a newer Go than they were built with. Locally, install it the same way: `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2`.
- `python3` for `make check-links`
- optional: `actionlint`, `kubeconform`, and `shellcheck` to run the asset checks that CI runs

## Repository layout

The repository contains three Go modules:

| Module | Path | Binary |
|---|---|---|
| `github.com/synit-io/synit-waf` | `/` | `synit-waf` (`cmd/synit-waf`) |
| `github.com/synit-io/synit-waf/services/ai-logs-receiver` | `services/ai-logs-receiver` | `ai-logs-receiver` |
| `github.com/synit-io/synit-waf/services/synit-llm-guard` | `services/synit-llm-guard` | `synit-llm-guard` |

There is no `go.work` file; run Go commands inside the module you work on. `tools/thirdparty` belongs to the root module.

- `cmd/synit-waf/`: process entry point and flags
- `internal/waf/`: configuration, request pipeline, proxying, health, logging, and metrics
- `services/ai-logs-receiver/`: log-ingestion service
- `services/synit-llm-guard/`: classifier sidecar
- `tools/thirdparty/`: generator for the third-party notice bundle
- `third_party/`: generated notices and manifest for the WAF binary (each service has its own copy)
- `assets/`: sample configuration, examples, rule profiles, OpenAPI description, Swarm example
- `deploy/`: Compose and Kubernetes templates
- `scripts/`: host and Docker end-to-end runners
- `test/e2e/`: black-box integration tests
- `docs/`: operator and developer documentation; `docs/design/` holds design notes and proposals

## Set up dependencies

Clone the repository and download dependencies without rewriting module files:

```bash
git clone https://github.com/synit-io/synit-waf.git
cd synit-waf

go mod download
(cd services/ai-logs-receiver && go mod download)
(cd services/synit-llm-guard && go mod download)
```

Use `go mod tidy` only when a source or dependency change requires it, then review the `go.mod` and `go.sum` changes and regenerate the third-party notices (see [Third-party notices](#third-party-notices)).

## Build

```bash
make build
./bin/synit-waf -version
```

`make build` runs `CGO_ENABLED=0 go build -trimpath` and injects the version with `-ldflags "-X github.com/synit-io/synit-waf/internal/waf.Version=..."`. The version is `git describe --tags --always --dirty`: the exact tag on a tagged commit, otherwise the last tag plus distance and commit (`v1.0.0-3-gabc1234`), or the commit alone in a repository without tags. Override it with `make build VERSION=v1.2.3`.

Direct builds work as well:

```bash
go build -o bin/synit-waf ./cmd/synit-waf
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/synit-waf-linux-arm64 ./cmd/synit-waf
```

The binary has no cgo dependencies. Build the container image with:

```bash
make docker-build          # synit-waf:local, VERSION from git describe
docker build --build-arg VERSION=v1.0.0 -t synit-waf:local .
```

The root `Dockerfile` copies only `go.mod`, `go.sum`, `cmd/`, `internal/`, `assets/rules/`, `third_party/`, `LICENSE`, and `NOTICE`; `.dockerignore` excludes the rest of the repository. The runtime image is distroless, runs as UID `65532`, installs the binary at `/usr/local/bin/synit-waf`, and carries `LICENSE`, `NOTICE`, and the third-party notices under `/usr/share/doc/synit-waf/`.

## Run locally

Start an upstream service, create a config that maps a hostname to it, and run the WAF on an unprivileged port. The [onboarding guide](./onboarding.md) provides a complete example.

```bash
go run ./cmd/synit-waf -config /absolute/path/config.yml -validate-config
EDGE_WAF_ADDR=127.0.0.1:8080 go run ./cmd/synit-waf -config /absolute/path/config.yml
```

Flags and environment variables:

- `-config`: configuration file path; default `/etc/waf/config.yml`
- `-validate-config`: validate and exit
- `-version`: print version and exit
- `EDGE_WAF_CONFIG`: default configuration path
- `EDGE_WAF_ADDR`: plain HTTP listen address; default `:80`; must differ from `global_settings.admin_address`

The same loader powers startup, reload, and `-validate-config`: it merges sibling `tenants.d` files, rejects duplicate tenants, applies environment overrides and `*_FILE` secrets, sets defaults, and validates the result.

## Test and verify

```bash
make vet               # go vet in all three modules
make test              # go test -race ./internal/... ./cmd/...
make test-services     # go test -race in both service modules
make lint              # golangci-lint in all three modules
make notices-check     # go run ./tools/thirdparty -check
make validate-examples # -validate-config for assets/config.sample.yml and assets/examples/*.yml
make check-links       # relative links and anchors in every *.md file
make test-e2e-host     # ./scripts/run-e2e.sh
make test-e2e-docker   # ./scripts/run-docker-e2e.sh
```

`make test` excludes `test/e2e`; the host end-to-end script runs those tests against a locally started process. The Docker suite builds the current source, proves proxying, rule enforcement, readiness, metrics, and audit mode against a local upstream, and removes its containers on exit.

Do not report a check as passing unless it was run. Concurrency, cache, or shared-state changes must include race testing.

## Configuration changes

When changing the schema:

1. Update types in `internal/waf/config.go`.
2. Add boundary checks in `internal/waf/config_validation.go`.
3. Add table-driven tests for valid and invalid values.
4. Update `assets/config.sample.yml`, the relevant examples, and `docs/configuration.md`; run `make validate-examples`.
5. Verify startup and reload behavior, not only YAML unmarshalling.

Keep environment overrides explicit in `ApplyEnvOverrides`. Invalid overrides must reject the candidate, and the shared `LoadConfig` path must apply them identically at startup and reload. Secrets that may live in a file go through `secretEnv`, which reads `<NAME>_FILE` when `<NAME>` is unset. Rule IDs `440000`-`440099` are reserved for generated directives; a new built-in rule takes the next free ID in that range and is added to the table in `docs/configuration.md`.

## Request-pipeline changes

`ProxyHandler.ServeHTTP` in `internal/waf/middleware_serve.go` runs these stages in order:

1. client IP resolution (`trust_forwarded_for` with `trusted_proxy_cidrs`) and tenant lookup by `Host`;
2. global IP block list, then the allow list is noted;
3. GeoIP country policy of the matched tenant (skipped for allow-listed clients);
4. global rate limit (skipped for allow-listed clients);
5. rejection of unknown hosts with `403`;
6. per-tenant rate limit (skipped for allow-listed clients);
7. JWT validation, then Basic Auth;
8. CrowdSec;
9. Coraza, GraphQL, and LLM inspection (skipped for allow-listed clients and for a valid `X-Synit-Dev-Bypass` header);
10. healthy upstream selection, then the reverse proxy: forwarding headers and request transforms in `Rewrite`, response masking, circuit breaking, and response transforms in `ModifyResponse`.

The access log line and the request metrics are written in a deferred function, so they also cover panics. Order is security behavior: add tests when moving or inserting a control, especially around allow-listed clients and the development bypass header.

## Optional services

### AI logs receiver

The receiver requires `AI_LOG_TOKENS`, a JSON object mapping tenant IDs to bearer tokens of at least 32 characters:

```bash
cd services/ai-logs-receiver
AI_LOG_TOKENS='{"demo":"'"$(openssl rand -hex 32)"'"}' \
LOGS_DIR=./logs \
PORT=8082 \
go run .
```

It exposes `GET /healthz`, `GET /readyz`, and the authenticated `POST /logs` for `application/x-ndjson` batches and single `application/json` events. See its [README](../services/ai-logs-receiver/README.md).

### LLM guard

Run the classifier sidecar with an exported Hugging Face-compatible ONNX model directory:

```bash
cd services/synit-llm-guard
MODEL_PATH=/absolute/path/to/model \
AUTH_TOKEN="$(openssl rand -hex 32)" \
PORT=5001 go run .
```

It exposes `/livez`, `/readyz`, and the bearer-authenticated `POST /v1/detect`. Startup fails without `MODEL_PATH` and `AUTH_TOKEN`. Inference uses Hugot's pure-Go ONNX path, so no ONNX Runtime shared library is required. See its [README](../services/synit-llm-guard/README.md).

## Third-party notices

`tools/thirdparty` generates `third_party/THIRD_PARTY_NOTICES.txt` and `third_party/manifest.json` for the WAF and identical copies under each service directory. It resolves the compiled dependencies of every binary for every released platform (the union of the release matrix, so the result does not depend on the host), identifies each dependency's SPDX licence, and collects the licence and notice files.

```bash
go run ./tools/thirdparty            # regenerate after a dependency change
go run ./tools/thirdparty -check     # CI: fail on drift or a GPL/AGPL/LGPL dependency
go run ./tools/thirdparty -root /path/to/checkout
```

Commit the regenerated files with the dependency change. Details are in [third_party.md](./third_party.md).

## CI

`.github/workflows/ci.yml` runs on pushes to `main` and `dev` and on pull requests. Runs are grouped by head branch so a push and its pull request do not run twice, and a newer run cancels an older one for the same branch. Jobs:

- Lint (Go): `golangci-lint` for all three modules.
- Unit Tests (Go): `gofmt` check, `go vet`, race tests for all three modules, `go mod verify`, `tools/thirdparty -check`, and `govulncheck`.
- Validate Workflows and Deployment Assets: `actionlint`, `kubeconform` for `deploy/kubernetes/`, `shellcheck`, `-validate-config` for every sample and example configuration, `docker compose config` for every Compose file, a YAML parse of `assets/openapi.yaml`, and `make check-links`.
- Build Container Images: builds the three Docker images without pushing and runs `synit-waf -version` in the WAF image.
- E2E (Host) and E2E (Docker).

`.github/workflows/codeql.yml` runs CodeQL for Go on the same branches and weekly. `.github/dependabot.yml` keeps Go modules, Dockerfiles, Compose and Kubernetes image references, and GitHub Actions current. All third-party actions are pinned to a commit SHA; the CodeQL actions use the `v3` tag and are pinned by Dependabot's first update.

## Release workflow

Releases are tag-driven through `.github/workflows/release.yml`.

Before tagging:

1. Review the release notes the workflow will generate. The commit history is the changelog: `scripts/release-notes.sh` groups the Conventional Commits between the previous tag and the new tag by type. Preview them with `git tag -f preview HEAD && ./scripts/release-notes.sh preview; git tag -d preview` and fix commit subjects with an interactive rebase before the branch is published. Commit conventions are in `CONTRIBUTING.md` and `AGENTS.md`.
2. Update every document affected by the release and run `make vet test test-services lint notices-check validate-examples check-links`.
3. Merge the release commit to `main` and wait for CI.
4. Create and push a SemVer tag with a `v` prefix:

```bash
git tag -s v1.0.0 -m "v1.0.0"
git push origin v1.0.0
```

A tag with a pre-release suffix (`v1.1.0-rc.1`) is published as a pre-release. The workflow:

- verifies formatting, modules, tests, `govulncheck`, and the third-party notices on the tagged commit;
- builds multi-architecture (`linux/amd64`, `linux/arm64`) images for `synit-waf`, `ai-logs-receiver`, and `synit-llm-guard` with SBOM and provenance attestations, and pushes them to Docker Hub as `synitio/<image>:X.Y.Z`. A stable release also receives the floating tags `X.Y`, `X`, and `latest` when it is the newest release of that line; a pre-release only gets its exact version. `ghcr.io/synit-io/<image>:latest` is updated only for the newest stable release, and older GHCR versions are pruned. Docker Hub needs the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`;
- builds `synit-waf` binaries for Linux (amd64, arm64, 386, armv7), macOS (amd64, arm64), and Windows (amd64, arm64, 386);
- publishes a GitHub Release whose notes are the grouped commit list plus the image references, together with the binaries, `THIRD_PARTY_NOTICES.txt`, `manifest.json`, `SHA256SUMS`, and a build provenance attestation for the checksums.

`workflow_dispatch` with an existing tag reruns the release for that tag. Rerunning an older tag never moves `latest`. After completion, verify the release notes, assets, image architectures, and tags.
