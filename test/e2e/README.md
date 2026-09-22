# E2E Tests

This folder contains end-to-end cross-component integration tests.

- `e2e_integration_test.go`: core black-box test covering WAF startup, routing, request blocking, phase 2 rules on bodiless requests, audit mode, and the admin endpoints.
- `e2e_tenant_features_test.go`: metrics, header transforms, custom block pages, JWT authentication, rate limiting, hot reload, and development bypass.
- `e2e_security_features_test.go`: IP filtering, response masking, and passive circuit-breaker coverage.
- `e2e_graphql_test.go`: GraphQL transport and policy enforcement, including paths outside `graphql.paths`.
- `e2e_llm_protection_test.go`: authenticated sidecar scores, static rules, cache, and failure mode against a mock guard that validates the request contract.
- `e2e_ai_analyst_test.go`: WAF log forwarding into the AI Logs Receiver as NDJSON batches.

`TestMain` builds the WAF and receiver binaries once. Each WAF process receives separate random public and admin addresses and is stopped with SIGTERM; a process that does not exit cleanly fails the test. Readiness and metrics assertions target the admin listener; application and liveness requests target the public listener.

Run the suite with `make test-e2e-host` or `./scripts/run-e2e.sh`. `./scripts/run-docker-e2e.sh` builds the container image and runs a smaller scenario through Docker Compose.

Package-level unit tests remain colocated with source files in each Go package, which is the standard Go test layout for testing package-internal behavior.
