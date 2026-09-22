# Synit WAF documentation

Synit WAF is a hostname-aware security reverse proxy. The runtime can inspect and control traffic for multiple applications from one process.

## Start here

- [Project overview](../README.md): purpose, architecture, features, endpoints, and limitations
- [Onboarding guide](./onboarding.md): build and run a local protected service
- [Configuration guide](./configuration.md): YAML schema, environment overrides, and policy reference
- [Use cases](./use-cases.md): practical rollout patterns for web, API, GraphQL, and LLM traffic
- [Deployment models](./deployment_models.md): binary, container, and multi-replica options

## Operate and extend

- [Developer guide](./developer.md): repository setup, build, test, and release workflow
- [Releases](https://github.com/synit-io/synit-waf/releases): notes generated from the commit history between tags
- [Docker Compose templates](../deploy/self-hosted/): self-hosted deployment starting points
- [Log receiver Compose template](../deploy/log-receiver/): WAF with the AI logs receiver
- [Kubernetes templates](../deploy/kubernetes/): multi-replica deployment starting points
- [Docker Swarm example](../assets/examples/cluster/): horizontal scaling example
- [End-to-end tests](../test/e2e/README.md): cross-component test layout

## Optional services

- [AI logs receiver](../services/ai-logs-receiver/README.md): token-authenticated log ingestion
- [LLM guard](../services/synit-llm-guard/README.md): authenticated ONNX prompt-classifier sidecar

## Community

- [Discord](https://www.synit.io/discord): questions, configuration help, and discussion with the maintainers at synit.io
- [Issues](https://github.com/synit-io/synit-waf/issues): defects and proposals

## Legal and dependency information

- [Third-party notices](./third_party.md): dependency attributions and license notices
- [Contributing](../CONTRIBUTING.md): change and verification expectations
- [Code of conduct](../CODE_OF_CONDUCT.md): community standards
- [Security policy](../SECURITY.md): supported versions and private vulnerability reporting

The deployment files are templates. Review image references, secrets, network policy, persistent volumes, TLS ownership, and configuration mounts before production use.
