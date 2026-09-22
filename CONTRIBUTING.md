# Contributing to Synit WAF

Thank you for improving Synit WAF. This document describes how to set up a development environment, which checks a change must pass, and how to submit it.

## Before you start

- Search the [issue tracker](https://github.com/synit-io/synit-waf/issues) for existing reports or proposals. For questions and configuration help, use the [Discord community](https://www.synit.io/discord).
- For a larger change (a new security control, a configuration schema change, a new dependency), open an issue first so the design can be discussed before code is written.
- Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md) instead.
- Everyone participating in the project is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Set up a development environment

Requirements: Go 1.27.0 or newer, Git, Docker with the Compose plugin, `curl`, `golangci-lint` v2, and `python3`. See the [developer guide](docs/developer.md) for details.

```bash
git clone https://github.com/synit-io/synit-waf.git
cd synit-waf
go mod download
(cd services/ai-logs-receiver && go mod download)
(cd services/synit-llm-guard && go mod download)
make build
```

The repository contains three Go modules (the WAF at the root and the two services under `services/`). Run Go commands inside the module you are changing.

## Make the change

- Keep a pull request focused on one change. Unrelated refactoring belongs in its own pull request.
- Follow the existing code style; `gofmt` output is the standard. Do not add a formatter or linter configuration in a feature change.
- Configuration changes touch `internal/waf/config.go`, `internal/waf/config_validation.go`, tests, `assets/config.sample.yml`, and `docs/configuration.md` together. Rule IDs `440000`-`440099` are reserved for the WAF's own directives.
- Changes to the request pipeline order in `internal/waf/middleware_serve.go` are security behaviour; add tests that prove the new order.
- A dependency change must regenerate the third-party notices (`make notices`) and must not add a GPL, AGPL, or LGPL licensed dependency (`make notices-check` fails otherwise).
- Update the documentation that describes the behaviour you changed in the same commit. There is no changelog file: the commit history is the changelog, so the commit subject must describe the user-visible effect (see below).

## Verify

Run the checks that apply to your change before opening the pull request. CI runs all of them.

```bash
gofmt -l .                # must print nothing
make vet                  # go vet in all three modules
make test                 # go test -race ./internal/... ./cmd/...
make test-services        # race tests of both service modules
make lint                 # golangci-lint in all three modules
make notices-check        # third-party notices are current and licence-clean
make validate-examples    # every sample and example configuration validates
make check-links          # relative links in Markdown files
make test-e2e-host        # host end-to-end tests
make test-e2e-docker      # Docker end-to-end scenario
```

Do not describe a check as passing unless you ran it. Concurrency, cache, or shared-state changes need the race detector.

## Commit messages

The git history is the changelog. The release workflow builds the GitHub release notes from the commits between two tags with `scripts/release-notes.sh`, so every commit must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) and describe the user-visible effect:

```text
fix(waf): run phase 2 rules for requests without a body
feat(config): add health_check.path for HTTP upstream checks
feat(waf)!: rename response_buffer_limit to request_body_limit
security(guard): score every chunk of a long text
docs: describe the two container registries
```

Types: `security`, `feat`, `fix`, `perf`, `refactor`, `docs`, `build`, `ci`, `test`, `revert`, `chore`. Scopes are optional (`waf`, `guard`, `receiver`, `deploy`, `e2e`, `thirdparty`, `config`, `docs`). A change that removes or renames configuration, changes a default, or changes a response code gets `!` and a `BREAKING CHANGE:` footer with the migration step. Use the `security` type for vulnerability fixes; they are listed first in the release notes. Keep one logical change per commit; `AGENTS.md` has the full rules. Preview the notes for a range with:

```bash
git tag -f preview HEAD && ./scripts/release-notes.sh preview v1.0.0; git tag -d preview
```

## Sign off (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) instead of a contributor licence agreement. By signing off a commit you certify that you wrote the change or have the right to submit it under the project licence. Every commit in a pull request must carry a `Signed-off-by` line with your real name and e-mail address:

```bash
git commit -s -m "fix(waf): reject oversize GraphQL batches before parsing"
```

`git commit -s` adds the line from your Git identity (`git config user.name` and `git config user.email`). To add the sign-off to commits you already made, use `git rebase --signoff` or `git commit --amend -s`.

## Licence of contributions

Synit WAF is licensed under the Apache License, Version 2.0 (`LICENSE`). Contributions are accepted under the same licence, inbound equals outbound: by submitting a change you agree that it is licensed under Apache-2.0, as stated in section 5 of the licence. Do not submit code you are not allowed to license this way, and do not copy code from projects under an incompatible licence.

## Open a pull request

1. Create a branch from `main` (or from `dev` when a maintainer asks you to target the development branch).
2. Push the branch and open a pull request against `main`. Fill in the pull request template: what changes, why, how it was tested, and which documentation was updated.
3. Link the issue the pull request addresses.
4. Make sure CI is green. A pull request with failing checks is not reviewed.
5. Respond to review comments with new commits. Before merge, squash fix-up commits so that every remaining commit is a complete Conventional Commit; the commits are what readers of the release notes see.

Maintainers are listed in `.github/CODEOWNERS`; GitHub requests their review automatically.

## Reporting security issues

Report suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not include exploit details in public issues, pull requests, or commit messages until a fix is released.
