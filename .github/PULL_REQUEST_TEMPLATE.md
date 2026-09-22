## What changes

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Why

<!-- The problem this solves, or the behaviour it changes and why the new behaviour is right. -->

## How it was tested

<!-- Which of these did you run? Delete the ones that do not apply. Do not tick a check you did not run. -->

- [ ] `gofmt -l .` prints nothing
- [ ] `make vet`
- [ ] `make test` (race detector)
- [ ] `make test-services`
- [ ] `make lint`
- [ ] `make notices-check` (after a dependency change: `make notices` and the regenerated files are included)
- [ ] `make validate-examples`
- [ ] `make check-links`
- [ ] `make test-e2e-host` / `make test-e2e-docker`
- [ ] manual verification (describe below)

## Documentation and commits

- [ ] `docs/configuration.md` and `assets/config.sample.yml` updated for configuration changes
- [ ] other affected documentation updated
- [ ] Every commit follows Conventional Commits with a subject that describes the user-visible effect, and is signed off (`git commit -s`)
- [ ] Breaking configuration or response changes carry `!` and a `BREAKING CHANGE:` footer
- [ ] not applicable

## Checklist

- [ ] Every commit is signed off (`git commit -s`, Developer Certificate of Origin)
- [ ] The change is licensed under Apache-2.0 like the rest of the project
- [ ] No secrets, credentials, or customer data in code, tests, or fixtures
- [ ] No new rule IDs in the reserved range `440000`-`440099` outside the built-in rule generator
