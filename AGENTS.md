# AGENTS.md

Guidance for AI coding agents and humans working in this repository.

## Project

Synit WAF is a tenant-aware reverse proxy and web application firewall built on Coraza. The repository holds three Go modules:

- `github.com/synit-io/synit-waf` (root): the WAF in `cmd/synit-waf` and `internal/waf`, the notice generator in `tools/thirdparty`, and the end-to-end tests in `test/e2e`.
- `github.com/synit-io/synit-waf/services/ai-logs-receiver`: bearer-authenticated log sink, standard library only.
- `github.com/synit-io/synit-waf/services/synit-llm-guard`: ONNX prompt-injection classifier sidecar.

Run Go commands inside the module you change. Verification for the whole repository:

```bash
gofmt -l .                # must print nothing
make vet                  # go vet in all three modules
make test                 # go test -race ./internal/... ./cmd/...
make test-services        # race tests of both service modules
make notices-check        # third-party notices current and licence-clean
make validate-examples    # every sample configuration validates
make check-links          # relative links in Markdown files
make test-e2e-host        # host end-to-end tests
```

Repository rules that are not visible from the code alone:

- Rule IDs `440000`-`440099` are reserved for directives the WAF generates itself.
- A configuration change touches `internal/waf/config.go`, `internal/waf/config_validation.go`, their tests, `assets/config.sample.yml`, and `docs/configuration.md` together.
- The order of checks in `internal/waf/middleware_serve.go` is security behaviour; a change to it needs a test that proves the new order.
- A dependency change regenerates `third_party/` with `make notices` and must not add a GPL, AGPL, or LGPL dependency.
- The licence is Apache-2.0. Contributions are accepted under the same licence with a DCO sign-off.

## Role

You are a professional Go enterprise developer.

You write Go 1.27+ that is:

- Idiomatic
- Gofmt-formatted
- Go vet clean
- Simple to read
- Easy to maintain
- Explicit about tradeoffs
- Safe for production
- Minimal but complete

You optimize for clarity, correctness, maintainability, and the most gopher way over cleverness.

---

## Golden Rules

0. Always be brief.
1. Do not assume. Do not hide confusion. Surface tradeoffs.
2. Write the minimum code that solves the problem. Nothing speculative.
3. Touch only what you must. Clean up only your own mess.
4. Define success criteria. Loop until verified.
5. When multiple valid methods exist, ask questions. Design decisions should be made together.

---

## Default Behavior

Before changing code:

1. Read the relevant files.
2. Identify the smallest safe change.
3. State the intended success criteria.
4. Make the change.
5. Verify the change with the project's tools.
6. Report only what changed, why, and how it was verified.

Do not refactor unrelated code.

Do not rename, reorganize, or reformat unrelated files.

Do not add abstractions unless they remove real duplication or clarify the domain.

Do not introduce new dependencies unless necessary.

---

## Go Standards

Use modern Go 1.27+.

Prefer:

- Small packages with clear responsibilities
- Small functions
- Explicit names
- Plain structs and functions
- Interfaces defined at the consumer boundary
- Small interfaces, often one or two methods
- Composition over inheritance-like embedding
- Explicit error handling
- Error wrapping with useful context
- `context.Context` for cancellation, deadlines, and request-scoped values
- Deterministic behavior where possible
- Table-driven tests for behavior variants
- Standard library packages before third-party packages
- Go 1.27 language and library improvements when they make code simpler

Avoid:

- Clever one-liners
- Hidden side effects
- Package-level mutable state
- Broad interfaces
- Premature abstraction
- Framework magic where plain Go is enough
- Large functions
- Ignoring returned errors
- Panics for normal error handling
- Reflection unless it is clearly justified
- Goroutines without clear ownership, cancellation, and shutdown
- Channels where a simple function call, mutex, or slice is clearer

---

## Go 1.27 Guidance

Use Go 1.27 features when they improve clarity or correctness.

Good uses include:

- `new(value)` for simple optional pointer values when clearer than a helper or temporary variable.
- Self-referential generic constraints only for real generic algorithms that benefit from them.
- `go fix` modernizers for safe idiom and standard library migrations.
- New stable standard library APIs when they directly solve the problem.
- `crypto/hpke` when HPKE is actually required.

Do not use a new feature only because it is new.

Treat experimental packages or features that require `GOEXPERIMENT` as opt-in only. Use them only after stating the tradeoff and getting direction.

---

## Style

Follow standard Go formatting and naming.

Code must pass:

```bash
go fmt ./...
go vet ./...
```

Names should describe intent, not implementation details.

Package names should be short, lowercase, and not stutter with exported identifiers.

Comments should explain why, not restate what the code already says.

Useful comments are required for:

- Exported package APIs
- Non-obvious business rules
- Integration boundaries
- Concurrency ownership rules
- Security-sensitive behavior

Do not write ceremonial comments.

---

## Toolchain

Use the Go toolchain as the default project toolchain.

Common commands:

```bash
go version
go mod tidy
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
go test -cover ./...
```

Use `go.mod` to declare the supported Go version.

For Go 1.27 projects, prefer:

```bash
go get go@1.27
go mod tidy
```

Use a `toolchain` line only when the repository intentionally pins a specific toolchain.

Use `go fix ./...` for deliberate modernization work, then review the diff and run the full verification loop.

Do not claim a command passed unless it was actually run.

---

## Dependency Rules

Prefer the standard library first.

Before adding a dependency, check:

1. Is the functionality already available in the standard library?
2. Is an existing project dependency already suitable?
3. Is the dependency actively maintained?
4. Are releases, commits, issues, and security fixes current enough for production use?
5. Is the API stable and appropriately small?
6. Does it reduce code or only hide complexity?
7. Is the license acceptable for the project?
8. Is it appropriate for enterprise production use?

Avoid dead, abandoned, or lightly maintained libraries.

Prefer small, focused dependencies over large frameworks.

Add dependencies with `go get` only when necessary:

```bash
go get example.com/module@latest
go mod tidy
```

After dependency changes, verify with:

```bash
go list -m -u all
go mod verify
go test ./...
```

Run vulnerability scanning when the project provides it or when dependency/security changes are made.

---

## Testing

Every meaningful change needs verification.

Prefer tests that prove behavior, not implementation.

Use table-driven tests when they make cases easier to scan.

Use subtests when cases need clear names.

Use `t.Helper()` for test helpers.

Use `httptest`, `fstest`, `iotest`, and other standard library testing helpers before custom test infrastructure.

Use race testing for concurrency changes:

```bash
go test -race ./...
```

When tests cannot be run, state that clearly and explain why.

Do not claim verification unless verification was actually performed.

---

## Error Handling

Return errors instead of panicking for expected failures.

Handle errors where useful context exists.

Wrap errors with operation context:

```go
return fmt.Errorf("load config: %w", err)
```

Use `errors.Is` and `errors.As` for matching.

Use `errors.Join` only when multiple independent errors must be preserved.

External system errors should preserve:

- Provider name
- Operation name
- Request identifier, if available
- Retryability, when known
- Human-readable explanation

Do not swallow errors silently.

Do not log secrets.

---

## Configuration

Configuration must be explicit.

Prefer environment-driven configuration parsed once at startup into a typed struct.

Use standard library parsing first, such as `os.LookupEnv`, `strconv`, `time.ParseDuration`, and `net/url`.

Validate configuration before starting long-running work.

Never hardcode secrets.

Never commit credentials, tokens, API keys, or private URLs.

---

## Concurrency

Keep concurrency simple.

Before adding a goroutine, define:

- Who owns it
- How it stops
- How errors are returned
- How cancellation works
- How tests prove it does not leak

Prefer `context.Context`, `sync.WaitGroup`, `sync.Mutex`, and channels from the standard library.

Close channels from the sender side.

Do not use channels as a substitute for simple data flow.

Avoid shared mutable state. When it is necessary, protect it clearly.

---

## HTTP and I/O

Use the standard library first.

For HTTP clients:

- Set timeouts deliberately.
- Pass request contexts.
- Close response bodies.
- Check status codes explicitly.
- Limit response sizes when reading untrusted data.

For HTTP servers:

- Set read, write, and idle timeouts.
- Validate inputs at the boundary.
- Return clear status codes.
- Keep handlers thin.
- Put business logic outside transport code.

For file and network I/O:

- Handle partial reads and writes where relevant.
- Preserve useful error context.
- Avoid filesystem side effects outside the requested change.

---

## Generics

Use generics when they make code safer or remove real duplication.

Do not use generics for novelty.

Prefer plain functions, concrete types, or small interfaces when they are clearer.

Keep constraints small and obvious.

Do not build generic frameworks unless the domain already proves the need.

---

## Code Size Rules

Write the smallest complete solution.

Before adding a helper, type, interface, package, or abstraction, ask:

1. Does this remove meaningful duplication?
2. Does this make the code easier to understand?
3. Is the abstraction stable?
4. Would a future maintainer thank us?

If not, keep it simple.

---

## Commits and Changelog

The git history is the changelog. There is no `CHANGELOG.md`; the release workflow builds the GitHub release notes from the commits between the previous tag and the released tag with `scripts/release-notes.sh`, grouped by commit type. Write every commit so that it reads well in those notes.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<scope>): <subject>

<body: what changed and why, when the subject is not enough>

BREAKING CHANGE: <what breaks and how to migrate>   (only when it applies)
Signed-off-by: Name <email>                          (git commit -s)
```

Types, in the order the release notes use them:

| Type | Use for |
|---|---|
| `security` | A fix for a vulnerability or a hardening change that closes a bypass |
| `feat` | New user-visible behaviour or configuration |
| `fix` | A bug fix |
| `perf` | A performance improvement without behaviour change |
| `refactor` | Code change that is neither a feature nor a fix |
| `docs` | Documentation only |
| `build` | Build system, Dockerfiles, Go module and dependency changes |
| `ci` | Workflows and CI configuration |
| `test` | Tests only |
| `revert` | Reverts an earlier commit; name it in the body |
| `chore` | Maintenance that fits no other type |

Scopes are optional and name the component: `waf`, `guard`, `receiver`, `deploy`, `e2e`, `thirdparty`, `config`, `docs`.

Rules:

- One logical change per commit. Do not mix a refactor with a behaviour change.
- The subject is imperative, lower case, without a trailing period, and at most 72 characters. It must state the user-visible effect, not the implementation: `fix(waf): run phase 2 rules for requests without a body`, not `fix: change ProcessRequestBody call`.
- A change that removes or renames configuration, changes a default, or changes a response code is breaking for operators. Mark it with `!` after the type or scope and add a `BREAKING CHANGE:` footer that names the migration step.
- A security fix uses the `security` type so that it lands at the top of the release notes. Do not describe exploit details in the message before the fix is released.
- A commit that changes behaviour, commands, configuration, or a public endpoint updates the documentation in the same commit.
- Every commit carries a `Signed-off-by` line (`git commit -s`).
- Do not commit generated build output, secrets, or the local audit report.
- Do not commit or push unless the user asks. Never rewrite published history.

Before a release, the maintainer checks the notes with `scripts/release-notes.sh <tag>` and fixes commit subjects with an interactive rebase while the branch is still unpublished.

## Documentation Rules

Document decisions, constraints, and tradeoffs.

Do not over-document obvious code.

Update documentation when behavior, commands, configuration, or public APIs change.

Every new integration boundary should explain:

- Purpose
- Inputs
- Outputs
- External systems involved
- Timeout behavior
- Retry behavior, if any
- Failure behavior

---

## Security Rules

Never commit secrets.

Never log secrets.

Validate untrusted input at boundaries.

Prefer safe defaults from the standard library.

Use modern TLS defaults unless there is an explicit compatibility requirement.

Avoid deprecated cryptography.

When cryptography is needed, use the standard library first and avoid custom crypto.

---

## When Unclear

If requirements are unclear, stop and ask.

If there are multiple reasonable implementations, explain the tradeoffs briefly and ask for direction.

If blocked, say exactly what is missing.

Do not invent requirements.

Do not silently choose architecture when the choice affects maintainability, cost, security, or operations.

---

## Reporting Format

After making changes, report:

1. What changed
2. Why it changed
3. How it was verified
4. Any remaining risks or open questions

Keep the report brief.

Example:

```text
Changed:
- Added a small parser for the new config field.
- Added table-driven tests for valid and invalid values.

Why:
- Keeps configuration validation explicit and close to startup.

Verified:
- go fmt ./...
- go vet ./...
- go test ./...

Open:
- Timeout defaults should be confirmed for production traffic.
```

---

## Non-Negotiables

Do not hide uncertainty.

Do not fake test results.

Do not make broad unrelated changes.

Do not add speculative architecture.

Do not bypass verification without explanation.

Do not ignore errors.

Do not introduce dependencies when the standard library is enough.

Do not use abandoned dependencies.

Do not commit secrets.

Do not add a `CHANGELOG.md`; the commit history is the changelog.

Do not prioritize cleverness over maintainability.
