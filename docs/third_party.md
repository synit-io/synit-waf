# Third-party notices

Synit WAF distributes the license and notice texts for the dependencies compiled into its three Go binaries. These notices are separate from the project's own license (Apache-2.0, see `LICENSE` and `NOTICE`).

## Generated artifacts

The canonical generated bundle is:

- `third_party/THIRD_PARTY_NOTICES.txt`: complete collected license, notice, patent, copyright, author, and contributor texts.
- `third_party/manifest.json`: deterministic machine-readable coverage, dependency versions, SPDX license identifiers, source file hashes, and the notice hash.

Identical generated copies under each service directory keep the Docker build contexts self-contained:

- `services/ai-logs-receiver/third_party/`
- `services/synit-llm-guard/third_party/`

All three runtime images install the bundle at `/usr/share/doc/synit-waf/third-party/`; the WAF image also carries `LICENSE` and `NOTICE` in `/usr/share/doc/synit-waf/`. Release assets publish the canonical notice and manifest beside the binaries, and both files are included in `SHA256SUMS` and the provenance attestation.

## Coverage

The generator (`tools/thirdparty`) follows compiled package dependencies, not every module retained in a module graph:

| Binary | Module directory | Entry point | Platforms |
|---|---|---|---|
| `synit-waf` | `/` | `./cmd/synit-waf` | every target of the release binary matrix: linux (amd64, arm64, 386, arm), darwin (amd64, arm64), windows (amd64, arm64, 386) |
| `ai-logs-receiver` | `services/ai-logs-receiver` | `.` | the container image platforms linux/amd64 and linux/arm64 |
| `synit-llm-guard` | `services/synit-llm-guard` | `.` | the container image platforms linux/amd64 and linux/arm64 |

For each binary it runs `go list -deps -json` once per platform with `GOOS`/`GOARCH` set and workspace mode disabled, and takes the union of the modules found. The result therefore does not depend on the machine that runs the generator, and a dependency that is compiled only on one platform (for example a Windows-only package) is still covered. The platform list mirrors the matrices in `.github/workflows/release.yml` and is recorded per binary in the manifest's `coverage` entries.

The generator records exact module versions and replacements, de-duplicates dependencies shared by several binaries (`used_by` lists the binaries), and collects notice-like files (`LICENSE*`, `LICENCE*`, `COPYING*`, `NOTICE*`, `PATENTS*`, `COPYRIGHT*`, `AUTHORS*`, `CONTRIBUTORS*`, `UNLICENSE*`) from each dependency's module root. The Go standard library and runtime license and patent grant are included explicitly. Generation fails if a compiled third-party module has no root notice file.

### License identification

Every dependency has a `license` field in the manifest. It holds a single SPDX identifier (for example `Apache-2.0`, `MIT`, `BSD-3-Clause`, `MPL-2.0`) when every license text of the module matches exactly one known license, and `NOASSERTION` when the texts are ambiguous, unknown, or combine several licenses. `NOASSERTION` is not an error; the collected texts are still shipped and must be reviewed by hand.

The artifact contains no timestamp or local module-cache path. Dependencies, consumers, and files are sorted before rendering. Text line endings are normalized, and every collected file is identified by SHA-256.

## Regenerate

Download all three module graphs, then run the generator from the repository:

```bash
go mod download
(cd services/ai-logs-receiver && go mod download)
(cd services/synit-llm-guard && go mod download)
go run ./tools/thirdparty        # or: make notices
```

It writes the canonical bundle and both service copies. Do not edit generated files by hand; commit them together with the dependency change that caused them.

The repository root is found with `git rev-parse --show-toplevel`, then by walking up from the working directory to the `go.mod` of `github.com/synit-io/synit-waf`. Outside a Git checkout, or when running against another checkout, pass it explicitly:

```bash
go run ./tools/thirdparty -root /path/to/synit-waf
```

## Verify

```bash
go run ./tools/thirdparty -check   # or: make notices-check
```

`-check` regenerates the bundle in memory and compares it byte-for-byte with the canonical and service copies; any difference fails. It also fails when a dependency carries a GPL, AGPL, or LGPL license text (any `GPL-*`, `AGPL-*`, or `LGPL-*` identifier, also when the dependency's overall `license` is `NOASSERTION`). Without `-check` the same finding is printed as a warning and the files are still written, so the problem can be inspected. CI and the release workflow run `-check` after `go mod verify`.

## Operator-supplied artifacts

Model files, GeoIP databases, additional WAF rules such as the OWASP Core Rule Set, base images, and other artifacts supplied by an operator are not covered by this Go dependency bundle. Review and distribute their license and notice requirements separately.
