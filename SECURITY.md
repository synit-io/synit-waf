# Security policy

## Supported versions

Security fixes are applied to the latest release and to the `main` branch. Older releases do not receive patches. Upgrade to the newest release after reviewing its release notes.

| Version | Supported |
|---|---|
| latest release (`1.x`) | yes |
| `main` branch | yes, as the base for the next release |
| older releases | no |

## Report a vulnerability

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting: open <https://github.com/synit-io/synit-waf/security/advisories/new> and fill in the form. Do not open a public issue, pull request, or discussion for an undisclosed vulnerability, do not post it in the Discord community, and do not include exploit details in commit messages.

Private vulnerability reporting must be enabled in the repository settings (Settings, Code security, "Private vulnerability reporting") for that link to work. Maintainers: keep it enabled.

Fallback contact for reporters who cannot use GitHub: [https://www.synit.io/.well-known/security.txt](https://www.synit.io/.well-known/security.txt)

Include in the report:

- the affected version, tag, or commit;
- the relevant configuration (with secrets removed);
- reproduction steps or a proof of concept;
- the impact you observed or expect;
- any suggested mitigation.

Remove credentials, customer data, and other secrets from the report.

## What to expect

- Maintainers acknowledge a report within 3 working days.
- The report is investigated and, when confirmed, fixed in a private advisory fork. The reporter is kept informed and may be asked for additional detail.
- A fix is released with a new version, a GitHub Security Advisory, and a `security:` commit that appears at the top of the release notes. Credit is given to the reporter unless they prefer otherwise.
- Response and fix timing depend on severity and reproducibility; critical issues take precedence over other work.

## Scope

In scope: the WAF binary (`cmd/synit-waf`, `internal/waf`), the two companion services (`services/ai-logs-receiver`, `services/synit-llm-guard`), the release container images, and the deployment templates in this repository.

Out of scope: vulnerabilities in operator-supplied rule sets (for example the OWASP Core Rule Set), classifier models, GeoIP databases, or in third-party services such as CrowdSec. Report those to the respective projects. Bypasses of the small example rule profiles under `assets/rules/profiles/` are expected; they are examples, not a complete protection.

For non-sensitive defects and hardening suggestions, use the public issue tracker.
