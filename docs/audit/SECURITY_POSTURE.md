# Security Posture and Release Status

Canonical, at-a-glance statement of where the repository stands on release provenance, supply chain, branch protection, and code scanning, plus the open security-debt board. This is the page an external reviewer should read first. Update it whenever any row below changes.

Last updated: 2026-06-16.

## Current release

| Field | Value |
|---|---|
| npm `latest` | `@sanctuary-framework/mcp-server@1.4.0` (published 2026-06-16) |
| Git tag | `v1.4.0` (annotated, at the published commit `1554fda1`) |
| GitHub release | `v1.4.0`, marked Latest, with the npm tarball digest in the notes |
| Supported versions | `1.4.x` (full), `1.3.x` (critical fixes, best effort). See [`SECURITY.md`](../../SECURITY.md). |
| Publish flow | npm Trusted Publishing (OIDC), manual `workflow_dispatch`. No static npm token. |

The npm artifact, the git tag, and the GitHub release all bind to the same source commit, so the published package is traceable to source.

## Supply chain

- **Shipped runtime tree: 0 known vulnerabilities.** `npm audit --omit=dev` is clean for both `server/` and `menubar/`. A user who installs the package pulls no known-vulnerable dependency.
- **Dev/build chain:** advisories that appear in a default `npm audit` (vite, esbuild, vitest, tsup, tsx) are test-and-build-only and are never installed by consumers. Volatile dev-chain majors that break the test harness are deferred deliberately rather than force-migrated (see the debt board).
- **Python sidecar:** `cryptography` is kept current (the one shipped-runtime dependency advisory was patched).
- **SBOM:** generated in CI (`sbom.yml`).

## Branch protection and CI

- `main` is protected by an active ruleset: required status checks (test-baseline-guard, test 22/24, lint, gate-a, parity, e2e, castle-wall-linux-integration, sanctuary-jail-static), required pull request, conversation-resolution required, strict (branches up to date before merge), and deletion plus non-fast-forward blocked.
- [`CODEOWNERS`](../../.github/CODEOWNERS) assigns ownership of CI, release, supply-chain, and security-sensitive subsystem paths.
- All workflows declare explicit least-privilege `permissions:` (read-only by default; OIDC publish scopes only where needed).
- Third-party Actions are pinned by commit SHA (with the version in a trailing comment so Dependabot can still bump them).
- Test baseline is enforced on every commit and PR (local hook plus the CI `test-baseline-guard`); Linux CI is the authoritative count.

## Code scanning (CodeQL)

- CodeQL runs on every PR and push to main.
- The backlog is actively triaged, not tolerated: production findings are fixed, and false positives are dismissed with a recorded per-alert rationale (test fixtures as `used in tests`, deliberate secure patterns as `false positive`, out-of-scope dev tooling and design-reference mockups as `won't fix`).
- Production correctness classes addressed in the 2026-06-16 remediation: API caught-exception envelopes (no stack or error message reaches a client), file-custody TOCTOU (descriptor-first reads, atomic writes), injection-detector ReDoS (bounded regexes), and daemon log-injection (control-char sanitization).

## Security-debt board (accepted risk and tracked follow-ups)

| Item | Status | Rationale |
|---|---|---|
| Markdown-image-exfil detector caps the URL path at 2048 chars | Accepted | Bound chosen to eliminate the ReDoS. It is a flag-only heuristic and the independent secret-pattern scan still runs. Widening the bound is free given the non-backtracking structure if broader coverage is wanted. |
| `dashboard/multi-server.ts` keeps a private `constantTimeEquals` duplicate | Tracked | Pre-existing duplication; the shared helper now lives in `http/auth.ts`. Consolidation is a cleanup, not a defect. |
| Issue #567 safe-mode root-owned socket-dir TOCTOU | Partially done | The boot-guard plist parse is hardened; the socket-path coordination remainder is tracked in #567. |
| Dev-chain dependency majors (vite, vitest) | Deferred | Break the test harness; dev-and-build-only, nothing shipped. Deferred via Dependabot major-ignore rather than force-migrated. |
| Fail-PR-on-new-CodeQL-alert | Pending | To be enabled as a repository code-scanning protection setting. |

## Reference

This posture reflects the remediation of the independent 2026-06-16 hygiene and security audit. The remediation landed across PRs #599 (root scripts, SECURITY.md, secret-fixture de-shape), #600 (legacy URL-token retirement), #601 (workflow least-privilege permissions, SHA-pinned actions, CODEOWNERS), #602 (custody-safe file API), #604 (API error envelopes), and #605 (ReDoS, log-injection, constant-time, approval-mutation auth). Each code change was independently reviewed before merge.
