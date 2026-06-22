# Security Posture and Release Status

Canonical, at-a-glance statement of where the repository stands on release provenance, supply chain, branch protection, and code scanning, plus the open security-debt board. This is the page an external reviewer should read first. Update it whenever any row below changes.

Last updated: 2026-06-17.

This posture reflects the remediation of the independent 2026-06-16 hygiene and security audit (which graded the repository B / 8.1 after the first remediation wave) and the 2026-06-17 follow-up wave that closed the remaining clean-win findings and documented the residue. The remaining open items below are either upstream-blocked, dev-and-build-only (never shipped), drill-gated, or deliberate maintainer-posture choices. Each is disclosed here rather than silently dismissed.

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
- **Dev/build chain (test-and-build only, never installed by consumers):** the advisories that appear in a default `npm audit` (vite, esbuild, vitest) are dev/build-chain. The patched versions exist (vite 7.3.5, vitest 3.2.6) but the bump breaks five tests in the proxy/SSE and context-gate test harness from a vitest 3.2.5+ behavior change, so it is parked rather than force-landed (Dependabot #586, #583). None of these tools is present in the shipped npm package. See the debt board.
- **Menubar (Tauri) native chain:** the Tauri origin-confusion advisory was patched by bumping to `tauri 2.11.1` + `tauri-build 2.6.1` (PR #609, `cargo build`-verified; this surface has no CI build job, so it is verified locally). The `glib 0.20.0` unsoundness advisory (RUSTSEC-2024-0429) is upstream-blocked: `tauri 2.11.1` pins `gtk 0.18.2` which pins `glib ^0.18`, so glib cannot reach 0.20 without an upstream Tauri/GTK-stack release. Tracked, not a vulnerability count.
- **Python sidecar:** `cryptography` is kept current (the one shipped-runtime dependency advisory was patched).
- **SBOM:** generated in CI (`sbom.yml`).

## Branch protection and CI

- `main` is protected by an active ruleset: required status checks (test-baseline-guard, test 22/24, lint, gate-a, parity, e2e, castle-wall-linux-integration, sanctuary-jail-static, CodeQL), required pull request, conversation-resolution required, strict (branches up to date before merge), and deletion plus non-fast-forward blocked.
- **Required approving reviews: 0, by deliberate solo-maintainer decision (2026-06-16).** On a single-maintainer repository GitHub blocks self-approval, so a required-approval rule would either deadlock every merge or be satisfied only by a self-bypass (which is theater). The honest posture is 0 required approvals plus the structural gates above (required CI, strict, conversation-resolution) plus advisory `CODEOWNERS` review-requests. This is a disclosed maintainer-posture choice, not an oversight, and is revisited if a second maintainer joins.
- [`CODEOWNERS`](../../.github/CODEOWNERS) assigns ownership of CI, release, supply-chain, and security-sensitive subsystem paths (advisory review-request).
- All workflows declare explicit least-privilege `permissions:` (read-only by default; OIDC publish scopes only where needed).
- Third-party Actions are pinned by commit SHA (with the version in a trailing comment so Dependabot can still bump them).
- Test baseline is enforced on every commit and PR (local hook plus the CI `test-baseline-guard`); Linux CI is the authoritative count.

## Code scanning (CodeQL)

- CodeQL runs on every PR and push to main.
- The backlog is actively triaged, not tolerated: production findings are fixed, and false positives are dismissed with a recorded per-alert rationale (test fixtures as `used in tests`, deliberate secure patterns as `false positive`, out-of-scope dev tooling and design-reference mockups as `won't fix`). The open code-scanning backlog is currently 0.
- Production correctness classes addressed across the 2026-06-16 and 2026-06-17 remediation: API caught-exception envelopes (no stack or error message reaches a client, including the legacy dashboard 500-paths completed in PR #608), file-custody TOCTOU (descriptor-first reads, atomic writes), injection-detector ReDoS (bounded regexes), and daemon log-injection (control-char sanitization).
- **Fail-PR-on-new-alert** is the one open gate (see debt board): setting the repository code-scanning check-failure threshold plus adding the CodeQL check to the `main` ruleset's required checks is a repository-settings action only the owner can write.

## Secret scanning

- **GitHub secret scanning + push protection are enabled** (the single historical alert was a synthetic test fixture, resolved `used_in_tests` and de-shaped).
- **A repo-local, runnable gitleaks policy now backs this in CI and locally** (PR #610): `.gitleaks.toml` at repo root plus `.github/workflows/secret-scan.yml` (a SHA-pinned `gitleaks/gitleaks-action`, least-privilege `contents: read`, runs on every PR and push to main and fails the job on a finding). A developer can run the same policy before pushing with `npm run secrets:scan` (requires `brew install gitleaks`). The policy keeps all high-signal provider rules on and disables only the `generic-api-key` entropy heuristic, which produced 63-for-63 false findings on the tracked tree (all synthetic fixtures); a tight, evidence-named allowlist covers the known synthetic provider fixtures without blanket-allowlisting any source directory. Wiring the gitleaks job as a required status check is an owner decision (see debt board).

## Security-debt board (accepted risk and tracked follow-ups)

| Item | Status | Rationale |
|---|---|---|
| Dev/build-chain advisories (vite, vitest, esbuild) | Parked (documented) | Patched versions exist (vite 7.3.5, vitest 3.2.6) but the bump breaks five proxy/SSE/context-gate harness tests from a vitest 3.2.5+ behavior change (Dependabot #586). The routine group bump (#583) breaks typecheck via a transitive `@libp2p/interface` type skew. All dev-and-build-only; none ship in the npm package. Deferred pending a focused test-harness fix rather than force-landed. |
| Tauri origin-confusion advisory | Resolved | Patched to `tauri 2.11.1` + `tauri-build 2.6.1` in PR #609, `cargo build`-verified locally (no CI build job covers this surface). |
| glib 0.20.0 unsoundness (RUSTSEC-2024-0429) | Accept (upstream-blocked) | `tauri 2.11.1` pins `gtk 0.18.2` which pins `glib ^0.18`; glib cannot reach 0.20 without an upstream Tauri/GTK-stack release. Transitive in the menubar desktop surface, not the shipped npm runtime. Re-evaluate when Tauri ships a GTK-0.20-compatible release. |
| Issue #567 safe-mode root-owned socket-dir TOCTOU | Partially done (drill-gated) | The boot-guard plist parse is hardened and the severe symlink-redirect escalation is closed; the residual by-name race is non-exploitable in any supported config (0700 operator-owned fortress dir + separate-uid enforcement). The clean relocation to a root-owned socket dir needs a boot drill on the signing host and rides the next Castle Wall macOS drill. |
| Required approving reviews = 0 | Accept (documented decision) | Deliberate solo-maintainer posture (2026-06-16); see Branch protection above. Structural gates (required CI, strict, conversation-resolution) plus advisory CODEOWNERS stand in. Revisited if a second maintainer joins. |
| Markdown-image-exfil detector caps the URL path at 8192 chars | Resolved (widened) | Bound exists only to keep matching linear (ReDoS-safe; pathological 50k input matches in 0.156ms). Widened from 2048 to 8192 in PR #607; the independent secret-pattern scan remains the backstop beyond the cap. |
| `dashboard/multi-server.ts` keeps a private `constantTimeEquals` duplicate | Tracked | Pre-existing duplication; the shared helper now lives in `http/auth.ts`. Consolidation is a cleanup, not a defect. |
| Fail-PR-on-new-CodeQL-alert | Pending (owner) | To be enabled as a repository code-scanning check-failure threshold plus a required-check entry on the `main` ruleset. Owner-only repository settings. |
| gitleaks job as a required status check | Pending (owner) | The gitleaks CI job exists and fails on findings (PR #610); promoting it to a required check on the `main` ruleset is an owner ruleset edit. |

## Reference

This posture reflects two remediation waves of the independent 2026-06-16 hygiene and security audit.

- First wave (2026-06-16): PRs #599 (root scripts, SECURITY.md, secret-fixture de-shape), #600 (legacy URL-token retirement), #601 (workflow least-privilege permissions, SHA-pinned actions, CODEOWNERS), #602 (custody-safe file API), #604 (API error envelopes), #605 (ReDoS, log-injection, constant-time, approval-mutation auth), #606 (this document), #607 (markdown-exfil bound).
- Follow-up wave (2026-06-17): PR #608 (completes the error-envelope sweep on the legacy dashboard 500-paths, ERROR-DETAIL-001), PR #609 (Tauri 2.11.1 origin-confusion patch), PR #610 (runnable gitleaks secret-scanning policy, SECRETS-POLICY-001), and the documentation of the accepted/parked/drill-gated residue above.

Each code change was independently reviewed before merge. This document is an AI-assisted hygiene and posture statement; it is not a substitute for a professional penetration test or formal cryptographic audit.
