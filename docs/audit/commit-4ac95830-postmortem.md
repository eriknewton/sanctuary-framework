---
title: Postmortem — commit 4ac95830 landed broken loader.ts on main
date: 2026-04-10
author: Erik Newton
status: draft-for-review
severity: low-impact, high-diagnostic-value
---

# Postmortem — commit `4ac95830` landed broken `loader.ts` on main

## One-paragraph summary

On 2026-04-09 at 15:18 PT, commit `e9c985f` ("feat: memory_attest tool") deleted `server/src/principal-policy/loader.ts` entirely (-377 lines) while adding the `memory_attest` feature. loader.ts had no implementation dependency on memory_attest; the deletion was almost certainly unintentional collateral from whatever file operation produced the commit. Four minutes later, commit `4ac95830` ("fix: restore loader.ts") recreated the file (+377 lines) and added the `memory_attest` entry to `tier3_always_allow`. In the rushed recreation, the closing `],` of the `tier3_always_allow` array was placed on the same line as a trailing `//` comment, absorbing the bracket into the comment. The array never closed. `loader.ts` failed to parse under esbuild; vitest aborted 10 test files during collection; the test baseline dropped from ~1113 passing to 1015 passing. The break was not detected until 2026-04-10 during EU AI Act compliance generator verification, approximately 26 hours after it landed. Fix committed in `3bc5cc6` (2026-04-10) as a 1-character structural correction.

## Evidence

**Commit metadata:**

| Field | e9c985f | 4ac95830 |
|---|---|---|
| Author | Erik Newton <eriknewton@gmail.com> | Erik Newton <eriknewton@gmail.com> |
| AuthorDate | 2026-04-09 15:18:20 -0700 | 2026-04-09 15:22:59 -0700 |
| Trailers | none | none |
| Co-Authored-By | none | none |
| loader.ts | **-377 lines (deleted)** | **+377 lines (new file)** |
| Tests run before commit | unverified | **no (would have caught the parse error)** |

**Diagnostic signature:** the `4-minute gap` between deletion and "restore" is the most revealing signal. A deliberate loader.ts change would not delete the entire file and then immediately restore it. This is the classic fingerprint of an agent or tooling action that ran a write operation on the wrong file, followed by a manual or agent-driven recovery attempt.

**Neither commit has any co-author trailer.** Git metadata alone cannot distinguish "Erik typed this by hand" from "an agent committed as Erik with Git user.name set to Erik." The absence of `Co-Authored-By: Claude ...` does not rule out Claude Code involvement — it only indicates that if an agent produced the commit, it was configured without the attribution trailer. The CLAUDE.md at project root specifies that Claude Code should always add the Co-Authored-By trailer; that instruction was either not active during that session or was not enforced by the harness.

## What tooling/agent produced the commit

**Producer: unverified, most likely Claude Code with trailer config not enforced.**

Git metadata shows both commits authored as "Erik Newton <eriknewton@gmail.com>" with no `Co-Authored-By` trailer. The 4-minute delete-then-restore cadence, the conventional-commits-style commit messages, and the "fix: restore" recovery pattern are all consistent with Claude Code behaviour when the per-session trailer instruction is not active. Alternate candidates (another agent harness, manual typing) are possible but structurally less likely.

Transcript retrieval is **not a blocker** for hardening. The hardening plan below addresses the failure mode (missing pre-commit gate) regardless of which specific agent or tool pipeline produced the commit, so producer identification is a diagnostic nice-to-have, not a prerequisite.

## The gate that was missing

**No pre-commit hook runs `npm test` or `npm run typecheck` before allowing a commit to land locally.** Repository state as of 2026-04-10:

- `.git/hooks/pre-commit.sample` — present (default sample, not activated)
- No `.husky/` directory
- No `package.json` `"husky"` config
- No `lint-staged` config
- `.github/workflows/ci.yml` exists but runs *post-push*, not *pre-commit*

**Consequence:** any broken commit can land locally and be pushed to main before CI has a chance to fail. If no one checks CI status manually, a broken main can persist for hours or days. In this case it persisted for approximately 26 hours undetected.

**Secondary gap:** there is no branch protection rule on `main` (not verifiable from a local clone, but no local config suggests otherwise). Branch protection with "require status checks to pass before merging" would have caught this via the GitHub CI run, but only if the commit went through a PR rather than a direct push.

## 3-step hardening plan

**Step 1 — Install a pre-commit hook that runs `npm test` on every commit to main.** Use `husky` + `lint-staged` or a plain `.git/hooks/pre-commit` shell script. Minimum contract: **every commit to main** must pass `cd server && npm run typecheck && npm test` before the commit is accepted, regardless of which paths the commit touches. Path-scoped hooks (e.g., "only run if `server/src/**/*.ts` changed") are explicitly rejected because the delete-then-restore failure mode that produced this incident would not be caught by a path scope — the "restore" commit appeared as a new file add, not a modification to an existing TS file, and a lenient path scope could miss it. A fast-path variant may run only `npm run typecheck` locally and defer the full test suite to a pre-push hook, but even the fast path must run unconditionally on every commit. **Effort: 10 minutes.** **Catches: today's bug category exactly — any syntax, typecheck, or test failure, without depending on which paths happened to change.**

**Step 2 — Enable GitHub branch protection on `main` requiring CI to pass.** Settings → Branches → Add rule → `main` → require status checks to pass before merging → require `build` and `test` jobs from `.github/workflows/ci.yml`. This adds a server-side enforcement layer so even if the pre-commit hook is bypassed (e.g., `--no-verify` flag, an agent writing commits through the git porcelain directly), main cannot move forward. **Effort: 5 minutes in the GitHub UI.** **Catches: bypassed local hooks, force-pushes, and commits landed without local test runs.**

**Step 3 — Audit agent-produced commits for the Co-Authored-By trailer and the unconditional pre-commit rule.** Update every agent harness configuration that commits to Sanctuary (Claude Code, any Newton Sovereign Agent pipeline, any managed agent) to (a) always emit the `Co-Authored-By: <agent>` trailer so future postmortems can attribute commits in one grep, and (b) refuse to commit without running the test suite first, regardless of whether a git hook is installed. The harness-level enforcement is the defence-in-depth layer behind the git hook. **Effort: 30 minutes across the agent configs.** **Catches: the upstream cause (an agent writing code without testing) rather than just the downstream symptom.**

## Drift pattern

This postmortem documents one incident (loader.ts delete-then-restore, the trigger for the session-long investigation), but the 2026-04-10 session surfaced a **second independent pre-existing drift** on the same repo within hours of the first: three TS6133 unused-import errors in `src/wrap/cli.ts`, `src/wrap/config-reader.ts`, and `src/l1-cognitive/memory-attest.ts` (paths shown under their current post-rename names) that blocked `npm run typecheck` cleanly. The typecheck drift was unrelated to loader.ts in provenance, unrelated in file paths, and almost certainly older — but it was sitting silently in main because nothing was running `npm run typecheck` before accepting commits. The pattern is clear: the Sanctuary baseline has been drifting across *multiple* dimensions simultaneously (test collection integrity *and* typecheck cleanliness), and any audit scope for a legal-adjacent artifact that cites "Sanctuary test integrity" as evidence of correctness must therefore include typecheck cleanliness, not just test-pass counts. A test suite that runs 1113 passing tests on top of a typecheck-failing codebase is not a credible provenance substrate for an EU AI Act compliance artifact. The hardening plan treats typecheck and test-collection as equally load-bearing first-class gates as a direct consequence.

## Residual risk after hardening

- `--no-verify` on manual commits can still bypass Steps 1 and 3. Step 2 (branch protection) is the enforcement that covers this case.
- Step 2 requires commits to flow through PRs. If you routinely push directly to main from your workstation, Step 2 adds friction. Recommendation: accept the friction for Sanctuary specifically, because Sanctuary is the security-critical spine of the Newton stack and broken main there is more expensive than the PR overhead.
- None of these steps prevent an agent from deleting an unrelated file during an unrelated feature commit. That class of error (scope creep in agent file operations) is a separate defence-in-depth concern not addressed by this plan.

## Scope decisions (recorded 2026-04-10)

- **Step 1 (pre-commit hook) and Step 2 (GitHub branch protection):** **Sanctuary-only** for now. The Sanctuary repo is the immediate security-critical spine and the source of the incident. Concordia, Verascore, and Wiki are not in scope for Steps 1–2 at this time.
- **Step 3 (harness trailer + pre-commit test enforcement at the agent level):** **all four repos** (Sanctuary, Concordia, Verascore, Wiki). The harness-level enforcement is a cross-cutting defense and should be uniform across every Erik-owned repo any agent commits into. Follow-up session.
- **Interim stopgap (already landed):** `Sanctuary/CLAUDE.md` carries a MANDATORY one-paragraph commit-discipline block requiring `npm run typecheck && npm test` against a clean working tree before staging any commit. This is the instruction-layer defense holding the line until the pre-commit hook ships.

---

*NOT a security incident. Low blast radius (test baseline drop only, no production impact, no data exposure). Filed as high-diagnostic-value because the root cause is a missing gate that would catch an entire class of future failures at near-zero ongoing cost.*
