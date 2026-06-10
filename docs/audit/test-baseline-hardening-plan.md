# Sanctuary Test Baseline Hardening Plan

**Context:** During the 2026-04-10 EU AI Act compliance generator build, Claude Code discovered that commit `4ac95830` ("fix: restore loader.ts") had silently broken the test baseline. A single stray token (the `],` absorbed into a line comment inside `src/policy/loader.ts`) caused 10 test files to abort before running. The regression went undetected for a full session cycle because no one ran `npm test` before or after the fix commit landed. Trigger incident technical detail: see `review/commit-4ac95830-postmortem.md`.

**Corrected drift numbers:** the pre-incident true baseline was **1113** passing / 69 test files, not 1079 — tests were added between when 1079 was recorded and the loader.ts break. After the loader.ts break, 1015 were running (59 files). After the 1-line fix in commit `3bc5cc6`, the baseline is back to 1113. The 1079 figure in earlier session notes is stale. This correction matters for the load-bearing nature of the hardening plan: **the silent drift was 1113 → 1015, 98 tests ghosted**, not 64. A failure mode where a "fix" commit causes the passing count to go *up* after the next legitimate change (because parse-broken files come back online) is exactly as dangerous as the count going down, and is why transform-error detection in Step 2 is not optional.

This is the second documented silent baseline drift. The pattern is a compliance liability for any downstream artifact that cites Sanctuary test integrity as evidence of correctness — including the EU AI Act compliance generator itself, which explicitly relies on test-suite integrity as part of its verifiability story.

**Second instance confirmed 2026-04-10:** during the same EU AI Act compliance build session, a second pre-existing baseline drift was found — three unused-import TS6133 errors (`src/wrap/cli.ts:32`, `src/wrap/config-reader.ts:182`, `src/l1-cognitive/memory-attest.ts:20`; paths shown under their current post-rename names) blocking the typecheck gate that the stopgap rule requires. Fixed in a separate minimal commit. The fact that two independent pre-existing drifts surfaced in a single session — one in test collection, one in typecheck — indicates the Sanctuary baseline has been drifting silently across multiple dimensions for some time, and that the hardening plan must treat typecheck and test collection as equally load-bearing gates, not just test-pass counts.

**Decision:** Enforce the test baseline structurally, not conventionally. Defense in depth across three layers: instruction, pre-commit hook, CI check. All three must be in place before the compliance generator ships to avoid building a legal artifact on a quietly drifting foundation.

**Sequencing:** Execute all three steps **after** the in-flight EU AI Act compliance generator build completes. Do not interleave. The compliance generator is the top P1 ship; the hardening plan protects the next ship.

---

## Step 1 — Instruction update in Sanctuary/CLAUDE.md (2 minutes)

Add the following block near the top of the commit workflow section in `Sanctuary/CLAUDE.md`:

> ### Test baseline enforcement (MANDATORY)
>
> Every commit to main MUST be preceded by a full `npm test` run against a clean working tree. If the passing-test count drops below the recorded baseline in `.test-baseline`, the commit is blocked until the regression is understood and either fixed or the baseline is legitimately updated with a separate commit explaining why.
>
> "I'm just fixing a typo" is how 1079 became 1015. No exceptions apply to agents, automation, or humans. The baseline is the contract with every downstream artifact that cites Sanctuary's test integrity as evidence.

**Owner:** Claude Code session after EU AI Act build completes
**Verification:** grep `test-baseline` in `Sanctuary/CLAUDE.md` after update
**Rollback:** trivial — revert the CLAUDE.md edit

---

## Step 2 — Git pre-commit hook (15 minutes)

Create `.husky/pre-commit` (or equivalent depending on Sanctuary's current hook tooling) with a script that:

1. Reads the baseline count from `.test-baseline` at repo root (single integer, one line)
2. Runs **`npm run typecheck`** and exits non-zero on any typecheck failure. Typecheck is a first-class gate, not an optional add-on — the 2026-04-10 session found three pre-existing TS6133 unused-import errors that a test-only hook would have missed entirely. Typecheck cleanliness is as load-bearing as test-pass count for any downstream artifact citing Sanctuary integrity.
3. Runs `npm test` in silent mode
4. Parses the passing-test count from vitest output
5. If the passing count is less than the baseline, prints a clear error and exits non-zero to block the commit
6. If the passing count is greater than the baseline, prints a warning reminding the author to update `.test-baseline` in a follow-up commit
7. If the passing count equals the baseline, allows the commit

**The commit is blocked if either `npm run typecheck` or `npm test` fails, regardless of which gate fails.** There is no fallback and no fast-path that skips typecheck.

**Also create `.test-baseline` at repo root** containing the current stable baseline number (`1113` as of commit `3bc5cc6`, 2026-04-10 — update at compliance generator merge time if that work legitimately adds tests).

**Additional safeguards in the hook:**

- **Transform-error detection is the most important part of this step, not an optional add-on.** The 2026-04-10 incident was discovered because Claude Code noticed a passing count going *up* after a fix (1015 → 1113) — which is indistinguishable from a normal improvement if you only count passes. A hook that only compares passing counts will happily accept a commit that silently ghosts 98 tests as long as the count doesn't drop. The hook MUST parse for any "transform error", "failed to collect", or "Cannot find module" messages in vitest output and exit non-zero regardless of passing count. This is the structural defense against the exact failure mode that caused the incident.
- Allow a `SKIP_TEST_BASELINE=1` environment variable override for emergency commits, but print a loud warning when it is used. Log the override in `.test-baseline-overrides.log` with timestamp and commit SHA.

**Owner:** Claude Code session after EU AI Act build completes
**Verification:** test the hook by staging an intentionally broken loader.ts change and confirming the commit is blocked
**Rollback:** delete the hook file and `.test-baseline`

**Shell sketch (not final — Claude Code should adapt to Sanctuary's actual hook tooling):**

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${SKIP_TEST_BASELINE:-}" == "1" ]]; then
  echo "⚠️  Test baseline enforcement SKIPPED via SKIP_TEST_BASELINE=1"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $(git rev-parse HEAD 2>/dev/null || echo 'unknown')" \
    >> .test-baseline-overrides.log
  exit 0
fi

if [[ ! -f .test-baseline ]]; then
  echo "❌ .test-baseline file missing. Create it with the current passing count."
  exit 1
fi

BASELINE=$(cat .test-baseline)

# Typecheck gate — must pass before we even run the test suite.
# Added 2026-04-10 after finding 3 pre-existing TS6133 errors that a
# test-only hook would have missed. Typecheck is a first-class gate.
if ! npm run typecheck 2>&1; then
  echo "❌ Typecheck failed. Fix all TS errors before committing."
  exit 1
fi

TEST_OUTPUT=$(npm test 2>&1)

# Detect transform/collect errors (the loader.ts failure class)
if echo "$TEST_OUTPUT" | grep -qE "(transform error|failed to collect|Cannot find module)"; then
  echo "❌ Test suite has transform or collection errors. Fix before committing."
  echo "$TEST_OUTPUT" | grep -E "(transform error|failed to collect|Cannot find module)" | head -20
  exit 1
fi

# Parse passing count from vitest output (adjust regex to match actual vitest format)
PASSING=$(echo "$TEST_OUTPUT" | grep -oE "Tests +[0-9]+ passed" | grep -oE "[0-9]+" | head -1)

if [[ -z "$PASSING" ]]; then
  echo "❌ Could not parse passing-test count from vitest output."
  exit 1
fi

if (( PASSING < BASELINE )); then
  echo "❌ Test baseline regression: expected >=$BASELINE, got $PASSING"
  echo "   Fix the regression or update .test-baseline in a separate explicitly-scoped commit."
  exit 1
fi

if (( PASSING > BASELINE )); then
  echo "⚠️  Passing count ($PASSING) exceeds baseline ($BASELINE). Update .test-baseline in a follow-up commit."
fi

exit 0
```

---

## Step 3 — CI check for test count, not just test success (30 minutes)

Existing CI likely fails on `npm test` exit code, which catches most failures — but not the specific silent-drift failure mode where vitest aborts test files before running them and reports "success" with a lower passing count. Add a CI step that:

1. Runs `npm test` and captures output
2. Parses the passing count
3. Compares against `.test-baseline`
4. Fails the workflow if passing count < baseline, with a clear log message naming the regression size (`"regression: 1079 → 1015, 64 tests missing"`)
5. Additionally fails if vitest emitted any "failed to collect" or "transform error" messages, regardless of exit code

**Implementation target:** add a new job `test-baseline-enforcement` to the existing GitHub Actions workflow (`.github/workflows/ci.yml` or equivalent). This job runs in parallel with the standard test job and is required for merge.

**Owner:** Claude Code session after EU AI Act build completes (same session as Step 2 if time permits)
**Verification:** open a test PR with an intentional drop in test count; confirm CI blocks merge
**Rollback:** remove the new job from the workflow

---

## Acceptance criteria for the hardening plan

All three of the following must be true before the plan is considered complete:

1. `Sanctuary/CLAUDE.md` contains the test baseline enforcement instruction block
2. `.husky/pre-commit` (or equivalent) exists, is executable, and blocks a commit when **either** `npm run typecheck` fails **or** the local test count drops below the recorded baseline; `.test-baseline` exists at repo root with the current stable baseline. Both gates must be tested during hook verification — a typecheck-failing commit attempt and a test-count-dropping commit attempt must each independently produce a blocked commit
3. `.github/workflows/ci.yml` has a `test-baseline-enforcement` job that fails on drop or on transform/collect errors; the job is marked required in branch protection rules (Erik to set required status in GitHub UI)

Once all three pass verification, the EU AI Act compliance generator can cite "Sanctuary test baseline is structurally enforced at 1113+ passing across three layers (instruction, pre-commit, CI), with transform-error detection blocking the silent-ghost failure class" in its evidence provenance documentation. That is a defensible claim under hostile audit.

## Related lineage

- Incident: loader.ts syntax error in commit `4ac95830` (2026-04-09), detected in EU AI Act compliance build session (2026-04-10)
- Fix commit: separate minimal commit following pattern `fix(principal-policy): close tier3_always_allow array accidentally absorbed into comment`
- Wiki decision entry: `Wiki/decisions/sanctuary-test-baseline-enforcement.md`
