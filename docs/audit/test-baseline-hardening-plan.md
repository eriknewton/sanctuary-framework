# Sanctuary Test Baseline Hardening Plan

**Context:** During the 2026-04-10 EU AI Act compliance generator build, Claude Code discovered that commit `4ac95830` ("fix: restore loader.ts") had silently broken the test baseline. A single stray token (the `],` absorbed into a line comment inside `src/policy/loader.ts`) caused 10 test files to abort before running. The regression went undetected for a full session cycle because no one ran `npm test` before or after the fix commit landed. Trigger incident technical detail: see `review/commit-4ac95830-postmortem.md`.

**Corrected drift numbers:** the pre-incident true baseline was **1113** passing / 69 test files, not 1079 — tests were added between when 1079 was recorded and the loader.ts break. After the loader.ts break, 1015 were running (59 files). After the 1-line fix in commit `3bc5cc6`, the baseline is back to 1113. The 1079 figure in earlier session notes is stale. This correction matters for the load-bearing nature of the hardening plan: **the silent drift was 1113 → 1015, 98 tests ghosted**, not 64. A failure mode where a "fix" commit causes the passing count to go *up* after the next legitimate change (because parse-broken files come back online) is exactly as dangerous as the count going down, and is why transform-error detection in Step 2 is not optional.

This is the second documented silent baseline drift. The pattern is a compliance liability for any downstream artifact that cites Sanctuary test integrity as evidence of correctness — including the EU AI Act compliance generator itself, which explicitly relies on test-suite integrity as part of its verifiability story.

**Second instance confirmed 2026-04-10:** during the same EU AI Act compliance build session, a second pre-existing baseline drift was found — three unused-import TS6133 errors (`src/wrap/cli.ts:32`, `src/wrap/config-reader.ts:182`, `src/cognitive/memory-attest.ts:20`; paths shown under their current post-rename names) blocking the typecheck gate that the stopgap rule requires. Fixed in a separate minimal commit. The fact that two independent pre-existing drifts surfaced in a single session — one in test collection, one in typecheck — indicates the Sanctuary baseline has been drifting silently across multiple dimensions for some time, and that the hardening plan must treat typecheck and test collection as equally load-bearing gates, not just test-pass counts.

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

---

## 2026-07-18 amendment: the platform-delta carve-out and the inert-hook bug

Two defects were found and fixed while reviewing why the emergency override was
being used routinely rather than exceptionally.

### The guard demanded an accounting that did not exist

On macOS the local passing count always exceeds the Linux floor by the platform
delta: a set of macOS-gated suites run locally and skip on Linux. So
`passing > baseline` is the **normal resting state** on a dev box, not evidence
of new tests.

The fail-above check treated that state as unaccounted drift and told the author
to raise `.test-baseline`. On a commit that stages nothing under `server/` (a
`ROADMAP.md` edit, a dev-script fix) there is no legitimate bump to make: the
Linux floor has not changed, and raising it to the local macOS count sets a floor
Linux can never reach, which breaks CI for everyone. The only way through was
`SKIP_TEST_BASELINE=1`.

That is how a gate stops being a gate. PR #965 alone logged two overrides, both
entirely legitimate, which is precisely the problem: once overriding is the
normal way to commit a docs edit, the override log stops distinguishing routine
work from a real bypass, and the audit trail it exists to provide is noise.

**Fix:** the fail-above demand now applies only when the commit stages something
under `server/` (test files, src, `package.json`, and vitest config can all move
the count). A commit staging nothing there cannot have added a test, so the
excess is platform delta by construction. It warns with the observed delta and
passes, leaving the floor untouched.

**Deliberately not relaxed:** the fail-below regression check still blocks on
every commit; any commit touching `server/` still owes the full accounting; and
the CI mirror is unchanged and still enforces the floor exactly. CI runs on
`ubuntu-latest`, where local equals CI and no delta exists, so it remains the
authority this local hook is only the fast convenience copy of.

### install-hooks installed the hook where git would never run it

In a worktree, `.git` is a file pointing at `<main>/.git/worktrees/<name>`, and
the installer wrote the hook into that directory's `hooks/`. Git does not run
per-worktree hooks: it resolves them against the **common** git dir and honors
`core.hooksPath` above both.

The failure was silent and the wrong way round. `npm run install-hooks` reported
success, wrote a file nothing would execute, and left the worktree running
whatever the main checkout happened to have, or no hook at all on a fresh clone.
Because worktree-per-build is the standard dispatch pattern, build threads that
dutifully installed the hook were unguarded while believing they were protected.

`resolveHooksDir` now asks `git rev-parse --git-path hooks`, which is
authoritative for both `core.hooksPath` and the commondir indirection, with a
commondir-aware pure-path fallback for when git cannot be invoked. The previous
test asserted the per-worktree path and so pinned the bug in place; it is
replaced by a regression test and an end-to-end test against a real git worktree.

**A note on that end-to-end test.** It shells out to real git, which makes it the
one test in the suite that can damage a developer's own repository, and it did:
run inside the pre-commit hook before the environment scrub existed, the
inherited `GIT_DIR` pointed at the Sanctuary repo, so `git init` marked that repo
bare and `git config user.*` overwrote its identity. Every subsequent git command
failed with "must be run in a work tree" until the config was repaired by hand.
No commit or object was affected; the damage was confined to three config keys.

The test is now isolated in three layers: the repo-scoping `GIT_*` variables are
scrubbed, `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` point at `/dev/null` so
config writes cannot reach real files even if the scrub were defeated, and a
containment assertion checks that git agrees the temp directory is its own top
level **before** any mutating command runs. The same scrub is applied in
`resolveHooksDir` itself, where an inherited `GIT_DIR` would otherwise make it
answer for the wrong repository while appearing perfectly healthy.

---

## 2026-08-19: the floor moved to `main`

Everything above stays true about *why* the floor exists. What changed is *who
writes it*.

**The measured problem.** The guard demanded that `.test-baseline` hold the exact
passing count, so a change that added tests had to state the new number in the
same pull request. That number is the count on Linux CI, which an author on macOS
cannot compute: a macOS box legitimately runs more tests than the Linux floor.
Every pull request that added a test therefore guessed, and on 2026-08-19 three
of three open pull requests guessed wrong. The remedy each time was to read the
number out of a failed run and push it back, which is a two-round-trip ritual
that teaches nothing and catches nothing.

**What replaced it.**

| Where | What runs | Authority |
|---|---|---|
| On a pull request | The observed passing count must not be **below** the floor in force, plus the unchanged gates: the suite executed, no transform or collection error, no silent test-file drop, zero failures. A count above the floor passes normally. | read-only |
| On a push to `main` | After the suite runs, the observed count is published to an Actions cache entry scoped to the default branch. No commit, no branch write, no pull request, no ruleset interaction. | none beyond the default token |

The floor in force is the published count when a cached entry is available, and
the committed integer in `.test-baseline` otherwise. That file stays in the tree
as a slow-moving fallback floor which humans update rarely, and it is never
silently preferred: when it is in use the job log says so. A cached count can
only ever RAISE the floor, so an evicted, truncated, stale, or out-of-order entry
fails towards the stricter number rather than weakening one a human committed.

**The mechanism holds no write authority at all.** It needs no ruleset bypass, no
deploy key, no app token, and no elevated actor, because a count travelling
through the Actions cache is not a change to the repository. Cache scope,
verified in this repository rather than assumed: a run triggered by
`pull_request` restores caches created on the default branch. Pull request 1281
restored `node-cache-Linux-x64-npm-7efea387...`, a key that exists under
`refs/heads/main` and not under that pull request's own ref.

**THE HONEST BOUND, and it replaces an earlier claim that was not one.** A pull
request fails when its count is below the floor in force. While a floor is stale
by D, a change can delete up to D passing tests and still pass. Publishing
happens on every push to `main`, so D is normally zero once that run completes,
but it is not zero by construction. Earlier drafts of this document said the
regression property was "unchanged" and that the floor was "at most one merge
behind". Neither is honest if publishing can fail, and both have been removed.

Decision logic lives in `scripts/test-baseline-floor.sh` and is exercised by
`scripts/test-baseline-floor-self-test.sh`, which the guard workflow runs before
it installs anything. An earlier attempt put the same decisions in workflow
steps, where the only way to exercise a branch was to merge it and watch.

**Two shapes were built and discarded before this one**, and both are worth
recording because each failed for a reason the next design had to answer. Having
CI write the integer to the pull request's own branch put a privileged write
downstream of code the proposer controls. Having CI open a pull request carrying
the integer removed that, but a pull request opened with the default token has
its workflow runs held for maintainer approval, so it waited rather than merging,
and a fixed-branch recorder was not convergent under the default concurrency
behaviour. Publishing a number to a cache needs no write at all, which is why it
survives where those did not.

**Failure mode, and the reason it needs its own alarm.** The new failure is
permissive rather than restrictive: if publishing fails or never runs, the floor
in force falls back to the committed integer, which is older, and the gate then
asserts less than it should. It still asserts something, and it says which floor
it used, which is the difference between this and a silent weakening.

**The deliberate-lowering path is still human.** Removing platform-agnostic tests
on purpose goes through an explicitly scoped commit with a written justification
that lowers `.test-baseline`. Because a cached count never lowers the floor, a
deliberate reduction also needs the published entry cleared before it takes
effect (`gh cache delete` on the `baseline-floor-main-count-` entry); after the
merge, the default branch's next run publishes the true lower count. That is a
rare, explicit maintainer action by design, and it is the property that matters:
nothing a pull request contains can lower the floor on its own.

**The residual, stated because it is not closed.** A count is not an inventory. A
change that removes N real tests and adds N trivial ones passes both the old rule
and this one. Closing that needs a base-versus-head comparison of collected test
identities rather than totals; that is separate, larger work and is not claimed
here.
