---
title: Sanctuary Branch Protection Setup — runbook
date: 2026-04-11
author: Erik Newton
status: runbook
severity: medium-impact, structural-enforcement
audience: repository owner (Erik Newton)
---

# Sanctuary Branch Protection Setup — runbook

**Purpose.** This runbook walks the repository owner through the exact GitHub branch-protection settings required to make the test-baseline guard a hard merge gate, rather than a check that runs but can be ignored. Claude Code cannot set branch protection rules through code; this is a manual click-through Erik executes in the GitHub UI.

**Prerequisites.**

- Commits `26db204a` (pre-commit hook) and `3035a47` (CI workflow) are on `main`.
- The `test-baseline-guard` workflow has run at least once on `main` and succeeded. If it has not, push an empty commit first so GitHub registers the check name.
- Erik has admin access to the `eriknewton/sanctuary-framework` repository.

**Estimated time.** 5 minutes.

---

## Step 1 — Confirm the workflow has run at least once

Before you can name a status check as "required", GitHub must have seen it complete at least once. Verify:

1. Go to `https://github.com/eriknewton/sanctuary-framework/actions`
2. Confirm there is at least one green `Test Baseline Guard` run on `main`. (It should show up automatically on the next push after commit `3035a47` lands.)
3. If no run is visible yet, push an empty commit to trigger it:
   ```bash
   git commit --allow-empty -m "ci: trigger test-baseline-guard registration"
   git push
   ```
4. Wait for the workflow to complete (≈ 1–2 minutes).

Do not proceed to step 2 until you have at least one successful `test-baseline-guard` run recorded in the Actions tab.

---

## Step 2 — Open branch protection settings

1. Go to `https://github.com/eriknewton/sanctuary-framework/settings/branches`
2. Under **Branch protection rules**, click **Add rule** (or **Edit** if a rule for `main` already exists).

---

## Step 3 — Configure the rule

Fill in the form with these exact settings. Items marked **(required)** are hard requirements from the hardening plan; items marked **(recommended)** are best-practice additions that make the guard harder to accidentally bypass.

### Branch name pattern

- Set to `main` — exact branch name match.

### Protect matching branches

- ☑ **Require a pull request before merging** **(required)**
  - ☑ Require approvals: **1** (or higher if you have collaborators)
  - ☑ Dismiss stale pull request approvals when new commits are pushed **(recommended)**
  - ☐ Require review from Code Owners — leave unchecked unless you have a CODEOWNERS file
  - ☐ Restrict who can dismiss pull request reviews — leave unchecked
- ☑ **Require status checks to pass before merging** **(required)**
  - ☑ Require branches to be up to date before merging **(required)** — forces every PR to rebase before merge, which ensures the status checks ran against the actual merge commit, not a stale one
  - In the **Status checks that are required** search box, add each of the following by name (each check must already have completed at least once for GitHub to find it):
    - `test-baseline-guard` **(required)** — the new CI job from commit `3035a47`
    - `test (22)` **(required)** — existing Node 22 test job from `ci.yml`
    - `test (24)` **(required)** — existing Node 24 test job from `ci.yml`

  All three should appear in the required list. If `test-baseline-guard` does not show up, return to step 1 and push an empty commit to trigger a workflow run.
- ☑ **Require conversation resolution before merging** **(recommended)**
- ☑ **Require signed commits** **(recommended)** — raises the bar for agent and tooling commits
- ☐ Require linear history — leave unchecked; merge commits are fine for this repo
- ☐ Require deployments to succeed — leave unchecked; not applicable
- ☐ Lock branch — leave unchecked

### Rules applied to everyone including administrators

- ☑ **Do not allow bypassing the above settings** **(required)**

  This is the critical box. Without it, repository administrators (including Erik) can force-push to main and bypass every other setting. With it, even the repo owner must go through a PR. The whole point of structural enforcement is to remove the "trust me, I'm careful" escape hatch.

- ☐ Allow force pushes — leave unchecked
- ☐ Allow deletions — leave unchecked

---

## Step 4 — Save

Click **Create** (or **Save changes**). GitHub will confirm the rule is active.

---

## Step 5 — Verify

Test the protection by attempting a direct push to `main` from a local clone with a trivial change:

```bash
echo "# verify branch protection" >> README.md
git add README.md
git commit -m "test: verify branch protection blocks direct push to main"
git push origin main
```

Expected result: GitHub rejects the push with an error like:

```
remote: error: GH006: Protected branch update failed for refs/heads/main.
remote: error: Changes must be made through a pull request.
```

If the push succeeds, branch protection is NOT active. Return to step 3 and verify the "Do not allow bypassing" checkbox is set.

After verifying rejection, revert the local change:

```bash
git reset --hard HEAD~1
```

---

## Rollback

To temporarily relax the rule for an emergency:

1. Settings → Branches → `main` rule → Edit
2. Uncheck **Do not allow bypassing** (allows admin bypass)
3. Save
4. Perform the emergency action
5. Immediately re-check **Do not allow bypassing** and save again

Full removal (NOT recommended under any normal circumstance):

1. Settings → Branches → `main` rule → Delete

Document any rollback action in `docs/audit/branch-protection-overrides.log` (create on first use) with timestamp, actor, and one-sentence reason.

---

## Why these exact settings

| Setting | Why |
|---|---|
| Require PR before merging | Blocks direct pushes to main. Every change goes through a PR where the status checks can run, review can happen, and history is auditable. The commit `4ac95830` postmortem calls out "direct pushes to main from any environment" as one of the four specific failure modes the CI layer must catch. |
| Require branches to be up to date before merging | Ensures the status checks ran against the actual merge commit, not a stale commit from N hours ago. Without this, a PR can sit on a stale base, get approved and merged, and the merge commit's behaviour can differ from what CI actually ran against. |
| `test-baseline-guard` required | The CI job that mirrors the pre-commit hook. Fails on typecheck errors, transform/collection errors, silent test file drops, and baseline regressions. This is the authoritative structural defense. |
| `test (22)` and `test (24)` required | The existing CI test matrix. Keeps compatibility coverage across supported Node versions. These already exist in `ci.yml` and are already running — making them required just closes the loophole where a PR could merge while one matrix job was red. |
| Dismiss stale PR approvals on new commits | A reviewer approves at commit A; author pushes commit B that breaks something; without dismissal, the approval from A still counts. This setting forces re-review on every push. |
| Require signed commits | Makes it harder for agents (or attackers) to commit as Erik without his signing key. Not strictly part of the test-baseline hardening but good hygiene for the same reason: structural over conventional. |
| **Do not allow bypassing (applies to admins)** | The load-bearing setting. Without it, all of the above is a convention that admins can override silently. With it, the protection is structural. |

---

## 2026-08-19: the recorded floor goes through the same gate as everything else

The `record-floor` job added on 2026-08-19 (see
[`test-baseline-hardening-plan.md`](./test-baseline-hardening-plan.md)) has to
get one line into `.test-baseline` on `main` after every merge. **It does that by
opening an ordinary pull request, not by pushing.** No ruleset change was needed
and none was made.

**Why that works here.** Read-only inspection of
`repos/eriknewton/sanctuary-framework/rulesets` and the repository settings:

- The `main` ruleset requires a pull request with
  `required_approving_review_count: 0` and no code-owner requirement.
- The repository has `allow_auto_merge: true`, `allow_squash_merge: true`, and
  `delete_branch_on_merge: true`.

So a machine-authored change can satisfy the rules exactly as a person's does:
the recorder pushes a branch, opens a pull request, and enables auto-merge. The
required checks run on it, it merges itself when they pass, and the branch is
cleaned up. **The pull-request requirement and every required check stay intact
for this change too**, which is the property that matters: the recorded floor is
not a privileged write, it is a normal change that happens to be written by CI.

**Considered and rejected: giving the job a bypass.** A ruleset bypass is granted
to an *actor* (a GitHub App, a repository role, a team, or a deploy key) and
applies to the whole ruleset on that branch. It cannot be scoped to a path, a
file, a workflow, or a job. The narrowest version of it would still lift the
pull-request requirement and the required checks for anything holding that token,
which is a much larger grant than "write one line". The pull-request route needs
none of it, so the bypass routes (Actions app, deploy key, personal token) were
all dropped rather than ranked.

**One constraint to confirm before relying on this.** A pull request opened with
the default `GITHUB_TOKEN` does not itself start new workflow runs; that is
GitHub's guard against a workflow triggering itself. If the required checks
therefore never report on the recorded-floor pull request, auto-merge cannot fire
and the pull request waits. The failure is bounded and alarmed rather than
silent: the recorder uses one fixed branch, so at most one such pull request
exists at a time and it always carries the newest count, and the scheduled check
in `.github/workflows/test-baseline-floor-drift.yml` reports a recorded-floor
pull request that stays open past its window. Clearing it needs either a token
whose events start workflow runs, or one human action on the waiting pull
request. Nothing about it can silently weaken the gate.

Failure-mode note for whoever looks at a waiting recorded-floor pull request:
"required checks red" and "required checks never reported" look similar in the
merge box and have opposite causes. Check whether the check runs exist at all
before hunting for a test failure.

---

## Related documents

- [`test-baseline-hardening-plan.md`](./test-baseline-hardening-plan.md) — the three-layer plan this runbook completes
- [`commit-4ac95830-postmortem.md`](./commit-4ac95830-postmortem.md) — the trigger incident
- [`../../CLAUDE.md`](../../CLAUDE.md) — the written instruction layer (stopgap block, updated to reference structural enforcement)
- [`../../.githooks/pre-commit`](../../.githooks/pre-commit) — the local hook mirror
- [`../../.github/workflows/test-baseline-guard.yml`](../../.github/workflows/test-baseline-guard.yml) — the CI mirror

---

_Runbook for Erik Newton. Sanctuary Framework. Apache-2.0._
