#!/usr/bin/env bash
# Stranded-fix detector.
#
# WHY THIS EXISTS (2026-08-04): a `fix(audit): align macos producer chain hash`
# commit sat on an unmerged drill branch from 2026-06-26 and never shipped. It was
# half the root cause of a HIGH durability defect that took a full session to
# re-diagnose six weeks later. The existing stale-branch report would have listed
# that branch, but "stale branch" is a housekeeping signal nobody actions; a NAMED
# UNSHIPPED FIX is a defect signal. This reports the second thing.
#
# The specific failure mode: a fix authored during a drill has no owner once the
# drill ends. The drill's question gets answered, the branch's job looks done, and
# the fix on it silently never ships. Age-based scanning cannot see that - a
# four-day-old drill branch looks perfectly healthy while already being orphaned.
#
# Report-only. Never deletes, never modifies a branch.
#
# Usage: stranded-fix-report.sh <owner/repo>
#   Requires: git (full history fetched), gh (authenticated).
#   Exits 0 always when it ran correctly; findings go to stdout. Exits non-zero
#   only on its OWN failure, so a broken detector is never mistaken for "clean".

set -euo pipefail

REPO="${1:?usage: stranded-fix-report.sh <owner/repo>}"

# Subjects that denote a correctness/security change worth shipping. Deliberately
# NOT feat( or docs( - an unshipped feature is a product decision, an unshipped
# fix is a defect still in the wild.
FIX_SUBJECT_RE='^(fix|hotfix|harden|sec|security|perf)(\(|:)'

# Branches that are never interesting: the trunk, publishing branches, and bot
# branches (a dependabot branch with no PR is already covered by other tooling).
skip_branch() {
  case "$1" in
    main | master | gh-pages) return 0 ;;
    dependabot/*) return 0 ;;
    *) return 1 ;;
  esac
}

# A branch whose PR MERGED has shipped its work even though a squash-merge leaves
# the original commits unreachable from main. Skipping these is what keeps the
# report small enough to act on. A branch with an OPEN PR is in flight, not
# stranded. Everything else - no PR, or a CLOSED-unmerged PR - is a candidate.
gh pr list --repo "$REPO" --state all --limit 500 \
  --json headRefName,state,number \
  --jq '.[] | "\(.headRefName)\t\(.state)\t\(.number)"' > /tmp/sfr_prs.tsv

pr_state_for() {
  # First match wins; PR list is newest-first, so a re-opened branch reports its
  # most recent PR.
  awk -F'\t' -v b="$1" '$1==b {print $2"\t"$3; exit}' /tmp/sfr_prs.tsv
}

findings=0
findings_body=""

while read -r br; do
  [ -n "$br" ] || continue
  skip_branch "$br" && continue

  state_and_num="$(pr_state_for "$br" || true)"
  state="${state_and_num%%$'\t'*}"
  prnum="${state_and_num##*$'\t'}"

  case "$state" in
    MERGED) continue ;;  # shipped (squash-merge hides the commits)
    OPEN) continue ;;    # in flight
  esac

  # `git cherry` compares by patch-id, so a commit already applied to main under a
  # different sha is marked '-' and skipped. Squash-merges defeat patch-id, which
  # is exactly why MERGED branches are excluded above rather than relied on here.
  while read -r mark sha; do
    [ "$mark" = "+" ] || continue
    subject="$(git log -1 --format=%s "$sha")"
    if printf '%s' "$subject" | grep -qE "$FIX_SUBJECT_RE"; then
      when="$(git log -1 --format=%cs "$sha")"
      if [ -n "$state" ]; then
        why="PR #${prnum} ${state}"
      else
        why="no PR"
      fi
      findings_body="${findings_body}- \`${br}\` (${why}) — \`${sha:0:9}\` ${when} — ${subject}"$'\n'
      findings=$((findings + 1))
    fi
  done < <(git cherry "origin/main" "origin/$br" 2>/dev/null || true)
done < <(git for-each-ref --format='%(refname:short)' refs/remotes/origin |
         sed 's|^origin/||' | grep -v '^origin$' | sort -u)

if [ "$findings" -eq 0 ]; then
  echo "CLEAN"
  exit 0
fi

echo "FINDINGS:${findings}"
printf '%s' "$findings_body"
