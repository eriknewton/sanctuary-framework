#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: scripts/verify-fail-before.sh <base-ref>" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

BASE_REF="$1"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

trim_ws() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# INVARIANT: the two reasons being compared are normalized identically, because
# the comparison decides whether an exemption was re-asserted. Leading and
# trailing whitespace is trimmed and internal runs are collapsed, so a cosmetic
# re-spacing of the reason cannot pass as a fresh assertion. A trailing space is
# invisible under GitHub's "Hide whitespace changes", so a comparison that
# honored it would let a re-assertion nobody can see in review stand as one.
normalize_reason() {
  local value
  value="$(printf '%s' "$1" | tr -s '[:space:]' ' ')"
  trim_ws "$value"
}

# The marker window is the first 30 lines of a test file. Prints the trimmed
# reason and returns 0 when a marker is present (the reason MAY be empty; the
# caller decides whether that is an error), 1 when the window carries none.
#
# INVARIANT: both sides of the base-vs-HEAD comparison below read through THIS
# function. A second, hand-written parser for the base side is how the two sides
# would drift about where the window ends or how whitespace is trimmed, and a
# drifted parser reads as "the reason changed", which exempts.
marker_reason_from_stdin() {
  local line=""
  local trimmed=""
  local reason=""
  local line_no=0

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_no=$((line_no + 1))
    if [[ "$line_no" -gt 30 ]]; then
      break
    fi
    trimmed="$(trim_ws "$line")"
    case "$trimmed" in
      "// fail-before-exempt:"*)
        reason="$(trim_ws "${trimmed#// fail-before-exempt:}")"
        printf '%s\n' "$reason"
        return 0
        ;;
    esac
  done

  return 1
}

exemption_reason_for_test_file() {
  local test_file="$1"
  local reason=""
  local status=0

  set +e
  reason="$(marker_reason_from_stdin < "$test_file")"
  status=$?
  set -e

  if [[ "$status" -ne 0 ]]; then
    return 1
  fi
  if [[ -z "$reason" ]]; then
    echo "FAIL: fail-before-exempt marker in $test_file has an empty reason; use // fail-before-exempt: <non-empty reason>." >&2
    return 2
  fi
  printf '%s\n' "$reason"
  return 0
}

# Resolves the path this file occupied at the merge base. Falls back to the
# file's own path, which is the answer for everything that was not renamed.
#
# INVARIANT: a rename must be paired before the base version is read. A
# pathspec-limited diff cannot pair a rename source, so a renamed file reads as
# wholly added and its INHERITED marker would read as introduced here. Failure
# mode from the outside: one directory reorg re-asserts every inherited
# exemption in the tree at once, and GitHub renders the move as `old -> new`
# with the marker line not highlighted at all, so there is nothing to review.
# A COPY is deliberately not paired: the copied path is genuinely new and its
# marker renders as an added line in review, which is the reviewable artifact
# this gate is asking for.
#
# BOUND (do not read the invariant above as total): pairing is only as good as
# git's own similarity detection. A rename combined with a rewrite of roughly
# half the file is not detected as a rename AT ANY `-M` threshold, so the moved
# file reads as an addition and its inherited marker exempts the new path. What
# keeps that honest rather than silent is the same fact that causes it: because
# git cannot pair it either, review renders a delete plus an add and the marker
# IS visible as added text. So the failure mode is a reviewer who does not look,
# not a gate that hides the line.
base_path_for_test_file() {
  local head_path="$1"
  local i=0
  while [[ "$i" -lt "${#RENAME_NEW_PATHS[@]}" ]]; do
    if [[ "${RENAME_NEW_PATHS[$i]}" == "$head_path" ]]; then
      printf '%s' "${RENAME_OLD_PATHS[$i]}"
      return 0
    fi
    i=$((i + 1))
  done
  printf '%s' "$head_path"
}

# INVARIANT: an exemption is a PER-CHANGE assertion, never a permanent property
# of a file. The marker exempts only the change that introduces or restates it,
# so a marker inherited unchanged from the merge base does not exempt this
# change's edits to the same file.
#
# The test is a CONTENT comparison: the marker reason at the merge base against
# the reason at HEAD, read through the same window by the same parser. It never
# looks at diff text, and that is the point. A diff-shaped test ("was a marker
# line added in this range?") is satisfiable three ways a reviewer cannot see:
# by a rename (the pathspec-limited diff cannot pair the source, so the whole
# file reads as added), by a marker-shaped line added anywhere ELSE in the file
# (so the line that proves re-assertion is not the line whose reason is consumed
# and logged), and by a trailing space on the marker line (which vanishes under
# "Hide whitespace changes"). Requiring the REASON itself to change makes
# re-assertion a real edit that shows up as changed text.
#
# This exists because the file-scoped version caused a proven silent miss. A
# marker written for one test in `server/test/mesh/lifecycle.test.ts` exempted
# that whole file permanently; a later security PR changed 86 lines of it
# alongside six other changed test files, the siblings satisfied the gate, and
# those 86 lines went mechanically unverified with NO signal at all. The loud
# failure (a change whose only edited test file is the exempt one) is the lucky
# case; the silent one is the dangerous one.
#
# Failure mode from the outside: an inherited marker now prints
# `INHERITED-EXEMPTION-IGNORED` and the file is verified normally. If that
# genuinely must not happen, restate the marker with a reason that describes
# THIS change, or use SKIP_FAIL_BEFORE with a reason, which is logged.
marker_is_asserted_by_this_change() {
  local test_file="$1"
  local head_reason="$2"
  local base_path=""
  local base_blob=""
  local base_reason=""
  local show_status=0
  local parse_status=0

  base_path="$(base_path_for_test_file "$test_file")"

  # No counterpart at the merge base (a genuinely new file, or a rename whose
  # source is itself new): a marker here cannot have been inherited.
  if ! git cat-file -e "$MERGE_BASE:$base_path" 2>/dev/null; then
    return 0
  fi

  # The blob is captured whole rather than piped into the parser. The parser
  # stops at the first marker, so a pipe would leave `git show` writing into a
  # closed pipe; with `pipefail` set at the top of this script, that SIGPIPE
  # (141) would propagate and be read as "no marker at the base", which exempts.
  # It only bites once a file exceeds the pipe buffer, so the marker's meaning
  # would silently depend on file size.
  set +e
  base_blob="$(git show "$MERGE_BASE:$base_path" 2>/dev/null)"
  show_status=$?
  set -e

  # The base version exists but could not be read. Fail closed: treat the marker
  # as inherited, which routes the file to normal verification.
  if [[ "$show_status" -ne 0 ]]; then
    return 1
  fi

  set +e
  base_reason="$(marker_reason_from_stdin <<<"$base_blob")"
  parse_status=$?
  set -e

  # No marker at the base: this change introduced it.
  if [[ "$parse_status" -ne 0 ]]; then
    return 0
  fi

  # Present at both. Only a CHANGED reason is a fresh assertion; an identical
  # reason is the inherited one wearing a new commit.
  [[ "$(normalize_reason "$base_reason")" != "$(normalize_reason "$head_reason")" ]]
}

record_file_exemption() {
  local test_file="$1"
  local reason="$2"
  # merge_base is recorded alongside base_ref because the merge base, not the
  # base branch tip, is the commit the exemption was judged against; an audit
  # reader who cannot see which commit the reason was compared to cannot check
  # the decision.
  printf '[%s] fail-before-exempt file=%s base_ref=%s merge_base=%s branch=%s head=%s actor=%s reason=%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "$test_file" \
    "$BASE_REF" \
    "$(git rev-parse --short "$MERGE_BASE")" \
    "$(git branch --show-current 2>/dev/null || echo unknown)" \
    "$(git rev-parse --short HEAD)" \
    "${GITHUB_ACTOR:-${USER:-unknown}}" \
    "$reason" >> .fail-before-overrides.log
}

if [[ "${SKIP_FAIL_BEFORE:-}" == "1" ]]; then
  REASON="${SKIP_REASON:-${FAIL_BEFORE_SKIP_REASON:-}}"
  if [[ -z "$REASON" ]]; then
    echo "SKIP_FAIL_BEFORE=1 requires SKIP_REASON or FAIL_BEFORE_SKIP_REASON." >&2
    exit 2
  fi
  {
    printf '[%s] SKIP_FAIL_BEFORE=1\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  base_ref: %s\n' "$BASE_REF"
    printf '  branch: %s\n' "$(git branch --show-current 2>/dev/null || echo unknown)"
    printf '  head: %s\n' "$(git rev-parse --short HEAD)"
    printf '  actor: %s\n' "${GITHUB_ACTOR:-${USER:-unknown}}"
    printf '  reason: %s\n' "$REASON"
  } >> .fail-before-overrides.log
  echo "SKIP_FAIL_BEFORE=1 override recorded in .fail-before-overrides.log: $REASON"
  exit 0
fi

if ! git rev-parse --verify "$BASE_REF^{commit}" >/dev/null 2>&1; then
  echo "Base ref does not resolve to a commit: $BASE_REF" >&2
  exit 2
fi

# INVARIANT: the base-side blob read must come from the SAME commit the
# three-dot diffs below compare against, or a file could read as "changed by
# this branch" against one commit and "unchanged" against another. `A...B` is by
# definition `merge-base(A,B) B`, so the merge base IS that commit; reading
# `$BASE_REF` directly would consult the base BRANCH TIP and mistake a marker
# that landed on main after the branch point for one this branch inherited.
# Failure mode from the outside: a shallow clone has no merge base, and this
# exits 2 loudly rather than silently treating every marker as introduced.
if ! MERGE_BASE="$(git merge-base "$BASE_REF" HEAD 2>/dev/null)"; then
  echo "FAIL: could not resolve a merge base between $BASE_REF and HEAD." >&2
  exit 2
fi

# INVARIANT: the source filter is a DOCUMENTATION DENYLIST, never an extension
# allowlist, because this guard must fail closed on any file type it does not
# recognize. Behavior under server/src is not carried by TypeScript alone: the
# reference-plugin executables (`substrate/reference-plugin/*/bin/*.mjs`), the
# policy templates (`principal-policy/templates/*.yaml`,
# `substrate/reference-plugin/*/governance.yaml`), the agent-template payloads
# (`templates/*/defaults.json`, `template.json`, `commitments.json`), the plugin
# trust anchors (`SIGNATURE.json`, `first-party-signer.json`), the eBPF probe
# loader (`sentinel/sentinels/ebpf/probe-loader.rs`), and the blocklist rules
# data (`rules/blocklist.txt`, `rules/hosts-blocklist.hosts`) all change shipped
# behavior. An allowlist of `.tsx?` drops every one of them, so a PR touching
# only those files prints "No server/src changes" and the guard is silently off,
# which is the failure this denylist exists to prevent: a disabled guard emits
# no signal at all, so nobody learns it stopped running.
#
# Only prose is exempt, and only `.md`. `.txt` is deliberately NOT exempt: the
# sole `.txt` under server/src is
# `substrate/reference-plugin/blocklist/rules/blocklist.txt`, which is rules
# data. Exempting the extension would reopen the hole on the one file that has
# it. A new prose extension gets added here explicitly, after confirming no
# behavior-bearing file shares it.
#
# The exemption exists because a docs-only edit to server/src/README.md would
# otherwise count as a source change and make the guard demand a failing test
# that no source change could produce. Failure mode when that drifts: the check
# reds with "server/src changed, but no changed server/test/*.test.ts files were
# found" on a PR that touched zero behavior. Must match the negated `paths`
# filter in .github/workflows/verify-fail-before.yml.
CHANGED_SRC_RAW="$(mktemp "${TMPDIR:-/tmp}/verify-fail-before-src-list.XXXXXX")"
if ! git diff --name-only "$BASE_REF"...HEAD -- server/src > "$CHANGED_SRC_RAW"; then
  echo "FAIL: could not inspect server/src changes between $BASE_REF and HEAD." >&2
  rm -f "$CHANGED_SRC_RAW"
  exit 2
fi

CHANGED_SRC=()
while IFS= read -r changed_src; do
  [[ -z "$changed_src" ]] && continue
  CHANGED_SRC+=("$changed_src")
done < <(grep -vE '\.md$' "$CHANGED_SRC_RAW" || true)
rm -f "$CHANGED_SRC_RAW"

CHANGED_TESTS_RAW="$(mktemp "${TMPDIR:-/tmp}/verify-fail-before-test-list.XXXXXX")"
if ! git diff --name-only --diff-filter=ACMR "$BASE_REF"...HEAD -- server/test > "$CHANGED_TESTS_RAW"; then
  echo "FAIL: could not inspect server/test changes between $BASE_REF and HEAD." >&2
  rm -f "$CHANGED_TESTS_RAW"
  exit 2
fi

CHANGED_TESTS=()
while IFS= read -r changed_test; do
  [[ -z "$changed_test" ]] && continue
  CHANGED_TESTS+=("$changed_test")
done < <(grep -E '\.test\.tsx?$' "$CHANGED_TESTS_RAW" || true)
rm -f "$CHANGED_TESTS_RAW"

if [[ ${#CHANGED_SRC[@]} -eq 0 ]]; then
  echo "No server/src changes between $BASE_REF and HEAD; fail-before check not required."
  exit 0
fi

if [[ ${#CHANGED_TESTS[@]} -eq 0 ]]; then
  echo "FAIL: server/src changed, but no changed server/test/*.test.ts files were found." >&2
  exit 1
fi

# `-M` asks git for the rename pairs it already detects; `--diff-filter=R` keeps
# only renames, so a copy stays an addition. Consumed by base_path_for_test_file
# above, whose invariant comment explains why pairing is load-bearing.
RENAME_OLD_PATHS=()
RENAME_NEW_PATHS=()
RENAME_RAW="$(mktemp "${TMPDIR:-/tmp}/verify-fail-before-renames.XXXXXX")"
if ! git diff -M --diff-filter=R --name-status "$MERGE_BASE" HEAD -- server/test > "$RENAME_RAW"; then
  echo "FAIL: could not resolve server/test rename pairs between $MERGE_BASE and HEAD." >&2
  rm -f "$RENAME_RAW"
  exit 2
fi
while IFS=$'\t' read -r rename_status rename_old rename_new; do
  [[ "$rename_status" == R* ]] || continue
  [[ -z "$rename_new" ]] && continue
  RENAME_OLD_PATHS+=("$rename_old")
  RENAME_NEW_PATHS+=("$rename_new")
done < "$RENAME_RAW"
rm -f "$RENAME_RAW"

COVERED_TESTS=()
EXEMPT_TESTS=()
for test_file in "${CHANGED_TESTS[@]}"; do
  set +e
  exemption_reason="$(exemption_reason_for_test_file "$test_file")"
  exemption_status=$?
  set -e

  # The reason compared here is the same string that is printed and logged
  # below, so the assertion that authorizes the exemption and the assertion the
  # audit record names can never be two different lines.
  if [[ "$exemption_status" -eq 0 ]] && ! marker_is_asserted_by_this_change "$test_file" "$exemption_reason"; then
    # The marker's reason is unchanged from the one at the merge base, so it was
    # written for a different change. It does not speak for this one.
    echo "INHERITED-EXEMPTION-IGNORED($test_file): the fail-before-exempt marker is unchanged from the merge base, so it was written for a different change and does not exempt this one; this file will be verified normally. Restate the marker with a reason that describes THIS change if the exemption genuinely applies."
    COVERED_TESTS+=("$test_file")
  elif [[ "$exemption_status" -eq 0 ]]; then
    EXEMPT_TESTS+=("$test_file")
    echo "EXEMPT($test_file): $exemption_reason"
    record_file_exemption "$test_file" "$exemption_reason"
  elif [[ "$exemption_status" -eq 2 ]]; then
    exit 2
  else
    COVERED_TESTS+=("$test_file")
  fi
done

if [[ ${#COVERED_TESTS[@]} -eq 0 ]]; then
  echo "FAIL: a source change with zero fail-before coverage is not verifiable — at least one changed test file must carry a real pre-fix-failing test" >&2
  exit 1
fi

SRC_PATCH="$(mktemp "${TMPDIR:-/tmp}/verify-fail-before-src.XXXXXX.patch")"
STASHED_SRC=0
STASH_REF=""
STASH_OBJECT=""
APPLIED_REVERSE=0

record_stash_ref() {
  STASHED_SRC=1
  STASH_REF="stash@{0}"
  STASH_OBJECT="$(git rev-parse --short "$STASH_REF" 2>/dev/null || true)"
}

stash_label() {
  if [[ -n "$STASH_OBJECT" ]]; then
    printf '%s (%s)' "$STASH_REF" "$STASH_OBJECT"
  else
    printf '%s' "${STASH_REF:-unknown}"
  fi
}

report_restore_failed() {
  local reason="$1"
  if [[ "$STASHED_SRC" -eq 1 ]]; then
    echo "RESTORE FAILED — your staged server/src state is in stash $(stash_label)" >&2
  else
    echo "RESTORE FAILED — server/src patch restore failed and no pre-run server/src stash was created" >&2
  fi
  echo "  $reason" >&2
  echo "  Resolve the restore manually before continuing." >&2
}

restore() {
  local status=$?
  local restore_failed=0
  set +e
  if [[ "$APPLIED_REVERSE" -eq 1 ]]; then
    git apply "$SRC_PATCH" >/dev/null 2>&1
    local apply_status=$?
    if [[ "$apply_status" -ne 0 ]]; then
      report_restore_failed "git apply failed while reapplying the server/src patch (exit $apply_status); patch left at $SRC_PATCH"
      restore_failed=1
    fi
  fi
  if [[ "$restore_failed" -eq 0 && "$STASHED_SRC" -eq 1 ]]; then
    git stash pop --index -q "$STASH_REF" >/dev/null 2>&1
    local stash_status=$?
    if [[ "$stash_status" -ne 0 ]]; then
      report_restore_failed "git stash pop --index $STASH_REF failed (exit $stash_status)"
      restore_failed=1
    fi
  fi
  if [[ "$restore_failed" -ne 0 ]]; then
    exit 1
  fi
  rm -f "$SRC_PATCH"
  exit "$status"
}
trap restore EXIT

git diff --binary "$BASE_REF"...HEAD -- server/src > "$SRC_PATCH"

if ! git diff --quiet -- server/src || ! git diff --cached --quiet -- server/src; then
  git stash push -q --include-untracked -m "verify-fail-before-src-$$" -- server/src
  record_stash_ref
else
  UNTRACKED_SRC=()
  while IFS= read -r untracked_src; do
    [[ -z "$untracked_src" ]] && continue
    UNTRACKED_SRC+=("$untracked_src")
  done < <(git ls-files --others --exclude-standard -- server/src)
  if [[ ${#UNTRACKED_SRC[@]} -gt 0 ]]; then
    git stash push -q --include-untracked -m "verify-fail-before-src-$$" -- server/src
    record_stash_ref
  fi
fi

if [[ -s "$SRC_PATCH" ]]; then
  git apply -R "$SRC_PATCH"
  APPLIED_REVERSE=1
fi

echo "Fail-before source delta removed; running changed tests against $BASE_REF source."
overall=0

for test_file in "${COVERED_TESTS[@]}"; do
  server_test="${test_file#server/}"
  echo
  echo "== $test_file =="
  set +e
  output="$(cd server && npx vitest run --reporter verbose "$server_test" 2>&1)"
  code=$?
  set -e
  printf '%s\n' "$output"
  if [[ "$code" -ne 0 ]]; then
    echo "PASS(failed-as-required): $test_file"
  else
    overall=1
    echo "FAIL(passed-without-the-fix): $test_file"
    survived="$(
      printf '%s\n' "$output" \
        | sed -n 's/^ ✓ //p' \
        | sed 's/[[:space:]][0-9][0-9]*ms$//' \
        | sed "s#^${server_test} > ##"
    )"
    if [[ -z "$survived" ]]; then
      echo "  survived: all tests in $test_file (vitest reported success)"
    else
      while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        echo "  survived: $name"
      done <<< "$survived"
    fi
  fi
done

if [[ "$overall" -ne 0 ]]; then
  echo
  echo "FAIL: at least one changed test passed against pre-fix source." >&2
  exit 1
fi

echo
if [[ ${#EXEMPT_TESTS[@]} -gt 0 ]]; then
  echo "PASS: every non-exempt changed test file failed against pre-fix source."
else
  echo "PASS: every changed test file failed against pre-fix source."
fi
