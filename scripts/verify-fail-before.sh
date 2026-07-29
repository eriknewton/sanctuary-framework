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

CHANGED_SRC=()
while IFS= read -r changed_src; do
  [[ -z "$changed_src" ]] && continue
  CHANGED_SRC+=("$changed_src")
done < <(git diff --name-only "$BASE_REF"...HEAD -- server/src)

CHANGED_TESTS=()
while IFS= read -r changed_test; do
  [[ -z "$changed_test" ]] && continue
  CHANGED_TESTS+=("$changed_test")
done < <(
  git diff --name-only --diff-filter=ACMR "$BASE_REF"...HEAD -- server/test \
    | grep -E '\.test\.tsx?$' || true
)

if [[ ${#CHANGED_SRC[@]} -eq 0 ]]; then
  echo "No server/src changes between $BASE_REF and HEAD; fail-before check not required."
  exit 0
fi

if [[ ${#CHANGED_TESTS[@]} -eq 0 ]]; then
  echo "FAIL: server/src changed, but no changed server/test/*.test.ts files were found." >&2
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

for test_file in "${CHANGED_TESTS[@]}"; do
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
echo "PASS: every changed test file failed against pre-fix source."
