#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY_SCRIPT="$SCRIPT_DIR/verify-fail-before.sh"

GIT_ENV_KEYS=(
  GIT_DIR
  GIT_COMMON_DIR
  GIT_WORK_TREE
  GIT_INDEX_FILE
  GIT_OBJECT_DIRECTORY
  GIT_ALTERNATE_OBJECT_DIRECTORIES
  GIT_NAMESPACE
  GIT_PREFIX
)

clean_git() (
  for key in "${GIT_ENV_KEYS[@]}"; do
    unset "$key"
  done
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_CONFIG_SYSTEM=/dev/null
  git -C "$@"
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_file() {
  local root="$1"
  local rel="$2"
  local body="$3"
  local path="$root/$rel"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$body" > "$path"
}

setup_fixture() {
  local root="$1"
  mkdir -p "$root/scripts" "$root/bin"
  cp "$VERIFY_SCRIPT" "$root/scripts/verify-fail-before.sh"
  chmod +x "$root/scripts/verify-fail-before.sh"

  cat > "$root/bin/npx" <<'FAKE_NPX'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> ../npx-calls.log
test_file=""
for arg in "$@"; do
  test_file="$arg"
done
case "$test_file" in
  test/real-pin.test.ts)
    if grep -q 'new-behavior' src/subject.ts; then
      echo "real-pin unexpectedly passed with fixed source"
      exit 0
    fi
    echo "real-pin failed against pre-fix source"
    exit 1
    ;;
  test/passthrough.test.ts|test/renamed-passthrough.test.ts)
    echo "passthrough has no behavioral delta"
    exit 0
    ;;
  *)
    echo "unexpected fake npx target: $test_file" >&2
    exit 44
    ;;
esac
FAKE_NPX
  chmod +x "$root/bin/npx"

  write_file "$root" "server/src/subject.ts" "export const behavior = 'old-behavior';
"

  clean_git "$root" init --quiet
  local top
  top="$(clean_git "$root" rev-parse --show-toplevel)"
  local root_real
  local top_real
  root_real="$(cd "$root" && pwd -P)"
  top_real="$(cd "$top" && pwd -P)"
  [[ "$top_real" == "$root_real" ]] || fail "temp git repo escaped fixture root"

  clean_git "$root" config --local user.email test@example.com
  clean_git "$root" config --local user.name "Fail Before Test"
  commit_all "$root" base
}

commit_all() {
  local root="$1"
  local message="$2"
  clean_git "$root" add .
  clean_git "$root" commit --quiet -m "$message" --no-verify
}

stage_source_change() {
  local root="$1"
  write_file "$root" "server/src/subject.ts" "export const behavior = 'new-behavior';
"
}

stage_real_pin() {
  local root="$1"
  write_file "$root" "server/test/real-pin.test.ts" "import { behavior } from '../src/subject.js';
it('pins behavior', () => {
  expect(behavior).toBe('new-behavior');
});
"
}

stage_exempt() {
  local root="$1"
  local marker="$2"
  write_file "$root" "server/test/passthrough.test.ts" "$marker
import { behavior } from '../src/subject.js';
it('passthrough compiles', () => {
  expect(typeof behavior).toBe('string');
});
"
}

# A passthrough test file with a caller-chosen marker line and optional appended
# body, so a case can vary the marker and the edit independently.
write_passthrough() {
  local root="$1"
  local rel="$2"
  local marker="$3"
  local appended="$4"
  write_file "$root" "$rel" "$marker
import { behavior } from '../src/subject.js';
it('passthrough compiles', () => {
  expect(typeof behavior).toBe('string');
});
$appended"
}

# The edit a later change makes to an already-exempt file. It is exactly the
# shape the historical miss had: new assertions nobody verified.
APPENDED_ASSERTION="it('a later change adds an assertion the old exemption never covered', () => {
  expect(typeof behavior).toBe('string');
});
"

commit_base_marker() {
  local root="$1"
  local reason="$2"
  write_passthrough "$root" "server/test/passthrough.test.ts" "// fail-before-exempt: $reason" ""
  commit_all "$root" "base commit carries the marker"
}

run_verify() {
  local root="$1"
  # Defaults to the linear-history base. Cases that build a real branch pass an
  # explicit ref so the merge-base semantics are actually exercised; on a linear
  # fixture `HEAD~1` IS the merge base, so those cases cannot see the difference.
  local base_ref="${2:-HEAD~1}"
  set +e
  (
    for key in "${GIT_ENV_KEYS[@]}"; do
      unset "$key"
    done
    export GIT_CONFIG_GLOBAL=/dev/null
    export GIT_CONFIG_SYSTEM=/dev/null
    export USER=verify-fail-before-test
    export PATH="$root/bin:$PATH"
    cd "$root"
    bash scripts/verify-fail-before.sh "$base_ref"
  ) > "$root/stdout.log" 2> "$root/stderr.log"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$root/status"
}

assert_status() {
  local root="$1"
  local expected="$2"
  local actual
  actual="$(cat "$root/status")"
  [[ "$actual" == "$expected" ]] || fail "expected status $expected, got $actual
stdout:
$(cat "$root/stdout.log")
stderr:
$(cat "$root/stderr.log")"
}

assert_contains() {
  local root="$1"
  local rel="$2"
  local needle="$3"
  grep -Fq "$needle" "$root/$rel" || fail "$rel did not contain: $needle
contents:
$(cat "$root/$rel" 2>/dev/null || true)"
}

assert_not_contains() {
  local root="$1"
  local rel="$2"
  local needle="$3"
  if [[ -f "$root/$rel" ]] && grep -Fq "$needle" "$root/$rel"; then
    fail "$rel unexpectedly contained: $needle
contents:
$(cat "$root/$rel")"
  fi
}

assert_empty_or_absent() {
  local root="$1"
  local rel="$2"
  if [[ -s "$root/$rel" ]]; then
    fail "$rel should be empty or absent
contents:
$(cat "$root/$rel")"
  fi
}

case_exempt_logs() {
  local root="$1"
  setup_fixture "$root"
  stage_source_change "$root"
  stage_real_pin "$root"
  stage_exempt "$root" "// fail-before-exempt: type-only fixture update"
  commit_all "$root" "source plus test changes"
  run_verify "$root"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts): type-only fixture update"
  assert_contains "$root" .fail-before-overrides.log "fail-before-exempt file=server/test/passthrough.test.ts"
  assert_contains "$root" .fail-before-overrides.log "base_ref=HEAD~1"
  assert_contains "$root" .fail-before-overrides.log "reason=type-only fixture update"
  assert_not_contains "$root" npx-calls.log "test/passthrough.test.ts"
}

case_empty_reason_errors() {
  local root="$1"
  setup_fixture "$root"
  stage_source_change "$root"
  stage_exempt "$root" "// fail-before-exempt:    "
  commit_all "$root" "empty exemption"
  run_verify "$root"
  assert_status "$root" 2
  assert_contains "$root" stderr.log "has an empty reason"
  assert_contains "$root" stderr.log "// fail-before-exempt: <non-empty reason>"
  assert_empty_or_absent "$root" .fail-before-overrides.log
  assert_empty_or_absent "$root" npx-calls.log
}

case_all_exempt_errors() {
  local root="$1"
  setup_fixture "$root"
  stage_source_change "$root"
  stage_exempt "$root" "// fail-before-exempt: passthrough shape change"
  commit_all "$root" "all exempt"
  run_verify "$root"
  assert_status "$root" 1
  assert_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts): passthrough shape change"
  assert_contains "$root" stderr.log "a source change with zero fail-before coverage is not verifiable"
  assert_contains "$root" stderr.log "at least one changed test file must carry a real pre-fix-failing test"
  assert_contains "$root" .fail-before-overrides.log "reason=passthrough shape change"
  assert_empty_or_absent "$root" npx-calls.log
}

# The regression this guards: a marker written for ONE change used to exempt its
# whole file FOREVER, so a later change to the same file went unverified with no
# signal. Here the marker is committed in the BASE, then a later change edits the
# same file; the exemption must NOT carry over, and the file must actually be run
# against pre-fix source.
case_inherited_exemption_is_ignored() {
  local root="$1"
  setup_fixture "$root"
  # Base commit carries the marker on a file that DOES have a behavioral pin.
  write_file "$root" "server/test/real-pin.test.ts" "// fail-before-exempt: written for an earlier change
import { behavior } from '../src/subject.js';
it('pins behavior', () => {
  expect(behavior).toBe('new-behavior');
});
"
  commit_all "$root" "base commit introduces the exemption"
  # A later change edits source and the same test file. The inherited marker
  # must not speak for it.
  stage_source_change "$root"
  write_file "$root" "server/test/real-pin.test.ts" "// fail-before-exempt: written for an earlier change
import { behavior } from '../src/subject.js';
it('pins behavior', () => {
  expect(behavior).toBe('new-behavior');
});
it('a later change adds a pin the old exemption never covered', () => {
  expect(behavior).toBe('new-behavior');
});
"
  commit_all "$root" "later change edits the exempt file"
  run_verify "$root"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "INHERITED-EXEMPTION-IGNORED(server/test/real-pin.test.ts)"
  # The whole point: the file is actually RUN against pre-fix source now.
  assert_contains "$root" npx-calls.log "test/real-pin.test.ts"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

# The complement: a marker introduced BY this change still exempts, so the
# per-change scoping did not simply delete the exemption mechanism.
case_marker_introduced_here_still_exempts() {
  local root="$1"
  setup_fixture "$root"
  stage_source_change "$root"
  stage_real_pin "$root"
  stage_exempt "$root" "// fail-before-exempt: introduced by this very change"
  commit_all "$root" "change introduces both a pin and an exemption"
  run_verify "$root"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts): introduced by this very change"
  assert_not_contains "$root" npx-calls.log "test/passthrough.test.ts"
}

case_mixed_passes() {
  local root="$1"
  setup_fixture "$root"
  stage_source_change "$root"
  stage_real_pin "$root"
  stage_exempt "$root" "// fail-before-exempt: type-required passthrough fixture"
  commit_all "$root" "mixed coverage"
  run_verify "$root"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "PASS(failed-as-required): server/test/real-pin.test.ts"
  assert_contains "$root" stdout.log "PASS: every non-exempt changed test file failed against pre-fix source."
  assert_contains "$root" npx-calls.log "test/real-pin.test.ts"
  assert_not_contains "$root" npx-calls.log "test/passthrough.test.ts"
  assert_contains "$root" server/src/subject.ts "new-behavior"
}

run_case() {
  local name="$1"
  local fn="$2"
  local root
  root="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-fail-before.XXXXXX")"
  "$fn" "$root"
  rm -rf "$root"
  echo "PASS: $name"
}

# The SILENT variant of the historical miss, and the one that actually pins the
# defect. `case_inherited_exemption_is_ignored` above has the exempt file as the
# ONLY changed test, so the pre-fix script reds it with "zero fail-before
# coverage" — the loud case, which main already catches. Here the exempt file
# changes ALONGSIDE a sibling that satisfies the gate, so the pre-fix script
# exits 0 and says nothing at all. Pre-fix: silent green. Post-fix: loud red.
case_inherited_exemption_with_satisfying_sibling() {
  local root="$1"
  setup_fixture "$root"
  commit_base_marker "$root" "written for an earlier change"
  stage_source_change "$root"
  stage_real_pin "$root"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: written for an earlier change" "$APPENDED_ASSERTION"
  commit_all "$root" "later change edits the exempt file alongside a real pin"
  run_verify "$root"
  # Red because the inherited-exempt file is now RUN and passes without the fix.
  assert_status "$root" 1
  assert_contains "$root" stdout.log "INHERITED-EXEMPTION-IGNORED(server/test/passthrough.test.ts)"
  assert_contains "$root" stdout.log "FAIL(passed-without-the-fix): server/test/passthrough.test.ts"
  # The sibling satisfied the gate, which is why the pre-fix script was silent.
  assert_contains "$root" stdout.log "PASS(failed-as-required): server/test/real-pin.test.ts"
  assert_contains "$root" npx-calls.log "test/passthrough.test.ts"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

# A genuine restatement, the remediation the error message instructs authors to
# perform: the reason CHANGES, so the exemption is re-asserted and holds.
case_restated_reason_exempts() {
  local root="$1"
  setup_fixture "$root"
  commit_base_marker "$root" "written for an earlier change"
  stage_source_change "$root"
  stage_real_pin "$root"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: restated for this change: the appended assertion is type-only" "$APPENDED_ASSERTION"
  commit_all "$root" "later change restates the exemption with a new reason"
  run_verify "$root"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts): restated for this change"
  assert_contains "$root" .fail-before-overrides.log "reason=restated for this change"
  assert_not_contains "$root" npx-calls.log "test/passthrough.test.ts"
}

# A rename must not re-assert. A pathspec-limited diff cannot pair the rename
# source, so a diff-shaped predicate reads the whole file as added and the
# INHERITED marker as introduced. GitHub renders this as `old -> new` with the
# marker line unhighlighted, so it is a re-assertion with nothing to review.
case_rename_does_not_reassert() {
  local root="$1"
  setup_fixture "$root"
  commit_base_marker "$root" "written for an earlier change"
  stage_source_change "$root"
  stage_real_pin "$root"
  clean_git "$root" mv server/test/passthrough.test.ts server/test/renamed-passthrough.test.ts
  write_passthrough "$root" "server/test/renamed-passthrough.test.ts" \
    "// fail-before-exempt: written for an earlier change" "$APPENDED_ASSERTION"
  commit_all "$root" "later change renames the exempt file and edits it"
  run_verify "$root"
  assert_status "$root" 1
  assert_contains "$root" stdout.log "INHERITED-EXEMPTION-IGNORED(server/test/renamed-passthrough.test.ts)"
  assert_contains "$root" npx-calls.log "test/renamed-passthrough.test.ts"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

# A trailing space on the marker line must not re-assert. It vanishes entirely
# under GitHub's "Hide whitespace changes", so honoring it would let the
# cheapest possible edit stand in for a reviewed assertion.
case_whitespace_touch_does_not_reassert() {
  local root="$1"
  setup_fixture "$root"
  commit_base_marker "$root" "written for an earlier change"
  stage_source_change "$root"
  stage_real_pin "$root"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt:  written   for an earlier change   " "$APPENDED_ASSERTION"
  commit_all "$root" "later change re-spaces the marker line"
  run_verify "$root"
  assert_status "$root" 1
  assert_contains "$root" stdout.log "INHERITED-EXEMPTION-IGNORED(server/test/passthrough.test.ts)"
  assert_contains "$root" npx-calls.log "test/passthrough.test.ts"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

# A marker-shaped line added ANYWHERE ELSE in the file must not re-assert the
# header marker. Otherwise the line that proves re-assertion and the line whose
# reason is consumed and logged are two different lines carrying two different
# reasons, and the audit record names an assertion nobody made. Reachable by
# accident: any `//` comment written to document the convention counts.
case_marker_shaped_line_elsewhere_does_not_reassert() {
  local root="$1"
  setup_fixture "$root"
  commit_base_marker "$root" "written for an earlier change"
  stage_source_change "$root"
  stage_real_pin "$root"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: written for an earlier change" \
    "// fail-before-exempt: a reason nobody reviewed, far below the marker window
$APPENDED_ASSERTION"
  commit_all "$root" "later change adds a marker-shaped line below the window"
  run_verify "$root"
  assert_status "$root" 1
  assert_contains "$root" stdout.log "INHERITED-EXEMPTION-IGNORED(server/test/passthrough.test.ts)"
  assert_contains "$root" npx-calls.log "test/passthrough.test.ts"
  assert_not_contains "$root" stdout.log "a reason nobody reviewed"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

# The only case with a real branch, so the only one where the merge base and the
# base BRANCH TIP differ. The branch introduces the marker on a file that had
# none at the branch point; main independently gains the identical marker after
# the branch point. Reading the base tip would call this inherited and red a
# legitimate introduction; reading the merge base calls it introduced. This is
# also the case that covers "a file that existed at the base without a marker
# gains one", which the linear fixtures cannot reach.
case_marker_introduced_on_branch_while_base_tip_gained_it_too() {
  local root="$1"
  setup_fixture "$root"
  local mainline
  mainline="$(clean_git "$root" rev-parse --abbrev-ref HEAD)"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "import { behavior as unusedBehavior } from '../src/subject.js';" ""
  commit_all "$root" "branch point: the file exists with no marker"

  clean_git "$root" checkout --quiet -b feature
  stage_source_change "$root"
  stage_real_pin "$root"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: introduced on this branch" "$APPENDED_ASSERTION"
  commit_all "$root" "branch introduces the marker"

  clean_git "$root" checkout --quiet "$mainline"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: introduced on this branch" ""
  commit_all "$root" "base branch independently gains the identical marker"
  clean_git "$root" checkout --quiet feature

  run_verify "$root" "$mainline"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts): introduced on this branch"
  assert_contains "$root" stdout.log "PASS(failed-as-required): server/test/real-pin.test.ts"
  assert_not_contains "$root" npx-calls.log "test/passthrough.test.ts"
}

# A marker's meaning must not depend on the SIZE of the file's diff. The
# diff-shaped predicate piped `git diff` into `grep -q`, which short-circuits on
# the first match; once a file's diff passed the pipe buffer `git diff` died of
# SIGPIPE, `pipefail` reported 141, and a marker the change genuinely INTRODUCED
# was announced as inherited with a factually false message and no remediation
# but SKIP_FAIL_BEFORE. The content comparison reads blobs and has no pipeline,
# so this is the witness that the size dependence is gone, not merely unlikely.
case_large_file_marker_introduction_still_exempts() {
  local root="$1"
  local filler=""
  setup_fixture "$root"
  # 3000 assertions is comfortably past the 64KB pipe buffer, and is the size of
  # test files this repo actually lands in a single change.
  filler="$(seq 0 2999 | sed "s/.*/it('base assertion &', () => { expect(typeof behavior).toBe('string'); });/")"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "import { behavior as unusedBehavior } from '../src/subject.js';" "$filler"
  commit_all "$root" "base commit carries a large file with no marker"
  stage_source_change "$root"
  stage_real_pin "$root"
  filler="$(seq 0 2999 | sed "s/.*/it('rewritten assertion &', () => { expect(typeof behavior).toBe('string'); });/")"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: introduced by this change on a large file" "$filler"
  commit_all "$root" "large file gains the marker and a rewritten body"
  run_verify "$root"
  assert_status "$root" 0
  assert_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts): introduced by this change on a large file"
  assert_not_contains "$root" npx-calls.log "test/passthrough.test.ts"
}

# The complement, and the one that pins the base-side read. The base blob is
# captured whole rather than piped into the parser, because the parser stops at
# the first marker and `pipefail` would then report the writer's SIGPIPE (141)
# as "no marker at the base" — which EXEMPTS. Piping would therefore make a
# large file's INHERITED marker silently exempt while a small file's does not.
# Without this case that substitution passes the whole suite green.
case_large_file_inherited_marker_is_still_ignored() {
  local root="$1"
  local filler=""
  setup_fixture "$root"
  filler="$(seq 0 2999 | sed "s/.*/it('base assertion &', () => { expect(typeof behavior).toBe('string'); });/")"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: written for an earlier change" "$filler"
  commit_all "$root" "base commit carries a large file whose marker is on line 1"
  stage_source_change "$root"
  stage_real_pin "$root"
  write_passthrough "$root" "server/test/passthrough.test.ts" \
    "// fail-before-exempt: written for an earlier change" "$filler$APPENDED_ASSERTION"
  commit_all "$root" "later change appends to the large exempt file"
  run_verify "$root"
  assert_status "$root" 1
  assert_contains "$root" stdout.log "INHERITED-EXEMPTION-IGNORED(server/test/passthrough.test.ts)"
  assert_contains "$root" npx-calls.log "test/passthrough.test.ts"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

# The marker is a FILE HEADER declaration, not something that can be buried. The
# window that enforces that now lives in the shared parser both sides of the
# comparison read through, so a regression there would silently widen what
# counts as an exemption on both sides at once. This case pins the boundary; it
# is a regression guard rather than a before/after witness, since the pre-change
# script read the same window.
case_marker_below_the_window_is_not_an_exemption() {
  local root="$1"
  local padding=""
  setup_fixture "$root"
  # 40 > the 30-line window, so the marker below it is out of scope by design.
  padding="$(seq 1 40 | sed "s|.*|// padding line \&|")"
  write_file "$root" "server/test/passthrough.test.ts" "$padding
import { behavior } from '../src/subject.js';
it('passthrough compiles', () => {
  expect(typeof behavior).toBe('string');
});
"
  commit_all "$root" "base commit carries the padded file with no marker"
  stage_source_change "$root"
  stage_real_pin "$root"
  write_file "$root" "server/test/passthrough.test.ts" "$padding
// fail-before-exempt: buried below the header window, so it is not a marker
import { behavior } from '../src/subject.js';
it('passthrough compiles', () => {
  expect(typeof behavior).toBe('string');
});
$APPENDED_ASSERTION"
  commit_all "$root" "later change buries a marker below the window"
  run_verify "$root"
  assert_status "$root" 1
  assert_not_contains "$root" stdout.log "EXEMPT(server/test/passthrough.test.ts)"
  assert_contains "$root" npx-calls.log "test/passthrough.test.ts"
  assert_empty_or_absent "$root" .fail-before-overrides.log
}

run_case "exempt file with reason is skipped and logged" case_exempt_logs
run_case "empty exemption reason is a hard error" case_empty_reason_errors
run_case "all-exempt source change is a hard error" case_all_exempt_errors
run_case "mixed real pin plus exempt file passes" case_mixed_passes
run_case "an inherited exemption does not exempt a later change" case_inherited_exemption_is_ignored
run_case "a marker introduced by this change still exempts" case_marker_introduced_here_still_exempts
run_case "an inherited exemption alongside a satisfying sibling reds (the silent shape)" case_inherited_exemption_with_satisfying_sibling
run_case "a restated reason re-asserts the exemption" case_restated_reason_exempts
run_case "a rename does not re-assert an inherited exemption" case_rename_does_not_reassert
run_case "a whitespace-only touch of the marker does not re-assert it" case_whitespace_touch_does_not_reassert
run_case "a marker-shaped line elsewhere in the file does not re-assert it" case_marker_shaped_line_elsewhere_does_not_reassert
run_case "the base is the merge base, not the base branch tip" case_marker_introduced_on_branch_while_base_tip_gained_it_too
run_case "a marker introduced on a large file still exempts (no size dependence)" case_large_file_marker_introduction_still_exempts
run_case "an inherited marker on a large file is still ignored (base read is not piped)" case_large_file_inherited_marker_is_still_ignored
run_case "a marker below the header window is not an exemption" case_marker_below_the_window_is_not_an_exemption

echo "PASS: verify-fail-before self-tests"
