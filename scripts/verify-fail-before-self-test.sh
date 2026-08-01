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
  test/passthrough.test.ts)
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

run_verify() {
  local root="$1"
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
    bash scripts/verify-fail-before.sh HEAD~1
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

run_case "exempt file with reason is skipped and logged" case_exempt_logs
run_case "empty exemption reason is a hard error" case_empty_reason_errors
run_case "all-exempt source change is a hard error" case_all_exempt_errors
run_case "mixed real pin plus exempt file passes" case_mixed_passes

echo "PASS: verify-fail-before self-tests"
