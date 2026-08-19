#!/usr/bin/env bash
# Self-test for scripts/ci/retry-with-timeout.sh -- the shared bounded-retry
# wrapper now used at every apt-get and pip-install CI site (see
# scripts/ci/retry-with-timeout.sh's header for the incident this exists
# to fix). Exercises the four paths the wrapper must get right without
# waiting on real CI or real network stalls: succeed on the first try,
# succeed after a transient failure, exhaust every retry and exit
# non-zero, and have its own per-attempt timeout actually fire.
#
# Every case overrides RETRY_ATTEMPT_TIMEOUT_S / RETRY_MAX_ATTEMPTS /
# RETRY_BACKOFF_S down to single-digit seconds, so this file finishes in a
# few seconds even though production call sites use 180s / 3 / 10s.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RETRY_SCRIPT="$SCRIPT_DIR/ci/retry-with-timeout.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# Resolved once, up front, against this process's real PATH. One case
# below (case_falls_back_without_coreutils) runs the wrapper itself with
# timeout/gtimeout hidden from ITS PATH, to prove the pure-bash fallback
# path works; this harness's own outer safety net must keep working
# regardless, so it uses this captured absolute path rather than a bare
# `timeout` lookup that the same PATH override would also break.
OUTER_TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
[ -n "$OUTER_TIMEOUT_BIN" ] || fail "no timeout/gtimeout on this machine to bound the self-test harness itself"

write_fake_cmd() {
  local path="$1"
  local body="$2"
  cat > "$path" <<FAKE_CMD
#!/usr/bin/env bash
$body
FAKE_CMD
  chmod +x "$path"
}

assert_status() {
  local expected="$1"
  local actual="$2"
  local log="$3"
  [ "$actual" = "$expected" ] || fail "expected exit status $expected, got $actual
log:
$(cat "$log")"
}

assert_contains() {
  local log="$1"
  local needle="$2"
  grep -Fq "$needle" "$log" || fail "log did not contain: $needle
log:
$(cat "$log")"
}

# Every run is itself bounded by an outer `timeout`, so a bug in the
# wrapper (an infinite retry loop, a watchdog that never fires) fails this
# self-test loudly instead of hanging the CI job running it -- the exact
# failure mode this whole change exists to eliminate one layer up.
run_wrapped() {
  local root="$1"
  shift
  (
    cd "$root"
    "$OUTER_TIMEOUT_BIN" 30s "$RETRY_SCRIPT" "$@"
  ) > "$root/stdout.log" 2> "$root/stderr.log"
}

run_case() {
  local name="$1"
  local fn="$2"
  local root
  root="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-retry-self-test.XXXXXX")"
  "$fn" "$root"
  rm -rf "$root"
  echo "PASS: $name"
}

case_succeeds_first_try() {
  local root="$1"
  write_fake_cmd "$root/cmd.sh" "exit 0"
  local status=0
  RETRY_ATTEMPT_TIMEOUT_S=2 RETRY_MAX_ATTEMPTS=3 RETRY_BACKOFF_S=0 \
    run_wrapped "$root" "succeed-first" -- "$root/cmd.sh" || status=$?
  assert_status 0 "$status" "$root/stdout.log"
  assert_contains "$root/stdout.log" "succeeded on attempt 1"
}

case_succeeds_on_retry() {
  local root="$1"
  local counter="$root/calls"
  : > "$counter"
  write_fake_cmd "$root/cmd.sh" "
echo x >> '$counter'
n=\$(wc -l < '$counter')
if [ \"\$n\" -lt 2 ]; then
  exit 7
fi
exit 0
"
  local status=0
  RETRY_ATTEMPT_TIMEOUT_S=2 RETRY_MAX_ATTEMPTS=3 RETRY_BACKOFF_S=0 \
    run_wrapped "$root" "succeed-on-retry" -- "$root/cmd.sh" || status=$?
  assert_status 0 "$status" "$root/stdout.log"
  assert_contains "$root/stderr.log" "attempt 1 failed"
  assert_contains "$root/stderr.log" "exited 7"
  assert_contains "$root/stdout.log" "succeeded on attempt 2"
  [ "$(wc -l < "$counter")" -eq 2 ] || fail "expected exactly 2 calls, got $(wc -l < "$counter")"
}

case_fails_all_retries() {
  local root="$1"
  write_fake_cmd "$root/cmd.sh" "exit 5"
  local status=0
  RETRY_ATTEMPT_TIMEOUT_S=2 RETRY_MAX_ATTEMPTS=2 RETRY_BACKOFF_S=0 \
    run_wrapped "$root" "fail-all" -- "$root/cmd.sh" || status=$?
  assert_status 5 "$status" "$root/stderr.log"
  assert_contains "$root/stderr.log" "failed all 2 attempts"
  assert_contains "$root/stderr.log" "exited 5"
}

case_timeout_fires() {
  local root="$1"
  write_fake_cmd "$root/cmd.sh" "sleep 10"
  local status=0
  # Single attempt (MAX_ATTEMPTS=1) so the case itself stays fast: it
  # only needs to prove the per-attempt timeout fires and is reported,
  # not exercise the retry loop again (that's the two cases above).
  RETRY_ATTEMPT_TIMEOUT_S=1 RETRY_MAX_ATTEMPTS=1 RETRY_BACKOFF_S=0 \
    run_wrapped "$root" "timeout-fires" -- "$root/cmd.sh" || status=$?
  assert_status 124 "$status" "$root/stderr.log"
  assert_contains "$root/stderr.log" "timed out after 1s"
  assert_contains "$root/stderr.log" "failed all 1 attempts"
}

# Builds a PATH with every directory that contains a `timeout` or
# `gtimeout` binary removed, so a subprocess using it cannot find either.
# Simulates the GitHub-hosted macOS runner, which this wrapper also runs
# on (synthetic-coverage.yml's ubuntu+macos matrix) and which does not
# reliably ship GNU coreutils' `timeout`.
path_without_timeout_binaries() {
  local dir
  local out=""
  local ifs_save="$IFS"
  IFS=':'
  for dir in $PATH; do
    if [ -x "$dir/timeout" ] || [ -x "$dir/gtimeout" ]; then
      continue
    fi
    out="${out:+$out:}$dir"
  done
  IFS="$ifs_save"
  printf '%s' "$out"
}

# Proves the pure-bash fallback in run_bounded (scripts/ci/retry-with-timeout.sh)
# works on its own, not just the GNU-timeout path every other case above
# exercises: a success still returns 0, and a stuck command is still
# killed and reported as 124, with neither coreutils binary reachable.
case_falls_back_without_coreutils() {
  local root="$1"
  local restricted
  restricted="$(path_without_timeout_binaries)"
  [ -n "$restricted" ] || fail "path_without_timeout_binaries produced an empty PATH"

  write_fake_cmd "$root/ok.sh" "exit 0"
  local status=0
  (
    # shellcheck disable=SC2030,SC2031 # the export is deliberately scoped
    # to this subshell only, to isolate the restricted PATH to the one
    # subprocess under test without touching the harness's own PATH.
    export PATH="$restricted"
    command -v timeout >/dev/null 2>&1 && fail "timeout still resolvable after stripping it from PATH"
    command -v gtimeout >/dev/null 2>&1 && fail "gtimeout still resolvable after stripping it from PATH"
    RETRY_ATTEMPT_TIMEOUT_S=2 RETRY_MAX_ATTEMPTS=1 RETRY_BACKOFF_S=0 \
      run_wrapped "$root" "fallback-success" -- "$root/ok.sh"
  ) || status=$?
  assert_status 0 "$status" "$root/stdout.log"
  assert_contains "$root/stdout.log" "succeeded on attempt 1"

  write_fake_cmd "$root/stuck.sh" "sleep 10"
  status=0
  (
    # shellcheck disable=SC2030,SC2031 # see the matching note above.
    export PATH="$restricted"
    RETRY_ATTEMPT_TIMEOUT_S=1 RETRY_MAX_ATTEMPTS=1 RETRY_BACKOFF_S=0 \
      run_wrapped "$root" "fallback-timeout" -- "$root/stuck.sh"
  ) || status=$?
  assert_status 124 "$status" "$root/stderr.log"
  assert_contains "$root/stderr.log" "timed out after 1s"
}

run_case "succeeds on the first attempt, one call made" case_succeeds_first_try
run_case "fails once then succeeds on retry" case_succeeds_on_retry
run_case "exhausts every retry and exits with the real command's status" case_fails_all_retries
run_case "a stuck command is killed at the attempt timeout and reported as 124" case_timeout_fires
run_case "falls back to the pure-bash watchdog when timeout/gtimeout are both absent" case_falls_back_without_coreutils

echo "PASS: retry-with-timeout self-tests"
