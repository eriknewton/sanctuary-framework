#!/usr/bin/env bash
# One-command demo reset: stop the demo fortress this script last started,
# then start a fresh seeded one that reuses the same operator token, so an open
# console tab only needs a reload.
#
# Usage (from server/): npm run demo:reset
#
# Environment (all optional):
#   SANCTUARY_DEMO_PORT        dashboard port (default 3517)
#   SANCTUARY_DEMO_STATE_DIR   where the token, log and last root are kept
#                              (default ~/.sanctuary-demo; never ~/.sanctuary)
#   SANCTUARY_DEMO_PASSPHRASE  passphrase for the throwaway fortress
#                              (default "demo passphrase"); the caller's own
#                              SANCTUARY_PASSPHRASE is deliberately not used
#
# This script only ever signals the demo it launched itself. At launch it
# records that process's pid, its start time (ps -o lstart) and its demo root;
# on the next reset it signals only when the pid is alive, still has that exact
# start time, and the root's own demo.pid still names it. Any mismatch (a reused
# pid, a hand-edited record) refuses and prints the manual command instead.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
server_dir=$(cd "$script_dir/../.." && pwd)

# Must match DEMO_SEED_DEFAULT_PORT in server/scripts/demo/seed-fortress-lib.ts.
port=${SANCTUARY_DEMO_PORT:-3517}
state_dir=${SANCTUARY_DEMO_STATE_DIR:-$HOME/.sanctuary-demo}
passphrase=${SANCTUARY_DEMO_PASSPHRASE:-demo passphrase}
token_file="$state_dir/operator-token"
# Three lines, written once the demo is ready: pid, ps lstart, demo root.
instance_file="$state_dir/demo-instance"
log_file="$state_dir/demo.log"
# Must match DEMO_PID_FILE_BASENAME in server/scripts/demo/seed-fortress-lib.ts.
pid_basename="demo.pid"
# The seeder handles SIGTERM by closing the dashboard and removing its root; a
# measured stop takes well under a second, so 40 polls 0.25 s apart (10 s) is ample.
stop_polls=40
# A measured start to ready takes about 3 s on a loaded Mac; 120 polls 0.25 s apart (30 s).
ready_polls=120
poll_interval_s=0.25

# The demo root is recorded and parsed one line at a time, so a temp parent
# containing a line break would be recorded truncated: the next reset would
# miss the live demo's pid file, or forget a crashed demo's root. Refuse first.
# Node's tmpdir() reads TMPDIR, then TMP, then TEMP.
for temp_var in TMPDIR TMP TEMP; do
  temp_value=${!temp_var:-}
  case "$temp_value" in
    *$'\n'* | *$'\r'*)
      echo "Refusing to start: $temp_var contains a line break, so the demo root could not be recorded. Unset it or choose a path without one." >&2
      exit 1
      ;;
  esac
done

umask 077
mkdir -p "$state_dir"
chmod 700 "$state_dir"

# ── Stop the demo this script started last time, if it is still running ──
if [ -f "$instance_file" ]; then
  rec_pid=""
  rec_lstart=""
  rec_root=""
  {
    IFS= read -r rec_pid || true
    IFS= read -r rec_lstart || true
    IFS= read -r rec_root || true
  } < "$instance_file"
  case "$rec_pid" in
    '' | *[!0-9]*)
      echo "Refusing to reset: $instance_file does not record a pid. Check for a running demo, then remove that file." >&2
      exit 1
      ;;
  esac
  if [ -z "$rec_lstart" ] || [ -z "$rec_root" ]; then
    echo "Refusing to reset: $instance_file is incomplete. Check for a running demo, then remove that file." >&2
    exit 1
  fi
  if kill -0 "$rec_pid" 2>/dev/null; then
    # Ownership is the launch identity, not a name: the same pid AND the same
    # start time AND the root's own pid file. A substring of the command line
    # would also match an editor or another seeder that reused the pid.
    # Bounded residual: ps lstart has one-second resolution, so after a crash
    # that leaves the root and its demo.pid behind, a process of the same user
    # that reuses the pid within the same second as the recorded launch passes
    # all three checks. Accepted for a single-operator demo tool.
    live_lstart=$(ps -o lstart= -p "$rec_pid" 2>/dev/null | awk '{$1=$1; print}' || true)
    root_pid=""
    if [ -f "$rec_root/$pid_basename" ]; then
      root_pid=$(tr -d '[:space:]' < "$rec_root/$pid_basename")
    fi
    if [ "$live_lstart" != "$rec_lstart" ] || [ "$root_pid" != "$rec_pid" ]; then
      echo "Refusing to stop pid $rec_pid: it is not the demo this script launched (its start time or demo root no longer match)." >&2
      echo "If that pid is your demo, stop it with: kill -TERM $rec_pid" >&2
      echo "Then remove $instance_file and rerun." >&2
      exit 1
    fi
    kill -TERM "$rec_pid"
    stopped=0
    for _ in $(seq 1 "$stop_polls"); do
      if ! kill -0 "$rec_pid" 2>/dev/null; then
        stopped=1
        break
      fi
      sleep "$poll_interval_s"
    done
    if [ "$stopped" -ne 1 ]; then
      echo "The previous demo (pid $rec_pid) did not stop within the wait; stop it by hand and rerun." >&2
      exit 1
    fi
  fi
  # A root left behind by a crash is removed through the seeder's own guarded teardown.
  if [ -d "$rec_root" ]; then
    (cd "$server_dir" && node --import tsx scripts/demo/seed-fortress.ts --teardown "$rec_root") || true
  fi
  # The record is dropped only once its root is gone, so a failed teardown is retried next time.
  if [ -d "$rec_root" ]; then
    echo "Could not remove the previous demo root $rec_root; the record in $instance_file is kept. Remove the root, then rerun." >&2
    exit 1
  fi
  rm -f "$instance_file"
fi

# ── Start a fresh demo in the background ──
# The whole background group's output goes to the log: redirecting only an
# inner command leaves the caller attached and it hangs until the demo exits.
: > "$log_file"
(
  cd "$server_dir"
  SANCTUARY_PASSPHRASE="$passphrase" exec nohup node --import tsx scripts/demo/seed-fortress.ts \
    --port "$port" --token-file "$token_file"
) > "$log_file" 2>&1 < /dev/null &
demo_pid=$!
# Captured at once, so any later signal to this pid can prove it is still this launch.
launch_lstart=$(ps -o lstart= -p "$demo_pid" 2>/dev/null | awk '{$1=$1; print}' || true)

ready=0
exited=0
for _ in $(seq 1 "$ready_polls"); do
  if grep -q '^Teardown: ' "$log_file"; then
    ready=1
    break
  fi
  if ! kill -0 "$demo_pid" 2>/dev/null; then
    exited=1
    break
  fi
  sleep "$poll_interval_s"
done
if [ "$ready" -ne 1 ]; then
  echo "The demo did not become ready. Last lines of $log_file:" >&2
  tail -n 20 "$log_file" >&2 || true
  if [ "$exited" -eq 1 ]; then
    # INVARIANT: a child that kill -0 already showed gone is never signalled;
    # its pid is free and may now belong to an unrelated process.
    echo "The demo process exited before it was ready." >&2
  else
    # A timed-out child is signalled only while its start time still matches
    # the one captured at launch (same one-second residual as the stop above).
    live_lstart=$(ps -o lstart= -p "$demo_pid" 2>/dev/null | awk '{$1=$1; print}' || true)
    if [ -n "$launch_lstart" ] && [ "$live_lstart" = "$launch_lstart" ]; then
      kill -TERM "$demo_pid" 2>/dev/null || true
      echo "Stopped the demo process (pid $demo_pid) this script launched." >&2
    else
      echo "Refusing to stop pid $demo_pid: its start time no longer matches the demo this script launched." >&2
      echo "If that pid is your demo, stop it with: kill -TERM $demo_pid" >&2
    fi
  fi
  exit 1
fi

new_root=$(sed -n 's/^Demo HOME: //p' "$log_file" | head -n 1)
new_lstart=$(ps -o lstart= -p "$demo_pid" 2>/dev/null | awk '{$1=$1; print}' || true)
# The recorded root must be the real one: it exists and its own pid file names this launch.
root_pid=""
if [ -n "$new_root" ] && [ -f "$new_root/$pid_basename" ]; then
  root_pid=$(tr -d '[:space:]' < "$new_root/$pid_basename")
fi
if [ -z "$new_lstart" ] || [ "$new_lstart" != "$launch_lstart" ]; then
  echo "The demo reported ready, but pid $demo_pid no longer has the start time captured at launch, so it was not recorded." >&2
  echo "If that pid is your demo, stop it with: kill -TERM $demo_pid" >&2
  exit 1
fi
if [ "$root_pid" != "$demo_pid" ]; then
  echo "The demo reported ready, but its demo root's $pid_basename does not name pid $demo_pid, so it was not recorded." >&2
  echo "If that pid is your demo, stop it with: kill -TERM $demo_pid" >&2
  exit 1
fi
printf '%s\n%s\n%s\n' "$demo_pid" "$new_lstart" "$new_root" > "$instance_file"
dashboard_url=$(sed -n 's/^Dashboard URL: //p' "$log_file" | head -n 1)

echo "Demo ready."
echo "Dashboard: $dashboard_url"
echo "Operator token file: $token_file (the same token after every reset; reload the open tab)"
echo "Log: $log_file"
echo "Stop: kill -TERM $demo_pid (or run npm run demo:reset again to restart)"
