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
# This script only ever stops the demo it recorded in its own state directory,
# and only after confirming that pid is still running the demo seeder, so a
# stale record can never signal an unrelated process.
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
server_dir=$(cd "$script_dir/../.." && pwd)

# Must match DEMO_SEED_DEFAULT_PORT in server/scripts/demo/seed-fortress-lib.ts.
port=${SANCTUARY_DEMO_PORT:-3517}
state_dir=${SANCTUARY_DEMO_STATE_DIR:-$HOME/.sanctuary-demo}
passphrase=${SANCTUARY_DEMO_PASSPHRASE:-demo passphrase}
token_file="$state_dir/operator-token"
root_file="$state_dir/demo-root"
log_file="$state_dir/demo.log"
# Must match DEMO_PID_FILE_BASENAME in server/scripts/demo/seed-fortress-lib.ts.
pid_basename="demo.pid"
# The seeder handles SIGTERM by closing the dashboard and removing its root; a
# measured stop takes well under a second, so 40 polls 0.25 s apart (10 s) is ample.
stop_polls=40
# A measured start to ready takes about 3 s on a loaded Mac; 120 polls 0.25 s apart (30 s).
ready_polls=120
poll_interval_s=0.25

umask 077
mkdir -p "$state_dir"
chmod 700 "$state_dir"

# ── Stop the demo this script started last time, if it is still running ──
if [ -f "$root_file" ]; then
  old_root=$(cat "$root_file")
  old_pid_file="$old_root/$pid_basename"
  if [ -f "$old_pid_file" ]; then
    old_pid=$(tr -d '[:space:]' < "$old_pid_file")
    case "$old_pid" in
      '' | *[!0-9]*)
        echo "Refusing to stop: $old_pid_file does not hold a pid." >&2
        exit 1
        ;;
    esac
    if kill -0 "$old_pid" 2>/dev/null; then
      old_command=$(ps -o command= -p "$old_pid" || true)
      case "$old_command" in
        *seed-fortress*) kill -TERM "$old_pid" ;;
        *)
          echo "Refusing to stop pid $old_pid: it is not the demo seeder (the pid was reused)." >&2
          exit 1
          ;;
      esac
      stopped=0
      for _ in $(seq 1 "$stop_polls"); do
        if ! kill -0 "$old_pid" 2>/dev/null; then
          stopped=1
          break
        fi
        sleep "$poll_interval_s"
      done
      if [ "$stopped" -ne 1 ]; then
        echo "The previous demo (pid $old_pid) did not stop within the wait; stop it by hand and rerun." >&2
        exit 1
      fi
    fi
  fi
  # A root left behind by a crash is removed through the seeder's own guarded teardown.
  if [ -d "$old_root" ]; then
    (cd "$server_dir" && node --import tsx scripts/demo/seed-fortress.ts --teardown "$old_root") || true
  fi
  rm -f "$root_file"
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

ready=0
for _ in $(seq 1 "$ready_polls"); do
  if grep -q '^Teardown: ' "$log_file"; then
    ready=1
    break
  fi
  if ! kill -0 "$demo_pid" 2>/dev/null; then
    break
  fi
  sleep "$poll_interval_s"
done
if [ "$ready" -ne 1 ]; then
  echo "The demo did not become ready. Last lines of $log_file:" >&2
  tail -n 20 "$log_file" >&2 || true
  kill -TERM "$demo_pid" 2>/dev/null || true
  exit 1
fi

new_root=$(sed -n 's/^Demo HOME: //p' "$log_file" | head -n 1)
printf '%s\n' "$new_root" > "$root_file"
dashboard_url=$(sed -n 's/^Dashboard URL: //p' "$log_file" | head -n 1)

echo "Demo ready."
echo "Dashboard: $dashboard_url"
echo "Operator token file: $token_file (the same token after every reset; reload the open tab)"
echo "Log: $log_file"
echo "Stop: kill -TERM $demo_pid (or run npm run demo:reset again to restart)"
