#!/bin/bash
# Sanctuary outbound-dependency audit (WP-V1.2 reshape, Step 7).
#
# Boots Sanctuary in a smoke-test fortress with no operator-configured
# external substrates, runs for the configured soak window with no
# operator interaction, captures all outbound TCP/UDP connections from
# the Sanctuary process tree, and asserts every outbound is to either
# localhost or a known-allowed substrate endpoint.
#
# Hard architecture rule the script enforces:
#   "Sanctuary initiates no network connection except to operator-
#    configured substrate endpoints. No phone-home for telemetry. No
#    version-check pings. No analytics. No Sanctuary-hosted SMTP relay."
#
# Usage:
#   ./outbound-audit.sh                     # 60s soak, default substrate
#   SOAK_SECONDS=120 ./outbound-audit.sh    # custom soak window
#   ./outbound-audit.sh --report-only       # print outbound list, no assertion
#
# Platform support:
#   - macOS: uses `lsof -i -p <pid>` per-second poll
#   - Linux: uses `ss -tunp` filtered by pid
#   - Other: exits 2 with "platform not supported"
#
# Exit codes:
#   0 = audit clean (no unauthorized outbound)
#   1 = audit FAILED (unauthorized outbound observed)
#   2 = setup failure (platform unsupported, fortress bootstrap failed,
#       Sanctuary process did not start)
#   3 = misuse (bad CLI args)

set -euo pipefail

SOAK_SECONDS="${SOAK_SECONDS:-60}"
REPORT_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --report-only) REPORT_ONLY=1 ;;
    --help|-h)
      sed -n '2,30p' "$0" | sed 's/^# //;s/^#//'
      exit 0
      ;;
    *)
      echo "outbound-audit: unknown arg: $arg" >&2
      exit 3
      ;;
  esac
done

PLATFORM="$(uname -s)"
case "$PLATFORM" in
  Darwin) ;;
  Linux) ;;
  *) echo "outbound-audit: platform $PLATFORM not supported (Darwin or Linux only)" >&2; exit 2 ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SMOKE_FORTRESS="$(mktemp -d -t sanctuary-outbound-audit-XXXXXX)"
SMOKE_LOG="$SMOKE_FORTRESS/sanctuary.log"
OUTBOUND_LOG="$SMOKE_FORTRESS/outbound.log"

cleanup() {
  if [ -n "${SANCTUARY_PID:-}" ] && kill -0 "$SANCTUARY_PID" 2>/dev/null; then
    kill "$SANCTUARY_PID" 2>/dev/null || true
    wait "$SANCTUARY_PID" 2>/dev/null || true
  fi
  rm -rf "$SMOKE_FORTRESS"
}
trap cleanup EXIT

echo "outbound-audit: smoke fortress at $SMOKE_FORTRESS"
echo "outbound-audit: soak window ${SOAK_SECONDS}s, platform $PLATFORM"

# Boot Sanctuary against the smoke fortress. SANCTUARY_PASSPHRASE is set
# inline so the cocoon unlocks without prompting; the smoke run is
# disposable, so the passphrase value does not matter beyond entropy.
export SANCTUARY_STORAGE_PATH="$SMOKE_FORTRESS"
export SANCTUARY_PASSPHRASE="audit-smoke-passphrase-$(date +%s)"

cd "$SERVER_DIR"
# Boot the dashboard subcommand: it is a long-running HTTP server and is
# representative of the always-on Sanctuary surface most operators run.
# The stdio MCP server exits without a peer; the dashboard is the right
# audit target. SANCTUARY_DASHBOARD_PORT=0 lets the OS pick a free port.
SANCTUARY_DASHBOARD_PORT=0 node dist/cli.js dashboard > "$SMOKE_LOG" 2>&1 &
SANCTUARY_PID=$!

# Wait briefly for the process to start; if it dies immediately, surface
# the error and exit before the soak begins.
sleep 2
if ! kill -0 "$SANCTUARY_PID" 2>/dev/null; then
  echo "outbound-audit: Sanctuary process died during boot. Log:" >&2
  cat "$SMOKE_LOG" >&2
  exit 2
fi

echo "outbound-audit: Sanctuary running as PID $SANCTUARY_PID. Capturing outbound connections..."

# Per-second poll of the process tree's outbound connections. Append to
# OUTBOUND_LOG; deduplicate at the end.
END_TS=$(($(date +%s) + SOAK_SECONDS))
while [ "$(date +%s)" -lt "$END_TS" ]; do
  if ! kill -0 "$SANCTUARY_PID" 2>/dev/null; then
    echo "outbound-audit: Sanctuary process exited mid-soak. Log:" >&2
    cat "$SMOKE_LOG" >&2
    exit 2
  fi
  case "$PLATFORM" in
    Darwin)
      # lsof -i lists IPv4/IPv6 connections; -nP suppresses DNS + port-name
      # lookups so we record raw addresses; -a -p narrows to the process.
      lsof -nP -i -a -p "$SANCTUARY_PID" 2>/dev/null \
        | awk 'NR>1 && /->/ {print $9}' \
        >> "$OUTBOUND_LOG" || true
      ;;
    Linux)
      # ss -tunp shows TCP+UDP with process info. Filter by the PID match
      # in the users column.
      ss -tunp 2>/dev/null \
        | awk -v pid="$SANCTUARY_PID" '$NF ~ "pid="pid"," {print $5}' \
        >> "$OUTBOUND_LOG" || true
      ;;
  esac
  sleep 1
done

echo "outbound-audit: soak complete; analyzing connections..."

# Deduplicate.
sort -u -o "$OUTBOUND_LOG" "$OUTBOUND_LOG" 2>/dev/null || touch "$OUTBOUND_LOG"

# Classify each entry as allowed (localhost or known-substrate) or
# unauthorized. The smoke fortress declares no operator-configured
# external substrates, so the only allowed outbound is localhost (the
# substrate selector defaults to "disabled" or local-Ollama at
# 127.0.0.1:11434 if available).
ALLOWED_PATTERNS=(
  "127\\.0\\.0\\.1"
  "::1"
  "localhost"
  "0\\.0\\.0\\.0"
)

UNAUTHORIZED=()
while IFS= read -r line; do
  [ -z "$line" ] && continue
  # Extract the destination side ("...->dest:port" on macOS;
  # "addr:port" on Linux).
  dest="${line##*->}"
  dest="${dest%% *}"
  matched=0
  for pat in "${ALLOWED_PATTERNS[@]}"; do
    if [[ "$dest" =~ $pat ]]; then
      matched=1
      break
    fi
  done
  if [ "$matched" -eq 0 ]; then
    UNAUTHORIZED+=("$dest")
  fi
done < "$OUTBOUND_LOG"

echo ""
echo "outbound-audit: connection summary"
echo "  total unique connections: $(wc -l < "$OUTBOUND_LOG" | tr -d ' ')"
echo "  unauthorized destinations: ${#UNAUTHORIZED[@]}"

if [ "${#UNAUTHORIZED[@]}" -gt 0 ]; then
  echo ""
  echo "outbound-audit: UNAUTHORIZED OUTBOUND DESTINATIONS observed:" >&2
  for dest in "${UNAUTHORIZED[@]}"; do
    echo "  $dest" >&2
  done
  echo "" >&2
  echo "Hard architecture rule violated: Sanctuary initiates no network connection" >&2
  echo "except to operator-configured substrate endpoints. Investigate the call sites" >&2
  echo "and surface to the no-outbound-by-default decision doc." >&2
  if [ "$REPORT_ONLY" -eq 1 ]; then
    echo "outbound-audit: --report-only set; not failing." >&2
    exit 0
  fi
  exit 1
fi

echo ""
echo "outbound-audit: PASS — no unauthorized outbound destinations."
echo "outbound-audit: full connection log preserved at $OUTBOUND_LOG (script cleans on exit)."
exit 0
