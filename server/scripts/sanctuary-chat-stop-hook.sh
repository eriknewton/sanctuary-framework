#!/usr/bin/env bash
# Sanctuary chat-autonomy Stop hook (v1.2.0 F10).
#
# Installed by `sanctuary wrap --install-hooks` at ~/.claude/settings.json.
# Reads the Stop event payload on stdin; if the wrapped Claude Code
# session has a pending operator message in Sanctuary's chat inbox,
# returns decision=block + reason so the next Claude turn drains the
# inbox and replies via chat/send_reply.
#
# Recursion guard: when this hook returns block + reason, the next Stop
# event fires with stop_hook_active=true. Exit 0 without polling on that
# pass; otherwise the agent and the hook loop forever.
#
# Failure mode: any non-zero exit code from sanctuary chat-poll, any
# missing env var, any inbox-read error: exit 0 silently. Claude
# proceeds to its idle prompt as normal. The hook only ever STOPS Claude
# from finishing; it never blocks Claude from running.

set -uo pipefail

STOP_PAYLOAD=$(cat 2>/dev/null || true)

# stop_hook_active recursion guard. See Claude Code hooks spec.
case "$STOP_PAYLOAD" in
  *'"stop_hook_active":true'*|*'"stop_hook_active": true'*)
    exit 0
    ;;
esac

# Required env: set by `sanctuary wrap --install-hooks` at install time.
# If any are missing, fail open (hook is best-effort autonomy, not a
# load-bearing security gate).
if [ -z "${SANCTUARY_AGENT_ID:-}" ]; then
  exit 0
fi

# Resolve sanctuary CLI. Prefer SANCTUARY_BIN if explicitly set by the
# installer (most reliable on operator machines that have Sanctuary
# installed via npm into a non-default prefix). Fall back to PATH.
SANCTUARY_BIN="${SANCTUARY_BIN:-sanctuary}"

# Drain inbox. --format flat emits tab-separated records, one per
# pending operator message. Empty stdout when the inbox is empty.
INBOX=$("$SANCTUARY_BIN" chat-poll \
  --agent-id "$SANCTUARY_AGENT_ID" \
  --format flat \
  --quiet 2>/dev/null) || exit 0

if [ -z "$INBOX" ]; then
  exit 0
fi

# Parse the first record. Format:
#   <session_id>\t<message_id>\t<created_at>\t<body>
# Multiple messages: join bodies with '; ' so the agent reads them
# all in the same turn.
SESSION_ID=$(printf '%s\n' "$INBOX" | head -n 1 | awk -F'\t' '{print $1}')

# Aggregate all message bodies; preserve order.
BODIES=$(printf '%s\n' "$INBOX" | awk -F'\t' '{print $4}' | paste -sd '; ' -)

if [ -z "$SESSION_ID" ] || [ -z "$BODIES" ]; then
  exit 0
fi

# JSON-escape the bodies for the reason field. Bash-safe: replace
# backslashes, double quotes, newlines, tabs, control chars.
JSON_BODIES=$(printf '%s' "$BODIES" \
  | sed 's/\\/\\\\/g; s/"/\\"/g' \
  | tr '\n' ' ' \
  | tr '\r' ' ' \
  | tr '\t' ' ')

# Emit decision=block. The reason is what Claude reads as its next
# instruction. Reply via chat/send_reply on the bound chat-server.
cat <<EOF
{"decision":"block","reason":"Operator message via Sanctuary dashboard chat: ${JSON_BODIES}. Reply via the chat/send_reply tool with session_id=\"${SESSION_ID}\". Treat this as the next operator instruction."}
EOF
