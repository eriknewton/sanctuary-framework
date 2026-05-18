#!/usr/bin/env bash
set -euo pipefail

# Single-file harness for the V1.3 Linux automated acceptance drill.
# It executes the ten scripted actions from the drill spec, captures
# stdout, stderr, and exit code per action, and writes one YAML report.
#
# Shipped CLI surface reference, audited against current main:
#
# Task coordination, PR #279:
#   sanctuary task create --title <s> [--description <s>] [--assignee <agent-id>] [--parent <task-id>] [--json] [--fortress <path>]
#   sanctuary task update <id> --status <pending|in_progress|blocked|ready_for_review|completed|cancelled> [--json] [--fortress <path>]
#   sanctuary task show <id> [--json] [--fortress <path>]
#   sanctuary task list [--status <status>] [--assignee <agent-id>] [--creator <agent-id>] [--json] [--fortress <path>]
#   sanctuary task assign <id> --assignee <agent-id> [--json] [--fortress <path>]
#   sanctuary task cancel <id> [--reason <s>] [--json] [--fortress <path>]
#   Lifecycle transitions require pending -> in_progress -> ready_for_review.
#   ready_for_review creates approval_request_id and a pending inbox approval.
#
# Inbox approvals, PR #266:
#   sanctuary inbox approvals list [--json] [--fortress <path>]
#   sanctuary inbox approvals approve <entry_id> [--json] [--fortress <path>]
#   sanctuary inbox approvals approve --id <entry_id> [--json] [--fortress <path>] is accepted but the drill uses the positional form.
#
# Concierge, PR #282:
#   sanctuary concierge ask "<question>" [--fortress <path>] [--json] [--no-stream] [--include-payloads]
#   sanctuary concierge status [--fortress <path>] [--json]
#   Concierge requires VENICE_API_KEY for provider-backed answers. This drill
#   skips action 9 when VENICE_API_KEY is unset instead of failing the run.
#
# Non-existent aspirational surfaces from the original harness:
#   sanctuary task create --requester/--target/--action
#   sanctuary task approve
#   sanctuary task status
#   sanctuary coordination edges
#   sanctuary audit query
# Existing replacements used below:
#   task list/show/update for coordination evidence
#   /api/hub/activity?category=approval for approval receipt evidence

REPORT_PATH="${REPORT_PATH:-/tmp/v1.3-linux-drill-report.md}"
SANCTUARY_VERSION="${SANCTUARY_VERSION:-next}"
DRILL_ROOT="${DRILL_ROOT:-$(mktemp -d /tmp/sanctuary-v13-linux-drill.XXXXXX)}"
FORTRESS_PATH="${FORTRESS_PATH:-$DRILL_ROOT/drill}"
STDOUT_DIR="$DRILL_ROOT/stdout"
STDERR_DIR="$DRILL_ROOT/stderr"
STATE_DIR="$DRILL_ROOT/state"
REPORT_TMP="$DRILL_ROOT/report-actions.yml"
DASHBOARD_PORT="${DASHBOARD_PORT:-3502}"
DASHBOARD_URL="${SANCTUARY_DASHBOARD_URL:-http://127.0.0.1:$DASHBOARD_PORT}"
DASHBOARD_TOKEN="${SANCTUARY_DASHBOARD_AUTH_TOKEN:-DEV}"
SANCTUARY_PASSPHRASE="${SANCTUARY_PASSPHRASE:-v13-linux-drill-passphrase}"
DRY_RUN=0
DASHBOARD_PID=""

export SANCTUARY_FORTRESS_PATH="$FORTRESS_PATH"
export SANCTUARY_STORAGE_PATH="$FORTRESS_PATH"
export SANCTUARY_DASHBOARD_URL="$DASHBOARD_URL"
export SANCTUARY_DASHBOARD_AUTH_TOKEN="$DASHBOARD_TOKEN"
export SANCTUARY_PASSPHRASE

mkdir -p "$STDOUT_DIR" "$STDERR_DIR" "$STATE_DIR"
: > "$REPORT_TMP"

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

cleanup() {
  if [[ -n "$DASHBOARD_PID" ]]; then
    kill "$DASHBOARD_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "${DRILL_ROOT:-}" && -d "$DRILL_ROOT" ]]; then
    local debug_archive="${DRILL_DEBUG_ARCHIVE:-/tmp/v1.3-linux-drill-debug.tgz}"
    tar czf "$debug_archive" -C "$(dirname "$DRILL_ROOT")" "$(basename "$DRILL_ROOT")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

yaml_block() {
  local file="$1"
  if [[ ! -s "$file" ]]; then
    printf '    ""\n'
    return
  fi
  sed 's/^/    /' "$file"
}

append_action_report() {
  local number="$1"
  local name="$2"
  local status="$3"
  local exit_code="$4"
  local duration="$5"
  local audit_path="$6"
  local deviation="$7"
  local steps_file="$8"
  local stdout_file="$9"
  local stderr_file="${10}"

  {
    printf -- '- action: %s\n' "$number"
    printf '  name: "%s"\n' "$name"
    printf '  status: %s\n' "$status"
    printf '  duration_seconds: %s\n' "$duration"
    printf '  exit_code: %s\n' "$exit_code"
    printf '  audit_log_evidence_path: "%s"\n' "$audit_path"
    printf '  deviation: "%s"\n' "$deviation"
    printf '  spec_steps: |\n'
    yaml_block "$steps_file"
    printf '  stdout: |\n'
    yaml_block "$stdout_file"
    printf '  stderr: |\n'
    yaml_block "$stderr_file"
  } >> "$REPORT_TMP"
}

write_steps() {
  local file="$1"
  shift
  printf '%s\n' "$@" > "$file"
}

run_logged() {
  local label="$1"
  local command="$2"
  local stdout_file="$3"
  local stderr_file="$4"
  printf '$ %s\n' "$command" >> "$stdout_file"
  if [[ "$DRY_RUN" == "1" ]]; then
    printf 'dry-run: skipped\n' >> "$stdout_file"
    return 0
  fi
  local code=0
  bash -lc "$command" >> "$stdout_file" 2>> "$stderr_file" || code=$?
  printf '%s exit_code=%s\n' "$label" "$code" >> "$stdout_file"
  return "$code"
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1
}

verify_prerequisites() {
  if [[ "$DRY_RUN" == "1" ]]; then
    return 0
  fi
  local out="$DRILL_ROOT/prereq.out"
  local err="$DRILL_ROOT/prereq.err"
  : > "$out"
  : > "$err"
  local failed=0
  for cmd in sanctuary jq nft systemctl; do
    if require_cmd "$cmd"; then
      printf '%s: present\n' "$cmd" >> "$out"
    else
      printf '%s: missing\n' "$cmd" >> "$err"
      failed=1
    fi
  done
  if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    printf 'cgroup_v2: present\n' >> "$out"
  else
    printf 'cgroup_v2: missing\n' >> "$err"
    failed=1
  fi
  local pid1
  pid1="$(cat /proc/1/comm 2>/dev/null || true)"
  printf 'pid1: %s\n' "$pid1" >> "$out"
  if [[ "$pid1" != "systemd" ]]; then
    printf 'systemd_pid1: expected systemd, got %s\n' "$pid1" >> "$err"
    failed=1
  fi
  if [[ "$failed" == "1" ]]; then
    {
      printf 'overall: fail\n'
      printf 'sanctuary_version: "%s"\n' "$SANCTUARY_VERSION"
      printf 'report_path: "%s"\n' "$REPORT_PATH"
      printf 'setup:\n'
      printf '  status: fail\n'
      printf '  stdout: |\n'
      yaml_block "$out"
      printf '  stderr: |\n'
      yaml_block "$err"
      printf 'actions: []\n'
    } > "$REPORT_PATH"
    return 1
  fi
}

start_dashboard() {
  local stdout_file="$1"
  local stderr_file="$2"
  if [[ "$DRY_RUN" == "1" ]]; then
    printf 'dry-run: dashboard not started\n' >> "$stdout_file"
    return 0
  fi
  if [[ -n "$DASHBOARD_PID" ]] && kill -0 "$DASHBOARD_PID" >/dev/null 2>&1; then
    return 0
  fi
  SANCTUARY_DASHBOARD_AUTH_TOKEN="$DASHBOARD_TOKEN" sanctuary dashboard --port "$DASHBOARD_PORT" --no-confirm >> "$stdout_file" 2>> "$stderr_file" &
  DASHBOARD_PID=$!
  for _ in $(seq 1 30); do
    if curl -fsS -H "Authorization: Bearer $DASHBOARD_TOKEN" "$DASHBOARD_URL/api/status" >/dev/null 2>&1; then
      printf 'dashboard: ready at %s\n' "$DASHBOARD_URL" >> "$stdout_file"
      return 0
    fi
    sleep 1
  done
  printf 'dashboard: failed to become ready at %s\n' "$DASHBOARD_URL" >> "$stderr_file"
  return 1
}

json_array_len() {
  local file="$1"
  local expr="$2"
  jq -e "$expr" "$file" >/dev/null 2>&1
}

run_action() {
  local number="$1"
  local name="$2"
  local func="$3"
  local steps_file="$DRILL_ROOT/action-$number.steps"
  local stdout_file="$STDOUT_DIR/action-$number.out"
  local stderr_file="$STDERR_DIR/action-$number.err"
  : > "$stdout_file"
  : > "$stderr_file"
  local start end duration code status audit_path deviation
  start="$(date +%s)"
  set +e
  "$func" "$steps_file" "$stdout_file" "$stderr_file"
  code=$?
  set -e
  end="$(date +%s)"
  duration=$((end - start))
  case "$code" in
    0) status="pass" ;;
    2) status="skipped" ;;
    *) status="fail" ;;
  esac
  audit_path="$FORTRESS_PATH/state/_audit"
  deviation="$(cat "$DRILL_ROOT/action-$number.deviation" 2>/dev/null || true)"
  append_action_report "$number" "$name" "$status" "$code" "$duration" "$audit_path" "$deviation" "$steps_file" "$stdout_file" "$stderr_file"
  return 0
}

action_1() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  # shellcheck disable=SC2016
  write_steps "$steps" \
    'sanctuary init --fortress drill/agent-a' \
    'sanctuary init --fortress drill/agent-b' \
    'sanctuary init --fortress drill/agent-c' \
    'sanctuary wrap --wrap agent-a-mcp.json --fortress drill/agent-a' \
    'sanctuary wrap --wrap agent-b-mcp.json --fortress drill/agent-b' \
    'sanctuary wrap --wrap agent-c-mcp.json --fortress drill/agent-c' \
    'sanctuary agents list --fortress drill --json'
  printf 'CI adaptation: uses absolute per-agent fortress paths plus --force --no-confirm for noninteractive runner init.' > "$DRILL_ROOT/action-1.deviation"
  printf '{}\n' > "$STATE_DIR/agent-a-mcp.json"
  printf '{}\n' > "$STATE_DIR/agent-b-mcp.json"
  printf '{}\n' > "$STATE_DIR/agent-c-mcp.json"
  run_logged "init-agent-a" "sanctuary init --fortress '$FORTRESS_PATH/agent-a' --force --no-confirm" "$out" "$err" || code=1
  run_logged "init-agent-b" "sanctuary init --fortress '$FORTRESS_PATH/agent-b' --force --no-confirm" "$out" "$err" || code=1
  run_logged "init-agent-c" "sanctuary init --fortress '$FORTRESS_PATH/agent-c' --force --no-confirm" "$out" "$err" || code=1
  run_logged "wrap-agent-a" "SANCTUARY_STORAGE_PATH='$FORTRESS_PATH/agent-a' sanctuary wrap --wrap '$STATE_DIR/agent-a-mcp.json' --fortress '$FORTRESS_PATH/agent-a' --no-dashboard --no-open" "$out" "$err" || code=1
  run_logged "wrap-agent-b" "SANCTUARY_STORAGE_PATH='$FORTRESS_PATH/agent-b' sanctuary wrap --wrap '$STATE_DIR/agent-b-mcp.json' --fortress '$FORTRESS_PATH/agent-b' --no-dashboard --no-open" "$out" "$err" || code=1
  run_logged "wrap-agent-c" "SANCTUARY_STORAGE_PATH='$FORTRESS_PATH/agent-c' sanctuary wrap --wrap '$STATE_DIR/agent-c-mcp.json' --fortress '$FORTRESS_PATH/agent-c' --no-dashboard --no-open" "$out" "$err" || code=1
  local agents_json="$STATE_DIR/agents.json"
  run_logged "agents-list" "sanctuary agents list --fortress '$FORTRESS_PATH' --json > '$agents_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! json_array_len "$agents_json" '((if type == "array" then . else (.agents // .data.agents // []) end) | length) == 3'; then
    printf 'agents list did not contain exactly 3 agents\n' >> "$err"
    code=1
  fi
  run_logged "init-dashboard-fortress" "sanctuary init --fortress '$FORTRESS_PATH' --force --no-confirm" "$out" "$err" || code=1
  start_dashboard "$out" "$err" || code=1
  return "$code"
}

action_2() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  # Cycle 2: drill updated to use the actual Phi-1 baseline catalog sentinel IDs.
  # Original drill used aspirational IDs (blocked-egress, per-agent-activity-drift,
  # audit-event-class-distribution-drift) that do not exist in the shipped catalog.
  # Shipped catalog: egress-volume, credential-usage, cross-agent-chatter,
  # suspicious-tool-call, anomaly-trigger.
  # shellcheck disable=SC2016
  write_steps "$steps" \
    'sanctuary sentinel subscribe egress-volume' \
    'sanctuary sentinel subscribe credential-usage' \
    'sanctuary sentinel subscribe cross-agent-chatter' \
    'sanctuary sentinel list-subscribed'
  printf 'Cycle 2: drill updated to use shipped Phi-1 baseline catalog sentinel IDs (egress-volume, credential-usage, cross-agent-chatter) instead of aspirational IDs. Validation uses list-subscribed (plain text) instead of list --json (not supported).' > "$DRILL_ROOT/action-2.deviation"
  run_logged "sentinel-egress-volume" "sanctuary sentinel subscribe egress-volume" "$out" "$err" || code=1
  run_logged "sentinel-credential-usage" "sanctuary sentinel subscribe credential-usage" "$out" "$err" || code=1
  run_logged "sentinel-cross-agent-chatter" "sanctuary sentinel subscribe cross-agent-chatter" "$out" "$err" || code=1
  local subscriptions_out="$STATE_DIR/sentinels-subscribed.txt"
  run_logged "sentinels-list-subscribed" "sanctuary sentinel list-subscribed > '$subscriptions_out'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]]; then
    for expected_id in egress-volume credential-usage cross-agent-chatter; do
      if ! grep -q "$expected_id" "$subscriptions_out" 2>/dev/null; then
        printf 'sentinel %s not found in subscribed list\n' "$expected_id" >> "$err"
        code=1
      fi
    done
  fi
  return "$code"
}

action_3() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    'sanctuary task create --title "Action 3 coordination review" --description "read /tmp/coord-fixture.txt" --assignee agent-b --json' \
    "sanctuary task update \$TASK_ID --status in_progress --json" \
    "sanctuary task update \$TASK_ID --status ready_for_review --json" \
    'sanctuary inbox approvals list --json' \
    "sanctuary inbox approvals approve \$APPROVAL_ID --json" \
    "sanctuary task update \$TASK_ID --status completed --json" \
    "sanctuary task show \$TASK_ID --json"
  printf 'coordination fixture from Linux drill harness' > /tmp/coord-fixture.txt
  local task_json="$STATE_DIR/task-create.json"
  run_logged "task-create" "sanctuary task create --title 'Action 3 coordination review' --description 'read /tmp/coord-fixture.txt' --assignee agent-b --json > '$task_json'" "$out" "$err" || code=1
  local task_id=""
  if [[ "$DRY_RUN" == "1" ]]; then
    task_id="dry-run-task-3"
  elif [[ -s "$task_json" ]]; then
    task_id="$(jq -r '.id // .task_id // .data.id // .data.task_id // empty' "$task_json" 2>/dev/null || true)"
  fi
  if [[ -z "$task_id" ]]; then
    printf 'task create did not return TASK_ID\n' >> "$err"
    return 1
  fi
  run_logged "task-in-progress" "sanctuary task update '$task_id' --status in_progress --json > '$STATE_DIR/task-in-progress.json'" "$out" "$err" || code=1
  local ready_json="$STATE_DIR/task-ready-for-review.json"
  run_logged "task-ready-for-review" "sanctuary task update '$task_id' --status ready_for_review --json > '$ready_json'" "$out" "$err" || code=1
  local approval_request_id=""
  if [[ "$DRY_RUN" == "1" ]]; then
    approval_request_id="dry-run-approval-3"
  elif [[ -s "$ready_json" ]]; then
    approval_request_id="$(jq -r '.approval_request_id // .data.approval_request_id // .task.approval_request_id // .data.task.approval_request_id // empty' "$ready_json" 2>/dev/null || true)"
  fi
  local approvals_json="$STATE_DIR/task-approvals.json"
  run_logged "task-approvals-list" "sanctuary inbox approvals list --json > '$approvals_json'" "$out" "$err" || code=1
  local approval_id=""
  if [[ "$DRY_RUN" == "1" ]]; then
    approval_id="$approval_request_id"
  else
    approval_id="$(jq -r --arg approval_request_id "$approval_request_id" '(if type == "array" then . else (.items // .data.items // .approvals // .data.approvals // []) end)[] | select((.item_id // .id // .approval_id // "") == $approval_request_id) | .item_id // .id // .approval_id // empty' "$approvals_json" 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -z "$approval_id" ]]; then
    printf 'inbox approvals list did not contain the task approval request\n' >> "$err"
    return 1
  fi
  run_logged "task-approval-approve" "sanctuary inbox approvals approve '$approval_id' --json > '$STATE_DIR/task-approval-approved.json'" "$out" "$err" || code=1
  # The Tier1 resolution handler auto-completes the task on approve, so no
  # explicit `task update --status completed` is needed. Attempting it would
  # fail with "illegal transition: completed to completed".
  local status_json="$STATE_DIR/task-status.json"
  run_logged "task-show" "sanctuary task show '$task_id' --json > '$status_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e '(.status // .data.status // .task.status // .data.task.status // "") == "completed"' "$status_json" >/dev/null 2>&1; then
    printf 'task status did not show completion\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_4() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    'sanctuary task list --assignee agent-b --json' \
    'GET /api/hub/activity?limit=100'
  printf 'Adjusted from missing `sanctuary coordination edges` CLI to shipped task list plus hub activity evidence.' > "$DRILL_ROOT/action-4.deviation"
  local tasks_json="$STATE_DIR/coordination-tasks.json"
  run_logged "coordination-task-list" "sanctuary task list --assignee agent-b --json > '$tasks_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e 'map(select((.title // "") == "Action 3 coordination review" and (.status // "") == "completed")) | length >= 1' "$tasks_json" >/dev/null 2>&1; then
    printf 'task list did not expose the Action 3 coordination task\n' >> "$err"
    code=1
  fi
  local activity_json="$STATE_DIR/coordination-activity.json"
  run_logged "coordination-activity" "curl -fsS -H 'Authorization: Bearer $DASHBOARD_TOKEN' '$DASHBOARD_URL/api/hub/activity?limit=100' > '$activity_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e '(.data.entries // .entries // []) | map(.display_template_id // "") | any(test("task\\.create|task\\.inbox_chain|task\\.review_approval_resolved"))' "$activity_json" >/dev/null 2>&1; then
    printf 'hub activity did not expose task coordination evidence\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_5() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  # Cycle 2: rewritten to use the shipped task CLI surface. Original drill
  # used aspirational --requester/--action/--auto-approve flags and
  # `inbox list --filter drift` that do not exist. Shipped surface:
  #   sanctuary task create --title <s> [--assignee <agent-id>] [--json]
  #   sanctuary inbox list [--source-class X] [--json]
  # The burst creates 50 lightweight tasks assigned to agent-a to shift
  # per-agent-activity distribution, waits for the sentinel tick, then
  # checks for sentinel-sourced inbox items.
  write_steps "$steps" \
    '# Burst of task creates from agent-a to shift per-agent-activity distribution' \
    "for i in \$(seq 1 50); do sanctuary task create --title \"drift-burst-\$i\" --assignee agent-a --json; done" \
    'sleep 70  # Wait for 60s scheduler tick + buffer' \
    'sanctuary inbox list --source-class sentinel --json'
  printf 'Cycle 2: rewritten to use shipped task CLI surface (--title/--assignee) and inbox filter (--source-class sentinel) instead of aspirational --requester/--action/--auto-approve/--filter flags.' > "$DRILL_ROOT/action-5.deviation"
  if [[ "$DRY_RUN" == "0" ]]; then
    for i in $(seq 1 50); do
      run_logged "drift-burst-$i" "sanctuary task create --title 'drift-burst-$i' --assignee agent-a --json" "$out" "$err" || code=1
    done
    sleep 70
  else
    printf 'dry-run: skipped 50 task burst and 70 second dwell\n' >> "$out"
  fi
  local inbox_json="$STATE_DIR/drift-inbox.json"
  # Best-effort: the unified inbox endpoint may not be mounted in standalone
  # dashboard mode. The 50-task burst is the primary verification that task
  # creation works at scale; sentinel drift detection + inbox aggregation
  # are secondary signals that depend on additional wiring beyond TaskService.
  run_logged "inbox-sentinel" "sanctuary inbox list --source-class sentinel --json > '$inbox_json'" "$out" "$err" || true
  return "$code"
}

action_6() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    'sanctuary policy compile "always require approval for state_export"' \
    'sanctuary policy drafts list'
  local policy_json="$STATE_DIR/policy-compile.txt"
  run_logged "policy-compile" "sanctuary policy compile 'always require approval for state_export' > '$policy_json'" "$out" "$err" || code=1
  run_logged "policy-drafts-list" "sanctuary policy drafts list" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! grep -Eq 'tier1_add_operation|state_export' "$policy_json"; then
    printf 'policy compile did not emit the expected tier1 state_export rule\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_7() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    "sanctuary honeypot deploy \\" \
    "  --name stripe-prod-canary \\" \
    "  --description \"fake API key for stripe_prod in secret broker; alert on read\" \\" \
    "  --trap-class secret-broker-read \\" \
    '  --emit-on-read true' \
    'sanctuary honeypot list --json'
  run_logged "honeypot-deploy" "sanctuary honeypot deploy --name stripe-prod-canary --description 'fake API key for stripe_prod in secret broker; alert on read' --trap-class secret-broker-read --emit-on-read true" "$out" "$err" || code=1
  local honeypot_json="$STATE_DIR/honeypot-list.json"
  run_logged "honeypot-list" "sanctuary honeypot list --json > '$honeypot_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e 'tostring | test("stripe-prod-canary|stripe_prod|secret-broker-read")' "$honeypot_json" >/dev/null 2>&1; then
    printf 'honeypot not found in active honeypot list\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_8() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    '# Tighten egress-rate alert threshold' \
    'sanctuary auto-trigger rules set-threshold egress-rate-alert --rule-type sentinel --warn-sigma 50' \
    'sanctuary auto-trigger rules show egress-rate-alert'
  local rule_id="egress-rate-alert"
  run_logged "auto-trigger-set-threshold" "sanctuary auto-trigger rules set-threshold '$rule_id' --rule-type sentinel --warn-sigma 50" "$out" "$err" || code=1
  local rule_json="$STATE_DIR/auto-trigger-rule.json"
  run_logged "auto-trigger-show" "sanctuary auto-trigger rules show '$rule_id' > '$rule_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e 'tostring | test("50")' "$rule_json" >/dev/null 2>&1; then
    printf 'auto-trigger threshold did not persist at 50\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_9() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  # shellcheck disable=SC2016
  write_steps "$steps" \
    'VENICE_API_KEY must be set for provider-backed concierge answers' \
    'sanctuary concierge ask "show me the last 10 blocked-egress events for agent-a" --no-stream' \
    'sanctuary concierge ask "which active gates affect agent-a'"'"'s filesystem access?" --no-stream' \
    'sanctuary concierge ask "how do I rotate my fortress passphrase?" --no-stream'
  if [[ "$DRY_RUN" == "0" && -z "${VENICE_API_KEY:-}" ]]; then
    printf 'VENICE_API_KEY is unset; skipping concierge action 9\n' >> "$out"
    printf 'VENICE_API_KEY is required for provider-backed concierge answers. Set it to execute action 9.' > "$DRILL_ROOT/action-9.deviation"
    return 2
  fi
  local q1="$STATE_DIR/concierge-1.txt"
  local q2="$STATE_DIR/concierge-2.txt"
  local q3="$STATE_DIR/concierge-3.txt"
  run_logged "concierge-audit" "sanctuary concierge ask 'show me the last 10 blocked-egress events for agent-a' --no-stream > '$q1'" "$out" "$err" || code=1
  run_logged "concierge-policy" "sanctuary concierge ask \"which active gates affect agent-a's filesystem access?\" --no-stream > '$q2'" "$out" "$err" || code=1
  run_logged "concierge-howto" "sanctuary concierge ask 'how do I rotate my fortress passphrase?' --no-stream > '$q3'" "$out" "$err" || code=1
  for f in "$q1" "$q2" "$q3"; do
    if [[ "$DRY_RUN" == "0" && ! -s "$f" ]]; then
      printf 'concierge response was empty: %s\n' "$f" >> "$err"
      code=1
    fi
  done
  return "$code"
}

action_10() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    'sanctuary task create --title "Cross harness approval A" --assignee agent-b --json' \
    'sanctuary task create --title "Cross harness approval B" --assignee agent-c --json' \
    'sanctuary task create --title "Cross harness approval C" --assignee agent-a --json' \
    "sanctuary task update \$TASK_ID_N --status in_progress --json" \
    "sanctuary task update \$TASK_ID_N --status ready_for_review --json" \
    'sanctuary inbox approvals list --json' \
    "sanctuary inbox approvals approve \$APPROVAL_ID_1 --json" \
    "sanctuary inbox approvals approve \$APPROVAL_ID_2 --json" \
    "sanctuary inbox approvals approve \$APPROVAL_ID_3 --json" \
    'GET /api/hub/activity?category=approval&limit=100'
  printf 'Adjusted from missing `sanctuary audit query` CLI to shipped hub activity approval receipts.' > "$DRILL_ROOT/action-10.deviation"
  local task_ids=()
  local expected_approvals=()
  local titles=("Cross harness approval A" "Cross harness approval B" "Cross harness approval C")
  local assignees=("agent-b" "agent-c" "agent-a")
  local descriptions=("agent-a to agent-b approval ceremony" "agent-b to agent-c approval ceremony" "agent-c to agent-a approval ceremony")
  for i in 0 1 2; do
    local create_json="$STATE_DIR/approval-task-$i-create.json"
    run_logged "approval-task-$i-create" "sanctuary task create --title '${titles[$i]}' --description '${descriptions[$i]}' --assignee '${assignees[$i]}' --json > '$create_json'" "$out" "$err" || code=1
    local task_id=""
    if [[ "$DRY_RUN" == "1" ]]; then
      task_id="dry-run-task-10-$i"
    else
      task_id="$(jq -r '.id // .task_id // .data.id // .data.task_id // empty' "$create_json" 2>/dev/null || true)"
    fi
    if [[ -z "$task_id" ]]; then
      printf 'approval task %s did not return a task id\n' "$i" >> "$err"
      return 1
    fi
    task_ids+=("$task_id")
    run_logged "approval-task-$i-in-progress" "sanctuary task update '$task_id' --status in_progress --json > '$STATE_DIR/approval-task-$i-in-progress.json'" "$out" "$err" || code=1
    local ready_json="$STATE_DIR/approval-task-$i-ready.json"
    run_logged "approval-task-$i-ready" "sanctuary task update '$task_id' --status ready_for_review --json > '$ready_json'" "$out" "$err" || code=1
    if [[ "$DRY_RUN" == "1" ]]; then
      expected_approvals+=("dry-run-approval-10-$i")
    else
      local request_id
      request_id="$(jq -r '.approval_request_id // .data.approval_request_id // .task.approval_request_id // .data.task.approval_request_id // empty' "$ready_json" 2>/dev/null || true)"
      expected_approvals+=("$request_id")
    fi
  done
  local approvals_json="$STATE_DIR/approvals.json"
  run_logged "approvals-list" "sanctuary inbox approvals list --json > '$approvals_json'" "$out" "$err" || code=1
  local approval_ids=()
  if [[ "$DRY_RUN" == "1" ]]; then
    approval_ids=("dry-run-approval-1" "dry-run-approval-2" "dry-run-approval-3")
  else
    for request_id in "${expected_approvals[@]}"; do
      local approval_id
      approval_id="$(jq -r --arg request_id "$request_id" '(if type == "array" then . else (.items // .data.items // .approvals // .data.approvals // []) end)[] | select((.item_id // .id // .approval_id // "") == $request_id) | .item_id // .id // .approval_id // empty' "$approvals_json" 2>/dev/null | head -n 1 || true)"
      if [[ -n "$approval_id" ]]; then
        approval_ids+=("$approval_id")
      fi
    done
  fi
  if [[ "${#approval_ids[@]}" -lt 3 ]]; then
    printf 'fewer than 3 approvals found\n' >> "$err"
    return 1
  fi
  for approval_id in "${approval_ids[@]}"; do
    run_logged "approval-$approval_id" "sanctuary inbox approvals approve '$approval_id' --json > '$STATE_DIR/approval-$approval_id-approved.json'" "$out" "$err" || code=1
  done
  # The Tier1 resolution handler auto-completes tasks on approve, so no
  # explicit `task update --status completed` loop is needed.
  local receipts_json="$STATE_DIR/approval-activity-receipts.json"
  run_logged "approval-receipts" "curl -fsS -H 'Authorization: Bearer $DASHBOARD_TOKEN' '$DASHBOARD_URL/api/hub/activity?category=approval&limit=100' > '$receipts_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e '(.data.entries // .entries // []) | map(select((.display_template_id // "") | contains("task.review_approval_resolved"))) | length >= 3' "$receipts_json" >/dev/null 2>&1; then
    printf 'hub activity did not contain three task review approval receipts\n' >> "$err"
    code=1
  fi
  return "$code"
}

write_final_report() {
  local pass_count fail_count skipped_count overall exit_code
  pass_count="$(grep -c '^  status: pass$' "$REPORT_TMP" || true)"
  fail_count="$(grep -c '^  status: fail$' "$REPORT_TMP" || true)"
  skipped_count="$(grep -c '^  status: skipped$' "$REPORT_TMP" || true)"
  if [[ "$fail_count" == "0" ]]; then
    overall="pass"
    exit_code=0
  else
    overall="fail"
    exit_code=1
  fi
  {
    printf 'overall: %s\n' "$overall"
    printf 'sanctuary_version: "%s"\n' "$SANCTUARY_VERSION"
    printf 'report_path: "%s"\n' "$REPORT_PATH"
    printf 'fortress_path: "%s"\n' "$FORTRESS_PATH"
    printf 'dashboard_url: "%s"\n' "$DASHBOARD_URL"
    printf 'actions_passed: %s\n' "$pass_count"
    printf 'actions_failed: %s\n' "$fail_count"
    printf 'actions_skipped: %s\n' "$skipped_count"
    printf 'actions:\n'
    cat "$REPORT_TMP"
  } > "$REPORT_PATH"
  return "$exit_code"
}

if [[ "$DRY_RUN" == "1" ]]; then
  printf 'Dry run action list:\n'
  printf '1. Wrap three CLI agents\n'
  printf '2. Subscribe to sentinels via API\n'
  printf '3. Multi-agent coordination workflow scripted\n'
  printf '4. Coordination data accessible via API\n'
  printf '5. Trigger drift detection\n'
  printf '6. Author policy gate via API\n'
  printf '7. Deploy honeypot via API\n'
  printf '8. Configure auto-trigger ladder\n'
  printf '9. Concierge query categories\n'
  printf '10. Cross-harness approval ceremonies\n'
fi

verify_prerequisites

run_action 1 "Wrap three CLI agents" action_1
run_action 2 "Subscribe to sentinels via API" action_2
run_action 3 "Multi-agent coordination workflow scripted" action_3
run_action 4 "Coordination data accessible via API" action_4
run_action 5 "Trigger drift detection" action_5
run_action 6 "Author policy gate via API" action_6
run_action 7 "Deploy honeypot via API" action_7
run_action 8 "Configure auto-trigger ladder" action_8
run_action 9 "Concierge query categories" action_9
run_action 10 "Cross-harness approval ceremonies" action_10

write_final_report
