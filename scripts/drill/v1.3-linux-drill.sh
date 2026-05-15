#!/usr/bin/env bash
set -euo pipefail

# Single-file harness for the V1.3 Linux automated acceptance drill.
# It executes the ten scripted actions from the drill spec, captures
# stdout, stderr, and exit code per action, and writes one YAML report.

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
    2) status="partial-pass" ;;
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
    'sanctuary init --fortress drill' \
    'sanctuary wrap --agent agent-a --harness cli' \
    'sanctuary wrap --agent agent-b --harness cli' \
    'sanctuary wrap --agent agent-c --harness cli' \
    'sanctuary agents list --json'
  printf 'CI adaptation: uses absolute fortress path plus --force --no-confirm for noninteractive runner init.' > "$DRILL_ROOT/action-1.deviation"
  run_logged "init" "sanctuary init --fortress '$FORTRESS_PATH' --force --no-confirm" "$out" "$err" || code=1
  run_logged "wrap-agent-a" "sanctuary wrap --agent agent-a --harness cli --fortress '$FORTRESS_PATH' --no-dashboard --no-open" "$out" "$err" || code=1
  run_logged "wrap-agent-b" "sanctuary wrap --agent agent-b --harness cli --fortress '$FORTRESS_PATH' --no-dashboard --no-open" "$out" "$err" || code=1
  run_logged "wrap-agent-c" "sanctuary wrap --agent agent-c --harness cli --fortress '$FORTRESS_PATH' --no-dashboard --no-open" "$out" "$err" || code=1
  local agents_json="$STATE_DIR/agents.json"
  run_logged "agents-list" "sanctuary agents list --json > '$agents_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! json_array_len "$agents_json" '((if type == "array" then . else (.agents // .data.agents // []) end) | length) == 3'; then
    printf 'agents list did not contain exactly 3 agents\n' >> "$err"
    code=1
  fi
  start_dashboard "$out" "$err" || code=1
  return "$code"
}

action_2() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  # shellcheck disable=SC2016
  write_steps "$steps" \
    'sanctuary sentinels subscribe blocked-egress' \
    'sanctuary sentinels subscribe per-agent-activity-drift' \
    'sanctuary sentinels subscribe audit-event-class-distribution-drift' \
    'sanctuary sentinels list --json'
  run_logged "sentinel-blocked-egress" "sanctuary sentinels subscribe blocked-egress" "$out" "$err" || code=1
  run_logged "sentinel-agent-drift" "sanctuary sentinels subscribe per-agent-activity-drift" "$out" "$err" || code=1
  run_logged "sentinel-audit-drift" "sanctuary sentinels subscribe audit-event-class-distribution-drift" "$out" "$err" || code=1
  local subscriptions_json="$STATE_DIR/sentinels.json"
  run_logged "sentinels-list" "sanctuary sentinels list --json > '$subscriptions_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e 'walk(if type == "object" then . else . end)' "$subscriptions_json" >/dev/null 2>&1; then
    printf 'sentinels list did not produce valid JSON\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_3() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    'sanctuary task create --requester agent-a --target agent-b --action "read /tmp/coord-fixture.txt"' \
    "sanctuary task approve --id \$TASK_ID" \
    "sanctuary task status --id \$TASK_ID --json"
  printf 'coordination fixture from Linux drill harness' > /tmp/coord-fixture.txt
  local task_json="$STATE_DIR/task-create.json"
  run_logged "task-create" "sanctuary task create --requester agent-a --target agent-b --action 'read /tmp/coord-fixture.txt' --json > '$task_json'" "$out" "$err" || code=1
  local task_id=""
  if [[ "$DRY_RUN" == "1" ]]; then
    task_id="dry-run-task"
  elif [[ -s "$task_json" ]]; then
    task_id="$(jq -r '.id // .task_id // .data.id // .data.task_id // empty' "$task_json" 2>/dev/null || true)"
  fi
  if [[ -z "$task_id" ]]; then
    printf 'task create did not return TASK_ID\n' >> "$err"
    return 1
  fi
  run_logged "task-approve" "sanctuary task approve --id '$task_id'" "$out" "$err" || code=1
  local status_json="$STATE_DIR/task-status.json"
  run_logged "task-status" "sanctuary task status --id '$task_id' --json > '$status_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e '(.status // .data.status // "") | test("complete|completed|done|success")' "$status_json" >/dev/null 2>&1; then
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
  write_steps "$steps" 'sanctuary coordination edges --since 5m --json'
  local edges_json="$STATE_DIR/coordination-edges.json"
  run_logged "coordination-edges" "sanctuary coordination edges --since 5m --json > '$edges_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! json_array_len "$edges_json" '((.edges // .data.edges // .data.entries // .entries // []) | length) >= 1'; then
    printf 'coordination edges did not include an Action 3 edge\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_5() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    '# Burst of tool calls from agent-a to shift per-agent-activity distribution' \
    "for i in \$(seq 1 50); do sanctuary task create --requester agent-a --action \"echo \$i\" --auto-approve; done" \
    'sleep 70  # Wait for 60s scheduler tick + buffer' \
    'sanctuary inbox list --filter drift --json'
  if [[ "$DRY_RUN" == "0" ]]; then
    for i in $(seq 1 50); do
      run_logged "drift-burst-$i" "sanctuary task create --requester agent-a --action 'echo $i' --auto-approve" "$out" "$err" || code=1
    done
    sleep 70
  else
    printf 'dry-run: skipped 50 task burst and 70 second dwell\n' >> "$out"
  fi
  local inbox_json="$STATE_DIR/drift-inbox.json"
  run_logged "inbox-drift" "sanctuary inbox list --filter drift --json > '$inbox_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e 'tostring | test("drift"; "i")' "$inbox_json" >/dev/null 2>&1; then
    printf 'drift alert did not appear in unified inbox\n' >> "$err"
    code=1
  fi
  return "$code"
}

action_6() {
  local steps="$1"
  local out="$2"
  local err="$3"
  local code=0
  write_steps "$steps" \
    "sanctuary policy gate create \\" \
    "  --name block-etc-writes \\" \
    "  --description \"block any agent from writing to /etc\" \\" \
    "  --substrate-selector '{\"action_class\":\"filesystem_write\",\"path_prefix\":\"/etc\"}' \\" \
    '  --action deny' \
    'sanctuary policy list --json'
  run_logged "policy-gate-create" "sanctuary policy gate create --name block-etc-writes --description 'block any agent from writing to /etc' --substrate-selector '{\"action_class\":\"filesystem_write\",\"path_prefix\":\"/etc\"}' --action deny" "$out" "$err" || code=1
  local policy_json="$STATE_DIR/policy-list.json"
  run_logged "policy-list" "sanctuary policy list --json > '$policy_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! jq -e 'tostring | test("block-etc-writes") and test("filesystem_write") and test("/etc")' "$policy_json" >/dev/null 2>&1; then
    printf 'policy gate not found in active policy list\n' >> "$err"
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
    'sanctuary auto-trigger rules list --json' \
    "RULE_ID=\$(sanctuary auto-trigger rules list --json | jq -r '.[] | select(.name==\"egress-rate-alert\") | .id')" \
    "sanctuary auto-trigger rules patch --id \"\$RULE_ID\" --threshold 50" \
    "sanctuary auto-trigger rules get --id \"\$RULE_ID\" --json" \
    'sanctuary audit query --action auto-trigger-rule-patch --json'
  local rules_json="$STATE_DIR/auto-trigger-rules.json"
  run_logged "auto-trigger-list" "sanctuary auto-trigger rules list --json > '$rules_json'" "$out" "$err" || code=1
  local rule_id=""
  if [[ "$DRY_RUN" == "1" ]]; then
    rule_id="egress-rate-alert"
  elif [[ -s "$rules_json" ]]; then
    rule_id="$(jq -r '(.rules // .data.rules // . // []) | .[]? | select(.name=="egress-rate-alert" or .id=="egress-rate-alert") | .id' "$rules_json" 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -z "$rule_id" ]]; then
    printf 'egress-rate-alert rule not found\n' >> "$err"
    return 1
  fi
  run_logged "auto-trigger-patch" "sanctuary auto-trigger rules patch --id '$rule_id' --threshold 50" "$out" "$err" || code=1
  local rule_json="$STATE_DIR/auto-trigger-rule.json"
  run_logged "auto-trigger-get" "sanctuary auto-trigger rules get --id '$rule_id' --json > '$rule_json'" "$out" "$err" || code=1
  run_logged "audit-auto-trigger" "sanctuary audit query --action auto-trigger-rule-patch --json" "$out" "$err" || code=1
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
    'sanctuary concierge ask "show me the last 10 blocked-egress events for agent-a"' \
    'sanctuary concierge ask "which active gates affect agent-a'"'"'s filesystem access?"' \
    'sanctuary concierge ask "how do I rotate my fortress passphrase?"'
  local q1="$STATE_DIR/concierge-1.txt"
  local q2="$STATE_DIR/concierge-2.txt"
  local q3="$STATE_DIR/concierge-3.txt"
  run_logged "concierge-audit" "sanctuary concierge ask 'show me the last 10 blocked-egress events for agent-a' > '$q1'" "$out" "$err" || code=1
  run_logged "concierge-policy" "sanctuary concierge ask \"which active gates affect agent-a's filesystem access?\" > '$q2'" "$out" "$err" || code=1
  run_logged "concierge-howto" "sanctuary concierge ask 'how do I rotate my fortress passphrase?' > '$q3'" "$out" "$err" || code=1
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
    'sanctuary task create --requester agent-a --target agent-b --action "approval-required-task-a"' \
    'sanctuary task create --requester agent-b --target agent-c --action "approval-required-task-b"' \
    'sanctuary task create --requester agent-c --target agent-a --action "approval-required-task-c"' \
    'sanctuary inbox approvals list --json' \
    "sanctuary inbox approvals approve --id \$APPROVAL_ID_1" \
    "sanctuary inbox approvals approve --id \$APPROVAL_ID_2" \
    "sanctuary inbox approvals approve --id \$APPROVAL_ID_3" \
    'sanctuary audit query --action approval-receipt --since 5m --json'
  run_logged "approval-task-a" "sanctuary task create --requester agent-a --target agent-b --action 'approval-required-task-a'" "$out" "$err" || code=1
  run_logged "approval-task-b" "sanctuary task create --requester agent-b --target agent-c --action 'approval-required-task-b'" "$out" "$err" || code=1
  run_logged "approval-task-c" "sanctuary task create --requester agent-c --target agent-a --action 'approval-required-task-c'" "$out" "$err" || code=1
  local approvals_json="$STATE_DIR/approvals.json"
  run_logged "approvals-list" "sanctuary inbox approvals list --json > '$approvals_json'" "$out" "$err" || code=1
  local approval_ids=()
  if [[ "$DRY_RUN" == "1" ]]; then
    approval_ids=("dry-run-approval-1" "dry-run-approval-2" "dry-run-approval-3")
  else
    while IFS= read -r approval_id; do
      approval_ids+=("$approval_id")
    done < <(jq -r '(.approvals // .data.approvals // .items // .data.items // [])[] | .id // .approval_id // .item_id // empty' "$approvals_json" 2>/dev/null | head -n 3)
  fi
  if [[ "${#approval_ids[@]}" -lt 3 ]]; then
    printf 'fewer than 3 approvals found\n' >> "$err"
    return 1
  fi
  for approval_id in "${approval_ids[@]}"; do
    run_logged "approval-$approval_id" "sanctuary inbox approvals approve --id '$approval_id'" "$out" "$err" || code=1
  done
  local receipts_json="$STATE_DIR/approval-receipts.json"
  run_logged "approval-receipts" "sanctuary audit query --action approval-receipt --since 5m --json > '$receipts_json'" "$out" "$err" || code=1
  if [[ "$DRY_RUN" == "0" ]] && ! json_array_len "$receipts_json" '((.events // .data.events // .entries // .data.entries // []) | length) >= 3'; then
    printf 'audit log did not contain three approval-receipt events\n' >> "$err"
    code=1
  fi
  return "$code"
}

write_final_report() {
  local pass_count fail_count partial_count overall exit_code
  pass_count="$(grep -c '^  status: pass$' "$REPORT_TMP" || true)"
  fail_count="$(grep -c '^  status: fail$' "$REPORT_TMP" || true)"
  partial_count="$(grep -c '^  status: partial-pass$' "$REPORT_TMP" || true)"
  if [[ "$fail_count" == "0" && "$partial_count" == "0" ]]; then
    overall="pass"
    exit_code=0
  elif [[ "$fail_count" == "1" && "$pass_count" == "9" ]]; then
    overall="partial-pass"
    exit_code=2
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
    printf 'actions_partial: %s\n' "$partial_count"
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
