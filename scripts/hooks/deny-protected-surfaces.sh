#!/bin/bash
# PreToolUse deny hook: refuses edits to Sanctuary's public and claim-bearing surfaces.
#
# Why this exists (AGENTS.md rule 9, MUST-NEVER #9): docs/ is the GitHub Pages source
# for sanctuaryprotocol.ai (the public marketing/blog surface) and must never carry a
# vulnerability detail, a defect file:line anchor, or an unauthorized capability claim.
# .github/workflows/ holds the CI gates themselves (test-baseline-guard,
# assurance-matrix-guard, etc.); a builder that can edit its own gate can weaken the
# gate that is supposed to catch it. .test-baseline and ASSURANCE_MATRIX.md are the two
# claim-bearing files the AGENTS.md commit-discipline and assurance rules pin directly
# (the passing-test floor and the proven/partial capability table) -- a silent edit to
# either one is exactly the "capability claim without a drill" failure mode the
# assurance rules exist to prevent. .claude/settings.json, .claude/settings.local.json,
# and everything under scripts/hooks/ are the guard's OWN configuration and
# implementation: a builder that can edit the guard has no guard, so this hook protects
# itself with the same mechanism it protects everything else with.
#
# This hook binds under `claude --dangerously-skip-permissions` per the Claude Code
# hooks guide (https://code.claude.com/docs/en/hooks-guide): "PreToolUse hooks fire
# before any permission-mode check, in every permission mode... A hook that returns
# permissionDecision: 'deny' blocks the tool even in bypassPermissions mode or with
# --dangerously-skip-permissions." That is the property this prototype relies on and
# that the drill in the accompanying report exists to verify empirically, per the
# AGENTS.md "no capability claim without a drill" rule.
#
# Bash-command matching below is deliberately best-effort textual pattern matching, not
# a parse of the shell command. The hooks guide says so explicitly: "Because the filter
# is best-effort, use the permission system rather than a hook to enforce a hard allow
# or deny." This hook is a prototype tripwire on top of that filter, not a replacement
# for it -- it can both over-block (a command that merely mentions a protected path in
# a read-only context alongside an unrelated '>') and under-block (an obfuscated or
# indirect write, e.g. through a wrapper script or a second shell).
#
# Override mechanism (VISIBILITY, NOT A SECURITY BOUNDARY): if the environment variable
# SANCTUARY_PUBLIC_SURFACE_EDIT is set to a non-empty reason string, this hook allows
# the call instead of denying it, and records "PUBLIC-SURFACE EDIT ALLOWED: <reason>"
# two ways: to stderr (for the hook's own debug log), and as the hooks-contract JSON
# `{"systemMessage": "..."}` field on stdout with exit 0, which Claude Code surfaces in
# the calling agent's own visible transcript (stderr alone is silent there on a
# non-blocking/allow decision). This is so the allowance lands in the session record
# instead of requiring the hook to be disabled, bypassed with --no-verify-equivalent
# flags, or silently worked around. Any builder invoked with --dangerously-skip-permissions
# can set this variable itself -- it is a record-keeping mechanism for a deliberate,
# legitimate public-surface change (a docs PR, a reviewed .test-baseline bump, a
# reviewed ASSURANCE_MATRIX.md edit), not a defense against a malicious or careless
# builder. Coordinator dispatch prompts set this variable only for workers explicitly
# scoped to docs/matrix/baseline work, and only for that dispatch.

set -euo pipefail

INPUT=$(cat)

TOOL_NAME=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty')
PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(printf '%s' "$INPUT" | jq -r '.cwd // empty')}"

PROTECTED_SET_DESC="docs/, .github/workflows/, .test-baseline, ASSURANCE_MATRIX.md, .claude/settings.json, .claude/settings.local.json, and scripts/hooks/"

deny() {
  local surface="$1"
  local rule="$2"
  if [ -n "${SANCTUARY_PUBLIC_SURFACE_EDIT:-}" ]; then
    printf 'PUBLIC-SURFACE EDIT ALLOWED: %s\n' "$SANCTUARY_PUBLIC_SURFACE_EDIT" >&2
    # systemMessage is a top-level field, a sibling of hookSpecificOutput, per the
    # hooks-contract JSON shape -- Claude Code relays it into the calling agent's
    # visible transcript, unlike plain stderr on a non-blocking/allow decision.
    jq -n \
      --arg msg "PUBLIC-SURFACE EDIT ALLOWED: $SANCTUARY_PUBLIC_SURFACE_EDIT" \
      '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "allow"}, systemMessage: $msg}'
    exit 0
  fi
  jq -n \
    --arg reason "Blocked: '$surface' is a protected surface (AGENTS.md rule 9 / commit-discipline). $rule" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

allow_silent() {
  exit 0
}

# Normalize an absolute or relative path to project-root-relative, best-effort.
normalize_path() {
  local p="$1"
  if [ -n "$PROJECT_DIR" ] && [[ "$p" == "$PROJECT_DIR"/* ]]; then
    p="${p#"$PROJECT_DIR"/}"
  fi
  p="${p#./}"
  printf '%s' "$p"
}

# True (exit 0) if the given project-relative path falls under a protected surface.
# Includes the guard's own config and implementation -- see header comment.
is_protected_path() {
  local rel="$1"
  case "$rel" in
    docs/*) return 0 ;;
    .github/workflows/*) return 0 ;;
    .test-baseline) return 0 ;;
    ASSURANCE_MATRIX.md) return 0 ;;
    .claude/settings.json) return 0 ;;
    .claude/settings.local.json) return 0 ;;
    scripts/hooks/*) return 0 ;;
    *) return 1 ;;
  esac
}

case "$TOOL_NAME" in
  Write|Edit|MultiEdit)
    FILE_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty')
    [ -z "$FILE_PATH" ] && allow_silent
    REL=$(normalize_path "$FILE_PATH")
    if is_protected_path "$REL"; then
      deny "$REL" "$TOOL_NAME calls against $PROTECTED_SET_DESC are refused; edit through a reviewed PR instead (or see the SANCTUARY_PUBLIC_SURFACE_EDIT override in this script's header for legitimate public-surface dispatches)."
    fi
    allow_silent
    ;;
  NotebookEdit)
    NB_PATH=$(printf '%s' "$INPUT" | jq -r '.tool_input.notebook_path // .tool_input.file_path // empty')
    [ -z "$NB_PATH" ] && allow_silent
    REL=$(normalize_path "$NB_PATH")
    if is_protected_path "$REL"; then
      deny "$REL" "NotebookEdit calls against $PROTECTED_SET_DESC are refused; edit through a reviewed PR instead (or see the SANCTUARY_PUBLIC_SURFACE_EDIT override in this script's header for legitimate public-surface dispatches)."
    fi
    allow_silent
    ;;
  Bash)
    COMMAND=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
    [ -z "$COMMAND" ] && allow_silent
    # Best-effort textual match only (see header comment): flag a command that both
    # names a protected path AND carries a mutation indicator (redirection, sed -i, or
    # tee). This does not parse the shell command and can be fooled by indirection.
    if printf '%s' "$COMMAND" | grep -qE '(^|[[:space:]/])(docs/|\.github/workflows/|\.test-baseline|ASSURANCE_MATRIX\.md|\.claude/settings\.json|\.claude/settings\.local\.json|scripts/hooks/)'; then
      if printf '%s' "$COMMAND" | grep -qE '(>>?[^=]|\bsed[[:space:]].*-i\b|\btee\b)'; then
        deny "(bash command mentioning a protected path with a redirection/sed -i/tee)" \
          "Bash commands that redirect, sed -i, or tee into $PROTECTED_SET_DESC are refused (best-effort textual match, not a shell parse)."
      fi
    fi
    allow_silent
    ;;
  *)
    allow_silent
    ;;
esac
