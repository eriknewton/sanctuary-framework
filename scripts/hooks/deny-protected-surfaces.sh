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
# (the passing-test floor and the proven/partial capability table). .claude/settings.json,
# .claude/settings.local.json, and everything under scripts/hooks/ are the guard's OWN
# configuration and implementation: a builder that can edit the guard has no guard, so
# this hook protects itself with the same mechanism it protects everything else with.
#
# This hook binds under `claude --dangerously-skip-permissions` per the Claude Code
# hooks guide (https://code.claude.com/docs/en/hooks-guide): "PreToolUse hooks fire
# before any permission-mode check, in every permission mode... A hook that returns
# permissionDecision: 'deny' blocks the tool even in bypassPermissions mode or with
# --dangerously-skip-permissions."
#
# ROUND-3 REDESIGN (subtraction, not addition): a round-2 adversarial review (Codex)
# found that the previous shell-semantics model for Bash commands -- tokenize, track a
# simulated cwd across `cd`, extract "the" destination of cp/mv/tee/sed -i/git
# checkout/an interpreter one-liner -- is a CLASS that cannot be closed by adding more
# cases to it: `P=docs/x.md; printf x > "$P"` (destination hidden behind a variable),
# `cd /missing || printf x > docs/x.md` (a failed cd desynchronizes the tracked cwd
# from the real one), `ln -s docs /tmp/alias && printf x > /tmp/alias/x.md` (the
# protected name is aliased through a symlink the hook cannot see because it does not
# exist until the command actually runs), `curl -o`, `rsync`, `patch`, `git apply` (each
# is one more command whose write-destination syntax would need its own case) all
# reached an ALLOW under the old model. The fix is to stop modeling the shell at all.
#
# THE RULE NOW (and only this rule) for a Bash command: remove every backslash-newline
# line-continuation pair, then strip every remaining `"`, `'`, and `\` character from
# the command text (character deletion, not shell parsing), then lowercase it (macOS's
# default filesystem is case-insensitive, so `DOCS/x.md` and `docs/x.md` name the same
# file), then check whether any protected-surface token appears at a path boundary:
# `docs/`, `.github/workflows/`, `.test-baseline`, `assurance_matrix.md`,
# `.claude/settings` (matches both settings.json and settings.local.json as a prefix),
# `scripts/hooks/`, and `docs`/`hooks` when adjacent to a path separator on at least one
# side (`docs/`, `/docs`, `hooks/`, `/hooks` -- see ROUND-4 hardening note below the
# BASH_PATTERNS array for why bare `docs`/`hooks` with no adjacent slash is deliberately
# NOT matched). If any DISTINCT surface matches, DENY; if more than one distinct surface
# matches in the same command, DENY unconditionally (never consulting the override --
# see ROUND-4 note 3). Otherwise ALLOW. There is no tokenization, no cwd tracking, no
# per-command write-destination table, and no interpreter-specific write-intent
# heuristic; what a command *does* with the string is irrelevant, only whether the
# string is present.
#
# THIS OVER-BLOCKS ON PURPOSE. `grep needle docs/x.md > /tmp/result` (read-only use of
# a protected path) now DENIES, where the round-2 destination-aware design allowed it.
# That is an accepted, deliberate trade: a destination-aware model is exactly the class
# that round 2 showed cannot be made sound against shell indirection, so this hook no
# longer tries to distinguish "reads from" versus "writes to" a protected path in a Bash
# command at all -- it refuses to run ANY command that spells a protected path, and the
# SANCTUARY_PUBLIC_SURFACE_EDIT override (below) is the escape hatch for legitimate
# work that trips it.
#
# THE ACCEPTED RESIDUAL: this is still a textual scan, not a real parser, so
# indirection that never spells the literal path text in the command string is not
# caught by this hook -- an encoded/obfuscated path (base64, string concatenation
# assembled at runtime), a path read from a variable or file set in an EARLIER,
# separately-evaluated command, a patch/diff file whose internal paths are inside a
# file this hook does not read (e.g. `git apply patch-with-no-path-on-the-cmdline`), AND
# (as of round 4's bare-word narrowing, see BASH_PATTERNS note 6) a symlink created from
# a BARE directory name with no adjacent path separator and then written through --
# `ln -s docs /tmp/alias && printf x > /tmp/alias/x.md` no longer denies, because
# neither `ln -s docs` (bare word, no adjacent `/`) nor `/tmp/alias/x.md` (never spells
# "docs") trips the scan. The same narrowing also reopens the plainer `cd docs &&
# printf x > x.md` (bare "docs" with a space, not a slash, on both sides) -- this hook
# does not track `cd`, so "x.md" alone spells nothing protected either. This residual is accepted, not closed, by this hook; the controls that stand behind
# it are: the commit-discipline pre-commit hook (`.githooks/pre-commit`, AGENTS.md) that
# runs typecheck+test on every local commit regardless of how a file was written, the
# CI disclosure-guard workflow that scans PR content and diffs for defect-disclosure
# patterns before merge, and GitHub branch protection requiring review before a change
# to a protected surface reaches main -- none of which depend on this hook catching the
# write at the moment a Bash tool call is made.
#
# FILE-PATH TOOLS (Write/Edit/MultiEdit/NotebookEdit) are unchanged in kind from round
# 1: file_path is resolved via Python's os.path.realpath (realpath -m semantics --
# resolves symlinks in existing ancestors, tolerates a nonexistent final component --
# this is what catches a symlink alias of docs/ and a `tmp/../docs/x.md` traversal).
# macOS's BSD `/bin/realpath` has no -m flag ("illegal option -- m", confirmed on this
# host) and macOS ships bash 3.2, so resolution goes through the embedded Python helper
# below rather than a shell `realpath -m` call. UNLIKE round 1, there is no bash-only
# fallback anymore: if python3 is not on PATH, a Write/Edit/MultiEdit/NotebookEdit call
# is DENIED outright, naming python3 as the reason (see require_python_or_deny) --
# round 2 found the previous bash fallback could fail open, so the fallback is deleted
# rather than hardened. The Bash-command text scan above needs no interpreter and has
# no such dependency.
#
# FAIL-CLOSED INPUT HANDLING: tool_name, file_path/notebook_path, and command are each
# read through a jq filter that requires the field to be present, non-null, and of
# JSON type "string" (see the `type == "string"` guards below) -- a missing key, an
# explicit JSON null, or a wrong-typed value (number, bool, array, object) all collapse
# to the empty string and trip the same explicit deny_missing_field() path, naming the
# field. This closes the round-2 finding that a JSON `null` for `command` rendered as
# the four-character text "null" (jq -r's encoding of a null value) rather than empty,
# which slipped past an `-z` check and reached an implicit allow. `set -euo pipefail`
# is active for the whole script, so an unparseable JSON payload on stdin, or any
# unexpected nonzero exit from jq/python3 inside a helper, aborts the script instead of
# continuing past the failure -- and this script's caller in .claude/settings.json
# already wraps the invocation in `<script> || echo '{...deny...}'`, so a nonzero exit
# here (crash, missing field the script does not otherwise catch, missing script)
# always resolves to an explicit deny, never to an unhandled default allow.
#
# OVERRIDE (VISIBILITY, NOT A SECURITY BOUNDARY): SANCTUARY_PUBLIC_SURFACE_EDIT must be
# "<surface>:<reason>" where surface is exactly one of docs, workflows, baseline,
# matrix, guard (guard covers .claude/settings.json, .claude/settings.local.json, and
# scripts/hooks/ together, since those are the guard's own config+implementation and
# are authorized as one unit). The reason is trimmed of leading/trailing whitespace
# BEFORE the non-empty check, so a whitespace-only reason (e.g. "docs:   ") is treated
# as no reason and denies -- round 2 found the previous sanitize-only (no trim) check
# let whitespace-only reasons through. A well-formed override allows ONLY a call whose
# classified surface matches; any other protected call is still denied while the
# variable is set, and the deny reason says the override did not cover this surface.
# Any builder invoked with --dangerously-skip-permissions can set this variable itself
# -- it exists so a deliberate, legitimate public-surface change leaves a record in the
# session transcript (the hooks-contract `systemMessage` field on an allow decision)
# instead of requiring the hook to be disabled or worked around.

set -euo pipefail

INPUT=$(cat)

# fix 5 (kept from round 1): strip newlines/CR (replaced with a space, not
# silently dropped) and other C0/DEL control bytes, then cap at 200 chars --
# applied to any user- or override-controlled text this hook echoes back into
# a systemMessage or permissionDecisionReason.
sanitize_text() {
  local s="$1"
  s="${s//$'\n'/ }"
  s="${s//$'\r'/ }"
  s=$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037\177')
  if [ "${#s}" -gt 200 ]; then
    s="${s:0:200}"
  fi
  printf '%s' "$s"
}

# Trims leading and trailing ASCII whitespace. Round-2 finding: an override
# reason of "   " (spaces only) passed sanitize_text's non-empty check
# because sanitize_text never trimmed. The override validity check below
# trims BEFORE testing non-empty.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

deny_json() {
  local reason
  reason=$(sanitize_text "$1")
  jq -n --arg reason "$reason" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
  exit 0
}

# fix 3: an event this hook cannot classify (missing/null/wrong-typed field)
# is denied, naming the field, rather than falling through to allow. Never
# overridable via SANCTUARY_PUBLIC_SURFACE_EDIT -- there is no surface to
# authorize when the call itself could not be classified.
deny_missing_field() {
  local field="$1"
  deny_json "Blocked: PreToolUse event for '$TOOL_NAME' carried no usable '$field' (missing, null, or non-string). Failing closed per AGENTS.md rule 5 (never silently degrade to a less-secure behavior on error)."
}

allow_silent() {
  exit 0
}

# jq helper: reads a top-level-or-nested string field, collapsing "missing",
# "null", and "present but not a JSON string" all to the empty string, so
# every caller can use one `[ -z "$X" ]` check to fail closed uniformly
# (round-2 finding: a JSON null for `command` rendered as the text "null"
# under the old `// empty` filter and slipped past an -z check).
jq_required_string() {
  local filter="$1"
  printf '%s' "$INPUT" | jq -r "$filter as \$v | if (\$v != null) and ((\$v|type) == \"string\") and (\$v != \"\") then \$v else \"\" end" 2>/dev/null || printf ''
}

TOOL_NAME=$(jq_required_string '.tool_name')
if [ -z "$TOOL_NAME" ]; then
  deny_json "Blocked: PreToolUse event carried no usable 'tool_name' (missing, null, or non-string). Failing closed per AGENTS.md rule 5."
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-$(printf '%s' "$INPUT" | jq -r '.cwd // empty')}"
if [ -z "$PROJECT_DIR" ]; then
  deny_json "Blocked: PreToolUse event carried neither CLAUDE_PROJECT_DIR nor .cwd; the protected-surfaces guard cannot resolve paths without a project root, failing closed per AGENTS.md rule 5."
fi

PROTECTED_SET_DESC="docs/, .github/workflows/, .test-baseline, ASSURANCE_MATRIX.md, .claude/settings.json, .claude/settings.local.json, and scripts/hooks/ (override surfaces: docs, workflows, baseline, matrix, guard -- see SANCTUARY_PUBLIC_SURFACE_EDIT format '<surface>:<reason>' in this script's header)"

# fix 4: parse SANCTUARY_PUBLIC_SURFACE_EDIT as "<surface>:<reason>". Anything
# that does not split on the first ':' into a known surface token plus a
# non-empty (after trim + sanitize) reason is treated as NO override.
OVERRIDE_RAW="${SANCTUARY_PUBLIC_SURFACE_EDIT:-}"
OVERRIDE_SURFACE=""
OVERRIDE_REASON=""
case "$OVERRIDE_RAW" in
  *:*)
    OVERRIDE_SURFACE="${OVERRIDE_RAW%%:*}"
    OVERRIDE_REASON="${OVERRIDE_RAW#*:}"
    ;;
esac
OVERRIDE_REASON_S=$(trim "$(sanitize_text "$OVERRIDE_REASON")")
OVERRIDE_VALID=0
case "$OVERRIDE_SURFACE" in
  docs|workflows|baseline|matrix|guard)
    if [ -n "$OVERRIDE_REASON_S" ]; then
      OVERRIDE_VALID=1
    fi
    ;;
esac

# Emits the final allow/deny decision for a classified, protected call.
# $1 = surface name (docs/workflows/baseline/matrix/guard), $2 = human-readable
# subject (resolved path or bash-match description), $3 = rule text.
emit_deny_or_override() {
  local surface="$1" subject="$2" rule_text="$3"
  if [ "$OVERRIDE_VALID" = "1" ] && [ "$OVERRIDE_SURFACE" = "$surface" ]; then
    local msg
    msg=$(sanitize_text "PUBLIC-SURFACE EDIT ALLOWED [$surface]: $OVERRIDE_REASON_S")
    printf '%s\n' "$msg" >&2
    # systemMessage is a top-level field, a sibling of hookSpecificOutput, per the
    # hooks-contract JSON shape -- Claude Code relays it into the calling agent's
    # visible transcript, unlike plain stderr on a non-blocking/allow decision.
    jq -n --arg msg "$msg" \
      '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "allow"}, systemMessage: $msg}'
    exit 0
  fi
  # Decision-critical content (what was blocked, its surface, and whether an
  # override was present but did not cover it) is placed FIRST, ahead of the
  # longer boilerplate rule_text -- sanitize_text's 200-char cap truncates
  # from the tail, so front-loading guarantees the actionable part survives.
  local override_note=""
  if [ -n "$OVERRIDE_RAW" ]; then
    override_note=" Override present but not valid for surface '$surface' (need '$surface:<reason>', got surface token '$OVERRIDE_SURFACE')."
  fi
  local subject_s
  subject_s=$(sanitize_text "$subject")
  deny_json "Blocked: '$subject_s' is protected (surface=$surface, AGENTS.md rule 9).${override_note} $rule_text"
}

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
fi

require_python_or_deny() {
  if [ -z "$PYTHON_BIN" ]; then
    deny_json "Blocked: python3 is required to resolve and classify a file path (symlink/traversal-safe realpath) and was not found on PATH. Failing closed per AGENTS.md rule 5 rather than falling back to a weaker matcher (round-2 finding: the previous bash-only fallback could fail open)."
  fi
}

CLASSIFY_PY=""
init_classify_py() {
  [ -n "$CLASSIFY_PY" ] && return 0
  CLASSIFY_PY=$(mktemp "${TMPDIR:-/tmp}/sanctuary-deny-classify.XXXXXX")
  trap 'rm -f "$CLASSIFY_PY"' EXIT
  cat > "$CLASSIFY_PY" <<'PYEOF'
import sys, os, json

# File-path classification only (fix 1). Bash-command classification no
# longer uses Python at all -- see the header's ROUND-3 REDESIGN note; it is
# a pure literal-text scan done directly in bash/grep below.

def resolve_abs(base_dir, raw):
    # realpath -m semantics: resolves symlinks in existing ancestors, tolerates
    # a nonexistent final path component -- this is what catches a symlink
    # alias of a protected directory, unlike a purely lexical '..' collapse.
    base_real = os.path.realpath(base_dir)
    absp = raw if os.path.isabs(raw) else os.path.join(base_real, raw)
    return os.path.realpath(absp)

def rel_to_project(project_dir, abs_path):
    proj_real = os.path.realpath(project_dir)
    if abs_path == proj_real:
        return "."
    prefix = proj_real + os.sep
    if abs_path.startswith(prefix):
        return abs_path[len(prefix):]
    return None

def classify_target(rel):
    # Round-4 finding: macOS's default filesystem (APFS/HFS+) is
    # case-INsensitive, so `DOCS/x.md` and `Docs/X.md` refer to the same
    # on-disk file as `docs/x.md` even though the string differs. Compare on
    # a lowercased copy so the predicate matches regardless of case; `rel`
    # itself (original case) is still what gets reported back to the caller.
    if rel is None:
        return None
    rel_l = rel.lower()
    if rel_l == "docs" or rel_l.startswith("docs/"):
        return "docs"
    if rel_l == ".github/workflows" or rel_l.startswith(".github/workflows/"):
        return "workflows"
    if rel_l == ".test-baseline":
        return "baseline"
    if rel_l == "assurance_matrix.md":
        return "matrix"
    if rel_l in (".claude/settings.json", ".claude/settings.local.json"):
        return "guard"
    if rel_l == "scripts/hooks" or rel_l.startswith("scripts/hooks/"):
        return "guard"
    return None

def main():
    payload = json.load(sys.stdin)
    project_dir = payload.get("project_dir", "")
    raw = payload.get("path", "")
    abs_path = resolve_abs(project_dir, raw)
    rel = rel_to_project(project_dir, abs_path)
    surface = classify_target(rel)
    print(json.dumps({"protected": surface is not None, "surface": surface, "resolved_rel": rel}))

main()
PYEOF
}

classify_file() {
  # CALLERS MUST call require_python_or_deny THEMSELVES, directly in the main
  # script flow, BEFORE invoking this function via command substitution
  # (`RESULT=$(classify_file ...)`). A `deny_json`/`exit` called from inside
  # a function that is itself running inside a `$(...)` subshell only exits
  # that subshell -- the exit status and stdout get swallowed into $RESULT,
  # and the main script keeps running past what looked like a deny. This is
  # exactly the shape of a round-3 self-review finding: require_python_or_deny
  # used to be called from inside this function and its deny never reached
  # the caller, silently falling through to allow_silent instead.
  local raw_path="$1"
  init_classify_py
  jq -n --arg pd "$PROJECT_DIR" --arg p "$raw_path" '{project_dir:$pd,path:$p}' \
    | "$PYTHON_BIN" "$CLASSIFY_PY"
}

# --- Bash-command classifier: pure literal-text token match (ROUND-3
# REDESIGN, see header). Strip quotes/backslashes, then check each
# protected-surface token at a path boundary. No tokenization, no cwd
# tracking, no per-command destination table, no interpreter heuristic --
# deliberately, per the adversarial finding that the previous
# destination-aware model could not be closed against shell indirection.
#
# ROUND-4 hardening (all inside this same "no shell modelling" rule, not a
# return to modelling):
#   1. Case-insensitivity: macOS's default filesystem is case-INsensitive, so
#      `DOCS/x.md` is the same on-disk target as `docs/x.md`. The command
#      text and every pattern below are lowercased before matching.
#   2. Line continuations: a backslash immediately followed by a newline is a
#      shell line-continuation that the real shell removes before `docs`
#      and `/x.md` are ever adjacent to each other; `do\`<LF>`cs/x.md` would
#      otherwise evade a literal scan. Every backslash-newline PAIR is
#      deleted before the general backslash/quote stripping (which would
#      otherwise leave the newline behind and still miss the join).
#   3. Multi-surface override scope: this function now returns the FULL set
#      of distinct surfaces matched, not just the first. The caller denies
#      unconditionally whenever more than one distinct surface is touched,
#      because a single SANCTUARY_PUBLIC_SURFACE_EDIT override names exactly
#      one surface and cannot cover two -- see the Bash case branch below.
#   6. Bare-word narrowing: `docs` and `hooks` alone (e.g. `rg 'hooks'
#      server/src`, `npm test -- --grep docs`) no longer match. Only forms
#      adjacent to a path separator on at least one side count: `docs/`,
#      `/docs`, `hooks/`, `/hooks`. This deliberately reopens part of the
#      round-3 residual: `ln -s docs /tmp/alias && printf x > /tmp/alias/x.md`
#      (bare "docs", no adjacent slash) is no longer caught by this hook --
#      it now falls into the same accepted-indirection residual as an
#      encoded path or a path read from an earlier command (see header), and
#      is NOT reopened as a special case, per the explicit instruction that
#      this trade (fewer false positives on ordinary words) is intentional.
#
# Boundary for the non-bare tokens = "not preceded by a word character
# (letter/digit/_)". Broader than requiring a specific separator on purpose:
# after quote-stripping, a path token inside code-like text (e.g.
# `open(docs/x.md,'w')` with its quotes already stripped) is adjacent to
# punctuation like '(' that a narrower boundary class would miss.
BASH_SURFACES=(docs workflows baseline matrix guard guard docs guard guard)
BASH_PATTERNS=(
  '(^|[^a-z0-9_])docs/'
  '(^|[^a-z0-9_])\.github/workflows/'
  '(^|[^a-z0-9_])\.test-baseline'
  '(^|[^a-z0-9_])assurance_matrix\.md'
  '(^|[^a-z0-9_])\.claude/settings'
  '(^|[^a-z0-9_])scripts/hooks/'
  '/docs([^a-z0-9_]|$)'
  '(^|[^a-z0-9_])hooks/'
  '/hooks([^a-z0-9_]|$)'
)

# Sets these globals; does NOT print/return via command substitution (fix 4,
# see the invariant comment at the Bash case branch's call site for why).
BASHCLS_SURFACES=()

classify_bash_cmd_into_globals() {
  local cmd="$1"
  BASHCLS_SURFACES=()

  # Step 1: character deletion (not shell parsing) of every quote and
  # backslash byte, so a quoted ("docs/x.md") or backslash-escaped path
  # token still matches the boundary-anchored scan below. Pure bash
  # parameter-expansion substring removal, no subprocess -- confirmed
  # reliable for a SINGLE literal character pattern inside a function.
  local stripped="${cmd//\\/}"
  stripped="${stripped//\"/}"
  stripped="${stripped//\'/}"

  # Step 2 (fix 2, and fix 4's "no bash-glob-escape footgun" note): remove
  # EVERY newline character -- not just ones immediately preceded by a
  # backslash -- via `tr -d '\n'`, run in the MAIN shell as its own simple
  # command substitution with $? checked immediately (same discipline as
  # the lowercasing step below). This is a deliberate SUPERSET of "remove
  # backslash-newline pairs": it also joins text split across an ordinary
  # (non-continuation) newline, which is consistent with this hook's
  # documented over-block-by-design bias. An EARLIER attempt used bash's
  # own `${var//$'\\\n'/}` parameter-expansion pattern substitution to
  # remove only backslash-newline pairs; that pattern's search string
  # contains a literal backslash, and bash's glob engine treats a backslash
  # in a SEARCH PATTERN as an escape character -- observed on this host's
  # bash 3.2 to behave inconsistently between top-level and in-function
  # scope (in-function, it silently matched nothing, leaving the pair
  # intact, which is exactly how this bug was found: `do\`<LF>`cs/x.md`
  # reached an ALLOW). Routing this through `tr` in the main shell (already
  # the established pattern for the lowercasing step, see fix 4) avoids the
  # bash-glob quirk entirely and gives an explicit status check.
  local nolines
  nolines=$(printf '%s' "$stripped" | tr -d '\n')
  local tr1_rc=$?
  if [ "$tr1_rc" -ne 0 ]; then
    deny_json "Blocked: the Bash-command classifier's newline-strip step (tr) exited $tr1_rc while scanning this command. Failing closed per AGENTS.md rule 5 rather than treating a helper failure as 'no match'."
  fi

  # Step 3 (fix 1): lowercase. The other remaining external-tool call in the
  # classifier (bash 3.2 has no builtin case-fold, no `${var,,}`). Same
  # discipline: single simple command substitution in the main shell, $?
  # checked immediately -- this is the round-4 fix-4 finding: bash 3.2 does
  # not inherit errexit into a command-substitution subshell, so a failing
  # helper several layers inside one opaque `RESULT=$(...)` capture could
  # silently fall through to "no match" instead of aborting. A tr failure
  # here denies explicitly rather than being reinterpreted as "no match".
  local lower
  lower=$(printf '%s' "$nolines" | tr '[:upper:]' '[:lower:]')
  local tr2_rc=$?
  if [ "$tr2_rc" -ne 0 ]; then
    deny_json "Blocked: the Bash-command classifier's lowercasing step (tr) exited $tr2_rc while scanning this command. Failing closed per AGENTS.md rule 5 rather than treating a helper failure as 'no match'."
  fi

  # Step 4: match against every pattern using bash's OWN builtin ERE engine
  # (`[[ =~ ]]`), not an external `grep` -- this spawns no subprocess at all
  # for the match step, so there is no external-tool exit code to
  # misinterpret, and it runs directly in the main shell (this function is
  # called directly, never via `$(...)`), so `set -e` applies normally: an
  # unexpected bash-internal error here aborts the script and the
  # `.claude/settings.json` `|| echo '{...deny...}'` wrapper resolves it to
  # an explicit deny rather than a silent allow.
  local i surf already s
  for i in "${!BASH_PATTERNS[@]}"; do
    if [[ "$lower" =~ ${BASH_PATTERNS[$i]} ]]; then
      surf="${BASH_SURFACES[$i]}"
      already=0
      for s in "${BASHCLS_SURFACES[@]:-}"; do
        if [ "$s" = "$surf" ]; then
          already=1
          break
        fi
      done
      if [ "$already" -eq 0 ]; then
        BASHCLS_SURFACES+=("$surf")
      fi
    fi
  done
}

case "$TOOL_NAME" in
  Write|Edit|MultiEdit)
    FILE_PATH=$(jq_required_string '.tool_input.file_path')
    if [ -z "$FILE_PATH" ]; then
      deny_missing_field "tool_input.file_path"
    fi
    require_python_or_deny
    RESULT=$(classify_file "$FILE_PATH")
    PROTECTED=$(printf '%s' "$RESULT" | jq -r '.protected')
    if [ "$PROTECTED" = "true" ]; then
      SURFACE=$(printf '%s' "$RESULT" | jq -r '.surface // empty')
      RESOLVED=$(printf '%s' "$RESULT" | jq -r '.resolved_rel // empty')
      emit_deny_or_override "$SURFACE" "$RESOLVED" "$TOOL_NAME refused; edit through a reviewed PR, or set SANCTUARY_PUBLIC_SURFACE_EDIT (see script header). Full protected set: $PROTECTED_SET_DESC"
    fi
    allow_silent
    ;;
  NotebookEdit)
    NB_PATH=$(jq_required_string '.tool_input.notebook_path')
    if [ -z "$NB_PATH" ]; then
      NB_PATH=$(jq_required_string '.tool_input.file_path')
    fi
    if [ -z "$NB_PATH" ]; then
      deny_missing_field "tool_input.notebook_path"
    fi
    require_python_or_deny
    RESULT=$(classify_file "$NB_PATH")
    PROTECTED=$(printf '%s' "$RESULT" | jq -r '.protected')
    if [ "$PROTECTED" = "true" ]; then
      SURFACE=$(printf '%s' "$RESULT" | jq -r '.surface // empty')
      RESOLVED=$(printf '%s' "$RESULT" | jq -r '.resolved_rel // empty')
      emit_deny_or_override "$SURFACE" "$RESOLVED" "NotebookEdit refused; edit through a reviewed PR, or set SANCTUARY_PUBLIC_SURFACE_EDIT (see script header). Full protected set: $PROTECTED_SET_DESC"
    fi
    allow_silent
    ;;
  Bash)
    COMMAND=$(jq_required_string '.tool_input.command')
    if [ -z "$COMMAND" ]; then
      deny_missing_field "tool_input.command"
    fi
    # fix 4: called DIRECTLY, never via `RESULT=$(classify_bash_cmd_into_globals ...)`.
    # Capturing this classifier's output through command substitution was the
    # round-4 finding: bash 3.2 does not inherit errexit into a `$(...)`
    # subshell, so an internal helper failure inside that subshell would not
    # abort it -- execution would fall through to whatever the function
    # printed last, and a caller that only inspects the captured JSON's
    # content (never the substitution's own exit status) would read that as
    # a clean "no match". Calling the classifier directly, with its result in
    # a global array, keeps it in the main shell where `set -e` behaves
    # normally and where classify_bash_cmd_into_globals's own explicit
    # tr-exit-status check (see its body) can call deny_json and have that
    # deny actually reach the caller.
    classify_bash_cmd_into_globals "$COMMAND"
    if [ "${#BASHCLS_SURFACES[@]}" -eq 0 ]; then
      allow_silent
    elif [ "${#BASHCLS_SURFACES[@]}" -eq 1 ]; then
      emit_deny_or_override "${BASHCLS_SURFACES[0]}" "bash command (matched: ${BASHCLS_SURFACES[0]})" "Bash command spells a protected-surface path token and is refused on that basis alone (see header: this over-blocks read-only use by design). Full protected set: $PROTECTED_SET_DESC"
    else
      # fix 3: more than one distinct surface matched in the same command
      # (e.g. `printf x > docs/a.md; printf y > .github/workflows/pwn.yml`).
      # A SANCTUARY_PUBLIC_SURFACE_EDIT override names exactly one surface,
      # so it cannot legitimately cover two -- deny unconditionally, never
      # consulting the override at all, and list every surface touched.
      MULTI_LIST="${BASHCLS_SURFACES[0]}"
      MULTI_I=1
      while [ "$MULTI_I" -lt "${#BASHCLS_SURFACES[@]}" ]; do
        MULTI_LIST="$MULTI_LIST,${BASHCLS_SURFACES[$MULTI_I]}"
        MULTI_I=$((MULTI_I + 1))
      done
      deny_json "Blocked: bash command spells protected-surface tokens for MULTIPLE surfaces ($MULTI_LIST). A single SANCTUARY_PUBLIC_SURFACE_EDIT override names exactly one surface and cannot cover two, so this is always denied (AGENTS.md rule 9)."
    fi
    ;;
  *)
    # fix 5: an unrecognized tool_name (e.g. a hypothetical future "FutureWrite")
    # is denied explicitly, naming the tool, rather than passing through
    # silently. In normal operation the settings.json matcher only invokes
    # this script for Write|Edit|MultiEdit|NotebookEdit|Bash, so this branch
    # exists for direct/manual invocation or a future matcher change; either
    # way, a tool_name this guard does not have a case for is unclassifiable
    # and must fail closed per AGENTS.md rule 5, not allow_silent.
    deny_json "Blocked: PreToolUse event carried unrecognized tool_name '$TOOL_NAME'. This guard only classifies Write, Edit, MultiEdit, NotebookEdit, and Bash; failing closed for any other value per AGENTS.md rule 5."
    ;;
esac
