# shellcheck shell=bash
#
# wrapper-main.sh - the privileged wrapper's main body.
#
# THIS FILE IS NOT EXECUTABLE ON ITS OWN. It assumes lib/rails.sh has already
# been concatenated above it by build-wrapper.sh, and that the assembled header
# has already set `set -euo pipefail`. That assembly is the whole point:
#
#   - The INSTALLED wrapper runs as root under a NOPASSWD grant, so it must be
#     SELF-CONTAINED. If it sourced lib/rails.sh out of the repo at runtime,
#     any write to the repo would be root code execution. That is not a
#     hardening nicety, it is the difference between a scoped grant and a
#     general one.
#   - But duplicating the rails into two files is how whack-a-mole starts, so
#     there is exactly one rails source and the wrapper is BUILT from it.
#   - `wrapper.sha256` and `rails_assert_wrapper_integrity` close the loop: the
#     driver re-assembles, hashes, and refuses to run on any mismatch between
#     repo, committed hash, and installed file.
#
# EVERYTHING here treats its arguments as hostile. This process is uid 0.

# The Sanctuary CLI this wrapper is permitted to invoke. Compiled in: never
# from argv, never from the environment. This is a DECLARED trust boundary, not
# a defended one - the entire purpose of the drill is to exercise the real
# product under sudo, so the product's own binary necessarily runs as root.
# What the wrapper guarantees is that it runs THIS path and no other, that the
# path is a root-owned, non-group-writable, non-symlink regular file, and that
# every argument handed to it has passed a rail.
WRAPPER_CLI='/usr/local/bin/sanctuary'

# Verbs this wrapper will run. Anything else is refused. There is no
# passthrough verb and no `--` escape into a general shell.
WRAPPER_VERBS='check kickstart-daemons arm repair unprotect clean-markers gate-state'

wrapper_die() {
  printf 'WRAPPER=REJECT reason=%s\n' "$*"
  printf 'sanctuary-drill-wrapper: %s\n' "$*" >&2
  exit 20
}

wrapper_usage() {
  cat >&2 <<'USAGE'
sanctuary-drill-wrapper <verb> --storage <dir> --operator-account <acct>
                        --agent-account <acct> --agent-uid <n>
                        [--passphrase-file <file>] [--endpoint <url>]

verbs:
  check             run every rail and print the verdict; NO side effects
  kickstart-daemons restart the gate + peer-resolver daemons on the current dist
  arm               protect --exclusive-egress against the disposable fortress
  repair            protect --repair-egress-gate (the gate-port rotation path)
  unprotect         protect --unprotect-egress-gate (teardown)
  clean-markers     remove loop-owned markers and stale locks under the storage dir
  gate-state        read-only gate/registry state dump

Every path and account argument passes lib/rails.sh before use. The wrapper
refuses to run on any host outside its compiled-in allowlist, and refuses the
operator's real fortress by both allowlist and denylist.
USAGE
}

# ---------------------------------------------------------------------------
# argument parsing - values only, no execution
# ---------------------------------------------------------------------------

WRAPPER_VERB=''
ARG_STORAGE=''
ARG_OPERATOR=''
ARG_AGENT=''
ARG_AGENT_UID=''
ARG_PASSFILE=''
ARG_ENDPOINT=''

wrapper_parse_args() {
  if [ "$#" -lt 1 ]; then
    wrapper_usage
    wrapper_die 'no verb given'
  fi
  WRAPPER_VERB="$1"
  shift
  local found='' v
  for v in $WRAPPER_VERBS; do
    if [ "$WRAPPER_VERB" = "$v" ]; then found='yes'; fi
  done
  if [ -z "$found" ]; then wrapper_die "unknown verb: $WRAPPER_VERB"; fi

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --storage)
        if [ "$#" -lt 2 ]; then wrapper_die '--storage needs a value'; fi
        ARG_STORAGE="$2"; shift 2 ;;
      --operator-account)
        if [ "$#" -lt 2 ]; then wrapper_die '--operator-account needs a value'; fi
        ARG_OPERATOR="$2"; shift 2 ;;
      --agent-account)
        if [ "$#" -lt 2 ]; then wrapper_die '--agent-account needs a value'; fi
        ARG_AGENT="$2"; shift 2 ;;
      --agent-uid)
        if [ "$#" -lt 2 ]; then wrapper_die '--agent-uid needs a value'; fi
        ARG_AGENT_UID="$2"; shift 2 ;;
      --passphrase-file)
        if [ "$#" -lt 2 ]; then wrapper_die '--passphrase-file needs a value'; fi
        ARG_PASSFILE="$2"; shift 2 ;;
      --endpoint)
        if [ "$#" -lt 2 ]; then wrapper_die '--endpoint needs a value'; fi
        ARG_ENDPOINT="$2"; shift 2 ;;
      *)
        wrapper_die "unknown or unsupported argument: $1" ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# the rail gauntlet - run in full for EVERY verb including `check`
# ---------------------------------------------------------------------------
#
# `check` is the oracle the driver and the tests trust, so it must run the
# SAME rails as a real verb and report the SAME verdict. The reviewed build's
# oracle printed `WRAPPER=ACCEPT storage=` for a path its own rails had
# rejected, because the rejection died inside a command substitution. Here
# every rail call uses the mandatory `|| wrapper_die` form and the accept token
# is printed exactly once, at the very end, after a non-empty post-condition.

STORAGE=''
OPERATOR_UID=''
AGENT_UID=''

wrapper_run_rails() {
  # 1. HOST. Deny-first, then the compiled-in allowlist, fail closed on
  #    anything unknown. Several observed identities are passed so a machine
  #    answering to the daily driver's name under ANY of them is refused; extra
  #    names can only ever cause rejection.
  local h_short h_full h_computer
  h_short="$(hostname -s 2>/dev/null || printf '')"
  h_full="$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf '')"
  h_computer="$(scutil --get ComputerName 2>/dev/null || printf '')"
  if [ -z "$h_short" ]; then wrapper_die 'cannot determine hostname; refusing'; fi
  # Aliases are only passed when non-empty: an empty identity is itself a
  # rejection inside the rail, and "this box has no ComputerName" is not a
  # reason to refuse a legitimate drill host.
  if [ -n "$h_full" ] && [ -n "$h_computer" ]; then
    rails_assert_host_allowed "$h_short" "$h_full" "$h_computer" \
      || wrapper_die "host rail rejected $h_short"
  elif [ -n "$h_full" ]; then
    rails_assert_host_allowed "$h_short" "$h_full" \
      || wrapper_die "host rail rejected $h_short"
  else
    rails_assert_host_allowed "$h_short" \
      || wrapper_die "host rail rejected $h_short"
  fi

  # 2. OPERATOR ACCOUNT, before any `sudo -u`. The reviewed build passed this
  #    straight through, so `--operator-account root` plus a caller-supplied URL
  #    yielded curl as root.
  if [ -z "$ARG_OPERATOR" ]; then wrapper_die '--operator-account is required'; fi
  OPERATOR_UID="$(rails_assert_non_root_account 'operator' "$ARG_OPERATOR")" \
    || wrapper_die "operator account rejected: $ARG_OPERATOR"
  if [ -z "$OPERATOR_UID" ]; then wrapper_die 'empty operator uid after rail'; fi

  # 3. AGENT ACCOUNT + UID pairing (this part held in review; keep it).
  if [ -n "$ARG_AGENT" ] || [ -n "$ARG_AGENT_UID" ]; then
    if [ -z "$ARG_AGENT" ]; then wrapper_die '--agent-uid given without --agent-account'; fi
    if [ -z "$ARG_AGENT_UID" ]; then wrapper_die '--agent-account given without --agent-uid'; fi
    AGENT_UID="$(rails_assert_account_uid 'agent' "$ARG_AGENT" "$ARG_AGENT_UID")" \
      || wrapper_die "agent account rejected: $ARG_AGENT"
    if [ -z "$AGENT_UID" ]; then wrapper_die 'empty agent uid after rail'; fi
  fi

  # 4. STORAGE. The BLOCKER. Note the mandatory call-site form, and note that
  #    the post-condition below treats empty as fatal rather than as "unset":
  #    an empty SANCTUARY_STORAGE_PATH resolves to the REAL default fortress.
  if [ -z "$ARG_STORAGE" ]; then wrapper_die '--storage is required'; fi
  local operator_home
  operator_home="$(wrapper_home_of "$ARG_OPERATOR")" \
    || wrapper_die "cannot resolve home directory for $ARG_OPERATOR"
  if [ -z "$operator_home" ]; then wrapper_die "empty home directory for $ARG_OPERATOR"; fi
  STORAGE="$(rails_assert_disposable_storage "$operator_home" "$ARG_STORAGE")" \
    || wrapper_die "storage rail rejected: $ARG_STORAGE"
  if [ -z "$STORAGE" ]; then wrapper_die 'empty storage after rail'; fi

  # 5. PASSPHRASE FILE, when supplied.
  if [ -n "$ARG_PASSFILE" ]; then
    rails_assert_secret_file_perms "$ARG_PASSFILE" "$ARG_OPERATOR" \
      || wrapper_die "passphrase-file rail rejected: $ARG_PASSFILE"
  fi

  # 6. ENDPOINT, when supplied. Only ever handed to the product CLI, never to a
  #    shell and never to curl-as-root, but screened anyway.
  if [ -n "$ARG_ENDPOINT" ]; then
    case "$ARG_ENDPOINT" in
      https://*) ;;
      *) wrapper_die "endpoint must be an https URL: $ARG_ENDPOINT" ;;
    esac
    case "$ARG_ENDPOINT" in
      *[!A-Za-z0-9:/._~%?=-]*) wrapper_die "endpoint has disallowed characters: $ARG_ENDPOINT" ;;
    esac
  fi
}

# Home directory of an account, read from the account database rather than
# guessed from a string. macOS `dscl` first, then getent, then the passwd file.
wrapper_home_of() {
  local acct="$1" home=''
  if command -v dscl >/dev/null 2>&1; then
    home="$(dscl . -read "/Users/$acct" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')"
  fi
  if [ -z "$home" ] && command -v getent >/dev/null 2>&1; then
    home="$(getent passwd "$acct" 2>/dev/null | awk -F: '{print $6}')"
  fi
  if [ -z "$home" ]; then
    home="$(awk -F: -v u="$acct" '$1==u{print $6}' /etc/passwd 2>/dev/null || printf '')"
  fi
  if [ -z "$home" ]; then return 1; fi
  case "$home" in /*) ;; *) return 1 ;; esac
  printf '%s\n' "$home"
}

# The compiled-in CLI must be a root-owned, non-symlink, non-group-writable
# regular file. A wrapper that execs an operator-writable path would hand the
# grant away.
#
# This runs immediately before every real CLI invocation, NOT as part of the
# argument gauntlet. The distinction matters for the `check` oracle: `check`
# answers "do the caller's arguments pass the safety rails", which is a
# question about the caller, and it must answer identically on a machine that
# has not installed the product yet. CLI availability is reported by `check` as
# an advisory field instead, and is a hard precondition for anything that
# actually executes.
wrapper_assert_cli() {
  local mode owner
  if [ -L "$WRAPPER_CLI" ]; then wrapper_die "CLI path is a symlink: $WRAPPER_CLI"; fi
  if [ ! -f "$WRAPPER_CLI" ]; then wrapper_die "CLI not found: $WRAPPER_CLI"; fi
  if [ ! -x "$WRAPPER_CLI" ]; then wrapper_die "CLI not executable: $WRAPPER_CLI"; fi
  if ! mode="$(rails__stat_mode "$WRAPPER_CLI")"; then wrapper_die "cannot stat $WRAPPER_CLI"; fi
  if [ $(( 8#$mode & 8#22 )) -ne 0 ]; then
    wrapper_die "CLI $WRAPPER_CLI is group- or world-writable (mode $mode)"
  fi
  if ! owner="$(rails__stat_owner_uid "$WRAPPER_CLI")"; then wrapper_die "cannot stat owner of $WRAPPER_CLI"; fi
  if [ "$owner" -ne 0 ]; then wrapper_die "CLI $WRAPPER_CLI is not owned by root (uid $owner)"; fi
}

# Non-fatal CLI probe, for the `check` advisory field only.
wrapper_cli_status() {
  if [ -L "$WRAPPER_CLI" ]; then printf 'symlink'; return 0; fi
  if [ ! -f "$WRAPPER_CLI" ]; then printf 'missing'; return 0; fi
  if [ ! -x "$WRAPPER_CLI" ]; then printf 'not-executable'; return 0; fi
  local mode owner
  if ! mode="$(rails__stat_mode "$WRAPPER_CLI")"; then printf 'unstattable'; return 0; fi
  if [ $(( 8#$mode & 8#22 )) -ne 0 ]; then printf 'writable'; return 0; fi
  if ! owner="$(rails__stat_owner_uid "$WRAPPER_CLI")"; then printf 'unstattable'; return 0; fi
  if [ "$owner" -ne 0 ]; then printf 'not-root-owned'; return 0; fi
  printf 'ok'
}

# ---------------------------------------------------------------------------
# verbs - reached only after the full gauntlet
# ---------------------------------------------------------------------------

wrapper_cli() {
  # SANCTUARY_STORAGE_PATH is exported ONLY here, only from $STORAGE, and only
  # after the non-empty post-condition above. Nothing else in this file exports
  # it, so there is one place to audit.
  if [ -z "$STORAGE" ]; then wrapper_die 'refusing to invoke the CLI with an empty storage path'; fi
  wrapper_assert_cli
  SANCTUARY_STORAGE_PATH="$STORAGE" "$WRAPPER_CLI" "$@"
}

wrapper_verb_check() {
  # Read-only. Reaching this line means every rail passed.
  printf 'WRAPPER=ACCEPT storage=%s operator=%s operator_uid=%s agent=%s agent_uid=%s cli=%s\n' \
    "$STORAGE" "$ARG_OPERATOR" "$OPERATOR_UID" "${ARG_AGENT:--}" "${AGENT_UID:--}" \
    "$(wrapper_cli_status)"
}

wrapper_verb_kickstart_daemons() {
  local label
  for label in com.sanctuary.egress-gate com.sanctuary.egress-gate-peer-resolver; do
    launchctl kickstart -k "system/$label" 2>/dev/null || true
  done
  printf 'WRAPPER=OK verb=kickstart-daemons\n'
}

wrapper_verb_arm() {
  if [ -z "$ARG_AGENT" ] || [ -z "$AGENT_UID" ]; then
    wrapper_die 'arm requires --agent-account and --agent-uid'
  fi
  # Pass the RAIL'S output, not the raw argument. The rail proved the two are
  # equal, so this is not a behavior change today; it is the habit that stops a
  # later edit from reintroducing a validated-then-unvalidated split.
  wrapper_cli protect --exclusive-egress --agent-account "$ARG_AGENT" --agent-uid "$AGENT_UID"
  printf 'WRAPPER=OK verb=arm storage=%s\n' "$STORAGE"
}

wrapper_verb_repair() {
  wrapper_cli protect --repair-egress-gate
  printf 'WRAPPER=OK verb=repair storage=%s\n' "$STORAGE"
}

wrapper_verb_unprotect() {
  wrapper_cli protect --unprotect-egress-gate
  printf 'WRAPPER=OK verb=unprotect storage=%s\n' "$STORAGE"
}

# Only ever deletes named files DIRECTLY under the rail-approved storage path.
# No globs, no recursion, no caller-supplied filenames.
wrapper_verb_clean_markers() {
  local rel
  for rel in \
    'exclusive-routing.json' \
    'state/_audit/.audit-write.lock' \
    'state/.provision.lock'
  do
    local target="$STORAGE/$rel"
    if [ -L "$target" ]; then
      printf 'WRAPPER=WARN skipped symlink %s\n' "$target"
      continue
    fi
    if [ -f "$target" ]; then
      rm -f -- "$target"
      printf 'WRAPPER=OK removed %s\n' "$target"
    fi
  done
  printf 'WRAPPER=OK verb=clean-markers storage=%s\n' "$STORAGE"
}

wrapper_verb_gate_state() {
  printf '--- launchctl ---\n'
  launchctl print system/com.sanctuary.egress-gate 2>/dev/null || printf '(no gate daemon)\n'
  launchctl print system/com.sanctuary.egress-gate-peer-resolver 2>/dev/null || printf '(no resolver daemon)\n'
  printf '--- pf anchor ---\n'
  pfctl -a com.sanctuary/egress -s rules 2>/dev/null || printf '(no anchor rules)\n'
  printf 'WRAPPER=OK verb=gate-state\n'
}

wrapper_main() {
  wrapper_parse_args "$@"
  wrapper_run_rails
  case "$WRAPPER_VERB" in
    check)             wrapper_verb_check ;;
    kickstart-daemons) wrapper_verb_kickstart_daemons ;;
    arm)               wrapper_verb_arm ;;
    repair)            wrapper_verb_repair ;;
    unprotect)         wrapper_verb_unprotect ;;
    clean-markers)     wrapper_verb_clean_markers ;;
    gate-state)        wrapper_verb_gate_state ;;
    *)                 wrapper_die "unreachable: unhandled verb $WRAPPER_VERB" ;;
  esac
}

# NOTE: there is no `wrapper_main "$@"` here. build-wrapper.sh appends the
# entrypoint line as the assembled artifact's footer, so this file is pure
# definitions. That is what lets the test battery compose the SAME rails and
# the SAME wrapper body with a couple of narrow overrides in between (a host
# allowlist that includes the test machine, and a home lookup that points at a
# temp directory) and still exercise the real `wrapper_run_rails` and the real
# `check` oracle. The shipped artifact is unaffected: the builder emits one
# fixed footer every time, and nothing in this file branches on being tested.
