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
WRAPPER_VERBS='check mint kickstart-daemons arm repair unprotect clean-markers gate-state pf-anchor-rules'

# The launchd labels this wrapper is permitted to restart. Compiled in.
WRAPPER_DAEMON_LABELS='com.sanctuary.egress-gate com.sanctuary.egress-gate-peer-resolver'

# The pf anchor the drill arms. Compiled in: never from argv.
WRAPPER_PF_ANCHOR='com.sanctuary/egress'

wrapper_die() {
  printf 'WRAPPER=REJECT reason=%s\n' "$*"
  printf 'sanctuary-drill-wrapper: %s\n' "$*" >&2
  exit 20
}

wrapper_usage() {
  cat >&2 <<'USAGE'
sanctuary-drill-wrapper <verb> --run-id <id> --operator-account <acct>
                        [--agent-account <acct> --agent-uid <n>]
                        [--passphrase-file <file>]

verbs:
  check             run every rail and print the verdict; the only thing it
                    changes is that this run's own empty disposable directory
                    exists afterwards, root-owned, like every other verb
  mint              same, said out loud, for a driver that wants only that
  kickstart-daemons restart the gate + peer-resolver daemons on the current dist
  arm               protect --exclusive-egress against the disposable fortress
  repair            protect --repair-egress-gate (the gate-port rotation path)
  unprotect         protect --unprotect-egress-gate (teardown)
  clean-markers     remove loop-owned markers and stale locks under the storage dir
  gate-state        read-only gate/registry state dump
  pf-anchor-rules   print the pf anchor's rules; nonzero if pf could not be read

THERE IS NO --storage FLAG. The caller supplies a RUN ID, which is not a path
and cannot contain a slash; the wrapper composes the storage path itself under
a root-owned base it compiled in. That is the fix for the 2026-07-25 BLOCKER:
an attacker cannot race, swap, or symlink a value they never supply.

Every account argument passes lib/rails.sh before use. The wrapper refuses to
run on any host outside its compiled-in allowlist, refuses any real fortress by
both allowlist and denylist, and refuses to act for an account other than the
one sudo says invoked it.
USAGE
}

# ---------------------------------------------------------------------------
# argument parsing - values only, no execution
# ---------------------------------------------------------------------------

WRAPPER_VERB=''
ARG_RUN_ID=''
ARG_OPERATOR=''
ARG_AGENT=''
ARG_AGENT_UID=''
ARG_PASSFILE=''

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
      --run-id)
        if [ "$#" -lt 2 ]; then wrapper_die '--run-id needs a value'; fi
        ARG_RUN_ID="$2"; shift 2 ;;
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
ANCHOR=''
DERIVED=''
OPERATOR_UID=''
AGENT_UID=''

# Run a rail that prints nothing and would otherwise `exit` straight past the
# wrapper's own oracle.
#
# `rails__die` exits 20. Inside `$(...)` that kills only the subshell, and the
# mandatory `|| wrapper_die` turns it into a parent abort that prints
# WRAPPER=REJECT. Called DIRECTLY, the same `exit` terminated the whole script
# and the oracle's REJECT token was never printed, so `check` had two different
# contracts depending on which rail said no (review finding L2). Wrapping the
# direct calls in a subshell gives every rejection one shape. The status is
# still mandatory: the `|| wrapper_die` is what makes this fail closed, exactly
# as in the command-substitution form.
wrapper_rail() {
  ( "$@" )
}

wrapper_run_rails() {
  # 0. CALLER BINDING. Root must know which unprivileged account invoked it.
  #    Without this the grant holder could aim every later rail at another
  #    account's directory (review finding M1). Runs first because everything
  #    below is scoped BY the operator account.
  if [ -z "$ARG_OPERATOR" ]; then wrapper_die '--operator-account is required'; fi
  wrapper_rail rails_assert_caller_binding "$(rails__euid)" "${SUDO_USER:-}" "$ARG_OPERATOR" \
    || wrapper_die "caller binding rejected: SUDO_USER='${SUDO_USER:-}' operator='$ARG_OPERATOR'"

  # 1. HOST. Deny-first, then the compiled-in allowlist, fail closed on
  #    anything unknown. EVERY observed identity is passed so a machine
  #    answering to the daily driver's name under ANY of them is refused; extra
  #    names can only ever cause rejection. `hostname` and `scutil` are resolved
  #    by ABSOLUTE path: the review defeated this rail on the real MacBook by
  #    planting a `hostname` binary earlier in PATH.
  local h_short h_full h_computer
  h_short="$(rails__sys hostname -s 2>/dev/null || printf '')"
  h_full="$(rails__sys hostname -f 2>/dev/null || rails__sys hostname 2>/dev/null || printf '')"
  h_computer="$(rails__sys scutil --get ComputerName 2>/dev/null || printf '')"
  if [ -z "$h_short" ]; then wrapper_die 'cannot determine hostname; refusing'; fi
  # Aliases are only passed when non-empty: an empty identity is itself a
  # rejection inside the rail, and "this box has no ComputerName" is not a
  # reason to refuse a legitimate drill host. Built as a list so no branch can
  # silently DROP an alias, which the reviewed build's `elif` chain did.
  local -a host_names=("$h_short")
  if [ -n "$h_full" ]; then host_names+=("$h_full"); fi
  if [ -n "$h_computer" ]; then host_names+=("$h_computer"); fi
  wrapper_rail rails_assert_host_allowed "${host_names[@]}" \
    || wrapper_die "host rail rejected $h_short"

  # 2. OPERATOR ACCOUNT, before any `sudo -u`. The reviewed build passed this
  #    straight through, so `--operator-account root` plus a caller-supplied URL
  #    yielded curl as root.
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

  # 4. STORAGE. THE BLOCKER, and the reason this looks nothing like the
  #    reviewed build. The caller supplies a RUN ID, never a path. The wrapper
  #    derives the path under a compiled-in, ROOT-OWNED base whose every
  #    component it re-verifies, then re-runs the full disposable-storage rail
  #    on its own derivation as a belt.
  #
  #    The post-condition still treats empty as fatal rather than as "unset":
  #    an empty SANCTUARY_STORAGE_PATH resolves to the REAL default fortress.
  if [ -z "$ARG_RUN_ID" ]; then wrapper_die '--run-id is required'; fi
  DERIVED="$(rails_derive_disposable_storage "$RAILS_DISPOSABLE_BASE" "$ARG_OPERATOR" "$ARG_RUN_ID")" \
    || wrapper_die "run id rejected: $ARG_RUN_ID"
  if [ -z "$DERIVED" ]; then wrapper_die 'empty derived storage path'; fi

  # 5. PASSPHRASE FILE, when supplied.
  if [ -n "$ARG_PASSFILE" ]; then
    wrapper_rail rails_assert_secret_file_perms "$ARG_PASSFILE" "$ARG_OPERATOR" \
      || wrapper_die "passphrase-file rail rejected: $ARG_PASSFILE"
  fi
}

# Create the root-owned base, the per-operator anchor and the disposable
# fortress leaf, then VERIFY what was created, then re-run the full
# disposable-storage rail on the result. Idempotent, and it runs for EVERY
# verb including `check`.
#
# Every directory is created by ROOT and left root-owned at 0755: the operator
# can read the drill's logs and markers and can traverse the tree, and cannot
# create, rename, replace or symlink anything inside it. That is what makes
# `clean-markers` and the preflight/teardown readers safe rather than merely
# checked. The Sanctuary CLI runs as root under this wrapper, so the fortress
# content it writes is root's either way; this only changes who owns the
# DIRECTORY, and it is the whole of BLOCKER 1's fix.
#
# WHY `check` DOES THIS TOO. `check` is the oracle the drivers and the tests
# trust, so it must answer the question a real verb would answer, on the same
# code path. Making it skip the directory step would leave the oracle testing
# something the real verbs do not do, which is the exact shape of the miss that
# started this whole harness. The one thing `check` changes is that the run's
# own empty disposable directory now exists, root-owned, under a base used for
# nothing else. That is a bounded and stated side effect, not a hidden one.
wrapper_ensure_storage() {
  local d verified
  for d in "$RAILS_DISPOSABLE_BASE" "$RAILS_DISPOSABLE_BASE/$ARG_OPERATOR" "$DERIVED"; do
    if [ -L "$d" ]; then wrapper_die "refusing to use a symlinked directory: $d"; fi
    if [ ! -d "$d" ]; then
      # `mkdir -p` walks the chain, so a component that is a symlink today
      # would be followed. Each component is lstat'd above before its turn
      # comes, and the trusted-chain rail below re-proves the whole result.
      rails__sys mkdir -m 0755 -p -- "$d" || wrapper_die "could not create $d"
    fi
  done

  # VERIFY WHAT EXISTS, not what we asked for. `mkdir -p` on an existing tree
  # is a no-op, so this is the check that catches a base somebody else created
  # with the wrong owner or mode.
  ANCHOR="$(rails_assert_trusted_dir_chain 'operator anchor' "$RAILS_DISPOSABLE_BASE/$ARG_OPERATOR")" \
    || wrapper_die "operator anchor is not a trusted root-owned chain: $RAILS_DISPOSABLE_BASE/$ARG_OPERATOR"
  if [ -z "$ANCHOR" ]; then wrapper_die 'empty operator anchor after rail'; fi
  verified="$(rails_assert_trusted_dir_chain 'disposable storage' "$DERIVED")" \
    || wrapper_die "storage is not a trusted root-owned chain: $DERIVED"
  if [ -z "$verified" ]; then wrapper_die 'empty storage after the trusted-chain rail'; fi

  # And the full disposable-storage rail on the CANONICAL result, as a belt.
  # Every rejection this rail has ever caught still applies; what has changed
  # is that its anchor is a root-owned directory rather than a home the caller
  # could rewrite underneath it.
  STORAGE="$(rails_assert_disposable_storage "$ANCHOR" "$verified")" \
    || wrapper_die "storage rail rejected the derived path: $verified"
  if [ -z "$STORAGE" ]; then wrapper_die 'empty storage after rail'; fi
}

# Resolve a path INSIDE the rail-approved storage directory through the ONE
# chokepoint. Nothing in this file walks a storage-relative path by hand.
wrapper_safe_path() {
  local p
  p="$(rails_assert_safe_subpath "$STORAGE" "$1")" \
    || wrapper_die "unsafe path under the storage directory: $1"
  if [ -z "$p" ]; then wrapper_die "empty path after the safe-subpath rail: $1"; fi
  printf '%s\n' "$p"
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
  # Reaching this line means every rail passed and the disposable directory
  # exists, root-owned, verified component by component.
  printf 'WRAPPER=ACCEPT storage=%s operator=%s operator_uid=%s agent=%s agent_uid=%s cli=%s\n' \
    "$STORAGE" "$ARG_OPERATOR" "$OPERATOR_UID" "${ARG_AGENT:--}" "${AGENT_UID:--}" \
    "$(wrapper_cli_status)"
}

wrapper_verb_mint() {
  printf 'WRAPPER=OK verb=mint storage=%s\n' "$STORAGE"
}

# The reviewed build ran `launchctl kickstart ... || true` and then printed
# WRAPPER=OK unconditionally, which made a failed restart read as a success.
# The kickstart IS this verb's entire job, so its status IS the verb's status.
wrapper_verb_kickstart_daemons() {
  local label failed='' restarted=''
  for label in $WRAPPER_DAEMON_LABELS; do
    if rails__sys launchctl kickstart -k "system/$label" >/dev/null 2>&1; then
      restarted="$restarted $label"
    else
      failed="$failed $label"
    fi
  done
  if [ -n "$failed" ]; then
    wrapper_die "kickstart failed for:$failed (restarted:${restarted:- none})"
  fi
  printf 'WRAPPER=OK verb=kickstart-daemons restarted=%s\n' "${restarted# }"
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

# Deletes a fixed list of named files under the rail-approved storage path.
# No globs, no recursion, no caller-supplied filenames.
#
# TWO of these three targets are NOT direct children, and the reviewed build's
# comment claimed otherwise. `[ -L "$target" ]` lstats only the FINAL
# component, so `state/` and `state/_audit/` were resolved by the kernel and
# never looked at. A reviewer made `state` a symlink and this verb deleted a
# file inside a (fake) real fortress as root, with every rail passing.
#
# Every target now goes through the ONE resolution chokepoint, which walks
# EVERY component and refuses any symlink anywhere in the chain. Under the
# root-owned base the operator cannot create a symlink here at all, so this is
# a belt over a structural brace. Both, because round 1's lesson was that one
# layer is one point of failure.
wrapper_verb_clean_markers() {
  local rel target
  for rel in \
    'exclusive-routing.json' \
    'state/_audit/.audit-write.lock' \
    'state/.provision.lock'
  do
    target="$(wrapper_safe_path "$rel")"
    if [ -f "$target" ]; then
      rails__sys rm -f -- "$target"
      printf 'WRAPPER=OK removed %s\n' "$target"
    fi
  done
  printf 'WRAPPER=OK verb=clean-markers storage=%s\n' "$STORAGE"
}

wrapper_verb_gate_state() {
  local label
  printf -- '--- launchctl ---\n'
  for label in $WRAPPER_DAEMON_LABELS; do
    rails__sys launchctl print "system/$label" 2>/dev/null || printf '(no %s daemon)\n' "$label"
  done
  printf -- '--- pf anchor ---\n'
  rails__sys pfctl -a "$WRAPPER_PF_ANCHOR" -s rules 2>/dev/null || printf '(no anchor rules)\n'
  printf 'WRAPPER=OK verb=gate-state\n'
}

# Read the pf anchor's rules, and say plainly whether pf could be read at all.
#
# This verb exists because `teardown-verify.sh` did
# `rules="$(sudo -n pfctl ... || printf '')"` and then read the empty string as
# CLEAN. A refused sudo, a pf error and a genuinely empty anchor were all one
# value, and the README itself says that pfctl grant does not exist. The
# stop-the-night check now gets a status it cannot confuse, and it needs no
# second sudo grant, because the wrapper is already what the NOPASSWD line
# covers.
wrapper_verb_pf_anchor_rules() {
  local rules rc=0
  rules="$(rails__sys pfctl -a "$WRAPPER_PF_ANCHOR" -s rules 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    wrapper_die "could not read the pf anchor $WRAPPER_PF_ANCHOR (pfctl rc=$rc); a check that observed nothing is not a clean verdict"
  fi
  printf 'WRAPPER=PF-ANCHOR-BEGIN\n'
  printf '%s' "$rules"
  printf '\nWRAPPER=PF-ANCHOR-END\n'
  printf 'WRAPPER=OK verb=pf-anchor-rules anchor=%s\n' "$WRAPPER_PF_ANCHOR"
}

wrapper_main() {
  wrapper_parse_args "$@"
  wrapper_run_rails
  wrapper_ensure_storage
  case "$WRAPPER_VERB" in
    check)             wrapper_verb_check ;;
    mint)              wrapper_verb_mint ;;
    pf-anchor-rules)   wrapper_verb_pf_anchor_rules ;;
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
# the SAME wrapper body with TWO narrow constant overrides in between (a host
# allowlist that includes the test machine, and a disposable base that points
# at a temp directory) and still exercise the real `wrapper_run_rails`, the
# real `wrapper_ensure_storage`, every real verb and the real `check` oracle.
#
# The reviewed build also overrode `wrapper_home_of`, a FUNCTION, in both
# batteries: mutating it to return `/var/root` left all 59 tests green. That
# function is gone, because the wrapper no longer looks up anybody's home. What
# remains is two CONSTANTS, and a structural test asserts the values the
# SHIPPED artifact carries, so an override in a battery cannot hide a change to
# what actually runs as root.
#
# The shipped artifact is unaffected: the builder emits one fixed footer every
# time, and nothing in this file branches on being tested.
