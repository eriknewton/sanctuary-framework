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

# The Sanctuary CLI this wrapper is permitted to invoke, as an ORDERED
# CANDIDATE LIST. Compiled in: never from argv, never from the environment,
# never resolved from PATH. This is a DECLARED trust boundary, not a defended
# one - the entire purpose of the drill is to exercise the real product under
# sudo, so the product's own binary necessarily runs as root. What the wrapper
# guarantees is that it runs one of THESE paths and no other, that the one it
# picked is a root-owned, non-group-writable, non-symlink regular file under a
# root-owned directory chain, and that every argument handed to it has passed
# a rail.
#
# WHY A LIST, AND WHY THE LIST DOES NOT WEAKEN ANYTHING. The third live
# supervised run refused every executing verb with
#
#   WRAPPER=REJECT reason=CLI not found: /usr/local/bin/sanctuary
#
# on a drill host that HAS the product CLI: `/usr/local/bin` does not exist
# there at all and `sanctuary` resolves to `/opt/homebrew/bin/sanctuary`. One
# hard-coded path made "the CLI is not installed on this host" and "the CLI is
# installed somewhere this wrapper was never told about" the same message. That
# is the same substitution as the PyYAML walk in preflight.sh, one layer down.
#
# The fix is NOT to let the caller name a path (`--cli`, `$SANCTUARY_CLI`, a
# PATH lookup), all of which would let the grant holder aim root at code it
# writes. It is a list of absolute, CODE-CONTROLLED paths, resolved by
# OBSERVATION: `wrapper_cli_candidate_state` probes each one and only a
# candidate that passes the full ownership gauntlet may be selected.
# EXISTENCE MUST NOT SELECT - that is precisely the defect this file keeps
# finding - so a candidate that exists but is operator-writable is REFUSED and
# named, never preferred over one further down the list.
#
# `/opt/homebrew/bin/sanctuary` is in the list so its state is MEASURED AND
# REPORTED, not so it is trusted. On the drill host it is an operator-owned
# symlink inside an operator-owned, group-writable directory, chaining into a
# checkout in the operator's home; the gauntlet refuses it on the first rule it
# breaks, and the operator learns from the refusal that the CLI they installed
# is not one root may execute. Naming it is the difference between an
# actionable refusal and a mystery.
#
# WHY THE REPO'S OWN `server/dist/cli.js` IS DELIBERATELY NOT A CANDIDATE.
# It is the code under test, in a checkout the operator writes to by
# construction, so it can never pass this gauntlet - listing it would add a
# candidate guaranteed to be refused, and, worse, would put standing pressure
# on a later edit to carve an exception into the ownership rule for exactly the
# one path that must not have one. It also cannot be executed without a second
# trusted program (an absolute `node`), and on the drill host `node` is itself
# an operator-owned symlink into an operator-owned Cellar, so the exception
# would have to be widened twice. The honest outcome on a host with no
# root-owned CLI is a loud refusal naming the remedy, not a quiet escalation.
WRAPPER_CLI_CANDIDATES='/usr/local/bin/sanctuary /opt/homebrew/bin/sanctuary'

# The SELECTED candidate, and the per-candidate probe record. Both are set only
# by `wrapper_resolve_cli`. `WRAPPER_CLI` empty means no trusted CLI has been
# selected; nothing reads it without having run the resolver first, and
# `wrapper_cli` re-asserts it immediately before every exec.
WRAPPER_CLI=''
WRAPPER_CLI_PROBED=''

# Verbs this wrapper will run. Anything else is refused. There is no
# passthrough verb and no `--` escape into a general shell.
#
# The four READ verbs (`registry-state`, `fortress-state`, `gate-log`,
# `pf-anchor-rules`) exist because of the round-3 class: the unprivileged
# drivers drew conclusions from files they were not allowed to read. The real
# registry is root-`0600` inside a `0700` directory, the gate log lives in the
# gate service account's `0700` home, and the product chmods the fortress to
# `0700` on every start. Every one of those reads returned "not found", which
# the drivers folded into "not there", which they reported as clean. A driver
# that cannot observe must be given a way to observe, or told plainly that it
# could not; these verbs are the first half and the drivers' tri-state verdicts
# are the second.
WRAPPER_VERBS='check mint kickstart-daemons arm repair unprotect clean-markers retire gate-state pf-anchor-rules registry-state fortress-state gate-log gate-port'

# How much of the gate log a single `gate-log` call returns.
WRAPPER_GATE_LOG_LINES=200

# NOTE: the pf anchor name and the launchd labels are NOT declared here any
# more. They are `RAILS_PRODUCT_*` constants in lib/rails.sh, pinned to the
# product's own exports by server/test/drill-loop/product-identifiers.test.ts.
# Round 3 found all four of this harness's product-facing identifiers wrong at
# once, which is what made a green night possible for three named defect layers
# it never measured; a second declaration site is how that happens again.

wrapper_die() {
  printf 'WRAPPER=REJECT reason=%s\n' "$*"
  printf 'sanctuary-drill-wrapper: %s\n' "$*" >&2
  exit 20
}

wrapper_usage() {
  cat >&2 <<'USAGE'
sanctuary-drill-wrapper <verb> --run-id <id> --operator-account <acct>
                        [--agent-account <acct> --agent-uid <n>]

verbs:
  check             run every rail and print the verdict; the only thing it
                    changes is that this run's own empty disposable directory
                    exists afterwards, root-owned, like every other verb
  mint              same, said out loud, for a driver that wants only that
  kickstart-daemons restart every product daemon that is PRESENT: the
                    always-installed host daemons, plus this agent's per-uid
                    gate + peer-resolver daemons once they exist (needs
                    --agent-account and --agent-uid: the per-uid labels are per
                    confined uid). Reports restarted, absent-and-expected,
                    absent-and-unexpected and restart-failed as four separate
                    fields; a per-uid daemon's absence is expected only while
                    the pf-anchor registry says this uid is not confined
  arm               protect --exclusive-egress against the disposable fortress
  repair            protect --repair-egress-gate (the gate-port rotation path)
  unprotect         protect --unprotect-egress-gate (teardown)
  clean-markers     remove loop-owned markers and stale locks under the storage dir
  retire            remove this run's whole disposable fortress
  gate-state        read-only gate/registry state dump (needs --agent-uid)
  pf-anchor-rules   print the pf anchor's rules; nonzero if pf could not be read
  registry-state    print the root-owned pf-anchor registry; nonzero if it
                    exists and could not be read. With --agent-account and
                    --agent-uid the verdict line ALSO carries the observed
                    arm state of that uid (arm_state + arm_basis), which is
                    the ONE decision that says whether a missing per-uid gate
                    daemon or plist is the expected pre-arm state or a defect
  fortress-state    report the marker and lock files inside this run's fortress
                    AS ROOT, so a driver observes rather than guesses
  gate-log          tail this agent's gate + peer-resolver daemon logs; nonzero
                    if there is no log to read (needs --agent-uid);
                    --log-cursor-only records per-log cursors and
                    --since-<stream> prints only bytes appended after them
  gate-port         report the port the gate daemon ACTUALLY bound for this
                    agent uid, and the generation it belongs to, read as root
                    from the daemon's own runtime state (needs --agent-uid).
                    Without this the drivers cannot address the gate at all:
                    it is a loopback CONNECT proxy on a per-generation port and
                    nothing redirects traffic into it.

THERE IS NO --storage FLAG. The caller supplies a RUN ID, which is not a path
and cannot contain a slash; the wrapper composes the storage path itself under
a root-owned base it compiled in. That is the fix for the 2026-07-25 BLOCKER:
an attacker cannot race, swap, or symlink a value they never supply.

THERE IS NO --passphrase-file FLAG either. It was parsed and rail-checked and
reached no verb: validated root-run surface with no consumer, which is round
2's `--endpoint` finding under a new name. It is gone rather than better
documented.

Every account argument passes lib/rails.sh before use. The wrapper refuses to
run on any host outside its compiled-in allowlist, refuses to act for an agent
account outside its compiled-in agent allowlist, refuses any real fortress by
both allowlist and denylist, and refuses to act for an operator account other
than the one sudo says invoked it.
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
ARG_LOG_CURSOR_ONLY=''
ARG_SINCE_GATE_OUT='0,0,0,0'
ARG_SINCE_GATE_ERR='0,0,0,0'
ARG_SINCE_PEER_OUT='0,0,0,0'
ARG_SINCE_PEER_ERR='0,0,0,0'

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
      --log-cursor-only)
        ARG_LOG_CURSOR_ONLY='yes'; shift ;;
      --since-gate-out)
        if [ "$#" -lt 2 ]; then wrapper_die '--since-gate-out needs a value'; fi
        ARG_SINCE_GATE_OUT="$(rails_assert_log_cursor "$2")" \
          || wrapper_die "bad gate stdout log cursor: ${2:-<missing>}"
        shift 2 ;;
      --since-gate-err)
        if [ "$#" -lt 2 ]; then wrapper_die '--since-gate-err needs a value'; fi
        ARG_SINCE_GATE_ERR="$(rails_assert_log_cursor "$2")" \
          || wrapper_die "bad gate stderr log cursor: ${2:-<missing>}"
        shift 2 ;;
      --since-peer-out)
        if [ "$#" -lt 2 ]; then wrapper_die '--since-peer-out needs a value'; fi
        ARG_SINCE_PEER_OUT="$(rails_assert_log_cursor "$2")" \
          || wrapper_die "bad peer stdout log cursor: ${2:-<missing>}"
        shift 2 ;;
      --since-peer-err)
        if [ "$#" -lt 2 ]; then wrapper_die '--since-peer-err needs a value'; fi
        ARG_SINCE_PEER_ERR="$(rails_assert_log_cursor "$2")" \
          || wrapper_die "bad peer stderr log cursor: ${2:-<missing>}"
        shift 2 ;;
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
  #    THE DECISION IS THE HARDWARE FINGERPRINT. Names are a deny-only belt.
  #    A live audit of the real machines found Mini1 answering `hostname -s`
  #    with the literal string "Mac", so a name allowlist able to admit Mini1
  #    would admit a large fraction of default-configured Macs. There is no
  #    name allowlist any more.
  local h_fp h_short h_full h_computer h_local
  h_fp="$(rails_host_fingerprint_local)" \
    || wrapper_die 'cannot establish this machine hardware identity; refusing'
  if [ -z "$h_fp" ]; then wrapper_die 'empty host fingerprint after rail'; fi
  h_short="$(rails__sys hostname -s 2>/dev/null || printf '')"
  h_full="$(rails__sys hostname -f 2>/dev/null || rails__sys hostname 2>/dev/null || printf '')"
  h_computer="$(rails__sys scutil --get ComputerName 2>/dev/null || printf '')"
  h_local="$(rails__sys scutil --get LocalHostName 2>/dev/null || printf '')"
  # ONE call, no branches, every observed identity handed over. The reviewed
  # build chose between three if/elif branches that passed different subsets,
  # and one of them silently DROPPED the ComputerName alias. The rail skips the
  # empty ones itself, so there is nothing here to get wrong. `scutil --get
  # HostName` is deliberately not consulted: it is UNSET on the drill host, and
  # a lookup that is empty on the machine we care about teaches nothing.
  wrapper_rail rails_assert_host_allowed_observed \
      "$h_fp" "$h_short" "$h_full" "$h_computer" "$h_local" \
    || wrapper_die "host rail rejected this machine (${h_short:-unnamed})"

  # 2. OPERATOR ACCOUNT, before any `sudo -u`. The reviewed build passed this
  #    straight through, so `--operator-account root` plus a caller-supplied URL
  #    yielded curl as root.
  OPERATOR_UID="$(rails_assert_non_root_account 'operator' "$ARG_OPERATOR")" \
    || wrapper_die "operator account rejected: $ARG_OPERATOR"
  if [ -z "$OPERATOR_UID" ]; then wrapper_die 'empty operator uid after rail'; fi

  # 3. AGENT ACCOUNT + UID pairing (this part held in review; keep it), plus
  #    the COMPILED-IN AGENT ALLOWLIST.
  #
  #    Round-3 M2: `--agent-account` was the one surviving caller-supplied
  #    steering input, and it is the input that decides WHO root acts against.
  #    Shape and non-rootness were checked; membership was not, so the grant
  #    holder could aim a root-run `protect --exclusive-egress` at any non-root
  #    local account. The allowlist rail runs BEFORE the uid pairing, so an
  #    account this drill was never provisioned for is refused before anything
  #    looks it up.
  if [ -n "$ARG_AGENT" ] || [ -n "$ARG_AGENT_UID" ]; then
    if [ -z "$ARG_AGENT" ]; then wrapper_die '--agent-uid given without --agent-account'; fi
    if [ -z "$ARG_AGENT_UID" ]; then wrapper_die '--agent-account given without --agent-uid'; fi
    wrapper_rail rails_assert_agent_account_allowed "$ARG_AGENT" \
      || wrapper_die "agent account is not on the compiled-in drill agent allowlist: $ARG_AGENT"
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
}

# Verbs whose whole subject is one confined agent need that agent's uid,
# because every product-facing identifier they touch is per-uid. Stated as its
# own guard so the failure is "this verb needs an agent" rather than a label
# composed from an empty string.
wrapper_require_agent() {
  if [ -z "$ARG_AGENT" ] || [ -z "$AGENT_UID" ]; then
    wrapper_die "$WRAPPER_VERB requires --agent-account and --agent-uid"
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

# Global return slot used so unsafe-path failures cannot be accidentally
# collapsed into "file absent" by command substitution.
WRAPPER_SAFE_TARGET=''
WRAPPER_SAFE_OPEN_SIZE=''
WRAPPER_SAFE_OPEN_IDENTITY=''

# Resolve an OPTIONAL existing regular file under an already-approved root.
# The resolver walks every component through `rails_assert_safe_subpath`; a
# missing final file returns 1, while a symlink, traversal, non-regular file or
# unsafe root is a wrapper rejection.
wrapper_resolve_optional_file_under() {
  local root="$1" rel="$2" label="$3" p
  WRAPPER_SAFE_TARGET=''
  p="$(rails_assert_safe_subpath "$root" "$rel")" \
    || wrapper_die "unsafe $label path under $root: $rel"
  if [ -z "$p" ]; then wrapper_die "empty $label path after the safe-subpath rail: $rel"; fi
  if [ ! -e "$p" ]; then return 1; fi
  if [ ! -f "$p" ]; then wrapper_die "$label path exists and is not a regular file: $p"; fi
  WRAPPER_SAFE_TARGET="$p"
  return 0
}

wrapper_cursor_size() {
  printf '%s' "${1%%,*}"
}

wrapper_cursor_identity() {
  local rest="${1#*,}"
  printf '%s' "$rest"
}

wrapper_open_safe_file_under() {
  local root="$1" rel="$2" label="$3" checked oldpwd parent_rel leaf expected actual oldifs noglob_was_set='' seg nlink fd_nlink
  WRAPPER_SAFE_TARGET=''
  WRAPPER_SAFE_OPEN_SIZE=''
  WRAPPER_SAFE_OPEN_IDENTITY=''
  exec 9<&- 2>/dev/null || true
  checked="$(rails_assert_safe_subpath "$root" "$rel")" \
    || wrapper_die "unsafe $label path under $root: $rel"
  if [ -z "$checked" ]; then wrapper_die "empty $label path after the safe-subpath rail: $rel"; fi
  WRAPPER_SAFE_TARGET="$checked"
  oldpwd="$(pwd -P 2>/dev/null || printf '/')"
  cd -P "$root" || wrapper_die "could not enter safe root for $label: $root"
  # ROUND-5 L4. Every DESCENDED component gets a `pwd -P`-vs-expected assertion
  # below; the root itself did not. The property was held by an invariant
  # somewhere else (`rails_assert_safe_subpath` refuses a non-canonical root,
  # and `rails_assert_trusted_dir_chain` returns a resolved one), which is
  # exactly the shape of the round-2 unchecked-intermediate finding: a
  # guarantee asserted at a distance instead of at the point that depends on
  # it. It is one line, and it is now here.
  actual="$(pwd -P)" || wrapper_die "could not resolve cwd after entering the safe root for $label: $root"
  if [ "$actual" != "$root" ]; then
    wrapper_die "$label safe root $root resolved to $actual; refusing to read under a root that is not what it says"
  fi
  expected="$root"
  parent_rel="${rel%/*}"
  leaf="${rel##*/}"
  if [ "$parent_rel" = "$rel" ]; then parent_rel=''; fi

  if [ -n "$parent_rel" ]; then
    oldifs="$IFS"
    case "$-" in *f*) noglob_was_set='yes' ;; esac
    set -f
    IFS='/'
    # shellcheck disable=SC2086
    set -- $parent_rel
    IFS="$oldifs"
    if [ -z "$noglob_was_set" ]; then set +f; fi
    for seg in "$@"; do
      if [ -z "$seg" ]; then continue; fi
      expected="$expected/$seg"
      if [ -L "$seg" ]; then
        wrapper_die "$label path component $expected is a symlink; refusing to follow it"
      fi
      if [ ! -e "$seg" ]; then
        cd -P "$oldpwd" 2>/dev/null || cd -P / || wrapper_die "could not restore cwd after absent $label"
        return 1
      fi
      if [ ! -d "$seg" ]; then
        wrapper_die "$label path component $expected is not a directory"
      fi
      cd -P "$seg" || wrapper_die "could not enter $label path component $expected"
      actual="$(pwd -P)" || wrapper_die "could not resolve cwd after entering $label path component $expected"
      if [ "$actual" != "$expected" ]; then
        wrapper_die "$label path component $expected resolved outside the approved root; refusing"
      fi
    done
  fi

  if [ -L "$leaf" ]; then
    wrapper_die "$label path $checked is a symlink; refusing to follow it"
  fi
  if [ ! -e "$leaf" ]; then
    cd -P "$oldpwd" 2>/dev/null || cd -P / || wrapper_die "could not restore cwd after absent $label"
    return 1
  fi
  if [ ! -f "$leaf" ]; then
    wrapper_die "$label path exists and is not a regular file: $checked"
  fi
  # ROUND-4 F1, closed at the ONE open chokepoint every privileged read shares
  # (gate-log tail, gate-log cursor, gate-port cat). The fd-identity check
  # below compares inode,uid,gid across the open, which catches a swapped or
  # symlinked leaf -- but a HARD LINK passes all three, because it IS the
  # target's inode. The gate service uid owns its own log dir and its runtime
  # uid dir, so it could plant a log name or `state.json` as a hard link at a
  # file outside the approved tree and this root-run wrapper would read the
  # target. No file this wrapper legitimately reads has a second name, so a
  # multiply-linked leaf is refused outright.
  #
  # ROUND-6 RE-GATE. This pathname lstat is a CHEAP EARLY REFUSAL and nothing
  # more. A previous version of this comment claimed a link added after it
  # "cannot help an attacker, because replacing the leaf changes the inode and
  # dies on the identity check below." That was WRONG, and was defeated by
  # execution: this lstat is a SEPARATE namei from the identity lstat below,
  # so an attacker who unlinks the leaf and hard-links a victim in its place
  # between the two has the count measured on the DISCARDED file while the
  # identity lstat and the open both see the hard link and agree with each
  # other. Nothing bound this read to the open. The binding read is the one on
  # the HELD FD after the open, below; that one measures the same object the
  # bytes come from, by construction.
  nlink="$(rails__stat_nlink "$leaf")" \
    || wrapper_die "could not read the link count for $label: $checked"
  case "$nlink" in
    ''|*[!0-9]*) wrapper_die "unparseable link count for $label: $checked" ;;
  esac
  if [ "$nlink" -gt 1 ]; then
    wrapper_die "$label has $nlink hard links; refusing to read a multiply-linked file that can alias a path outside the approved tree: $checked"
  fi
  WRAPPER_SAFE_OPEN_IDENTITY="$(rails__stat_identity "$leaf")" \
    || wrapper_die "could not stat identity for $label before open: $checked"
  WRAPPER_SAFE_OPEN_SIZE="$(rails__stat_size "$leaf")" \
    || wrapper_die "could not stat size for $label before open: $checked"
  exec 9< "$leaf" || wrapper_die "could not open $label: $checked"
  if [ "$(rails__stat_identity /dev/fd/9)" != "$WRAPPER_SAFE_OPEN_IDENTITY" ]; then
    exec 9<&-
    wrapper_die "$label changed between path resolution and fd open; refusing to read a substituted path: $checked"
  fi
  # THE AUTHORITATIVE LINK-COUNT READ. Same fd the bytes come from, so it is
  # bound to the open the way the identity compare above is; the pathname
  # pre-check is not, and a swap in its window is a real attack (round-6
  # re-gate, proved by execution on both `gate-port` and `gate-log`). `stat`
  # on `/dev/fd/<n>` reports the TARGET's link count on both stat families,
  # the same way it already reports the target's inode/uid/gid for the
  # identity compare, so this needs no new mechanism -- just the right object.
  fd_nlink="$(rails__stat_nlink /dev/fd/9)" \
    || { exec 9<&-; wrapper_die "could not read the link count for $label from its checked fd: $checked"; }
  case "$fd_nlink" in
    ''|*[!0-9]*) exec 9<&-; wrapper_die "unparseable link count for $label from its checked fd: $checked" ;;
  esac
  if [ "$fd_nlink" -gt 1 ]; then
    exec 9<&-
    wrapper_die "$label has $fd_nlink hard links; refusing to read a multiply-linked file that can alias a path outside the approved tree: $checked"
  fi
  cd -P "$oldpwd" 2>/dev/null || cd -P / || wrapper_die "could not restore cwd after opening $label"
  return 0
}

wrapper_emit_log_cursor() {
  local key="$1" root="$2" rel="$3" label="$4"
  if wrapper_open_safe_file_under "$root" "$rel" "$label"; then
    printf 'WRAPPER=GATE-LOG-CURSOR key=%s cursor=%s,%s file=%s\n' \
      "$key" "$WRAPPER_SAFE_OPEN_SIZE" "$WRAPPER_SAFE_OPEN_IDENTITY" "$WRAPPER_SAFE_TARGET"
    exec 9<&-
  else
    printf 'WRAPPER=GATE-LOG-CURSOR key=%s cursor=0,0,0,0 file=absent\n' "$key"
  fi
}

wrapper_cat_safe_file_under() {
  local root="$1" rel="$2" label="$3" target
  wrapper_open_safe_file_under "$root" "$rel" "$label" || return 1
  target="$WRAPPER_SAFE_TARGET"
  rails__sys cat <&9 || { exec 9<&-; wrapper_die "could not read $label from its checked fd: $target"; }
  exec 9<&-
  return 0
}

wrapper_tail_safe_file_under() {
  local root="$1" rel="$2" label="$3" cursor="$4" target size since cursor_id start
  cursor="$(rails_assert_log_cursor "$cursor")" \
    || wrapper_die "bad log cursor for $label: $cursor"
  since="$(wrapper_cursor_size "$cursor")"
  cursor_id="$(wrapper_cursor_identity "$cursor")"
  if ! wrapper_open_safe_file_under "$root" "$rel" "$label"; then
    if [ "$cursor_id" != '0,0,0' ]; then
      wrapper_die "$label disappeared after cursor $cursor; the appended log window cannot be trusted"
    fi
    return 1
  fi
  target="$WRAPPER_SAFE_TARGET"
  size="$WRAPPER_SAFE_OPEN_SIZE"
  if [ "$cursor_id" != '0,0,0' ]; then
    if [ "$WRAPPER_SAFE_OPEN_IDENTITY" != "$cursor_id" ]; then
      wrapper_die "$label identity changed since cursor $cursor; refusing to attribute stale log bytes: $target"
    fi
    if [ $((10#$size)) -lt $((10#$since)) ]; then
      wrapper_die "$label shrank since cursor $cursor; refusing to attribute a rotated or truncated log: $target"
    fi
  fi
  printf 'WRAPPER=GATE-LOG-BEGIN file=%s cursor=%s\n' "$target" "$cursor"
  if [ "$cursor" = '0,0,0,0' ]; then
    rails__sys tail -n "$WRAPPER_GATE_LOG_LINES" <&9 \
      || { exec 9<&-; wrapper_die "could not read $label from its checked fd: $target"; }
  else
    start=$((10#$since + 1))
    rails__sys tail -c +"$start" <&9 \
      || { exec 9<&-; wrapper_die "could not read appended bytes from $label: $target"; }
  fi
  exec 9<&-
  printf '\nWRAPPER=GATE-LOG-END file=%s\n' "$target"
  return 0
}

# ONE preparation for every verb that reads a SERVICE-OWNED subtree: trust-chain
# only the root-owned base, because the remainder of the path is owned by the
# product's service uid ON PURPOSE (the gate account owns its own home; the gate
# daemon's runtime uid dir is chowned to the gate uid at arming time,
# `server/src/egress-gate/runtime-fs-plan.ts`). The service-owned remainder is
# then hand-walked through `wrapper_open_safe_file_under`, which proves each
# component is a real, non-symlink directory that resolves where it says and
# reads the leaf through a checked fd -- but applies NO root-or-self ownership
# rail, because on a real host the owner IS the service uid and a root-run read
# across that ownership boundary is the whole point of the verb.
#
# ROUND-6 H1. `gate-port` did not use this shape. It resolved the runtime state
# through `wrapper_resolve_absolute_optional_file`, whose trusted-chain rail
# covers the WHOLE parent -- including `/var/db/sanctuary/gate-runtime/<uid>`,
# which the product chowns to the gate uid -- so on a real host the root-run
# wrapper deterministically died reading the daemon's own document and every
# through-gate probe reported UNOBSERVED. The selftest stayed green because its
# sandbox is owned by the caller (self == owner satisfies the rail), which is
# the same stub-fidelity blind spot that kept round-5 B1 alive. Both gate verbs
# now prepare their base HERE, so there is one matcher, not two that can drift;
# the ownership shape itself is exercised by an injected-owner selftest.
wrapper_prepare_service_base() {
  local label="$1" base="$2"
  WRAPPER_SAFE_TARGET=''
  if [ ! -e "$base" ]; then return 1; fi
  WRAPPER_SAFE_TARGET="$(rails_assert_trusted_dir_chain "$label" "$base")" \
    || wrapper_die "$label is not a trusted root-owned chain: $base"
  if [ -z "$WRAPPER_SAFE_TARGET" ]; then wrapper_die "empty $label after trusted-chain rail"; fi
  return 0
}

wrapper_prepare_gate_log_root() {
  wrapper_prepare_service_base 'gate account home base' "$RAILS_PRODUCT_GATE_HOME_BASE"
}

wrapper_prepare_gate_runtime_root() {
  wrapper_prepare_service_base 'gate runtime base' "$RAILS_PRODUCT_GATE_RUNTIME_DIR"
}

wrapper_resolve_absolute_optional_file() {
  local abs="$1" label="$2" parent leaf root
  WRAPPER_SAFE_TARGET=''
  if [ -z "$abs" ]; then wrapper_die "empty absolute path for $label"; fi
  case "$abs" in /*) ;; *) wrapper_die "$label path is not absolute: $abs" ;; esac
  case "$abs" in
    *$'\n'*|*$'\t'*|*$'\r'*) wrapper_die "$label path contains a control character" ;;
  esac
  abs="$(rails__squeeze_slashes "$abs")"
  case "$abs/" in
    */../*|*/./*) wrapper_die "$label path contains a relative component: $abs" ;;
  esac
  parent="${abs%/*}"
  leaf="${abs##*/}"
  if [ -z "$parent" ] || [ "$parent" = "$abs" ]; then parent='/'; fi
  if [ ! -e "$parent" ]; then return 1; fi
  root="$(rails_assert_trusted_dir_chain "$label parent" "$parent")" \
    || wrapper_die "$label parent is not a trusted root-owned chain: $parent"
  if [ -z "$root" ]; then wrapper_die "empty trusted parent for $label: $parent"; fi
  wrapper_resolve_optional_file_under "$root" "$leaf" "$label"
}

# ONE candidate's state, as a single token. Every branch is an OBSERVATION:
# there is no state here that means "I did not look", the same rule the
# tri-state verify checks in teardown-verify.sh live by.
#
#   symlink                      the leaf is a symlink; lstat'd FIRST, so a
#                                dangling one reads as `symlink` and not as
#                                `absent`
#   absent                       nothing at the path
#   not-a-regular-file           a directory, socket, device
#   not-executable
#   unstattable                  it is there and we could not read its metadata,
#                                which is not the same as it being fine
#   group-or-world-writable(...)
#   not-root-owned(uid=N)
#   untrusted-parent(DIR)        the file is root-owned but sits in a directory
#                                chain that is not, so it can be UNLINKED AND
#                                REPLACED by whoever owns that directory. This
#                                is the rule the single-path version was missing
#                                entirely: `/usr/local/bin` is operator-owned on
#                                a Mac often enough that this repo already
#                                refuses to put it on PATH, and the compiled-in
#                                CLI lived there with only its own mode and
#                                owner checked.
#   ok
#
# `rails_assert_trusted_dir_chain` fails by `exit`, deliberately (rails design
# rule 2), so it is called in an explicit SUBSHELL: a candidate that fails must
# advance the walk, not kill a uid-0 process mid-verb.
wrapper_cli_candidate_state() {
  local cand="$1" mode owner parent
  if [ -L "$cand" ]; then printf 'symlink'; return 0; fi
  if [ ! -e "$cand" ]; then printf 'absent'; return 0; fi
  if [ ! -f "$cand" ]; then printf 'not-a-regular-file'; return 0; fi
  if [ ! -x "$cand" ]; then printf 'not-executable'; return 0; fi
  if ! mode="$(rails__stat_mode "$cand")"; then printf 'unstattable'; return 0; fi
  if [ $(( 8#$mode & 8#22 )) -ne 0 ]; then
    printf 'group-or-world-writable(mode=%s)' "$mode"; return 0
  fi
  if ! owner="$(rails__stat_owner_uid "$cand")"; then printf 'unstattable'; return 0; fi
  if [ "$owner" -ne 0 ]; then printf 'not-root-owned(uid=%s)' "$owner"; return 0; fi
  parent="${cand%/*}"
  if [ -z "$parent" ]; then parent='/'; fi
  if ! ( rails_assert_trusted_dir_chain 'cli parent' "$parent" ) >/dev/null 2>&1; then
    printf 'untrusted-parent(%s)' "$parent"; return 0
  fi
  printf 'ok'
}

# Walk the compiled-in candidates and select the FIRST TRUSTED one, recording
# what every candidate probed before it did. Sets `WRAPPER_CLI` and
# `WRAPPER_CLI_PROBED`; returns non-zero when no candidate is trustworthy.
#
# FIRST TRUSTED, never first existing. The walk stops at the first `ok` because
# a later candidate's state is not evidence about a question already answered
# yes, and it does NOT stop at the first candidate that merely exists, which is
# the whole point.
wrapper_resolve_cli() {
  local cand state
  WRAPPER_CLI=''
  WRAPPER_CLI_PROBED=''
  for cand in $WRAPPER_CLI_CANDIDATES; do
    state="$(wrapper_cli_candidate_state "$cand")"
    WRAPPER_CLI_PROBED="$WRAPPER_CLI_PROBED $cand=$state"
    if [ "$state" = 'ok' ]; then WRAPPER_CLI="$cand"; break; fi
  done
  [ -n "$WRAPPER_CLI" ]
}

# The wrapper may exec only a candidate that passed the whole gauntlet. A
# wrapper that execs an operator-writable path would hand the grant away.
#
# This runs immediately before every real CLI invocation, NOT as part of the
# argument gauntlet. The distinction matters for the `check` oracle: `check`
# answers "do the caller's arguments pass the safety rails", which is a
# question about the caller, and it must answer identically on a machine that
# has not installed the product yet. CLI availability is reported by `check` as
# an advisory field instead, and is a hard precondition for anything that
# actually executes.
#
# ON TOTAL FAILURE THE REFUSAL NAMES EVERY CANDIDATE AND WHAT WAS WRONG WITH
# EACH, and then names the remedy. "No trusted CLI anywhere" and "the CLI you
# installed is one root must not run" are two very different mornings, and the
# operator can only act on the second if the message tells them which it is.
wrapper_assert_cli() {
  if ! wrapper_resolve_cli; then
    wrapper_die "no trusted Sanctuary CLI on this host; probed:$WRAPPER_CLI_PROBED -- this wrapper runs the CLI as ROOT, so it will not execute an operator-writable path, a symlink, or a file under a directory chain the operator can replace it in; install the product CLI as a root-owned non-group-writable regular file under a root-owned directory (for example: sudo install -o root -g wheel -m 0755 <cli> /usr/local/bin/sanctuary, with /usr/local/bin itself root-owned and not group-writable)"
  fi
}

# Non-fatal CLI probe, for the `check` advisory field only. Two fields: the
# selected path (or `-`), and the per-candidate record either way, so `check`
# on a host with no usable CLI says which candidates it looked at rather than
# one bare token.
wrapper_cli_status() {
  if wrapper_resolve_cli; then
    printf 'ok cli_path=%s cli_probed:%s' "$WRAPPER_CLI" "$WRAPPER_CLI_PROBED"
  else
    printf 'none cli_path=- cli_probed:%s' "$WRAPPER_CLI_PROBED"
  fi
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
  # Post-condition, in the same shape as the two non-empty storage
  # post-conditions above: the resolver is the ONLY writer of `WRAPPER_CLI`,
  # and an empty one here would exec the argument vector through the shell.
  if [ -z "$WRAPPER_CLI" ]; then wrapper_die 'empty CLI path after the resolver'; fi
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

# ---------------------------------------------------------------------------
# DAEMON OBSERVATION, for `kickstart-daemons`
# ---------------------------------------------------------------------------

# One evidence field: the accumulated space-prefixed list, comma-joined, or `-`
# when it is empty. A field that is EMPTY and a field that is ABSENT must not
# look the same in an evidence line somebody reads at 7am.
wrapper_daemon_field() {
  local v="${1# }"
  if [ -z "$v" ]; then printf -- '-'; return 0; fi
  printf '%s' "${v// /,}"
}

# Does this daemon EXIST on this host? Two independent signals, and either one
# is enough:
#
#   - launchd has the job loaded (`launchctl print` answers). This is true for
#     an on-demand job that is not currently running, which is why it is the
#     first question and not "is there a pid".
#   - the product's plist for it is on disk. A plist present with no loaded job
#     is a real state (an install that never bootstrapped), and it MUST read as
#     "exists" so that the kickstart of it is attempted and its failure named --
#     reading it as "not installed" is how a broken install would pass as the
#     expected pre-arm absence.
#
# Deliberately NOT inferred from `launchctl kickstart`'s exit code, which is
# non-zero both for "no such service" and for "it would not restart".
wrapper_daemon_present() {
  local label="$1" plist
  if rails__sys launchctl print "system/$label" >/dev/null 2>&1; then return 0; fi
  plist="$(rails_product_daemon_plist_path "$label")" \
    || wrapper_die "could not compose the plist path for $label"
  if [ -z "$plist" ]; then wrapper_die "empty plist path composed for $label"; fi
  if [ -e "$plist" ]; then return 0; fi
  return 1
}

# `restarted`, `restart-failed` or `absent` for one label. The caller decides
# what an `absent` MEANS, because that depends on the label's class and on the
# observed arm state, and this function deliberately knows neither.
wrapper_kickstart_classify() {
  local label="$1"
  if ! wrapper_daemon_present "$label"; then printf 'absent\n'; return 0; fi
  if rails__sys launchctl kickstart -k "system/$label" >/dev/null 2>&1; then
    printf 'restarted\n'
  else
    printf 'restart-failed\n'
  fi
}

# Is this uid CONFINED right now, according to the product's own record?
#
# Sets WRAPPER_ARM_STATE (`armed` / `not-armed`) and WRAPPER_ARM_BASIS, which
# names WHICH observation produced the answer, so the evidence line carries the
# reason and not just the verdict.
#
# There is no third value for "I could not look": a registry that exists and
# cannot be read is a REFUSAL, because an unobserved arm state cannot decide
# whether a missing gate daemon is the expected pre-arm state or a defect, and
# guessing would have to guess in the direction that makes absence look fine.
wrapper_observe_arm_state() {
  local uid="$1" reg="$RAILS_PRODUCT_ANCHOR_REGISTRY" content rc=0 parent leaf root names
  WRAPPER_ARM_STATE=''
  WRAPPER_ARM_BASIS=''
  if ! wrapper_resolve_absolute_optional_file "$reg" 'pf-anchor registry'; then
    # No registry at all: nothing on this host is confined, so no gate daemon
    # is owed. This is an OBSERVED answer, the same one `registry-state`
    # reports as `state=absent`, not an assumption.
    WRAPPER_ARM_STATE='not-armed'
    WRAPPER_ARM_BASIS='registry-absent'
    return 0
  fi
  parent="${WRAPPER_SAFE_TARGET%/*}"
  leaf="${WRAPPER_SAFE_TARGET##*/}"
  root="$parent"
  content="$(wrapper_cat_safe_file_under "$root" "$leaf" 'pf-anchor registry')" || rc=$?
  if [ "$rc" -ne 0 ]; then
    wrapper_die "could not READ the pf-anchor registry at $reg (cat rc=$rc); the arm state of uid $uid is UNOBSERVED, and an unobserved arm state cannot say whether a missing gate daemon is expected"
  fi
  names="$(rails_registry_names_agent_uid "$content" "$uid")" \
    || wrapper_die "could not probe the pf-anchor registry for uid $uid"
  case "$names" in
    yes) WRAPPER_ARM_STATE='armed';     WRAPPER_ARM_BASIS='registry-names-uid' ;;
    no)  WRAPPER_ARM_STATE='not-armed'; WRAPPER_ARM_BASIS='registry-silent-on-uid' ;;
    *)   wrapper_die "unrecognised registry probe answer '$names' for uid $uid" ;;
  esac
}

# The reviewed build ran `launchctl kickstart ... || true` and then printed
# WRAPPER=OK unconditionally, which made a failed restart read as a success.
# The kickstart IS this verb's entire job, so its status IS the verb's status.
#
# ROUND 3 (H3): the labels were `com.sanctuary.egress-gate{,-peer-resolver}` and
# the product's are `ai.sanctuaryprotocol.egress-gate{,-peer-resolver}.<uid>`.
# Both halves were wrong -- a different reverse-DNS prefix AND no uid suffix --
# so no prefix substitution could have fixed them, and this verb had no
# `--agent-uid` in its call path at all. Since this is step 0 of every
# iteration and a failed kickstart is (correctly) fatal, the loop as shipped
# could not complete a single iteration. The labels now come from
# `rails_product_daemon_labels`, which is pinned to the product's exports.
#
# 2026-07-25, THE FIRST LIVE SUPERVISED RUN (Mini1): the verb still could not
# let iteration 1 begin, for a reason no amount of correcting strings reaches.
# It restarted the two PER-UID gate labels and nothing else, and it read a
# non-zero `launchctl kickstart` as one thing: a failed restart. On a clean,
# disarmed host those two daemons DO NOT EXIST YET -- the arm creates them, and
# the arm is step 3 of the ladder this verb is step 0 of -- so the loop refused
# to start for the state it is designed to start from, reporting
# `(restarted: none)`, which is equally what a total restart failure looks like.
#
# THREE STATES, NOT TWO, AND ALL THREE OBSERVED:
#
#   restarted        the daemon was seen to exist and `kickstart -k` succeeded.
#   absent-expected  the daemon was seen NOT to exist, and its class says
#                    absence is the expected state right now.
#   absent-unexpected / restart-failed
#                    the two failures, kept apart in the evidence because they
#                    need different mornings: one means "the thing that should
#                    be here is not", the other means "it is here and it would
#                    not restart".
#
# EXISTENCE IS OBSERVED, NEVER INFERRED FROM THE RESTART'S EXIT CODE. That
# inference is the whole defect: `launchctl kickstart` exits non-zero for
# "no such service" and for "the service refused to restart" alike.
#
# WHAT MAKES ABSENCE EXPECTED IS ALSO OBSERVED. It is not the iteration number
# and not the step index -- both of those would go stale the first time the
# ladder re-kickstarts after arming, and would make this verb permanently blind
# to a gate daemon that SHOULD exist by then. It is the product's own
# root-owned pf-anchor registry: if that registry names this uid, the uid is
# confined and its gate daemons must be there. A registry that exists and
# cannot be READ is neither answer, and gets neither: the verb refuses, because
# an unobserved arm state cannot decide whether an absence is expected.
wrapper_verb_kickstart_daemons() {
  wrapper_require_agent
  local host_labels gate_labels label klass
  local restarted='' absent_expected='' absent_unexpected='' restart_failed=''

  wrapper_observe_arm_state "$AGENT_UID"

  host_labels="$(rails_product_host_daemon_labels)" \
    || wrapper_die 'could not compose the product host daemon labels'
  if [ -z "$host_labels" ]; then wrapper_die 'empty host daemon label list after the rail'; fi
  gate_labels="$(rails_product_daemon_labels "$AGENT_UID")" \
    || wrapper_die "could not compose the product daemon labels for uid $AGENT_UID"
  if [ -z "$gate_labels" ]; then wrapper_die 'empty per-uid daemon label list after the rail'; fi

  # The host daemons are installed by the product and do not depend on any arm,
  # so there is no state of this host in which their absence is expected. An
  # iteration that ran without them would measure code nobody restarted.
  for label in $host_labels; do
    klass="$(wrapper_kickstart_classify "$label")" \
      || wrapper_die "could not classify the host daemon $label"
    case "$klass" in
      restarted)      restarted="$restarted $label" ;;
      restart-failed) restart_failed="$restart_failed $label" ;;
      absent)         absent_unexpected="$absent_unexpected $label" ;;
      *)              wrapper_die "unrecognised daemon classification '$klass' for $label" ;;
    esac
  done

  # The per-uid gate daemons exist only while this uid is armed. Note that the
  # arm state governs ONLY what an ABSENCE means: a gate daemon that is present
  # is restarted, and its restart failure is fatal, armed or not.
  for label in $gate_labels; do
    klass="$(wrapper_kickstart_classify "$label")" \
      || wrapper_die "could not classify the gate daemon $label"
    case "$klass" in
      restarted)      restarted="$restarted $label" ;;
      restart-failed) restart_failed="$restart_failed $label" ;;
      absent)
        if [ "$WRAPPER_ARM_STATE" = 'armed' ]; then
          absent_unexpected="$absent_unexpected $label"
        else
          absent_expected="$absent_expected $label"
        fi ;;
      *)              wrapper_die "unrecognised daemon classification '$klass' for $label" ;;
    esac
  done

  if [ -n "$restart_failed" ] || [ -n "$absent_unexpected" ]; then
    # The leading token stays `kickstart failed for:` so the one thing a
    # morning reader greps for has not moved, and the three-way breakdown
    # follows it: today's `(restarted: none)` was ambiguous between "everything
    # failed to restart", "nothing was there" and "nothing was there and that
    # was fine".
    wrapper_die "kickstart failed for:$restart_failed$absent_unexpected (arm_state=$WRAPPER_ARM_STATE arm_basis=$WRAPPER_ARM_BASIS restarted=$(wrapper_daemon_field "$restarted") absent_expected=$(wrapper_daemon_field "$absent_expected") absent_unexpected=$(wrapper_daemon_field "$absent_unexpected") restart_failed=$(wrapper_daemon_field "$restart_failed"))"
  fi
  printf 'WRAPPER=OK verb=kickstart-daemons arm_state=%s arm_basis=%s restarted=%s absent_expected=%s absent_unexpected=%s restart_failed=%s\n' \
    "$WRAPPER_ARM_STATE" "$WRAPPER_ARM_BASIS" \
    "$(wrapper_daemon_field "$restarted")" "$(wrapper_daemon_field "$absent_expected")" \
    "$(wrapper_daemon_field "$absent_unexpected")" "$(wrapper_daemon_field "$restart_failed")"
}

wrapper_verb_arm() {
  wrapper_require_agent
  # Pass the RAIL'S output, not the raw argument. The rail proved the two are
  # equal, so this is not a behavior change today; it is the habit that stops a
  # later edit from reintroducing a validated-then-unvalidated split.
  wrapper_cli protect --exclusive-egress --agent-account "$ARG_AGENT" --agent-uid "$AGENT_UID"
  # WHICH CANDIDATE RAN, in the verdict line. An evidence file that records the
  # arm but not the binary that armed it cannot answer "which build was this"
  # on a host with more than one install.
  printf 'WRAPPER=OK verb=arm storage=%s cli=%s\n' "$STORAGE" "$WRAPPER_CLI"
}

wrapper_verb_repair() {
  wrapper_cli protect --repair-egress-gate
  printf 'WRAPPER=OK verb=repair storage=%s cli=%s\n' "$STORAGE" "$WRAPPER_CLI"
}

wrapper_verb_unprotect() {
  wrapper_cli protect --unprotect-egress-gate
  printf 'WRAPPER=OK verb=unprotect storage=%s cli=%s\n' "$STORAGE" "$WRAPPER_CLI"
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
    # The mandatory form, including here. `wrapper_safe_path` dies inside this
    # command substitution, so without the `||` the abort would depend on
    # `set -e` alone, and relying on `set -e` alone is exactly what this
    # codebase decided not to do after round 1.
    target="$(wrapper_safe_path "$rel")" \
      || wrapper_die "unsafe path under the storage directory: $rel"
    if [ -z "$target" ]; then wrapper_die "empty path after the safe-subpath rail: $rel"; fi
    if [ -f "$target" ]; then
      rails__sys rm -f -- "$target"
      printf 'WRAPPER=OK removed %s\n' "$target"
    fi
  done
  printf 'WRAPPER=OK verb=clean-markers storage=%s\n' "$STORAGE"
}

# Read-only state dump. It used to print `WRAPPER=OK verb=gate-state`
# UNCONDITIONALLY after printing `(no ... daemon)` and `(no anchor rules)`
# (round-3 L3), which is the same shape as the `kickstart-daemons` fail-open one
# function above it: an evidence file that looks like a successful read of two
# daemons that do not exist under those labels. A dump verb that observed
# NOTHING is not an OK dump.
wrapper_verb_gate_state() {
  wrapper_require_agent
  local labels label observed=0
  labels="$(rails_product_daemon_labels "$AGENT_UID")" \
    || wrapper_die "could not compose the product daemon labels for uid $AGENT_UID"
  printf -- '--- launchctl ---\n'
  for label in $labels; do
    if rails__sys launchctl print "system/$label" 2>/dev/null; then
      observed=$(( observed + 1 ))
    else
      printf '(no %s daemon)\n' "$label"
    fi
  done
  printf -- '--- pf anchor ---\n'
  if rails__sys pfctl -a "$RAILS_PRODUCT_PF_ANCHOR" -s rules 2>/dev/null; then
    observed=$(( observed + 1 ))
  else
    printf '(pf anchor %s could not be read)\n' "$RAILS_PRODUCT_PF_ANCHOR"
  fi
  if [ "$observed" -eq 0 ]; then
    wrapper_die "gate-state observed NOTHING: neither daemon under $labels answered and the pf anchor $RAILS_PRODUCT_PF_ANCHOR could not be read; an empty dump is not a successful read"
  fi
  printf 'WRAPPER=OK verb=gate-state observed=%s agent_uid=%s\n' "$observed" "$AGENT_UID"
}

# Read the ROOT-OWNED pf-anchor registry, and say plainly which of the three
# answers this is: absent, present-and-readable, or present-and-unreadable.
#
# ROUND-3 H1 / Codex finding 3. Both `preflight.sh` and `teardown-verify.sh` did
#
#     if [ -f "$registry" ] && grep -q -- "$STORAGE" "$registry" 2>/dev/null
#     then dirty; else clean; fi
#
# against a path the product does not use. Correcting the path alone makes it
# WORSE-looking and no better: the real registry is root-`0600` inside a `0700`
# directory, so an unprivileged `grep` returns 2 and the `else` branch still
# says CLEAN. "no match", "cannot read" and "not there" were one verdict. Root
# can actually read it, so root is who reads it.
#
# 2026-07-25 FOLLOW-ON: THIS VERB IS ALSO WHERE THE ARM-STATE DECISION IS
# PUBLISHED, AND IT IS PUBLISHED ONCE.
#
# `kickstart-daemons` learned that a per-uid gate daemon's absence is expected
# only while the registry is silent on this uid. `preflight.sh` screens exactly
# the same per-uid daemons one step later and needs exactly the same decision.
# The tempting shape is for the driver to fetch the registry bytes (it already
# does, for `orphan-registry`) and answer the question itself -- which would put
# TWO implementations of one predicate in the tree, in two languages of shell,
# maintained by whoever next touches either. This project has already lost a
# round to two copies of one matcher drifting apart, so the driver gets the
# WRAPPER'S answer instead of its own: `wrapper_observe_arm_state` is the single
# source, the same function `kickstart-daemons` calls, and this verb just prints
# what it said.
#
# The arm fields ride on the EXISTING single verdict line, after the content
# region, for the reason the `state=` field is read from there (ROUND-5 L2): the
# registry's own bytes are printed between REGISTRY-BEGIN and REGISTRY-END, so a
# token a driver greps for must never be one that content could contain.
#
# `arm_state=unqueried` when no agent was named. An ABSENT field and a field
# meaning "you did not ask" must not look the same to a driver that DID ask:
# a consumer that requested a uid and got `unqueried` has been answered by a
# wrapper that did not understand the question, and that is a refusal, not a
# not-armed.
wrapper_verb_registry_state() {
  local reg="$RAILS_PRODUCT_ANCHOR_REGISTRY" content rc=0 parent leaf root
  local arm_fields
  if [ -n "$AGENT_UID" ]; then
    # Refuses (dies) on a registry that exists and cannot be read, which is the
    # same refusal the read below makes, for the same reason.
    wrapper_observe_arm_state "$AGENT_UID"
    arm_fields="$(printf 'arm_state=%s arm_basis=%s agent_uid=%s' \
      "$WRAPPER_ARM_STATE" "$WRAPPER_ARM_BASIS" "$AGENT_UID")"
  else
    arm_fields='arm_state=unqueried arm_basis=no-agent-uid-given'
  fi
  if ! wrapper_resolve_absolute_optional_file "$reg" 'pf-anchor registry'; then
    printf 'WRAPPER=REGISTRY-ABSENT path=%s\n' "$reg"
    printf 'WRAPPER=OK verb=registry-state state=absent path=%s %s\n' "$reg" "$arm_fields"
    return 0
  fi
  parent="${WRAPPER_SAFE_TARGET%/*}"
  leaf="${WRAPPER_SAFE_TARGET##*/}"
  root="$parent"
  content="$(wrapper_cat_safe_file_under "$root" "$leaf" 'pf-anchor registry')" || rc=$?
  if [ "$rc" -ne 0 ]; then
    wrapper_die "could not READ the pf-anchor registry at $reg (cat rc=$rc); a check that observed nothing is not a clean verdict"
  fi
  printf 'WRAPPER=REGISTRY-BEGIN path=%s\n' "$reg"
  printf '%s' "$content"
  printf '\nWRAPPER=REGISTRY-END\n'
  printf 'WRAPPER=OK verb=registry-state state=present path=%s %s\n' "$reg" "$arm_fields"
}

# Report the marker and lock files inside THIS run's disposable fortress, AS
# ROOT, through the one resolution chokepoint.
#
# ROUND-3, the builder's own finding taken the rest of the way:
# `tightenStoragePermissions` chmods the fortress to 0700 on every server start
# and the fortress is root-owned, so from the first arm onward the unprivileged
# drivers cannot look inside it. Their stale-marker, zero-byte-lock, marker and
# lock checks all read ABSENCE as GOOD, and a directory you may not traverse is
# indistinguishable from an empty one. Refusing to conclude was the honest
# stopgap; this is the fix. Every entry gets a NAMED state, and there is no
# state that means "I did not look".
wrapper_verb_fortress_state() {
  local rel target
  printf 'WRAPPER=FORTRESS-BEGIN storage=%s\n' "$STORAGE"
  for rel in \
    'exclusive-routing.json' \
    'state/_audit/.audit-write.lock' \
    'state/.provision.lock'
  do
    # A SYMLINKED ENTRY NEVER REACHES THE CLASSIFIER. `rails_assert_safe_subpath`
    # refuses any symlink anywhere in the chain, so this verb FAILS on one
    # rather than giving it a state, and the driver reads that as
    # COULD-NOT-OBSERVE. That is the stronger answer and it is why there is no
    # `state=symlink` branch below: it would be unreachable, and an unreachable
    # security predicate that reads as covered is its own finding class (the
    # round-3 sticky-bit note).
    #
    # It matters that this is the chokepoint and not a local `[ -L ]`: `[ -e ]`
    # is FALSE for a dangling symlink, so a hand-rolled check would report a
    # symlinked marker as ABSENT, which is the absence-means-good class wearing
    # a different hat.
    target="$(wrapper_safe_path "$rel")" \
      || wrapper_die "unsafe path under the storage directory: $rel"
    if [ -z "$target" ]; then wrapper_die "empty path after the safe-subpath rail: $rel"; fi
    if [ ! -e "$target" ]; then
      printf 'FORTRESS entry=%s state=absent\n' "$rel"
    elif [ ! -f "$target" ]; then
      printf 'FORTRESS entry=%s state=not-a-regular-file\n' "$rel"
    elif [ ! -s "$target" ]; then
      # A ZERO-LENGTH audit write lock is UNBREAKABLE by design and bricks a
      # fortress permanently; it gets its own state, never folded into
      # "present".
      printf 'FORTRESS entry=%s state=present-empty\n' "$rel"
    else
      printf 'FORTRESS entry=%s state=present\n' "$rel"
    fi
  done
  printf 'WRAPPER=FORTRESS-END\n'
  printf 'WRAPPER=OK verb=fortress-state storage=%s\n' "$STORAGE"
}

# Tail this agent's gate and peer-resolver daemon logs, AS ROOT, from the exact
# paths the product actually writes.
#
# ROUND-3 M5. The probe battery read `<fortress>/logs/egress-gate.log`, which
# NOTHING writes, and could not have read it anyway (root-owned 0700 fortress).
# The gate daemon's stdout/stderr go to
# `<gate account home>/logs/egress-gate-<uid>.{out,err}.log` inside a 0700 home
# owned by the gate service uid; the peer resolver's go to
# `<fortress>/logs/peer-resolver-<uid>.{out,err}.log`. So `P1-reason` was always
# SKIP, `N3` was always SKIP and `N1` always failed for the wrong reason: the
# reason-half of the ladder -- the half that exists because the 2026-07-24 drill
# hid a live `peer_unresolved` strangle behind green-looking denials for a full
# day -- was structurally dead.
#
# ROUND-4 BLOCKER 1. The first pass then hand-checked base/home/logdir/file and
# invoked `tail` on the same mutable pathname under a gate-owned directory. That
# merely moved the unchecked-component class: a reviewer swapped the final log
# between the checks and `tail`, and the wrapper printed a file outside the
# gate log. This verb now has no path-specific hand rail. It composes one exact
# gate home from the product's account derivation, resolves every log path
# through `rails_assert_safe_subpath`, opens the file once, verifies the opened
# fd still has the lstat'd identity, and reads from that fd rather than
# reopening the pathname.
# ROUND-5 M3. The four streams are NOT interchangeable and this verb treated
# them as if they were. `allowlist`, `peer=` and `peer_uid_mismatch` are
# written by the GATE DAEMON, whose log lives in the gate service account's
# home; the peer-resolver's logs live in the disposable fortress. When
# `wrapper_prepare_gate_log_root` returned 1 the two gate streams were skipped
# SILENTLY, and a single readable peer-resolver log made `found=1` and this
# verb exit 0. The driver then grepped for a gate reason, missed, and reported
# `N1 FAIL "denied but not for an allowlist reason"` -- a GATE-BLAMED FAILURE
# for a HARNESS-BLIND condition. It fails in the safe direction and tells the
# wrong story in the morning, which is the failure mode that cost a full day on
# 2026-07-24.
#
# So read mode now emits one `WRAPPER=GATE-LOG-READ key=<k> state=read|absent`
# line PER STREAM, exactly as cursor mode already did, and the driver decides
# per PATTERN which stream class would have carried it. "The stream that would
# have carried this reason was absent" is then a distinct answer from "the
# stream was read and the reason was not in it", which is the whole point.
wrapper_verb_gate_log() {
  wrapper_require_agent
  local gate_base='' gate_account found=0 rel stream key cursor root
  gate_account="$(rails_product_gate_account_for_agent_account "$ARG_AGENT")" \
    || wrapper_die "could not derive the product gate account from agent account $ARG_AGENT"

  if wrapper_prepare_gate_log_root; then
    gate_base="$WRAPPER_SAFE_TARGET"
  fi

  # CURSOR MODE prints no content, so its per-key lines can be interleaved.
  if [ -n "$ARG_LOG_CURSOR_ONLY" ]; then
    for stream in out err; do
      rel="$gate_account/$RAILS_PRODUCT_GATE_LOG_DIR/egress-gate-$AGENT_UID.$stream.log"
      if [ "$stream" = 'out' ]; then key='gate_out'; else key='gate_err'; fi
      if [ -n "$gate_base" ]; then
        wrapper_emit_log_cursor "$key" "$gate_base" "$rel" "$key"
      else
        printf 'WRAPPER=GATE-LOG-CURSOR key=%s cursor=0,0,0,0 file=absent\n' "$key"
      fi
    done
    for stream in out err; do
      rel="$RAILS_PRODUCT_GATE_LOG_DIR/peer-resolver-$AGENT_UID.$stream.log"
      if [ "$stream" = 'out' ]; then key='peer_out'; else key='peer_err'; fi
      wrapper_emit_log_cursor "$key" "$STORAGE" "$rel" "$key"
    done
    printf 'WRAPPER=OK verb=gate-log mode=cursor agent_uid=%s gate_account=%s\n' "$AGENT_UID" "$gate_account"
    return 0
  fi

  # READ MODE: THE PER-STREAM REPORT COMES FIRST, BEFORE ANY CONTENT.
  #
  # This ordering is load-bearing and it is a defect I found in my own first
  # pass at the M3 fix. Emitting `WRAPPER=GATE-LOG-READ` after each stream's
  # bytes puts a machine token INSIDE the content region, and the gate log is
  # written by the gate service uid. A log line reading
  # `WRAPPER=GATE-LOG-READ key=gate_out state=read` would then have told the
  # driver a stream had been read that had not: exactly the round-5 L2 class
  # (a token trusted from inside content) committed while closing round-5 M3.
  #
  # So the header pass decides read-vs-absent with `wrapper_open_safe_file_under`,
  # which prints NOTHING, emits all four verdicts, and closes the region with a
  # sentinel the driver stops parsing at. The tail pass then re-runs the FULL
  # resolution and cursor checks, so a file swapped between the two passes dies
  # there rather than being attributed: the header can only ever be more
  # pessimistic than the content, never more optimistic.
  for stream in gate_out gate_err peer_out peer_err; do
    case "$stream" in
      gate_out) key='gate_out'; rel="$gate_account/$RAILS_PRODUCT_GATE_LOG_DIR/egress-gate-$AGENT_UID.out.log" ;;
      gate_err) key='gate_err'; rel="$gate_account/$RAILS_PRODUCT_GATE_LOG_DIR/egress-gate-$AGENT_UID.err.log" ;;
      peer_out) key='peer_out'; rel="$RAILS_PRODUCT_GATE_LOG_DIR/peer-resolver-$AGENT_UID.out.log" ;;
      *)        key='peer_err'; rel="$RAILS_PRODUCT_GATE_LOG_DIR/peer-resolver-$AGENT_UID.err.log" ;;
    esac
    case "$stream" in
      gate_*) root="$gate_base" ;;
      *)      root="$STORAGE" ;;
    esac
    if [ -n "$root" ] && wrapper_open_safe_file_under "$root" "$rel" "$key"; then
      exec 9<&-
      printf 'WRAPPER=GATE-LOG-READ key=%s state=read\n' "$key"
    else
      printf 'WRAPPER=GATE-LOG-READ key=%s state=absent\n' "$key"
    fi
  done
  printf 'WRAPPER=GATE-LOG-CONTENT-BEGIN\n'

  for stream in out err; do
    rel="$gate_account/$RAILS_PRODUCT_GATE_LOG_DIR/egress-gate-$AGENT_UID.$stream.log"
    if [ "$stream" = 'out' ]; then key='gate_out'; cursor="$ARG_SINCE_GATE_OUT"; else key='gate_err'; cursor="$ARG_SINCE_GATE_ERR"; fi
    if [ -n "$gate_base" ] && wrapper_tail_safe_file_under "$gate_base" "$rel" "$key" "$cursor"; then
      found=$(( found + 1 ))
    fi
  done

  # The peer resolver logs under the FORTRESS, so they go through the same
  # resolution chokepoint every other in-fortress path does.
  for stream in out err; do
    rel="$RAILS_PRODUCT_GATE_LOG_DIR/peer-resolver-$AGENT_UID.$stream.log"
    if [ "$stream" = 'out' ]; then key='peer_out'; cursor="$ARG_SINCE_PEER_OUT"; else key='peer_err'; cursor="$ARG_SINCE_PEER_ERR"; fi
    if wrapper_tail_safe_file_under "$STORAGE" "$rel" "$key" "$cursor"; then
      found=$(( found + 1 ))
    fi
  done

  if [ "$found" -eq 0 ]; then
    wrapper_die "no gate or peer-resolver log for agent uid $AGENT_UID under $RAILS_PRODUCT_GATE_HOME_BASE/$gate_account or $STORAGE/$RAILS_PRODUCT_GATE_LOG_DIR; the reason half of the probe ladder CANNOT be evaluated, and a probe that observed nothing is not a probe that passed"
  fi
  printf 'WRAPPER=OK verb=gate-log agent_uid=%s files=%s\n' "$AGENT_UID" "$found"
}

# THE PORT THE GATE ACTUALLY BOUND. Read as root from the gate daemon's own
# published runtime state, and reported with the generation it belongs to.
#
# ROUND-5 B1, the blocker this verb exists for. The exclusive-egress gate is a
# CONNECT proxy on `127.0.0.1:<gate_port>`; the pf anchor passes that one
# loopback destination for the agent uid and block-drops the rest, and there is
# no `rdr`, so NOTHING is transparently redirected into the gate. A request
# only traverses the gate if the client was pointed at the port. The port is
# chosen per generation by a bind-first on `127.0.0.1:0`, so it cannot be
# compiled in. The harness had no way to learn it -- `gate_port` occurred in
# the whole `scripts/drill-loop` tree only inside comments and inside a
# `RESULT=PASS ... through the gate` string -- so every probe in the ladder was
# a bare `curl` that could not have gone through the gate, `N3` could never
# produce the `peer_uid_mismatch` it exists to observe, and `P1`/`F1-F2`
# printed through-gate PASS lines for requests that provably were not.
#
# THREE ANSWERS, NEVER TWO. `present` (with port + generation), `absent` (no
# gate has published state for this uid: a real, legitimate condition before
# arming and after teardown), and a hard refusal when the document exists and
# cannot be read or does not parse. A driver that cannot tell those apart is
# how "no gate port" becomes "port 0" becomes a green-looking probe.
wrapper_verb_gate_port() {
  wrapper_require_agent
  local state_path content runtime_base rel port generation
  state_path="$(rails_product_gate_runtime_state_path "$AGENT_UID")" \
    || wrapper_die "could not compose the gate runtime state path for uid $AGENT_UID"
  if [ -z "$state_path" ]; then wrapper_die 'empty gate runtime state path after the composer'; fi

  # ROUND-6 H1. The per-uid dir under the runtime base is chowned to the GATE
  # uid by the product, so the ownership rail must stop at the root-owned base
  # and the gate-owned remainder is hand-walked -- exactly how `gate-log` reads
  # its gate-owned tree, through the same two functions. An absent base or an
  # absent uid dir/state file are both the legitimate `absent` answer; a
  # symlink, a hard link, a traversal, or a swap across the open all die inside
  # the shared chokepoints.
  if ! wrapper_prepare_gate_runtime_root; then
    printf 'WRAPPER=GATE-PORT state=absent path=%s\n' "$state_path"
    printf 'WRAPPER=OK verb=gate-port state=absent agent_uid=%s path=%s\n' "$AGENT_UID" "$state_path"
    return 0
  fi
  runtime_base="$WRAPPER_SAFE_TARGET"
  rel="$AGENT_UID/$RAILS_PRODUCT_GATE_RUNTIME_STATE_FILE"
  if ! wrapper_open_safe_file_under "$runtime_base" "$rel" 'gate runtime state'; then
    printf 'WRAPPER=GATE-PORT state=absent path=%s\n' "$state_path"
    printf 'WRAPPER=OK verb=gate-port state=absent agent_uid=%s path=%s\n' "$AGENT_UID" "$state_path"
    return 0
  fi
  content="$(rails__sys cat <&9)" \
    || { exec 9<&-; wrapper_die "could not READ the gate runtime state at $state_path from its checked fd; a port this wrapper did not read is not a port a probe may aim at"; }
  exec 9<&-
  port="$(rails_json_flat_number "$content" gate_port)" \
    || wrapper_die "the gate runtime state at $state_path carries no readable gate_port"
  port="$(rails_assert_tcp_port "$port")" \
    || wrapper_die "the gate runtime state at $state_path names an impossible gate_port"
  generation="$(rails_json_flat_number "$content" generation_id)" \
    || wrapper_die "the gate runtime state at $state_path carries no readable generation_id"
  # The uid the DOCUMENT names must be the uid the caller asked about. Reading
  # one uid's state and reporting it as another's would be this harness's own
  # defect class committed by the wrapper.
  local stated_uid
  stated_uid="$(rails_json_flat_number "$content" agent_uid)" \
    || wrapper_die "the gate runtime state at $state_path carries no readable agent_uid"
  if [ "$stated_uid" != "$AGENT_UID" ]; then
    wrapper_die "the gate runtime state at $state_path names agent uid $stated_uid, not $AGENT_UID; refusing to report another agent's gate port"
  fi
  printf 'WRAPPER=GATE-PORT state=present port=%s generation=%s agent_uid=%s path=%s\n' \
    "$port" "$generation" "$AGENT_UID" "$state_path"
  printf 'WRAPPER=OK verb=gate-port state=present agent_uid=%s port=%s generation=%s\n' \
    "$AGENT_UID" "$port" "$generation"
}

# Remove this run's whole disposable fortress.
#
# ROUND-3 M1: nothing removed them, while the README said the loop "tears it
# down each night". Consequences were unbounded accumulation of root-owned
# directories under the base, one per iteration forever, AND a dead
# `[ ! -d "$STORAGE" ]` branch in teardown-verify whose three `clean_pass` lines
# read as a covered case that could never be reached.
#
# This is the most dangerous line in the file, so it is the most re-checked. By
# the time it runs, `wrapper_run_rails` and `wrapper_ensure_storage` have
# already proven: every component of the chain is a root-owned, non-symlink,
# non-writable directory; the leaf is not a symlink; the leaf's parent resolves
# to the approved anchor; the basename carries the disposable prefix; and the
# path is not on the fortress denylist lexically OR after resolution. The rail
# is then re-run on the value about to be removed, and its own output -- not the
# variable -- is what `rm` is handed.
wrapper_verb_retire() {
  local again
  again="$(rails_assert_disposable_storage "$ANCHOR" "$STORAGE")" \
    || wrapper_die "the storage rail refused the path retire was about to remove: $STORAGE"
  if [ -z "$again" ]; then wrapper_die 'empty path after the storage rail; refusing to remove anything'; fi
  if [ "$again" != "$STORAGE" ]; then
    wrapper_die "the storage rail re-resolved $STORAGE to $again; refusing to remove either"
  fi
  case "${again##*/}" in
    "$RAILS_DISPOSABLE_PREFIX"?*) ;;
    *) wrapper_die "refusing to remove a path whose basename is not a disposable loop fortress: $again" ;;
  esac
  if [ "${again%/*}" != "$ANCHOR" ]; then
    wrapper_die "refusing to remove $again: its parent is not the approved operator anchor $ANCHOR"
  fi
  rails__sys rm -rf -- "$again" || wrapper_die "could not remove the disposable fortress: $again"
  if [ -e "$again" ]; then
    wrapper_die "the disposable fortress SURVIVED removal: $again"
  fi
  printf 'WRAPPER=OK verb=retire removed=%s\n' "$again"
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
#
# ROUND 3 (H2): this was the fix the previous round was proudest of, and it was
# closed against the WRONG ANCHOR. It asked `pfctl` about `com.sanctuary/egress`
# while the product arms `sanctuary.egress-gate`, so depending on pfctl's exit
# status for an unknown anchor it either reported CLEAN while the real anchor
# was still armed, or stopped the night every time. The name now comes from
# `RAILS_PRODUCT_PF_ANCHOR`, pinned to the product's own `PF_ANCHOR_NAME`.
wrapper_verb_pf_anchor_rules() {
  local rules rc=0
  rules="$(rails__sys pfctl -a "$RAILS_PRODUCT_PF_ANCHOR" -s rules 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    wrapper_die "could not read the pf anchor $RAILS_PRODUCT_PF_ANCHOR (pfctl rc=$rc); a check that observed nothing is not a clean verdict"
  fi
  printf 'WRAPPER=PF-ANCHOR-BEGIN\n'
  printf '%s' "$rules"
  printf '\nWRAPPER=PF-ANCHOR-END\n'
  printf 'WRAPPER=OK verb=pf-anchor-rules anchor=%s\n' "$RAILS_PRODUCT_PF_ANCHOR"
}

wrapper_main() {
  wrapper_parse_args "$@"
  wrapper_run_rails
  wrapper_ensure_storage
  case "$WRAPPER_VERB" in
    check)             wrapper_verb_check ;;
    mint)              wrapper_verb_mint ;;
    pf-anchor-rules)   wrapper_verb_pf_anchor_rules ;;
    registry-state)    wrapper_verb_registry_state ;;
    fortress-state)    wrapper_verb_fortress_state ;;
    gate-log)          wrapper_verb_gate_log ;;
    gate-port)         wrapper_verb_gate_port ;;
    kickstart-daemons) wrapper_verb_kickstart_daemons ;;
    arm)               wrapper_verb_arm ;;
    repair)            wrapper_verb_repair ;;
    unprotect)         wrapper_verb_unprotect ;;
    clean-markers)     wrapper_verb_clean_markers ;;
    retire)            wrapper_verb_retire ;;
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
