# shellcheck shell=bash
#
# rails.sh - THE SINGLE SOURCE OF TRUTH for the autonomous drill loop's safety
# rails.
#
# WHAT THIS FILE IS FOR
#
# The drill loop runs unattended, at night, and part of it runs as ROOT under a
# NOPASSWD sudoers grant. The rails are the only thing standing between "a
# looping driver with a bug" and "the operator's real fortress got re-armed and
# re-pinned as root". The rails are the product; the loop is the packaging.
#
# The first version of this harness was reviewed UNSOUND. Every rule below
# closes a specific, proven fail-open from that review
# (Review/Sanctuary/DrillLoop_SafetyRail_Review_2026-07-25.md). Each is
# annotated with the finding it closes. Do not "simplify" one away.
#
# DESIGN RULES (these are load-bearing, not style)
#
#   1. PURE FUNCTIONS, EXPLICIT ARGUMENTS. No rail reads an environment
#      variable, ever. Testability hooks that read the environment are exactly
#      where fail-opens hide, and `sudo`'s env_reset is the only reason the
#      host rail survived the first review. Tests pass test values as
#      arguments; production passes compiled-in or derived values.
#
#   2. FAIL CLOSED VIA `exit`. `rails__die` prints a reason to stderr and
#      EXITS with status 20. In a direct call this terminates the script. In a
#      command substitution it terminates the subshell with status 20, which
#      the MANDATORY call-site form turns into a parent abort:
#
#          STORAGE="$(rails_assert_disposable_storage "$HOME_DIR" "$IN")" \
#            || die "storage rail rejected: $IN"
#
#      Both shapes fail closed. What must NEVER happen is a `$(...)` call whose
#      status is ignored: that is the BLOCKER from the review, where the parent
#      sailed on with STORAGE="" and an empty SANCTUARY_STORAGE_PATH resolves
#      to the REAL ~/.sanctuary (server/src/paths.ts resolveStoragePath).
#      Treat empty as the single most dangerous value in this system.
#
#   3. `if` STATEMENTS, NOT `&&` CHAINS. Under `set -e`, `[ cond ] && die` in
#      statement position aborts the script when the condition is FALSE. Every
#      guard below uses an explicit `if`.
#
#   4. NO SHELL OPTIONS SET HERE. This is a library. Each consuming script sets
#      `set -euo pipefail` itself; the assembled wrapper sets it in its header.
#
#   5. NO SIDE EFFECTS except the lock rail, which by definition mutates a lock
#      directory, and even that only under paths the caller supplies.
#
# PATH RESOLUTION: WHY POSIX `cd -P` AND NOT realpath/python3
#
# R2 requires real resolution, not string math. The obvious tools are wrong
# here: `/usr/bin/realpath` does not exist on this Mac (macOS ships it at
# /bin/realpath, and older macOS does not ship it at all), `readlink -f` is a
# GNU extension BSD readlink lacks, and shelling out to `python3` adds an
# interpreter-path plus import-environment attack surface to a root-run script
# for no benefit. `( CDPATH='' cd -P -- "$dir" && pwd -P )` is a shell builtin
# pair, present on every bash everywhere, and it resolves EVERY symlink in the
# traversal, which is precisely the "resolve the parent chain" requirement.
# The final component is handled separately with `[ -L ]`, which uses lstat and
# so is correct even for a dangling symlink that `cd` could never follow.

# Compiled-in constants. These are assigned UNCONDITIONALLY (never
# `${VAR:-default}`), so an inherited environment variable of the same name is
# overwritten rather than honored. That is deliberate: see design rule 1. They
# are intentionally not `readonly`, so this file can be sourced twice without
# erroring; unconditional assignment already gives the security property.

# The one directory-name prefix the loop may ever operate on, directly under
# the operator's home. Declared as a standing disposable row in FORTRESS_KEYS.md.
RAILS_DISPOSABLE_PREFIX='.sanctuary-loop-'

# Hosts that may NEVER run the privileged wrapper, checked BEFORE the allowlist
# and not overridable by any argument. Erik's MacBook Air is his daily driver.
# Normalized form: lowercase, domain suffix stripped.
RAILS_HOST_DENY='eriks-macbook-air eriksmacbookair erik-macbook-air erikmbp'

# The only hosts that may run it. Compiled in, fail closed on anything else.
# `agents-mac-mini` is Mini1. `mini2` is provisional: if Mini2's local short
# hostname turns out to differ, the wrapper will refuse there until this list
# is edited and re-reviewed. Refusing is the correct failure mode.
RAILS_HOST_ALLOW='agents-mac-mini mini2'

# Fortress paths that are never disposable, checked BEFORE the allowlist so the
# ordering matches the host rail's proven deny-first shape. The `$HOME`-relative
# entries are expanded by the caller's home argument; the absolute entries cover
# the known drill accounts even if the home argument were wrong.
RAILS_DENY_RELATIVE='.sanctuary .sanctuary-protect-drill .sanctuary-s5-drill .sanctuary-slicem-drill .sanctuary-b2-drill .sanctuary-a2b2-drill sanctuary-v1.1-test sanctuary-fortress-key-backups'
RAILS_DENY_ABSOLUTE='/Users/agentmac/.sanctuary /Users/eriknewton/.sanctuary /var/root/.sanctuary /root/.sanctuary'

# Status used for every rail rejection, so a call site can tell "the rail said
# no" apart from "the command blew up".
RAILS_REJECT_STATUS=20

# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------

# Fail closed. See design rule 2 for why this is `exit` and not `return`.
rails__die() {
  printf 'RAILS_REJECT: %s\n' "$*" >&2
  exit "$RAILS_REJECT_STATUS"
}

# Physically resolve an existing DIRECTORY. Returns nonzero (does not die) so
# callers can attach a specific message; every caller must check.
rails__resolve_dir() {
  ( CDPATH='' cd -P -- "$1" >/dev/null 2>&1 && pwd -P ) || return 1
}

# Octal file mode, GNU stat then BSD stat. Returns nonzero if neither works.
rails__stat_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null || return 1
}

# Numeric owner uid, GNU stat then BSD stat.
rails__stat_owner_uid() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1" 2>/dev/null || return 1
}

# `id -u <account>` via an ABSOLUTE path where one exists. A root-run wrapper
# that resolved `id` through PATH would let a caller who can influence PATH
# decide what every account resolves to, which is the whole account rail. sudo's
# secure_path already narrows this; the absolute path removes the question.
rails__id_u() {
  if [ -x /usr/bin/id ]; then /usr/bin/id -u "$1" 2>/dev/null; return $?; fi
  if [ -x /bin/id ]; then /bin/id -u "$1" 2>/dev/null; return $?; fi
  id -u "$1" 2>/dev/null
}

# Collapse runs of `/` and strip trailing `/` from an ABSOLUTE path.
#
# Deliberately NOT `${p//\/\//\/}`. The replacement text of a bash parameter
# expansion is not processed the way it reads: bash 3.2 (which is what macOS
# ships, and therefore what the drill hosts run) keeps the backslash, and
# quoting the replacement keeps the quote characters. Both variants silently
# corrupt the path into something that then fails a later check for the wrong
# reason, which is exactly the failure mode a safety rail must not have. Word
# splitting on IFS='/' has no such surprises. `set -f` is on for the split so a
# path segment containing a glob character cannot expand against the
# filesystem.
rails__squeeze_slashes() {
  local s="$1" out='' seg noglob_was_set='' oldifs="$IFS"
  case "$-" in *f*) noglob_was_set='yes' ;; esac
  set -f
  IFS='/'
  # shellcheck disable=SC2086
  set -- $s
  IFS="$oldifs"
  if [ -z "$noglob_was_set" ]; then set +f; fi
  for seg in "$@"; do
    if [ -n "$seg" ]; then out="$out/$seg"; fi
  done
  if [ -z "$out" ]; then out='/'; fi
  printf '%s' "$out"
}

rails__now() {
  date +%s
}

rails__sleep_tick() {
  sleep 0.2 2>/dev/null || sleep 1
}

# Lowercase, strip any domain suffix, so `Eriks-MacBook-Air.local`,
# `ERIKS-MACBOOK-AIR` and `eriks-macbook-air` are all one identity.
rails__normalize_host() {
  local h="$1"
  h="${h%%.*}"
  printf '%s' "$h" | tr '[:upper:]' '[:lower:]'
}

# SHA-256 of a file, GNU then BSD tooling, bare hex digest on stdout.
rails_sha256_file() {
  if [ "$#" -ne 1 ]; then rails__die "rails_sha256_file: expected 1 arg, got $#"; fi
  if [ ! -f "$1" ]; then rails__die "rails_sha256_file: not a regular file: $1"; fi
  local out
  if out="$(sha256sum "$1" 2>/dev/null)"; then
    printf '%s\n' "${out%% *}"
    return 0
  fi
  if out="$(shasum -a 256 "$1" 2>/dev/null)"; then
    printf '%s\n' "${out%% *}"
    return 0
  fi
  rails__die "rails_sha256_file: no sha256sum or shasum available"
}

# Deny-list screen, run on BOTH the lexical and the resolved form of a
# candidate path. Closes the "allowlist satisfied by a path that is actually a
# real fortress" class, and runs BEFORE the allowlist by construction: every
# caller invokes it first.
rails__assert_not_denylisted() {
  local home="$1" p="$2" stage="$3" entry
  for entry in $RAILS_DENY_RELATIVE; do
    if [ "$p" = "$home/$entry" ]; then
      rails__die "$stage path is a protected fortress, never disposable: $p"
    fi
  done
  for entry in $RAILS_DENY_ABSOLUTE; do
    if [ "$p" = "$entry" ]; then
      rails__die "$stage path is a protected fortress, never disposable: $p"
    fi
  done
  if [ "$p" = "$home" ]; then
    rails__die "$stage path is the home directory itself: $p"
  fi
  if [ "$p" = "/" ]; then
    rails__die "$stage path is the filesystem root"
  fi
  # Belt: any path whose final component is exactly `.sanctuary` is a default
  # fortress somewhere, regardless of whose home it sits in.
  if [ "${p##*/}" = '.sanctuary' ]; then
    rails__die "$stage path names a default fortress directory: $p"
  fi
}

# ---------------------------------------------------------------------------
# R2 / BLOCKER - the disposable-storage rail
# ---------------------------------------------------------------------------
#
# Prints the CANONICAL RESOLVED path on stdout and nothing else, so the
# mandatory call-site form captures a value it can trust:
#
#   STORAGE="$(rails_assert_disposable_storage "$HOME_DIR" "$IN")" || die "..."
#   [ -n "$STORAGE" ] || die "empty storage after rail"
#
# Rejects, in order: bad arity, empty/relative/control-character input, `.` and
# `..` components, DENYLIST (lexical), then the allowlist (basename prefix and
# charset), then a symlinked final component, then resolution of the parent
# chain with a re-assertion of both dirname==home and the basename prefix on
# the RESOLVED path, then the DENYLIST again on the resolved path, then a
# post-condition that an existing target resolves to itself.
#
# The symlink case is the specific R2 fail-open: `~/.sanctuary-loop-evil` as a
# symlink to `~/.sanctuary` passes every lexical check and the CLI follows it.
rails_assert_disposable_storage() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_disposable_storage: expected 2 args (home, candidate), got $#"
  fi
  local home_in="$1" cand="$2"

  if [ -z "$home_in" ]; then rails__die "empty home argument"; fi
  if [ -z "$cand" ]; then
    rails__die "empty storage path: empty resolves to the REAL default fortress, never treat it as unset"
  fi

  case "$home_in" in /*) ;; *) rails__die "home is not an absolute path: $home_in" ;; esac
  home_in="$(rails__squeeze_slashes "$home_in")"
  case "$cand" in /*) ;; *) rails__die "storage path is not an absolute path: $cand" ;; esac
  # ANSI-C quoting, NOT command substitution: `$(printf '\n')` strips the
  # trailing newline and yields the EMPTY string, which turns the pattern into
  # `**` and matches every path. That would be a rail that accepts nothing,
  # which reads as "strict" right up until someone deletes it for being noisy.
  case "$cand" in
    *$'\n'*) rails__die "storage path contains a newline" ;;
    *$'\t'*) rails__die "storage path contains a tab" ;;
    *$'\r'*) rails__die "storage path contains a carriage return" ;;
  esac

  # Lexical normalization: collapse runs of `/` and strip trailing `/`.
  local norm
  norm="$(rails__squeeze_slashes "$cand")"
  if [ -z "$norm" ]; then rails__die "storage path normalized to empty: $cand"; fi

  # Reject relative components anywhere. Note this is necessary but NOT
  # sufficient (a symlink needs no `..`), which is the whole point of R2.
  case "$norm/" in
    */../*|*/./*) rails__die "storage path contains a relative component: $cand" ;;
  esac

  # DENYLIST FIRST (mirrors the host rail's proven ordering).
  rails__assert_not_denylisted "$home_in" "$norm" 'lexical'

  local base="${norm##*/}"
  local dir="${norm%/*}"
  if [ -z "$dir" ]; then dir='/'; fi

  # Allowlist: the disposable prefix plus a non-empty stamp, conservative charset.
  case "$base" in
    "$RAILS_DISPOSABLE_PREFIX"?*) ;;
    *) rails__die "basename is not a disposable loop fortress (${RAILS_DISPOSABLE_PREFIX}<stamp>): $base" ;;
  esac
  case "$base" in
    *[!A-Za-z0-9._-]*) rails__die "basename contains disallowed characters: $base" ;;
  esac

  # R2: never follow an operator-writable symlink as root. `-L` is an lstat, so
  # this is correct even when the link dangles.
  if [ -L "$norm" ]; then
    rails__die "final component is a symlink; refusing to follow it as root: $norm"
  fi

  # R2: resolve, then RE-ASSERT the lexical properties on the resolved form.
  local rhome rdir
  if ! rhome="$(rails__resolve_dir "$home_in")"; then
    rails__die "home does not resolve to an existing directory: $home_in"
  fi
  if [ "$rhome" = "/" ]; then rails__die "home resolves to the filesystem root; refusing"; fi
  if ! rdir="$(rails__resolve_dir "$dir")"; then
    rails__die "parent directory does not resolve to an existing directory: $dir"
  fi
  if [ "$rdir" != "$rhome" ]; then
    rails__die "resolved parent ($rdir) is not the resolved home ($rhome)"
  fi

  local resolved="$rdir/$base"
  case "${resolved##*/}" in
    "$RAILS_DISPOSABLE_PREFIX"?*) ;;
    *) rails__die "resolved basename lost the disposable prefix: $resolved" ;;
  esac
  rails__assert_not_denylisted "$rhome" "$resolved" 'resolved'

  # Post-condition: if the target already exists it must be a plain directory
  # that resolves to itself. Redundant with the `-L` check by design.
  if [ -e "$resolved" ]; then
    if [ ! -d "$resolved" ]; then
      rails__die "storage path exists and is not a directory: $resolved"
    fi
    local rself
    if ! rself="$(rails__resolve_dir "$resolved")"; then
      rails__die "existing storage path does not resolve: $resolved"
    fi
    if [ "$rself" != "$resolved" ]; then
      rails__die "storage path resolves elsewhere ($rself); refusing"
    fi
  fi

  printf '%s\n' "$resolved"
}

# ---------------------------------------------------------------------------
# R6 - the host rail (PRESERVED; this one held under review)
# ---------------------------------------------------------------------------
#
#   rails_assert_host_allowed <primary> [alias...]
#
# EVERY name supplied, primary and aliases alike, is screened against the
# un-overridable denylist first. Only the PRIMARY is then matched against the
# compiled-in allowlist. So an extra argument can only ever cause a rejection;
# there is no argument, environment variable, or flag anywhere in this harness
# that can ADD a host. Callers pass several observed identities (`hostname -s`,
# `hostname -f`, `scutil --get ComputerName`) precisely so that a machine that
# answers to the MacBook's name under ANY of them is refused.
#
# There is deliberately no `--allow-host`, no DRILL_LOOP_ALLOWED_HOSTS, and the
# sudoers grant carries no env_keep, so sudo's env_reset means the privileged
# path always uses these compiled-in lists.
rails_assert_host_allowed() {
  if [ "$#" -lt 1 ]; then rails__die "rails_assert_host_allowed: expected at least 1 arg"; fi
  local n e norm
  for n in "$@"; do
    if [ -z "$n" ]; then rails__die "empty host identity supplied"; fi
    norm="$(rails__normalize_host "$n")"
    if [ -z "$norm" ]; then rails__die "host identity normalizes to empty: $n"; fi
    for e in $RAILS_HOST_DENY; do
      # Both sides are normalized, so a list entry that someone later types
      # with capitals still matches. A denylist that silently stops matching
      # because of a capital letter is the worst possible bug in this file.
      if [ "$norm" = "$(rails__normalize_host "$e")" ]; then
        rails__die "host '$norm' is on the un-overridable denylist (daily driver); refusing"
      fi
    done
  done
  local primary
  primary="$(rails__normalize_host "$1")"
  for e in $RAILS_HOST_ALLOW; do
    if [ "$primary" = "$(rails__normalize_host "$e")" ]; then return 0; fi
  done
  rails__die "host '$primary' is not on the compiled-in drill-host allowlist; refusing (fail closed)"
}

# ---------------------------------------------------------------------------
# R3 - account rails
# ---------------------------------------------------------------------------
#
# Prints the resolved numeric uid on stdout. Refuses root by BOTH name and uid:
# a name-only check is bypassable through an aliased uid-0 account, and the
# review's proven pivot was `--operator-account root` plus an attacker-supplied
# URL yielding `curl` as root.
rails_assert_non_root_account() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_non_root_account: expected 2 args (label, account), got $#"
  fi
  local label="$1" acct="$2" uid
  if [ -z "$acct" ]; then rails__die "$label: empty account name"; fi
  if [ "${#acct}" -gt 31 ]; then rails__die "$label: account name longer than 31 characters"; fi
  # Charset allowlist ^[a-z_][a-z0-9_-]{0,30}$. The leading-character rule also
  # guarantees the value can never be read as an option by `id` or `sudo`.
  case "$acct" in
    [a-z_]*) ;;
    *) rails__die "$label: account must start with a lowercase letter or underscore: $acct" ;;
  esac
  case "$acct" in
    *[!a-z0-9_-]*) rails__die "$label: account contains disallowed characters: $acct" ;;
  esac
  if [ "$acct" = 'root' ]; then rails__die "$label: refusing the root account by name"; fi
  if ! uid="$(rails__id_u "$acct")"; then
    rails__die "$label: account does not exist on this host: $acct"
  fi
  rails_assert_nonroot_uid "$label" "$acct" "$uid" \
    || rails__die "$label: uid rail rejected $acct"
  printf '%s\n' "$uid"
}

# The uid half of the account rail, split out as a PURE predicate so the
# "an account resolving to uid 0 under a non-root name" refusal is testable
# without an actual uid-0 alias account (this Mac has none, and creating one to
# satisfy a test would be a worse idea than the test is worth). Production and
# the test battery run the same function; only the source of the uid differs.
#
# A name-only root check is bypassable exactly this way, which is why both
# halves exist.
rails_assert_nonroot_uid() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_assert_nonroot_uid: expected 3 args (label, account, uid), got $#"
  fi
  local label="$1" acct="$2" uid="$3"
  case "$uid" in
    ''|*[!0-9]*) rails__die "$label: uid for $acct is not a plain non-negative integer: '$uid'" ;;
  esac
  if [ "$uid" -eq 0 ]; then
    rails__die "$label: account '$acct' resolves to uid 0; refusing root by uid"
  fi
}

# Assert an account resolves to the uid the caller expects, so a renamed or
# re-created account cannot silently redirect a confinement probe.
rails_assert_account_uid() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_assert_account_uid: expected 3 args (label, account, expected_uid), got $#"
  fi
  local label="$1" acct="$2" want="$3" got
  case "$want" in
    ''|*[!0-9]*) rails__die "$label: expected uid is not numeric: $want" ;;
  esac
  if [ "$want" -eq 0 ]; then rails__die "$label: expected uid 0; refusing"; fi
  got="$(rails_assert_non_root_account "$label" "$acct")" \
    || rails__die "$label: account rail rejected $acct"
  if [ "$got" != "$want" ]; then
    rails__die "$label: account '$acct' is uid $got, expected $want"
  fi
  printf '%s\n' "$got"
}

# ---------------------------------------------------------------------------
# R5 - secret-file permission rail
# ---------------------------------------------------------------------------
#
# The review's LOW finding: the old check inspected only the last octal digit
# (`*[2367]`), so a group-writable 0660 file passed while the comment claimed
# otherwise. This masks properly, and additionally refuses group/other READ,
# which is the right bar for a passphrase file even though the finding only
# required the write bits.
rails_assert_secret_file_perms() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_secret_file_perms: expected 2 args (path, owner_account), got $#"
  fi
  local p="$1" acct="$2" mode want_uid have_uid
  if [ -z "$p" ]; then rails__die "empty secret-file path"; fi
  if [ -L "$p" ]; then rails__die "secret file is a symlink; refusing: $p"; fi
  if [ ! -f "$p" ]; then rails__die "secret file is not a regular file: $p"; fi
  if ! mode="$(rails__stat_mode "$p")"; then rails__die "cannot stat secret file: $p"; fi
  case "$mode" in
    ''|*[!0-7]*) rails__die "unparseable octal mode for $p: $mode" ;;
  esac
  # The R5 requirement, stated literally: mask the write bits against 022.
  if [ $(( 8#$mode & 8#22 )) -ne 0 ]; then
    rails__die "secret file $p is group- or world-WRITABLE (mode $mode)"
  fi
  # Stricter than the finding required, and correct for a passphrase file.
  if [ $(( 8#$mode & 8#77 )) -ne 0 ]; then
    rails__die "secret file $p is readable or writable by group or other (mode $mode)"
  fi
  want_uid="$(rails_assert_non_root_account 'secret-file owner' "$acct")" \
    || rails__die "secret-file owner account rejected: $acct"
  if ! have_uid="$(rails__stat_owner_uid "$p")"; then
    rails__die "cannot read owner uid of secret file: $p"
  fi
  if [ "$have_uid" != "$want_uid" ]; then
    rails__die "secret file $p is owned by uid $have_uid, expected $want_uid ($acct)"
  fi
}

# ---------------------------------------------------------------------------
# R4 - the lock rail
# ---------------------------------------------------------------------------
#
# Invariant: a scheduled nightly run and an interactive drill can never
# interleave on one host.
#
# The review's finding was that `mv -> rm -rf -> mkdir` lets two processes both
# observe one stale lock and both proceed. Naively adding an atomic rename is
# not enough either, because of a subtler steal: A renames the stale lock away,
# B then wins `mkdir` and legitimately holds the lock, and C - still working
# from its own earlier observation - renames B's LIVE lock away and proceeds.
#
# So reclaim happens under its own single-winner reclaim lock, and the
# stale-ness facts are RE-READ while holding it:
#
#   acquire loop:
#     mkdir "$LOCK"                      -> atomic test-and-set; winner writes
#                                           its pid, settles, re-reads, and
#                                           aborts unless it reads back $$.
#     lock exists, holder alive          -> refuse (this is the invariant).
#     lock exists, pid file not yet
#       written                          -> the winner is mid-acquire: wait and
#                                           re-observe; only after a grace
#                                           window is an empty lock treated as
#                                           abandoned.
#     lock exists, holder dead           -> mkdir "$LOCK.reclaim". Exactly one
#                                           process can win that. Under it,
#                                           re-read the pid, re-confirm it is
#                                           the same dead pid, THEN rename the
#                                           lock aside and delete it. Nobody
#                                           else can mkdir "$LOCK" while it
#                                           still exists, and no other
#                                           reclaimer can act, so B's live lock
#                                           can never be stolen.
#
# A reclaimer that dies mid-reclaim leaves "$LOCK.reclaim" behind and every
# later run refuses with an explicit message naming the directory to remove.
# That is deliberate: a safety rail that cannot establish the facts must stop,
# not guess.
rails_lock_acquire() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_lock_acquire: expected 2 args (lockdir, max_wait_seconds), got $#"
  fi
  local lock="$1" max_wait="$2"
  if [ -z "$lock" ]; then rails__die "empty lock path"; fi
  case "$lock" in /*) ;; *) rails__die "lock path is not absolute: $lock" ;; esac
  case "$max_wait" in
    ''|*[!0-9]*) rails__die "max_wait_seconds is not numeric: $max_wait" ;;
  esac

  local reclaim="$lock.reclaim"
  local deadline=$(( $(rails__now) + max_wait ))
  local empty_since=0
  local holder readback stale

  while :; do
    if mkdir "$lock" 2>/dev/null; then
      printf '%s\n' "$$" > "$lock/pid"
      # Compare-after-write: only the mkdir winner can have created this
      # directory, so reading back anything else means the world is not what we
      # think it is. Stop rather than proceed.
      readback="$(cat "$lock/pid" 2>/dev/null || printf '')"
      if [ "$readback" != "$$" ]; then
        rails__die "lock pid readback mismatch (wrote $$, read '$readback'); refusing"
      fi
      return 0
    fi

    if [ ! -d "$lock" ]; then
      # It vanished between mkdir failing and this test; just retry.
      rails__sleep_tick
      continue
    fi

    holder="$(cat "$lock/pid" 2>/dev/null || printf '')"

    if [ -n "$holder" ]; then
      case "$holder" in
        ''|*[!0-9]*) rails__die "lock $lock has a non-numeric pid file ('$holder'); refusing" ;;
      esac
      empty_since=0
      if kill -0 "$holder" 2>/dev/null; then
        rails__die "drill lock $lock is held by live pid $holder; refusing to interleave"
      fi
      # Dead holder: try to become the single reclaimer.
      if mkdir "$reclaim" 2>/dev/null; then
        # Re-read the facts while holding the reclaim right.
        if [ -d "$lock" ]; then
          holder="$(cat "$lock/pid" 2>/dev/null || printf '')"
          if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
            stale="$lock.stale.$$"
            if mv "$lock" "$stale" 2>/dev/null; then
              rm -rf "$stale"
            fi
          fi
        fi
        rmdir "$reclaim" 2>/dev/null || true
      fi
      rails__sleep_tick
    else
      # Directory exists but no pid file yet: either a winner mid-acquire, or a
      # genuinely abandoned empty lock. Only the second is reclaimable, and only
      # after a grace window.
      if [ "$empty_since" -eq 0 ]; then
        empty_since="$(rails__now)"
      elif [ $(( $(rails__now) - empty_since )) -ge 5 ]; then
        if mkdir "$reclaim" 2>/dev/null; then
          if [ -d "$lock" ] && [ ! -s "$lock/pid" ]; then
            stale="$lock.stale.$$"
            if mv "$lock" "$stale" 2>/dev/null; then
              rm -rf "$stale"
            fi
          fi
          rmdir "$reclaim" 2>/dev/null || true
        fi
        empty_since=0
      fi
      rails__sleep_tick
    fi

    if [ "$(rails__now)" -ge "$deadline" ]; then
      if [ -d "$reclaim" ]; then
        rails__die "drill lock $lock not acquired within ${max_wait}s and a reclaim lock is stuck at $reclaim; remove it by hand after confirming no drill is running"
      fi
      rails__die "drill lock $lock not acquired within ${max_wait}s; refusing"
    fi
  done
}

# Release a lock this process owns. Refuses to release someone else's, so a
# confused driver cannot unlock a live drill.
rails_lock_release() {
  if [ "$#" -ne 1 ]; then rails__die "rails_lock_release: expected 1 arg (lockdir), got $#"; fi
  local lock="$1" holder
  if [ ! -d "$lock" ]; then return 0; fi
  holder="$(cat "$lock/pid" 2>/dev/null || printf '')"
  if [ "$holder" != "$$" ]; then
    rails__die "refusing to release lock $lock held by pid '$holder' (this process is $$)"
  fi
  rm -rf "$lock"
}

# ---------------------------------------------------------------------------
# wrapper-integrity rail
# ---------------------------------------------------------------------------
#
# The installed wrapper runs as root and must be self-contained: it may never
# `source` a file out of the operator-writable repo, because that would make
# any repo write a root code-execution primitive. But the rails must still have
# exactly one source of truth, so the wrapper is ASSEMBLED from this file plus
# wrapper-main.sh and its hash is committed.
#
# This rail is what makes assembly safe: before the driver uses the privileged
# wrapper it re-assembles from the repo, hashes, and compares against BOTH the
# committed hash and the installed file. That catches "you edited the repo and
# forgot to reinstall" and "someone edited the installed wrapper" with one
# check. Mismatch means refuse, loudly.
# Hash agreement across all three copies. Split out from the ownership half so
# this one has a testable ACCEPT path: proving the ownership half accepts needs
# a genuinely root-owned file, which only exists after a real install, and a
# rail nobody has ever seen say yes is not a rail anyone should trust.
rails_assert_wrapper_hash() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_assert_wrapper_hash: expected 3 args (assembled, installed, expected_sha_file), got $#"
  fi
  local assembled="$1" installed="$2" shafile="$3"
  local want got_assembled got_installed
  if [ ! -f "$shafile" ]; then rails__die "committed wrapper hash file missing: $shafile"; fi
  want="$(tr -d ' \t\n\r' < "$shafile")"
  if [ "${#want}" -ne 64 ]; then rails__die "committed wrapper hash is not 64 hex chars: $shafile"; fi
  case "$want" in
    *[!0-9a-f]*) rails__die "committed wrapper hash is not lowercase hex: $shafile" ;;
  esac

  if [ ! -f "$assembled" ]; then rails__die "assembled wrapper missing: $assembled"; fi
  got_assembled="$(rails_sha256_file "$assembled")" || rails__die "cannot hash $assembled"
  if [ "$got_assembled" != "$want" ]; then
    rails__die "assembled wrapper does not match the committed hash (repo drift): $got_assembled != $want"
  fi

  if [ -L "$installed" ]; then rails__die "installed wrapper is a symlink: $installed"; fi
  if [ ! -f "$installed" ]; then rails__die "installed wrapper missing: $installed"; fi
  got_installed="$(rails_sha256_file "$installed")" || rails__die "cannot hash $installed"
  if [ "$got_installed" != "$want" ]; then
    rails__die "installed wrapper does not match the committed hash (installed drift): $got_installed != $want"
  fi
}

# Ownership half: the installed wrapper must be a root-owned, non-symlink,
# non-group-writable regular file, or the NOPASSWD grant points at content
# somebody other than root can rewrite.
rails_assert_wrapper_ownership() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_assert_wrapper_ownership: expected 1 arg (installed), got $#"
  fi
  local installed="$1" mode owner
  if [ -L "$installed" ]; then rails__die "installed wrapper is a symlink: $installed"; fi
  if [ ! -f "$installed" ]; then rails__die "installed wrapper missing: $installed"; fi
  if ! mode="$(rails__stat_mode "$installed")"; then rails__die "cannot stat $installed"; fi
  if [ $(( 8#$mode & 8#22 )) -ne 0 ]; then
    rails__die "installed wrapper $installed is group- or world-writable (mode $mode)"
  fi
  if ! owner="$(rails__stat_owner_uid "$installed")"; then rails__die "cannot read owner of $installed"; fi
  if [ "$owner" -ne 0 ]; then
    rails__die "installed wrapper $installed is not owned by root (uid $owner)"
  fi
}

# The chokepoint the driver actually calls.
rails_assert_wrapper_integrity() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_assert_wrapper_integrity: expected 3 args (assembled, installed, expected_sha_file), got $#"
  fi
  rails_assert_wrapper_hash "$1" "$2" "$3"
  rails_assert_wrapper_ownership "$2"
}
