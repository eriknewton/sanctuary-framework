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
#          STORAGE="$(rails_assert_disposable_storage "$ANCHOR" "$IN")" \
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
# the per-operator directory of RAILS_DISPOSABLE_BASE below. Declared as a
# standing disposable row in FORTRESS_KEYS.md.
RAILS_DISPOSABLE_PREFIX='.sanctuary-loop-'

# ###########################################################################
# THE ROOT-OWNED BASE. This is the one line to change if the location moves,
# and this comment is the reason it may not move casually.
#
# SECURITY PROPERTY: no component of this path may be writable by the operator
# account. That single property is what turns the path rail from a guess into a
# decision. An unprivileged caller cannot create, rename, or replace any
# component of the path the root wrapper walks, so there is no
# time-of-check-to-time-of-use window to win, and there is no operator-writable
# intermediate for a symlink to hide in.
#
# It exists because the 2026-07-25 re-review round proved BOTH halves of the
# alternative wrong, by execution, against fake fortresses in a temp home:
#
#   * an unchecked INTERMEDIATE component (`state/`, `state/_audit/`) let a
#     root-run `rm` delete a file inside a real fortress while every rail
#     passed, and
#   * the accepted directory could be swapped for a symlink to a real fortress
#     AFTER validation and BEFORE use, winning the race in 44 attempts.
#
# Both were possible only because the disposable fortress lived under the
# operator's own home, which the operator owns and can therefore rewrite.
# Moving this constant back under an operator-writable directory reopens both.
#
# The drill hosts are Macs, where /private/var is the canonical root-owned
# location and /var is a symlink to it. The wrapper creates this directory
# itself, as root, mode 0755, and re-verifies the whole chain before use, so
# there is no separate install step to forget.
# ###########################################################################
RAILS_DISPOSABLE_BASE='/private/var/sanctuary-drill'

# Directories a root-run script may resolve a command name from. Deliberately
# excludes /usr/local/bin: on a Mac with Homebrew that directory is
# OPERATOR-WRITABLE, and `#!/usr/bin/env bash` there selects an
# operator-writable interpreter to run as root. See the assembled header in
# build-wrapper.sh, which pins PATH to exactly this list.
RAILS_SYSTEM_BIN_DIRS='/usr/bin /bin /usr/sbin /sbin'

# The SAME list in PATH form, so the unprivileged drivers can pin their own PATH
# from the single source of truth rather than each repeating the string. A
# structural test asserts these two constants and the assembled wrapper's
# hard-coded header line all agree; the header cannot use the constant because
# it runs BEFORE lib/rails.sh is concatenated in.
RAILS_SYSTEM_PATH='/usr/bin:/bin:/usr/sbin:/sbin'

# Longest run identifier the caller may supply. A run id is NOT a path: it
# cannot contain a slash, and the wrapper composes the path from it.
RAILS_RUN_ID_MAX=64

# How long the hardware-identity lookup may take before it is a REJECTION.
#
# Round-3 (Codex finding 5): every unusable `ioreg` answer failed closed except
# one, because a HANG is not an answer at all. An unattended night whose host
# rail hangs is a night that produced no evidence and no refusal either. A
# timeout is a REJECT, like every other unusable lookup.
RAILS_IOREG_TIMEOUT_SECONDS=10

# ###########################################################################
# PRODUCT-FACING IDENTIFIERS. These are the names, paths and labels of the
# SANCTUARY PRODUCT, not of this harness, and they are the whole reason round 3
# was UNSOUND: every one of them was wrong, so three named-defect checks
# reported PASS/CLEAN having observed nothing, and step 0 of every iteration
# kickstarted labels that do not exist.
#
# CORRECTING THE STRINGS IS THE SYMPTOM, NOT THE FIX. The fix is that
# `server/test/drill-loop/product-identifiers.test.ts` imports the product's own
# exports and asserts that these constants (as carried by the SHIPPED assembled
# artifact) are derived from them. The product renames things; when it does,
# that test goes red instead of this harness silently resuming its lying.
#
# Never edit one of these to "fix" a failing pin test. The pin test failing
# means the product moved and this harness has not: follow the product.
# ###########################################################################

# `PF_ANCHOR_NAME`, server/src/egress-gate/pf-anchor.ts.
RAILS_PRODUCT_PF_ANCHOR='sanctuary.egress-gate'

# `EGRESS_GATE_DAEMON_LABEL_PREFIX`, server/src/egress-gate/gate-daemon.ts.
# The live label is `<prefix>.<agent uid>`: one daemon per confined agent.
RAILS_PRODUCT_GATE_LABEL_PREFIX='ai.sanctuaryprotocol.egress-gate'

# `PEER_RESOLVER_DAEMON_LABEL_PREFIX`,
# server/src/egress-gate/peer-resolver-daemon.ts. Same per-uid shape.
RAILS_PRODUCT_RESOLVER_LABEL_PREFIX='ai.sanctuaryprotocol.egress-gate-peer-resolver'

# `PF_ANCHOR_REGISTRY_PATH`, server/src/egress-gate/anchor-registry.ts.
# ROOT-OWNED 0600 inside a 0700 directory, which is why correcting the path
# alone does not fix the check that reads it: an unprivileged `grep` still
# cannot read it and still lands in the "clean" branch. It is read through the
# wrapper's `registry-state` verb, as root, and the driver distinguishes
# read-and-empty from could-not-read.
RAILS_PRODUCT_ANCHOR_REGISTRY='/var/db/sanctuary/egress-anchor-registry.json'

# `GATE_ACCOUNT_HOME_BASE`, server/src/egress-gate/arming-wiring.ts, and
# `GATE_ACCOUNT_NAME_PREFIX`, server/src/egress-gate/gate-account.ts. The gate
# daemon's stdout/stderr land in `<home>/logs/egress-gate-<uid>.{out,err}.log`
# (`egressGateDaemonLogPaths`), i.e. in the GATE SERVICE ACCOUNT's home, NOT in
# the fortress. The harness read `<fortress>/logs/egress-gate.log`, which
# nothing writes, so the reason-half of the probe ladder was structurally dead.
#
# The gate account is exact, never prefix-enumerated: product wiring derives
# `sanctuary-<agent id>` for the agent account and `sanctuary-gate-<agent id>`
# for the gate account. The shell composer below mirrors that relation and is
# pinned by `product-identifiers.test.ts`.
RAILS_PRODUCT_AGENT_ACCOUNT_PREFIX='sanctuary-'
RAILS_PRODUCT_GATE_HOME_BASE='/var/sanctuary-agents'
RAILS_PRODUCT_GATE_ACCOUNT_PREFIX='sanctuary-gate-'
RAILS_PRODUCT_GATE_LOG_DIR='logs'

# `EGRESS_GATE_RUNTIME_DIR` + `egressGateRuntimeStatePath`,
# server/src/egress-gate/gate-daemon.ts. The gate daemon publishes
# `<dir>/<agent uid>/state.json` AFTER a successful bind, carrying the port it
# actually bound and the generation it belongs to.
#
# ROUND-5 B1. This constant is why the harness can finally reach its own
# subject. The gate is an `HTTPS_PROXY` CONNECT proxy on `127.0.0.1:<port>`;
# the pf anchor's rules are `on lo0 ... user = <agent uid>` with no `rdr`, so
# nothing is transparently redirected and a bare `curl` NEVER traverses the
# gate. The port is chosen per generation (bind-first on `127.0.0.1:0`), so it
# cannot be compiled in either. `gate_port` appeared in this harness only
# inside comments and inside a PASS string, which is exactly how "reachable
# through the gate" survived four review rounds attached to requests that could
# not have gone through it. The wrapper's `gate-port` verb reads this document
# as root and the battery proxies to what it says.
RAILS_PRODUCT_GATE_RUNTIME_DIR='/var/db/sanctuary/gate-runtime'
RAILS_PRODUCT_GATE_RUNTIME_STATE_FILE='state.json'

# ###########################################################################
# THE TWO CLASSES OF PRODUCT DAEMON, AND WHY THE HARNESS MUST NOT CONFLATE THEM
#
# 2026-07-25, the FIRST live supervised run on Mini1 stopped at step 0 of
# iteration 1 with
#
#   WRAPPER=REJECT reason=kickstart failed for: ai.sanctuaryprotocol.egress-gate.503
#     ai.sanctuaryprotocol.egress-gate-peer-resolver.503 (restarted: none)
#
# on a host where NOTHING was wrong. The two labels named there are the PER-UID
# GATE daemons, and the product only brings them into existence when a uid is
# ARMED -- which happens at step 3 of the SAME ladder that had just refused to
# get past step 0. On a clean, disarmed host they legitimately do not exist, so
# no iteration could ever run: their absence is the expected pre-arm state, and
# the verb reported it as a restart failure.
#
# The daemons that DO exist on every installed host, whatever is armed, are the
# two below. They are the ones that have to be restarted for an iteration to be
# measuring the dist that was just built, and a restart failure on one of THEM
# is a genuine, fatal problem.
#
# So the harness carries two label classes, and `wrapper_verb_kickstart_daemons`
# treats absence differently for each:
#
#   HOST daemons  - installed by the product, independent of any arm. Absence is
#                   NEVER expected: the iteration would measure nothing.
#   PER-UID gate  - created by the arm. Absence is expected BEFORE this uid is
#                   armed and is a defect AFTER it, and which of those two the
#                   host is in is OBSERVED (the root-owned pf-anchor registry),
#                   never inferred from an iteration number or a step index.
# ###########################################################################

# `CASTLE_WALL_BOOT_LABEL`, server/src/cli/castle-wall-boot.ts.
RAILS_PRODUCT_CASTLE_WALL_LABEL='ai.sanctuaryprotocol.castle-wall.daemon'

# `CASTLE_SIGNER_HELPER_LABEL`, server/src/cli/castle-wall-signer-helper.ts.
RAILS_PRODUCT_SIGNER_HELPER_LABEL='ai.sanctuaryprotocol.macos.castle-wall.signer-helper'

# The directory every one of the product's system daemons installs its plist
# into (`CASTLE_WALL_BOOT_PLIST_PATH`, `egressGateDaemonPlistPath`,
# `peerResolverDaemonPlistPath` all compose `<dir>/<label>.plist`). Declared
# once here so the wrapper and the drivers ask the same question of the same
# place; a second declaration site is how four identifiers drifted at once.
RAILS_PRODUCT_LAUNCHDAEMONS_DIR='/Library/LaunchDaemons'

# ###########################################################################
# HOST IDENTITY IS A HARDWARE FINGERPRINT, NOT A NAME.
#
# A live audit of the real machines (2026-07-25) killed the name-based
# allowlist outright:
#
#   Mini1, the intended drill host:  hostname -s = "Mac"
#                                    scutil HostName = UNSET
#                                    scutil LocalHostName = Agents-Mac-mini
#                                    scutil ComputerName  = Agent's Mac mini
#   MBA, which must NEVER run it:    hostname -s = Eriks-MacBook-Air
#
# Two things follow, and both are fatal to the old design:
#
#   1. Allowing Mini1 by `hostname -s` means putting the literal string "Mac"
#      on the allowlist. A large fraction of default-configured Macs answer
#      exactly that. An allowlist containing "Mac" is close to no allowlist at
#      all: it silently converts "fail closed on an unknown host" into "pass on
#      many unknown hosts". There is no version of that which is safe to ship.
#   2. `scutil --get HostName` is unset on Mini1, so any branch that leans on
#      it gets an empty string there. An empty identity must be a REJECT, never
#      a skip and never a non-match that reads as "well, it isn't the MacBook".
#
# And a name is forgeable anyway: BLOCKER 2 was a planted `hostname` on PATH
# producing WRAPPER=ACCEPT on the MacBook Air. A check whose input an attacker
# can write is not a check.
#
# So the DECISION is made on the machine's hardware UUID (IOPlatformUUID, read
# from ioreg by absolute path), and the allowlist and the denylist live in the
# SAME identifier space. A denylist keyed on names beside an allowlist keyed on
# hardware would silently stop matching, which is the single worst bug this
# file can have.
#
# What is stored here is the SHA-256 of the UUID, not the UUID. This is a
# public repository; a fingerprint compares exactly, carries no raw machine
# identifier, and is not reversible into one.
# ###########################################################################

# Machines that may NEVER run the privileged wrapper. Checked BEFORE the
# allowlist, in the same space as the allowlist, not overridable by anything.
# Currently: Erik's MacBook Air, his daily driver. MEASURED, not guessed.
RAILS_HOST_DENY_FP='0b97135457bbb970241f6c37af3ced6e4477163e92ca5258dc9f549cea0d8f34'

# The only machines that may run it.
#
# DELIBERATELY EMPTY. Mini1's and Mini2's fingerprints have not been measured:
# the audit above was an observation of names only, and this session did not
# and must not reach those machines. An empty allowlist means the wrapper
# refuses EVERYWHERE, which is the correct failure mode and the same posture
# the harness already takes toward an unknown host.
#
# To provision, on the drill host, once, alongside the sudoers grant:
#
#     scripts/drill-loop/host-fingerprint.sh
#
# and paste the printed fingerprint here, with the machine named in a comment.
# Re-review the diff: this list is the whole host allowlist.
#
# c793843d... = Mini1, ComputerName "Agent's Mac mini", macOS 26.5.2, operator
# account agentmac. The dedicated drill box: stripped, unencrypted, no real
# tenant, and not a coordinator host. Measured with host-fingerprint.sh on the
# machine itself 2026-07-26.
RAILS_HOST_ALLOW_FP='c793843d54555cfe0334e206967811d69df3f4f309c58d3447668d0c1837724d'

# NAME denylist, kept as a BELT and never as the mechanism. Names cannot ADD a
# host (there is no name allowlist any more), so an entry here can only ever
# cause a refusal, which is the only direction a forgeable input may push a
# safety rail. Matched on the aggressively normalized form.
RAILS_HOST_DENY='eriks-macbook-air eriksmacbookair erik-macbook-air erikmbp'

# ###########################################################################
# THE AGENT PRINCIPAL, COMPILED IN.
#
# Round 3 (M2): this design's whole thesis is "eliminate the attacker-supplied
# value instead of validating it", and it was applied to the storage path, the
# CLI path, the verbs, the pf anchor and the daemon labels -- but NOT to the one
# argument that steers WHAT ROOT DOES TO WHOM. `--agent-account` was validated
# for shape and non-rootness and then handed to `protect --exclusive-egress`
# running as root, so the grant holder could point a root-run exclusive-egress
# arm at any non-root local account: pf confinement rules, a harness
# LaunchDaemon and a gate service account provisioned against a uid the drill
# has nothing to do with.
#
# So the permitted agent account(s) are compiled in, exactly the way the host
# allowlist is, and `--agent-account` may now only SELECT from this list.
#
# DELIBERATELY EMPTY, for the same reason RAILS_HOST_ALLOW_FP is: no drill host
# has been provisioned, so no drill agent account has been named. Empty means
# every verb that takes an agent principal refuses, which is the correct
# failure mode. Provision it in the same reviewed diff as the host fingerprint
# (see README "Install"), space separated, and re-review: this list is the
# entire set of principals root will act against.
#
# sanctuary-hermes (uid 503 on Mini1, shell /usr/bin/false, home under
# /var/sanctuary-agents) is the confined agent principal every prior S5 drill
# used. Deliberately ONE entry: sanctuary-gate-hermes (504) is the gate's own
# service account, which the product provisions, never a drill principal; and
# sanctuary-agent (502) has a live login shell, so it is not named here.
RAILS_AGENT_ACCOUNT_ALLOW='sanctuary-hermes'

# Fortress paths that are never disposable, checked BEFORE the allowlist so the
# ordering matches the host rail's proven deny-first shape. The relative entries
# are expanded against the caller's ANCHOR argument; the absolute entries cover
# the known drill accounts even if the anchor argument were wrong.
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

# ---------------------------------------------------------------------------
# ABSOLUTE COMMAND RESOLUTION (BLOCKER 2, 2026-07-25 re-review)
# ---------------------------------------------------------------------------
#
# The re-review planted a `hostname` binary earlier in PATH and made the root
# artifact print `WRAPPER=ACCEPT` **on the operator's MacBook Air**, the one
# machine the design says must be structurally unable to run it. The
# "un-overridable" host denylist was exactly as strong as whatever `hostname`
# resolved to. A planted `bash` substituted the interpreter outright.
#
# So there are now two layers, and both are asserted by a structural test:
#
#   1. the assembled artifact pins PATH to RAILS_SYSTEM_BIN_DIRS as its first
#      executable line, and uses an absolute interpreter in its shebang;
#   2. every security-relevant command goes through the resolver below, which
#      only ever looks in root-owned system directories, whatever PATH says.
#
# Layer 2 is what makes layer 1 belt-and-suspenders rather than the whole
# defense, and it holds in the DRIVERS too, which run under the operator's own
# PATH and get no sudo secure_path.

# Absolute path to a system command, or nonzero if it is not in a root-owned
# system directory. Never consults PATH.
rails__abs_cmd() {
  local name="$1" d
  for d in $RAILS_SYSTEM_BIN_DIRS; do
    if [ -x "$d/$name" ]; then printf '%s' "$d/$name"; return 0; fi
  done
  return 1
}

# Run a system command by absolute path. Status 127 if it is not present in a
# root-owned system directory, which is the same status a missing command gets.
rails__sys() {
  local name="$1" abs
  shift
  if ! abs="$(rails__abs_cmd "$name")"; then return 127; fi
  "$abs" "$@"
}

# Absolute path to a command the caller's EVIDENCE depends on, or a REJECTION.
#
# ROUND-3 BLOCKER 1. `rails__sys` was used everywhere the privileged wrapper
# looked at the world, and nowhere the unprivileged DRIVERS did. The drivers ran
# bare `sudo`, `curl`, `tail` and `grep`, resolved through the operator's own
# PATH with no sudo `secure_path` in front of them, so a planted `sudo` earlier
# in PATH returned whatever observations the driver wanted to see: Codex
# executed it and got a fully green probe battery and a clean teardown with no
# real sudo, no installed wrapper, no pfctl and no agent account.
#
# The privileged path was hardened and the EVIDENCE path was not. This is what
# holds the evidence path to the same standard: a driver resolves every tool its
# conclusions rest on ONCE, up front, through this function, and then invokes
# only the absolute result. A tool that is not in a root-owned system directory
# is a hard refusal, never a fallback to whatever PATH offers.
rails_require_cmd() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_require_cmd: expected 1 arg (command name), got $#"
  fi
  local name="$1" abs
  if [ -z "$name" ]; then rails__die "rails_require_cmd: empty command name"; fi
  if ! abs="$(rails__abs_cmd "$name")"; then
    rails__die "required command '$name' is not present in a root-owned system directory ($RAILS_SYSTEM_BIN_DIRS); refusing rather than resolving it through PATH (fail closed)"
  fi
  printf '%s\n' "$abs"
}

# Run a system command by absolute path under a wall-clock deadline.
#
# Status 124 on expiry, the GNU `timeout` convention. macOS ships no
# `timeout(1)` and bash 3.2 has no `wait -n`, so this is the portable shape: run
# in the background, poll, then TERM and KILL. Output is buffered to a temp file
# so the caller still gets it on the success path.
#
# The reason this exists at all is Codex round-3 finding 5: every unusable
# `ioreg` answer failed closed EXCEPT a hang, and a rail that hangs produced
# neither evidence nor a refusal.
rails__sys_timeout() {
  if [ "$#" -lt 2 ]; then
    rails__die "rails__sys_timeout: expected <seconds> <command> [args...], got $#"
  fi
  local secs="$1" name="$2"
  shift 2
  case "$secs" in
    ''|*[!0-9]*) rails__die "rails__sys_timeout: seconds is not numeric: '$secs'" ;;
  esac
  local abs out marker rc=0 pid watchdog
  if ! abs="$(rails__abs_cmd "$name")"; then return 127; fi
  if ! out="$(rails__sys mktemp "${TMPDIR:-/tmp}/rails-timeout.XXXXXX" 2>/dev/null)"; then
    rails__die "rails__sys_timeout: could not create a temp file for '$name'"
  fi
  marker="$out.timeout"
  "$abs" "$@" >"$out" 2>/dev/null &
  pid=$!
  # A WATCHDOG rather than a polling loop, so the FAST path costs nothing: the
  # host rail runs on every single wrapper invocation, and a poll granularity
  # coarse enough to be cheap is also coarse enough to add a second to each of
  # them. `wait` returns the instant the command does.
  #
  # The watchdog's own stdout is closed off deliberately: this whole function is
  # called inside a command substitution, and a lingering `sleep` holding the
  # inherited pipe open would hang the caller rather than time anything out.
  (
    rails__sys sleep "$secs"
    if kill -0 "$pid" 2>/dev/null; then
      : > "$marker"
      kill -TERM "$pid" 2>/dev/null || true
      rails__sys sleep 1
      kill -KILL "$pid" 2>/dev/null || true
    fi
  ) >/dev/null 2>&1 &
  watchdog=$!
  wait "$pid" || rc=$?
  kill -TERM "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  if [ -f "$marker" ]; then
    rails__sys rm -f -- "$out" "$marker" 2>/dev/null || true
    return 124
  fi
  rails__sys cat -- "$out" 2>/dev/null || true
  rails__sys rm -f -- "$out" "$marker" 2>/dev/null || true
  return "$rc"
}

# Effective uid of THIS process, read through the absolute resolver.
rails__euid() {
  rails__sys id -u 2>/dev/null || printf ''
}

# Physically resolve an existing DIRECTORY. Returns nonzero (does not die) so
# callers can attach a specific message; every caller must check.
rails__resolve_dir() {
  ( CDPATH='' cd -P -- "$1" >/dev/null 2>&1 && pwd -P ) || return 1
}

# Octal file mode INCLUDING the setuid/setgid/STICKY bits. GNU stat, then BSD.
#
# ROUND-3 L2. The BSD branch used to read `%Lp`, which drops the high bits:
# measured on this Mac, `/private/tmp` is `%Lp=777` while its real mode is
# `1777`. So `8#$mode & 8#1000` was ALWAYS zero on macOS and the sticky-bit
# carve-out in `rails_assert_trusted_component` -- documented as "what makes
# /tmp safe as a path component" -- could never fire on the platform the drill
# actually runs on. A security predicate that behaves differently on macOS and
# Linux while being documented as if it worked on both is a defect even when it
# fails in the safe direction.
#
# `%Op` is the FULL `st_mode` in octal, file-type bits included (`41777` for a
# sticky directory, `100644` for a regular file). The permission word is the low
# TWELVE bits, i.e. the last FOUR octal digits, so that is what is taken.
# Concatenating `%Mp%Lp` is NOT equivalent: `%Lp` is not zero-padded (mode 0007
# prints as `7`), so mode 1007 would concatenate to `17`.
#
# STATED PLAINLY, because it is a LOOSENING on macOS and should be reviewed as
# one: with the sticky bit now visible, a world-writable STICKY component is
# accepted on macOS where it used to be refused, which is what Linux has always
# done. The reviewer's two options were "read %Op" or "delete the carve-out";
# the carve-out cannot be deleted because it is load-bearing on Linux CI, where
# `$TMPDIR` is unset and the batteries run under a 1777 `/tmp`. What contains
# the loosening is that `RAILS_DISPOSABLE_BASE` is a COMPILED-IN constant whose
# shipped value is asserted structurally, so no caller can aim the chain at
# `/private/tmp` in the first place. A mode reader that misreports the mode is
# wrong whichever direction it errs in.
rails__stat_mode() {
  local m
  if m="$(rails__sys stat -c '%a' "$1" 2>/dev/null)"; then
    printf '%s' "$m"
    return 0
  fi
  if m="$(rails__sys stat -f '%Op' "$1" 2>/dev/null)"; then
    if [ "${#m}" -gt 4 ]; then m="${m#"${m%????}"}"; fi
    printf '%s' "$m"
    return 0
  fi
  return 1
}

# Numeric owner uid, GNU stat then BSD stat.
rails__stat_owner_uid() {
  rails__sys stat -c '%u' "$1" 2>/dev/null || rails__sys stat -f '%u' "$1" 2>/dev/null || return 1
}

# File size in bytes, GNU stat then BSD stat.
rails__stat_size() {
  rails__sys stat -c '%s' "$1" 2>/dev/null || rails__sys stat -f '%z' "$1" 2>/dev/null || return 1
}

# Hard-link count, GNU stat then BSD stat.
#
# ROUND-4 F1 / ROUND-6 M1. The fd-identity rail compares inode,uid,gid across
# an open, which catches a swapped or symlinked leaf -- but a HARD LINK passes
# all three, because it IS the target's inode. Every privileged read that
# hand-walks a service-owned subtree therefore also refuses a multiply-linked
# leaf, and this is where the count comes from.
#
# The AUTHORITATIVE call site passes `/dev/fd/<n>`, not a pathname. A count
# read from a pathname is a SEPARATE namei from the open, and an attacker who
# swaps the leaf in that window has the count measured on a discarded file --
# which is how the first version of this guard was defeated by execution.
# Both stat families report the TARGET's link count for an open fd (`%h` GNU,
# `%l` BSD), exactly as they already report its inode for the identity rail.
rails__stat_nlink() {
  rails__sys stat -c '%h' "$1" 2>/dev/null || rails__sys stat -f '%l' "$1" 2>/dev/null || return 1
}

# Stable identity for an opened regular file: inode, owner uid, group id.
#
# This intentionally omits device on macOS because `stat /dev/fd/<n>` reports
# the `/dev/fd` device while preserving the target inode/uid/gid. That is still
# enough to catch the reviewed gate-log substitution: the file lstat'd before
# open and the fd read afterwards are different objects.
rails__stat_identity() {
  rails__sys stat -c '%i,%u,%g' "$1" 2>/dev/null || rails__sys stat -f '%i,%u,%g' "$1" 2>/dev/null || return 1
}

# `id -u <account>` via an ABSOLUTE path. A root-run wrapper that resolved `id`
# through PATH would let a caller who can influence PATH decide what every
# account resolves to, which is the whole account rail.
rails__id_u() {
  rails__sys id -u "$1" 2>/dev/null
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
  rails__sys date +%s
}

rails__sleep_tick() {
  rails__sys sleep 0.2 2>/dev/null || rails__sys sleep 1
}

# Lowercase, strip any domain suffix, so `Eriks-MacBook-Air.local`,
# `ERIKS-MACBOOK-AIR` and `eriks-macbook-air` are all one identity. This is the
# CONSERVATIVE form, and it is what the ALLOWLIST matches on: it must never
# make two genuinely different machine names collide.
rails__normalize_host() {
  local h="$1"
  h="${h%%.*}"
  printf '%s' "$h" | rails__sys tr '[:upper:]' '[:lower:]'
}

# The AGGRESSIVE form, used only by the DENYLIST. Everything that is not a
# lowercase letter or a digit is deleted, so all of these are one identity:
#
#   Eriks-MacBook-Air        -> eriksmacbookair
#   Eriks-MacBook-Air.local  -> eriksmacbookair
#   Erik's MacBook Air       -> eriksmacbookair     (`scutil --get ComputerName`)
#
# The asymmetry is deliberate and it only ever runs in the safe direction: a
# coarser match can produce MORE refusals and never more acceptances. The
# review found that the ComputerName alias was being passed to the rail and
# then matching nothing, because a denylist of space-separated words cannot
# hold `Erik's MacBook Air`. It can hold `eriksmacbookair`.
rails__normalize_host_strict() {
  local h="$1"
  h="${h%%.*}"
  printf '%s' "$h" | rails__sys tr '[:upper:]' '[:lower:]' | rails__sys tr -cd 'a-z0-9'
}

# SHA-256 of a file, GNU then BSD tooling, bare hex digest on stdout.
rails_sha256_file() {
  if [ "$#" -ne 1 ]; then rails__die "rails_sha256_file: expected 1 arg, got $#"; fi
  if [ ! -f "$1" ]; then rails__die "rails_sha256_file: not a regular file: $1"; fi
  local out
  if out="$(rails__sys sha256sum "$1" 2>/dev/null)"; then
    printf '%s\n' "${out%% *}"
    return 0
  fi
  if out="$(rails__sys shasum -a 256 "$1" 2>/dev/null)"; then
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
  local anchor="$1" p="$2" stage="$3" entry
  for entry in $RAILS_DENY_RELATIVE; do
    if [ "$p" = "$anchor/$entry" ]; then
      rails__die "$stage path is a protected fortress, never disposable: $p"
    fi
  done
  for entry in $RAILS_DENY_ABSOLUTE; do
    if [ "$p" = "$entry" ]; then
      rails__die "$stage path is a protected fortress, never disposable: $p"
    fi
  done
  if [ "$p" = "$anchor" ]; then
    rails__die "$stage path is the anchor directory itself: $p"
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
# BLOCKER 1 (2026-07-25 round 2) - eliminate the attacker-supplied path
# ---------------------------------------------------------------------------
#
# Round 1's defect class was "a rail rejection never reached the code that used
# the value". Round 2's was worse and subtler: "a rail APPROVED a value, and
# then the code used something else." Three independent lenses found the same
# verb from three directions, and two of them wrote working exploits.
#
# The fix is not another check. Validating a path an attacker supplies is a
# losing game, so the caller stops supplying one:
#
#   rails_assert_run_id             the caller supplies a run IDENTIFIER, which
#                                   is not a path and cannot contain a slash.
#   rails_derive_disposable_storage the wrapper COMPOSES the path itself, under
#                                   a base it compiled in.
#   rails_assert_trusted_dir_chain  every component of that base is root-owned
#                                   and not operator-writable, so no component
#                                   can be created, renamed or replaced by the
#                                   caller. This is what kills the TOCTOU class
#                                   rather than narrowing its window.
#   rails_assert_safe_subpath       the ONE resolution chokepoint every
#                                   privileged filesystem operation goes
#                                   through, resolving EVERY component and
#                                   refusing any symlink anywhere in the chain.
#
# All four are needed and they are not redundant: derivation removes the input,
# the root-owned base removes the race, and the chokepoint removes the
# unchecked-intermediate walk. `clean-markers`, `preflight.sh` and
# `teardown-verify.sh` all call the chokepoint; no verb walks a path by hand.

# A RUN IDENTIFIER, not a path. The caller may choose it; it may not contain a
# slash, a relative component, a control character or anything outside a
# conservative charset, and it can therefore never name a directory.
rails_assert_run_id() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_assert_run_id: expected 1 arg (run id), got $#"
  fi
  local id="$1"
  if [ -z "$id" ]; then rails__die "empty run id"; fi
  if [ "${#id}" -gt "$RAILS_RUN_ID_MAX" ]; then
    rails__die "run id longer than $RAILS_RUN_ID_MAX characters: $id"
  fi
  # LOWERCASE ONLY, and the reason is the filesystem rather than taste.
  #
  # ROUND-3 MED (both lenses): the drill hosts are Macs, whose default APFS
  # volume is CASE-INSENSITIVE. `A` and `a` were two accepted, distinct run ids
  # that derive to two distinct path STRINGS naming ONE directory entry, so two
  # runs could operate on one disposable fortress and one evidence identity
  # while every rail said they were separate. Codex reproduced it.
  #
  # Rejected rather than silently folded: the evidence must show the exact id
  # the caller supplied, and a rail that quietly rewrites its input is a rail
  # whose output nobody can reason about.
  case "$id" in
    *[!a-z0-9._-]*) rails__die "run id contains disallowed characters (lowercase a-z, 0-9, dot, underscore and dash only; the drill hosts' filesystem is case-insensitive, so an uppercase id would alias a lowercase one): $id" ;;
  esac
  # A leading dot or dash would let a run id read as `.`, `..` or an option.
  case "$id" in
    [!a-z0-9]*) rails__die "run id must start with a lowercase letter or a digit: $id" ;;
  esac
  printf '%s\n' "$id"
}

# ---------------------------------------------------------------------------
# PRODUCT-FACING IDENTIFIER COMPOSERS
# ---------------------------------------------------------------------------
#
# The product's daemon labels are PER AGENT UID (`<prefix>.<uid>`), which is why
# no substitution of the harness's old reverse-DNS prefix could ever have fixed
# them: the uid suffix was missing too, and the verb that used them had no
# `--agent-uid` in its call path at all.

rails__assert_agent_uid_shape() {
  local label="$1" uid="$2"
  case "$uid" in
    ''|*[!0-9]*) rails__die "$label: agent uid is not a plain non-negative integer: '$uid'" ;;
  esac
  if [ "$uid" -eq 0 ]; then rails__die "$label: agent uid 0; refusing"; fi
}

# `egressGateDaemonLabel(uid)`, server/src/egress-gate/gate-daemon.ts.
rails_product_gate_label() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_gate_label: expected 1 arg (agent uid), got $#"; fi
  rails__assert_agent_uid_shape 'gate daemon label' "$1"
  printf '%s.%s\n' "$RAILS_PRODUCT_GATE_LABEL_PREFIX" "$1"
}

# `peerResolverDaemonLabel(uid)`, server/src/egress-gate/peer-resolver-daemon.ts.
rails_product_resolver_label() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_resolver_label: expected 1 arg (agent uid), got $#"; fi
  rails__assert_agent_uid_shape 'peer-resolver daemon label' "$1"
  printf '%s.%s\n' "$RAILS_PRODUCT_RESOLVER_LABEL_PREFIX" "$1"
}

# `egressGateRuntimeStatePath(uid)`, server/src/egress-gate/gate-daemon.ts.
# The document that names the port the gate ACTUALLY bound for this uid.
rails_product_gate_runtime_state_path() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_gate_runtime_state_path: expected 1 arg (agent uid), got $#"; fi
  rails__assert_agent_uid_shape 'gate runtime state path' "$1"
  printf '%s/%s/%s\n' \
    "$(rails__squeeze_slashes "$RAILS_PRODUCT_GATE_RUNTIME_DIR")" "$1" "$RAILS_PRODUCT_GATE_RUNTIME_STATE_FILE"
}

# Both PER-UID labels, space separated, in the order the wrapper restarts them.
# These exist only once the uid is armed; see the two-classes block above.
rails_product_daemon_labels() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_daemon_labels: expected 1 arg (agent uid), got $#"; fi
  local gate resolver
  gate="$(rails_product_gate_label "$1")" || rails__die "gate label rejected for uid $1"
  resolver="$(rails_product_resolver_label "$1")" || rails__die "resolver label rejected for uid $1"
  printf '%s %s\n' "$gate" "$resolver"
}

# The ALWAYS-INSTALLED host daemons, space separated. Not per-uid: these are the
# product's own, one per host, and they are the ones whose absence means the
# product is not installed rather than "not armed yet".
rails_product_host_daemon_labels() {
  if [ "$#" -ne 0 ]; then rails__die "rails_product_host_daemon_labels: expected 0 args, got $#"; fi
  printf '%s %s\n' "$RAILS_PRODUCT_CASTLE_WALL_LABEL" "$RAILS_PRODUCT_SIGNER_HELPER_LABEL"
}

# `<LaunchDaemons dir>/<label>.plist`, the path the product installs a system
# daemon's job description at. Used as ONE of the two existence signals: a job
# launchd has loaded answers `launchctl print`, and a job whose plist is on disk
# exists even when launchd has not bootstrapped it (which is itself a defect,
# and one this harness must be able to SEE rather than read as "not installed").
rails_product_daemon_plist_path() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_daemon_plist_path: expected 1 arg (label), got $#"; fi
  local label="$1"
  if [ -z "$label" ]; then rails__die 'empty daemon label; refusing to compose a plist path'; fi
  case "$label" in
    *[!a-zA-Z0-9._-]*) rails__die "daemon label contains characters that cannot compose a safe plist path: $label" ;;
  esac
  printf '%s/%s.plist\n' "$(rails__squeeze_slashes "$RAILS_PRODUCT_LAUNCHDAEMONS_DIR")" "$label"
}

# ---------------------------------------------------------------------------
# OBSERVED ARM STATE: does the product's own registry name this uid?
# ---------------------------------------------------------------------------
#
# PURE. Content in, uid in, `yes`/`no` out, so the decision that governs whether
# a missing gate daemon is expected can be driven exhaustively by the battery on
# any platform, without a host, root, pf, or launchd.
#
# The subject is `PF_ANCHOR_REGISTRY_PATH`'s JSON, written by
# server/src/egress-gate/anchor-registry.ts: one `{"agent_uid":<n>,...}` object
# per confined uid. This is a SCANNER for that key, not a JSON parser, and the
# distinction is deliberate: a hand-rolled JSON parser inside a root process is
# more defect surface than the question is worth, and this question is an
# EXPECTATION signal ("would absence surprise us"), never a security boundary.
# The file is root-owned 0600 and only the product writes it, so the one way to
# fool the scanner -- a string VALUE containing the literal `"agent_uid": <n>` --
# requires already being able to write the registry as root.
#
# Whitespace between the key, the colon and the number is tolerated because
# tolerating it costs three lines and NOT tolerating it would make a
# pretty-printed registry read as "no uid is armed", which is the fail-open
# direction: it is the answer that makes a missing gate daemon look expected.
rails_registry_names_agent_uid() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_registry_names_agent_uid: expected 2 args (content, agent uid), got $#"
  fi
  local content="$1" uid="$2" rest c num
  rails__assert_agent_uid_shape 'registry agent uid probe' "$uid"
  rest="$content"
  while :; do
    case "$rest" in
      *'"agent_uid"'*) ;;
      *) printf 'no\n'; return 0 ;;
    esac
    rest="${rest#*'"agent_uid"'}"
    while :; do
      c="${rest%"${rest#?}"}"
      case "$c" in ' '|$'\t'|$'\n'|$'\r') rest="${rest#?}" ;; *) break ;; esac
    done
    case "$rest" in
      :*) rest="${rest#:}" ;;
      *) continue ;;
    esac
    while :; do
      c="${rest%"${rest#?}"}"
      case "$c" in ' '|$'\t'|$'\n'|$'\r') rest="${rest#?}" ;; *) break ;; esac
    done
    num=''
    while :; do
      c="${rest%"${rest#?}"}"
      case "$c" in [0-9]) num="$num$c"; rest="${rest#?}" ;; *) break ;; esac
    done
    # A number longer than any real uid is not this uid, and feeding it to
    # arithmetic would abort the wrapper under `set -e` rather than answer.
    if [ -n "$num" ] && [ "${#num}" -le 10 ] && [ "$((10#$num))" -eq "$((10#$uid))" ]; then
      printf 'yes\n'
      return 0
    fi
  done
}

rails_product_agent_id_from_account() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_agent_id_from_account: expected 1 arg (agent account), got $#"; fi
  local acct="$1" id
  if [ -z "$acct" ]; then rails__die "empty agent account; cannot derive the gate account"; fi
  case "$acct" in
    *[!a-z0-9._-]*) rails__die "agent account contains characters that cannot derive a safe gate account: $acct" ;;
  esac
  case "$acct" in
    "$RAILS_PRODUCT_AGENT_ACCOUNT_PREFIX"?*) id="${acct#"$RAILS_PRODUCT_AGENT_ACCOUNT_PREFIX"}" ;;
    *) id="$acct" ;;
  esac
  if [ -z "$id" ]; then rails__die "empty agent id derived from account $acct"; fi
  case "$id" in
    *[!a-z0-9._-]*) rails__die "agent id contains characters that cannot derive a safe gate account: $id" ;;
  esac
  printf '%s\n' "$id"
}

# `deriveGateAccountName(agentId)`, server/src/egress-gate/gate-account.ts,
# composed from the agent account the root wrapper already validated and
# allowlisted. This pins the one gate home to inspect; `gate-log` must never
# enumerate every prefix-matching home again.
rails_product_gate_account_for_agent_account() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_gate_account_for_agent_account: expected 1 arg (agent account), got $#"; fi
  local id gate
  id="$(rails_product_agent_id_from_account "$1")" || rails__die "could not derive agent id from $1"
  gate="$RAILS_PRODUCT_GATE_ACCOUNT_PREFIX$id"
  if [ "${#gate}" -gt 64 ]; then rails__die "derived gate account is longer than 64 characters: $gate"; fi
  printf '%s\n' "$gate"
}

rails_product_gate_home_for_agent_account() {
  if [ "$#" -ne 1 ]; then rails__die "rails_product_gate_home_for_agent_account: expected 1 arg (agent account), got $#"; fi
  local gate
  gate="$(rails_product_gate_account_for_agent_account "$1")" || rails__die "could not derive gate account from $1"
  printf '%s/%s\n' "$(rails__squeeze_slashes "$RAILS_PRODUCT_GATE_HOME_BASE")" "$gate"
}

# ---------------------------------------------------------------------------
# THE AGENT PRINCIPAL ALLOWLIST (round-3 M2)
# ---------------------------------------------------------------------------
#
# Compiled in, deny-by-default, and PURE in the same way the fingerprint
# decision is: value in, list in, verdict out, so the ACCEPT path is testable
# even though the shipped list is empty. Production passes
# `$RAILS_AGENT_ACCOUNT_ALLOW` and nothing else; there is no flag, argument or
# environment variable anywhere in this harness that reaches the list.
rails_assert_agent_account_against() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_agent_account_against: expected 2 args (account, allowlist), got $#"
  fi
  local acct="$1" allow="$2" e
  if [ -z "$acct" ]; then rails__die "empty agent account; refusing (fail closed)"; fi
  if [ -z "$allow" ]; then
    rails__die "the drill AGENT-ACCOUNT allowlist is EMPTY, so root will act for no agent principal; name the drill agent account in RAILS_AGENT_ACCOUNT_ALLOW alongside the host fingerprint (refusing, fail closed)"
  fi
  for e in $allow; do
    if [ "$acct" = "$e" ]; then return 0; fi
  done
  rails__die "agent account '$acct' is not on the compiled-in drill agent allowlist; refusing to point a root-run exclusive-egress arm at an account this drill was not provisioned for (fail closed)"
}

# The production chokepoint: shape rail first, then the compiled-in allowlist.
rails_assert_agent_account_allowed() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_assert_agent_account_allowed: expected 1 arg (account), got $#"
  fi
  rails_assert_agent_account_against "$1" "$RAILS_AGENT_ACCOUNT_ALLOW"
}

# ---------------------------------------------------------------------------
# THE AGGREGATION RULE: A SKIP CAN NEVER BECOME A PASS (round-3, Codex #2)
# ---------------------------------------------------------------------------
#
# `run-probe-battery.sh` reported `N3 SKIP`, left its failure count at zero,
# exited 0, and `run-loop.sh` wrote `"result":"PASS"` for the whole probe step
# into FINDINGS.jsonl. A declared negative probe that never observed the reason
# it exists to prove, banked as a pass. That is the 2026-07-24 false-green class
# with a machine doing the summarizing.
#
# So the fold is a PURE FUNCTION here rather than an `if` in the loop, for the
# same reason `rails_assert_nonroot_uid` and `rails_assert_fingerprint_against`
# are: it can then be driven exhaustively over every (status, summary) pair,
# including the pairs a live night would take weeks to produce.
#
# TWO INDEPENDENT SIGNALS MUST AGREE before this says PASS: the battery's exit
# status must be 0 AND its own summary line must say `verified=yes`. Either one
# alone would be a single point of failure, and not having one of those is this
# harness's entire subject. Anything else is UNVERIFIED or FAIL.
#
#   rails_probe_result <exit-status> <summary-line>  ->  PASS | UNVERIFIED | FAIL
rails_probe_result() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_probe_result: expected 2 args (status, summary), got $#"
  fi
  local rc="$1" summary="$2"
  case "$rc" in
    ''|*[!0-9]*) rails__die "rails_probe_result: status is not numeric: '$rc'" ;;
  esac
  # A missing or unparseable summary is UNVERIFIED, never PASS: a battery that
  # did not say what it measured has not been read.
  case "$summary" in
    *'verified=no'*)  printf 'UNVERIFIED\n'; return 0 ;;
    *'verified=yes'*) ;;
    *)                printf 'UNVERIFIED\n'; return 0 ;;
  esac
  # Belt: a summary claiming `verified=yes` while NAMING skipped probes is
  # self-contradictory, and the safe reading of a contradiction is the
  # unverified one. `skipped=` is the summary's last field, so anything after it
  # is a non-empty skip list.
  case "$summary" in
    *'skipped='?*) printf 'UNVERIFIED\n'; return 0 ;;
  esac
  if [ "$rc" -eq 0 ]; then printf 'PASS\n'; return 0; fi
  if [ "$rc" -eq 3 ]; then printf 'UNVERIFIED\n'; return 0; fi
  printf 'FAIL\n'
}

# ###########################################################################
# THE ROUND-6 CHOKEPOINT: A VERDICT MAY NOT OUTRUN ITS OBSERVATION
# ###########################################################################
#
# Six review rounds found six "different" defects that are ONE defect:
#
#   r1-r2  a rejected `--storage` still armed the real fortress, because `die`
#          inside `$(...)` killed only the subshell.
#   r3     the harness manufactured green evidence from a planted `sudo`.
#   r4     `N3` could report `verified=yes` while the current wrong-uid request
#          had SUCCEEDED.
#   r5 B1  `P1` and `F1-F2` printed `RESULT=PASS "... through the gate"` for
#          bare `curl` calls that were never pointed at the gate.
#   r5 M1  `--repeats 0` produced PASS / `verified=yes` / exit 0 having made
#          ZERO requests.
#   r5 M2  `N3`'s verdict read a `$code` its own loop may never have written -
#          the value came from the N1 loop.
#   r5 M3  an ABSENT gate log became a gate-blamed FAIL instead of a
#          could-not-observe.
#
# THE CLASS: every one of those verdicts was computed from something other than
# the thing it claimed to have measured. Patching them one at a time produces a
# round 7 with a seventh instance. So the seam moves: a probe no longer decides
# anything from ambient shell state. It RECORDS observations, each one naming
# the probe that made it, the mechanism it went through, and whether it was
# observed at all; and a verdict must name the specific observations that
# justify it. The four rails below are the pure, exhaustively drivable half of
# that chokepoint (`lib/probe.sh` drives every one of them); the ledger itself
# lives in `drivers/run-probe-battery.sh`, which is its only consumer.
#
# Four properties follow structurally rather than by inspection:
#
#   1. a verdict with no observation cannot be a PASS, because the basis is a
#      required argument and an empty basis is not a basis. "I made zero
#      requests" is therefore UNOBSERVED, always, and `--repeats 0` cannot
#      produce a green battery.
#   2. a verdict cannot borrow another probe's observation, because every
#      record carries its probe and a cross-probe basis is refused.
#   3. "I could not observe" is a different record state from "I observed a
#      denial", so the two can never be folded into one verdict.
#   4. a claim that NAMES a mechanism ("through the gate") may only be emitted
#      by a basis that exercised it (`rails_assert_claim_supported`).

# A TCP port, as a number, with no leading zero.
#
# The leading-zero rule is not pedantry: `08` reaching an arithmetic context is
# an invalid octal literal and `010` is 8, so a token that READS as one port
# would be a different port to the shell. Ports also come from a root-written
# JSON document here, and this is the one place that decides the value is sane.
rails_assert_tcp_port() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_assert_tcp_port: expected 1 arg (port), got $#"
  fi
  local port="$1"
  if [ -z "$port" ]; then rails__die "empty tcp port"; fi
  case "$port" in
    *[!0-9]*) rails__die "tcp port is not a decimal integer: '$port'" ;;
  esac
  case "$port" in
    0*) rails__die "tcp port has a leading zero (or is zero): '$port'" ;;
  esac
  if [ "$port" -gt 65535 ]; then rails__die "tcp port out of range: $port"; fi
  printf '%s\n' "$port"
}

# Trim ASCII whitespace from both ends. Local helper; not a rail.
rails__trim_ws() {
  local s="${1-}"
  while :; do
    case "$s" in
      ' '*|"	"*) s="${s#?}" ;;
      *' '|*"	") s="${s%?}" ;;
      *) break ;;
    esac
  done
  printf '%s' "$s"
}

# Extract ONE bare decimal field from a FLAT JSON object, or refuse.
#
# WHY NOT A JSON PARSER, AND WHY NOT `grep -o`. The document this reads is the
# gate daemon's runtime state (`/var/db/sanctuary/gate-runtime/<uid>/state.json`,
# `JSON.stringify` of a flat five-field object). A regex scan would happily
# match a `gate_port` nested inside some future sub-object and report it as THE
# port, which is the same "read a value from somewhere other than what you
# claimed" defect this whole block exists to end. So: the text is split on the
# structural characters, each token must be exactly one `"key":value` pair, and
# a field that appears more than ONCE - the shape a nested or duplicated key
# produces - is REFUSED rather than resolved by position. Anything that is not
# a bare decimal is refused too, so `"gate_port":"8080"` does not silently work.
rails_json_flat_number() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_json_flat_number: expected 2 args (json, field), got $#"
  fi
  local json="$1" field="$2" tok value='' hits='' oldifs="$IFS" reglob=''
  case "$field" in
    ''|*[!a-z_]*) rails__die "json field name must be lowercase letters and underscores: '$field'" ;;
  esac
  # Word-splitting IS the parse here, so globbing must be off for it: an
  # unquoted expansion would otherwise let a `*` inside the document expand
  # against the working directory.
  case "$-" in *f*) ;; *) reglob='yes' ;; esac
  set -f
  IFS=',{}[]'
  # shellcheck disable=SC2086
  set -- $json
  IFS="$oldifs"
  if [ -n "$reglob" ]; then set +f; fi
  for tok in "$@"; do
    tok="$(rails__trim_ws "$tok")"
    case "$tok" in
      "\"$field\":"*)
        value="${tok#"\"$field\":"}"
        hits="$hits."
        ;;
    esac
  done
  if [ -z "$hits" ]; then
    rails__die "json carries no \"$field\" field"
  fi
  if [ "$hits" != '.' ]; then
    rails__die "json carries the \"$field\" field more than once; refusing to guess which one is meant"
  fi
  value="$(rails__trim_ws "$value")"
  case "$value" in
    ''|*[!0-9]*) rails__die "json field \"$field\" is not a bare decimal number: '$value'" ;;
  esac
  printf '%s\n' "$value"
}

# Which MECHANISMS does this verdict text claim? One token per line, or nothing.
#
# A verdict line is product copy: it is what somebody reads at 3am when
# deciding whether the wall held. "reachable through the gate" is not a
# statement about an outcome, it is a statement about a MECHANISM - it says the
# bytes traversed the CONNECT proxy. Round 5 found `P1` printing exactly that
# sentence for a bare `curl` that had no `--proxy` and could not have had one,
# because the harness had no way to learn the gate's port. The fix is not to
# reword that one string; it is to make the string's mechanism words checkable
# against what the probe actually did.
#
# The vocabulary is deliberately SMALL and matched case-insensitively on
# substrings. A new phrase that means "through the gate" and is not listed here
# is a gap, and it is named in the attack list rather than pretended away.
rails_claim_mechanisms() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_claim_mechanisms: expected 1 arg (text), got $#"
  fi
  local text="$1" lower
  lower="$(printf '%s' "$text" | rails__sys tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz')" \
    || rails__die 'could not case-fold the verdict text'
  case "$lower" in
    *'through the gate'*|*'through-gate'*|*'at the gate'*|*'via the gate'*|*'to the gate'*|*'gate path'*)
      printf 'gate-channel\n' ;;
  esac
  case "$lower" in
    *'allowlist'*|*'peer_uid_mismatch'*|*'peer_unresolved'*|*'peer='*|*'gate log'*|*'gate-log'*|*'log window'*)
      printf 'gate-log\n' ;;
  esac
}

# Refuse a verdict text that claims a mechanism its basis did not exercise.
#
# `supported` is the space-separated set of mechanisms derived FROM THE BASIS
# RECORDS - never from the text, never from a flag, never from anything the
# caller can assert on its own say-so.
rails_assert_claim_supported() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_claim_supported: expected 2 args (text, supported-mechanisms), got $#"
  fi
  local text="$1" supported=" $2 " mechs need
  # Mandatory form: `rails__die` inside `$( )` would otherwise kill only the
  # subshell and leave an empty mechanism list looking like "claims nothing".
  # That is round 1's defect, and it would defeat this rail specifically.
  mechs="$(rails_claim_mechanisms "$text")" \
    || rails__die "could not classify the mechanisms claimed by the verdict text: $text"
  for need in $mechs; do
    case "$supported" in
      *" $need "*) ;;
      *) rails__die "verdict text claims the '$need' mechanism, but no observation in its basis exercised it: $text" ;;
    esac
  done
}

# Cursor token used by the probe battery to bind a log reason to bytes appended
# after a specific request boundary. Shape: `size,inode,uid,gid`, or
# `0,0,0,0` for "the file did not exist at the cursor".
rails_assert_log_cursor() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_assert_log_cursor: expected 1 arg (cursor), got $#"
  fi
  local token="$1" oldifs="$IFS" a b c d extra
  if [ -z "$token" ]; then rails__die "empty log cursor"; fi
  case "$token" in
    *[!0-9,]*) rails__die "log cursor contains disallowed characters: $token" ;;
  esac
  IFS=','
  # shellcheck disable=SC2086
  set -- $token
  IFS="$oldifs"
  if [ "$#" -ne 4 ]; then rails__die "log cursor must have four numeric fields (size,inode,uid,gid): $token"; fi
  a="$1"; b="$2"; c="$3"; d="$4"; extra="${5:-}"
  if [ -n "$extra" ]; then rails__die "log cursor has extra fields: $token"; fi
  for n in "$a" "$b" "$c" "$d"; do
    case "$n" in
      ''|*[!0-9]*) rails__die "log cursor field is not numeric: $token" ;;
    esac
    if [ "${#n}" -gt 18 ]; then rails__die "log cursor field is implausibly long: $token"; fi
  done
  printf '%s,%s,%s,%s\n' "$a" "$b" "$c" "$d"
}

# Compose the disposable fortress path. PURE: it validates and prints, it never
# touches the filesystem, and it is the ONLY place the path is spelled out.
#
#   <base>/<operator-account>/.sanctuary-loop-<run-id>
#
# The per-operator directory exists so two drill accounts on one host cannot
# collide, and so the leaf's parent is a directory the wrapper created rather
# than one the caller named.
rails_derive_disposable_storage() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_derive_disposable_storage: expected 3 args (base, operator, run_id), got $#"
  fi
  local base="$1" operator="$2" run_id="$3" id
  if [ -z "$base" ]; then rails__die "empty disposable base"; fi
  case "$base" in /*) ;; *) rails__die "disposable base is not an absolute path: $base" ;; esac
  case "$base/" in
    */../*|*/./*) rails__die "disposable base contains a relative component: $base" ;;
  esac
  # The operator name has already passed the account rail at every production
  # call site; re-screening it here means this function is safe on its own.
  case "$operator" in
    [a-z_]*) ;;
    *) rails__die "operator account must start with a lowercase letter or underscore: $operator" ;;
  esac
  case "$operator" in
    *[!a-z0-9_-]*) rails__die "operator account contains disallowed characters: $operator" ;;
  esac
  id="$(rails_assert_run_id "$run_id")" || rails__die "run id rejected: $run_id"
  if [ -z "$id" ]; then rails__die "empty run id after rail"; fi
  printf '%s\n' "$(rails__squeeze_slashes "$base")/$operator/$RAILS_DISPOSABLE_PREFIX$id"
}

# The PURE half of the trusted-chain rail, split out so the security logic is
# testable exhaustively without root and without a fixture filesystem, exactly
# the way `rails_assert_nonroot_uid` is. Production and the tests run THIS
# function; only the source of the three facts differs.
#
# A component is trusted when:
#   * it is owned by root, or by the very process doing the walking (so an
#     unprivileged driver can validate its own sandbox, while the root wrapper
#     accepts nothing but root); AND
#   * it is not group- or other-writable, UNLESS it carries the sticky bit, in
#     which case only the entry's own owner may rename or remove entries in it
#     and replacement is still impossible (this is what makes /tmp safe as a
#     path component and what lets the batteries run in a temp directory).
rails_assert_trusted_component() {
  if [ "$#" -ne 4 ]; then
    rails__die "rails_assert_trusted_component: expected 4 args (path, owner_uid, mode, self_uid), got $#"
  fi
  local p="$1" owner="$2" mode="$3" self="$4"
  case "$owner" in
    ''|*[!0-9]*) rails__die "unparseable owner uid for $p: '$owner'" ;;
  esac
  case "$self" in
    ''|*[!0-9]*) rails__die "unparseable self uid while walking $p: '$self'" ;;
  esac
  case "$mode" in
    ''|*[!0-7]*) rails__die "unparseable octal mode for $p: '$mode'" ;;
  esac
  if [ "$owner" -ne 0 ] && [ "$owner" != "$self" ]; then
    rails__die "path component $p is owned by uid $owner, which is neither root nor this process (uid $self); it could be replaced under us"
  fi
  if [ $(( 8#$mode & 8#22 )) -ne 0 ] && [ $(( 8#$mode & 8#1000 )) -eq 0 ]; then
    rails__die "path component $p is group- or world-writable without the sticky bit (mode $mode); its entries could be replaced under us"
  fi
}

# Walk EVERY component of an absolute directory path and require each one to be
# a real, non-symlink, trusted directory. Prints the resolved path.
#
# The base is a COMPILED-IN CONSTANT, never caller input, so resolving it once
# with `cd -P` first is safe and is what makes this work on a Mac, where /var
# and /tmp are themselves symlinks into /private. Every component of the
# RESOLVED path is then required to be a real directory.
rails_assert_trusted_dir_chain() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_trusted_dir_chain: expected 2 args (label, path), got $#"
  fi
  local label="$1" p="$2" self resolved acc='' seg mode owner
  if [ -z "$p" ]; then rails__die "$label: empty path"; fi
  case "$p" in /*) ;; *) rails__die "$label: not an absolute path: $p" ;; esac
  p="$(rails__squeeze_slashes "$p")"
  self="$(rails__euid)"
  if [ -z "$self" ]; then rails__die "$label: cannot determine this process's uid"; fi
  # The FINAL component of the given path is lstat'd before anything is
  # resolved. Intermediates are allowed to be symlinks because the base is a
  # compiled-in constant and /var is a symlink into /private on every Mac; the
  # LEAF is the component an attacker would swap, and the walk below then
  # re-proves that every component of the resolved chain is a real, trusted
  # directory.
  if [ -L "$p" ]; then
    rails__die "$label: $p is a symlink; refusing to treat it as a trusted directory"
  fi
  if ! resolved="$(rails__resolve_dir "$p")"; then
    rails__die "$label: does not resolve to an existing directory: $p"
  fi
  if [ "$resolved" = '/' ]; then rails__die "$label: resolves to the filesystem root: $p"; fi

  local oldifs="$IFS" noglob_was_set=''
  case "$-" in *f*) noglob_was_set='yes' ;; esac
  set -f
  IFS='/'
  # shellcheck disable=SC2086
  set -- $resolved
  IFS="$oldifs"
  if [ -z "$noglob_was_set" ]; then set +f; fi

  for seg in "$@"; do
    if [ -z "$seg" ]; then continue; fi
    acc="$acc/$seg"
    if [ -L "$acc" ]; then
      rails__die "$label: path component $acc is a symlink; refusing to walk it"
    fi
    if [ ! -d "$acc" ]; then
      rails__die "$label: path component $acc is not a directory"
    fi
    if ! mode="$(rails__stat_mode "$acc")"; then rails__die "$label: cannot stat $acc"; fi
    if ! owner="$(rails__stat_owner_uid "$acc")"; then rails__die "$label: cannot read owner of $acc"; fi
    rails_assert_trusted_component "$acc" "$owner" "$mode" "$self" \
      || rails__die "$label: untrusted path component $acc"
  done
  printf '%s\n' "$resolved"
}

# THE resolution chokepoint. Every privileged filesystem operation that reaches
# INSIDE an already-approved root goes through this and nothing else.
#
#   TARGET="$(rails_assert_safe_subpath "$STORAGE" 'state/_audit/.audit-write.lock')" || die
#
# It resolves the chain component by component and refuses if ANY component,
# intermediate or final, is a symlink. The executed exploit deleted a real
# fortress's audit lock as root because `[ -L "$target" ]` lstats only the
# FINAL component while `state/` and `state/_audit/` were followed by the
# kernel without ever being looked at.
#
# A component that does not exist is not an error: the whole point is that the
# caller may then safely conclude the target is absent. What is refused is
# TRAVERSING something that is not what it appears to be.
rails_assert_safe_subpath() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_safe_subpath: expected 2 args (root, relative path), got $#"
  fi
  local root="$1" rel="$2" acc seg rroot
  if [ -z "$root" ]; then rails__die "safe-subpath: empty root"; fi
  case "$root" in /*) ;; *) rails__die "safe-subpath: root is not an absolute path: $root" ;; esac
  if [ -z "$rel" ]; then rails__die "safe-subpath: empty relative path under $root"; fi
  case "$rel" in
    /*) rails__die "safe-subpath: relative path must not be absolute: $rel" ;;
  esac
  case "$rel" in
    *$'\n'*|*$'\t'*|*$'\r'*) rails__die "safe-subpath: relative path contains a control character" ;;
  esac
  case "$rel" in
    *[!A-Za-z0-9._/-]*) rails__die "safe-subpath: relative path contains disallowed characters: $rel" ;;
  esac
  case "/$rel/" in
    */../*|*/./*|*//*) rails__die "safe-subpath: relative path contains a relative or empty component: $rel" ;;
  esac

  # The root must itself still be a real, self-resolving directory at this
  # moment. Under the root-owned base nothing can have changed it, and asserting
  # it anyway is what keeps this function correct if the base ever moves.
  if [ -L "$root" ]; then rails__die "safe-subpath: root $root is a symlink"; fi
  if ! rroot="$(rails__resolve_dir "$root")"; then
    rails__die "safe-subpath: root does not resolve to an existing directory: $root"
  fi
  if [ "$rroot" != "$(rails__squeeze_slashes "$root")" ]; then
    rails__die "safe-subpath: root must be given in canonical resolved form; $root resolves to $rroot"
  fi

  acc="$rroot"
  local oldifs="$IFS" noglob_was_set=''
  case "$-" in *f*) noglob_was_set='yes' ;; esac
  set -f
  IFS='/'
  # shellcheck disable=SC2086
  set -- $rel
  IFS="$oldifs"
  if [ -z "$noglob_was_set" ]; then set +f; fi

  for seg in "$@"; do
    if [ -z "$seg" ]; then continue; fi
    acc="$acc/$seg"
    if [ -L "$acc" ]; then
      rails__die "safe-subpath: component $acc is a symlink; refusing to follow it"
    fi
    if [ -d "$acc" ]; then
      # An existing intermediate directory must resolve to itself. Redundant
      # with the lstat above by design: two independent ways to notice.
      local racc
      if ! racc="$(rails__resolve_dir "$acc")"; then
        rails__die "safe-subpath: component $acc does not resolve"
      fi
      if [ "$racc" != "$acc" ]; then
        rails__die "safe-subpath: component $acc resolves elsewhere ($racc); refusing"
      fi
    fi
  done
  printf '%s\n' "$acc"
}

# M1 - bind the privileged caller to the account it claims to be acting for.
#
# PURE predicate so the uid-0 branch is testable without root. `SUDO_USER`
# appeared nowhere in the reviewed artifact, so the grant holder could point the
# wrapper at any other account's directory. Failing when SUDO_USER is EMPTY and
# the process is root is deliberate: this wrapper is only ever reached through
# sudo, and "root with no caller identity" is a state it should refuse rather
# than guess about.
rails_assert_caller_binding() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_assert_caller_binding: expected 3 args (self_uid, sudo_user, operator), got $#"
  fi
  local self="$1" sudo_user="$2" operator="$3"
  case "$self" in
    ''|*[!0-9]*) rails__die "caller binding: self uid is not numeric: '$self'" ;;
  esac
  if [ "$self" -ne 0 ]; then return 0; fi
  if [ -z "$sudo_user" ]; then
    rails__die "caller binding: running as root with no SUDO_USER; this wrapper is only ever reached through sudo"
  fi
  if [ "$sudo_user" != "$operator" ]; then
    rails__die "caller binding: sudo caller is '$sudo_user' but --operator-account says '$operator'; refusing to act for another account"
  fi
}

# Convert a `ps -o etime=` value to seconds. Pure, so preflight's daemon
# freshness check has a testable core. Accepts [[DD-]HH:]MM:SS.
rails_etime_to_seconds() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_etime_to_seconds: expected 1 arg (etime), got $#"
  fi
  local e="$1" days=0 rest hh=0 mm ss
  # Strip the surrounding whitespace ps pads with.
  e="${e#"${e%%[![:space:]]*}"}"
  e="${e%"${e##*[![:space:]]}"}"
  if [ -z "$e" ]; then rails__die "empty etime"; fi
  case "$e" in
    *-*) days="${e%%-*}"; rest="${e#*-}" ;;
    *)   rest="$e" ;;
  esac
  case "$days" in
    ''|*[!0-9]*) rails__die "unparseable etime day field: $e" ;;
  esac
  case "$rest" in
    *:*:*) hh="${rest%%:*}"; rest="${rest#*:}"; mm="${rest%%:*}"; ss="${rest#*:}" ;;
    *:*)   mm="${rest%%:*}"; ss="${rest#*:}" ;;
    *)     rails__die "unparseable etime: $e" ;;
  esac
  case "$hh$mm$ss" in
    ''|*[!0-9]*) rails__die "unparseable etime field: $e" ;;
  esac
  printf '%s\n' "$(( (10#$days * 86400) + (10#$hh * 3600) + (10#$mm * 60) + 10#$ss ))"
}

# ---------------------------------------------------------------------------
# R2 / BLOCKER - the disposable-storage rail
# ---------------------------------------------------------------------------
#
# Prints the CANONICAL RESOLVED path on stdout and nothing else, so the
# mandatory call-site form captures a value it can trust:
#
#   STORAGE="$(rails_assert_disposable_storage "$ANCHOR" "$IN")" || die "..."
#   [ -n "$STORAGE" ] || die "empty storage after rail"
#
# Rejects, in order: bad arity, empty/relative/control-character input, `.` and
# `..` components, DENYLIST (lexical), then the allowlist (basename prefix and
# charset), then a symlinked final component, then resolution of the parent
# chain with a re-assertion of both dirname==ANCHOR and the basename prefix on
# the RESOLVED path, then the DENYLIST again on the resolved path, then a
# post-condition that an existing target resolves to itself.
#
# The symlink case is the specific R2 fail-open: a `.sanctuary-loop-evil`
# symlink to a real fortress passes every lexical check and the CLI follows it.
#
# ANCHOR, NOT HOME. The anchor is `<RAILS_DISPOSABLE_BASE>/<operator>`, a
# ROOT-OWNED directory the wrapper created, not the operator's home. This rail
# is check-then-use by construction, and the ONLY thing that makes
# check-then-use sound is that no unprivileged caller can change any component
# of the path between the two moments. Point it back at an operator-writable
# directory and the 2026-07-25 race (won in 44 attempts, against the real
# artifact) comes back with it.
rails_assert_disposable_storage() {
  if [ "$#" -ne 2 ]; then
    rails__die "rails_assert_disposable_storage: expected 2 args (anchor, candidate), got $#"
  fi
  local anchor_in="$1" cand="$2"

  if [ -z "$anchor_in" ]; then rails__die "empty anchor argument"; fi
  if [ -z "$cand" ]; then
    rails__die "empty storage path: empty resolves to the REAL default fortress, never treat it as unset"
  fi

  case "$anchor_in" in /*) ;; *) rails__die "anchor is not an absolute path: $anchor_in" ;; esac
  anchor_in="$(rails__squeeze_slashes "$anchor_in")"
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
  rails__assert_not_denylisted "$anchor_in" "$norm" 'lexical'

  local base="${norm##*/}"
  local dir="${norm%/*}"
  if [ -z "$dir" ]; then dir='/'; fi

  # Allowlist: the disposable prefix plus a non-empty stamp, conservative charset.
  case "$base" in
    "$RAILS_DISPOSABLE_PREFIX"?*) ;;
    *) rails__die "basename is not a disposable loop fortress (${RAILS_DISPOSABLE_PREFIX}<stamp>): $base" ;;
  esac
  # Lowercase only, for the same case-insensitive-APFS reason the run id is:
  # `.sanctuary-loop-A` and `.sanctuary-loop-a` are two strings and one
  # directory entry on the drill hosts.
  case "$base" in
    *[!a-z0-9._-]*) rails__die "basename contains disallowed characters (lowercase only; the drill hosts' filesystem is case-insensitive): $base" ;;
  esac

  # R2: never follow an operator-writable symlink as root. `-L` is an lstat, so
  # this is correct even when the link dangles.
  if [ -L "$norm" ]; then
    rails__die "final component is a symlink; refusing to follow it as root: $norm"
  fi

  # R2: resolve, then RE-ASSERT the lexical properties on the resolved form.
  local ranchor rdir
  if ! ranchor="$(rails__resolve_dir "$anchor_in")"; then
    rails__die "anchor does not resolve to an existing directory: $anchor_in"
  fi
  if [ "$ranchor" = "/" ]; then rails__die "anchor resolves to the filesystem root; refusing"; fi
  if ! rdir="$(rails__resolve_dir "$dir")"; then
    rails__die "parent directory does not resolve to an existing directory: $dir"
  fi
  if [ "$rdir" != "$ranchor" ]; then
    rails__die "resolved parent ($rdir) is not the approved anchor ($ranchor)"
  fi

  local resolved="$rdir/$base"
  case "${resolved##*/}" in
    "$RAILS_DISPOSABLE_PREFIX"?*) ;;
    *) rails__die "resolved basename lost the disposable prefix: $resolved" ;;
  esac
  rails__assert_not_denylisted "$ranchor" "$resolved" 'resolved'

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
  if [ "$#" -lt 1 ]; then
    rails__die "rails_assert_host_allowed: expected at least 1 arg (fingerprint)"
  fi
  local fp="$1" n e norm strict
  shift

  # NAME BELT, first, and deny-only. Every observed name is screened; none of
  # them can ADD a host, because there is no name allowlist. That asymmetry is
  # the point: names are forgeable (a planted `hostname` on PATH defeated the
  # previous design on the real MacBook Air), so a name may push this rail
  # toward refusal and never toward acceptance.
  for n in "$@"; do
    if [ -z "$n" ]; then rails__die "empty host identity supplied"; fi
    norm="$(rails__normalize_host "$n")"
    if [ -z "$norm" ]; then rails__die "host identity normalizes to empty: $n"; fi
    strict="$(rails__normalize_host_strict "$n")"
    if [ -z "$strict" ]; then rails__die "host identity normalizes to empty: $n"; fi
    for e in $RAILS_HOST_DENY; do
      # BOTH sides go through the aggressive form, so a list entry that someone
      # later types with capitals, hyphens, spaces or an apostrophe still
      # matches. A denylist that silently stops matching because of punctuation
      # is the worst possible bug in this file, and the review found exactly
      # that for `scutil --get ComputerName`.
      if [ "$strict" = "$(rails__normalize_host_strict "$e")" ]; then
        rails__die "host '$norm' is on the un-overridable name denylist (daily driver); refusing"
      fi
    done
  done

  # THE DECISION, on the hardware fingerprint, against the compiled-in lists.
  rails_assert_fingerprint_against "$fp" "$RAILS_HOST_DENY_FP" "$RAILS_HOST_ALLOW_FP"
}

# The PURE half of the fingerprint decision: value in, lists in, verdict out.
#
# Split out for the same reason `rails_assert_nonroot_uid` is: the shipped
# allowlist is DELIBERATELY EMPTY until a drill host is measured, so the only
# way to exercise the ACCEPT path is to drive the predicate with lists. A rail
# nobody has ever seen say yes is not a rail anyone should trust, and an
# allowlist that has never been shown to admit anything is not obviously
# distinguishable from one that is broken.
#
# Production passes the compiled-in constants and nothing else; there is no
# argument, flag or environment variable anywhere in the harness that reaches
# these lists.
rails_assert_fingerprint_against() {
  if [ "$#" -ne 3 ]; then
    rails__die "rails_assert_fingerprint_against: expected 3 args (fingerprint, deny, allow), got $#"
  fi
  local fp="$1" deny="$2" allow="$3" e

  # Fail closed on anything that is not a well-formed fingerprint: empty, an
  # error string, a truncated read and an unparseable one are all REFUSALS,
  # never "well, it isn't the MacBook, so it must be fine".
  if [ -z "$fp" ]; then
    rails__die "no host fingerprint supplied; refusing (fail closed)"
  fi
  if [ "${#fp}" -ne 64 ]; then
    rails__die "host fingerprint is not 64 hex characters; refusing (fail closed)"
  fi
  case "$fp" in
    *[!0-9a-f]*) rails__die "host fingerprint is not lowercase hex; refusing (fail closed)" ;;
  esac

  # DENY FIRST, in the SAME identifier space as the allowlist. A denylist keyed
  # on names beside an allowlist keyed on hardware would silently stop
  # matching, which is the single worst bug this file can have.
  for e in $deny; do
    if [ "$fp" = "$e" ]; then
      rails__die "this machine's hardware fingerprint is on the un-overridable denylist (daily driver); refusing"
    fi
  done
  if [ -z "$allow" ]; then
    rails__die "the drill-host allowlist is EMPTY, so no machine may run this; run scripts/drill-loop/host-fingerprint.sh on the drill host and add its fingerprint to RAILS_HOST_ALLOW_FP (refusing, fail closed)"
  fi
  for e in $allow; do
    if [ "$fp" = "$e" ]; then return 0; fi
  done
  rails__die "this machine's hardware fingerprint is not on the compiled-in drill-host allowlist; refusing (fail closed)"
}

# Read this machine's hardware UUID and reduce it to a fingerprint.
#
# `ioreg` by ABSOLUTE path: an attacker who can put an `ioreg` on PATH could
# otherwise answer this question for us, which is precisely how the name-based
# rail was defeated. The UUID's shape is checked strictly (8-4-4-4-12 uppercase
# hex) so a truncated read, an error message, or a lookup on a machine that has
# no such property CANNOT be mistaken for an identity.
#
# Prints a 64-character lowercase hex fingerprint, or dies. There is no
# "unknown" return value: this rail has no third answer.
rails_host_fingerprint_local() {
  local out uuid rc=0
  # BOUNDED. A hang is not an answer, and an unattended host rail that hangs
  # produces neither evidence nor a refusal (Codex round-3 finding 5).
  out="$(rails__sys_timeout "$RAILS_IOREG_TIMEOUT_SECONDS" ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null)" || rc=$?
  if [ "$rc" -eq 124 ]; then
    rails__die "reading this machine's hardware identity TIMED OUT after ${RAILS_IOREG_TIMEOUT_SECONDS}s (ioreg did not answer); refusing (fail closed)"
  fi
  if [ -z "$out" ]; then
    rails__die "cannot read this machine's hardware identity (ioreg produced nothing); refusing (fail closed)"
  fi
  uuid="$(printf '%s\n' "$out" | rails__sys sed -n 's/.*"IOPlatformUUID" = "\([^"]*\)".*/\1/p' | rails__sys head -1)"
  if [ -z "$uuid" ]; then
    rails__die "this machine reports no IOPlatformUUID; refusing (fail closed)"
  fi
  rails_host_fingerprint_of "$uuid"
}

# The PURE half: UUID in, fingerprint out. Split out so the shape validation
# and the hashing are testable exhaustively without depending on what machine
# the battery happens to run on.
rails_host_fingerprint_of() {
  if [ "$#" -ne 1 ]; then
    rails__die "rails_host_fingerprint_of: expected 1 arg (uuid), got $#"
  fi
  local uuid="$1" fp
  if [ -z "$uuid" ]; then rails__die "empty hardware UUID; refusing (fail closed)"; fi
  if [ "${#uuid}" -ne 36 ]; then
    rails__die "hardware UUID is not 36 characters; refusing (fail closed): $uuid"
  fi
  case "$uuid" in
    [0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]-[0-9A-F][0-9A-F][0-9A-F][0-9A-F]-[0-9A-F][0-9A-F][0-9A-F][0-9A-F]-[0-9A-F][0-9A-F][0-9A-F][0-9A-F]-[0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F][0-9A-F]) ;;
    *) rails__die "hardware UUID is not in 8-4-4-4-12 uppercase-hex form; refusing (fail closed)" ;;
  esac
  fp="$(printf '%s' "$uuid" | { rails__sys sha256sum 2>/dev/null || rails__sys shasum -a 256 2>/dev/null; } | rails__sys awk '{print $1}')"
  if [ -z "$fp" ]; then rails__die "could not hash the hardware UUID; refusing (fail closed)"; fi
  if [ "${#fp}" -ne 64 ]; then rails__die "hardware fingerprint is not 64 hex characters; refusing"; fi
  printf '%s\n' "$fp"
}

# Screen EVERY observed identity, dropping none, skipping only the empty ones.
#
# This exists because the reviewed wrapper collected `hostname -s`, `hostname -f`
# and `scutil --get ComputerName` and then chose between three `if`/`elif`
# branches that passed different subsets: when `hostname -f` was empty but
# ComputerName was not, the ComputerName alias was SILENTLY DROPPED. A rail can
# only refuse what it is shown, so a branch that drops an identity is a
# fail-open no matter how strict the rail is.
#
# Putting the collection in ONE function with no branches makes that
# impossible, and makes it testable without needing a machine whose
# `scutil --get ComputerName` happens to be interesting: pass three values, one
# of them denied, and the rail must refuse whichever position it is in.
#
# An empty identity is skipped rather than refused: "this box has no
# ComputerName" is not a reason to refuse a legitimate drill host. All-empty is
# refused, because then nothing was observed at all.
rails_assert_host_allowed_observed() {
  if [ "$#" -lt 1 ]; then
    rails__die "rails_assert_host_allowed_observed: expected at least 1 arg (fingerprint)"
  fi
  local fp="$1" n
  shift
  local -a observed=()
  for n in "$@"; do
    if [ -n "$n" ]; then observed+=("$n"); fi
  done
  # Zero observed NAMES is fine: Mini1 has no `scutil --get HostName` at all,
  # and the decision does not rest on names anyway. Zero FINGERPRINT is not
  # fine, and `rails_assert_host_allowed` refuses it.
  if [ "${#observed[@]}" -eq 0 ]; then
    rails_assert_host_allowed "$fp"
    return $?
  fi
  rails_assert_host_allowed "$fp" "${observed[@]}"
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
    if rails__sys mkdir "$lock" 2>/dev/null; then
      printf '%s\n' "$$" > "$lock/pid"
      # Compare-after-write: only the mkdir winner can have created this
      # directory, so reading back anything else means the world is not what we
      # think it is. Stop rather than proceed.
      readback="$(rails__sys cat "$lock/pid" 2>/dev/null || printf '')"
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

    holder="$(rails__sys cat "$lock/pid" 2>/dev/null || printf '')"

    if [ -n "$holder" ]; then
      case "$holder" in
        ''|*[!0-9]*) rails__die "lock $lock has a non-numeric pid file ('$holder'); refusing" ;;
      esac
      empty_since=0
      if kill -0 "$holder" 2>/dev/null; then
        rails__die "drill lock $lock is held by live pid $holder; refusing to interleave"
      fi
      # Dead holder: try to become the single reclaimer.
      if rails__sys mkdir "$reclaim" 2>/dev/null; then
        # Re-read the facts while holding the reclaim right.
        if [ -d "$lock" ]; then
          holder="$(rails__sys cat "$lock/pid" 2>/dev/null || printf '')"
          if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
            stale="$lock.stale.$$"
            if rails__sys mv "$lock" "$stale" 2>/dev/null; then
              rails__sys rm -rf "$stale"
            fi
          fi
        fi
        rails__sys rmdir "$reclaim" 2>/dev/null || true
      fi
      rails__sleep_tick
    else
      # Directory exists but no pid file yet: either a winner mid-acquire, or a
      # genuinely abandoned empty lock. Only the second is reclaimable, and only
      # after a grace window.
      if [ "$empty_since" -eq 0 ]; then
        empty_since="$(rails__now)"
      elif [ $(( $(rails__now) - empty_since )) -ge 5 ]; then
        if rails__sys mkdir "$reclaim" 2>/dev/null; then
          if [ -d "$lock" ] && [ ! -s "$lock/pid" ]; then
            stale="$lock.stale.$$"
            if rails__sys mv "$lock" "$stale" 2>/dev/null; then
              rails__sys rm -rf "$stale"
            fi
          fi
          rails__sys rmdir "$reclaim" 2>/dev/null || true
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
  holder="$(rails__sys cat "$lock/pid" 2>/dev/null || printf '')"
  if [ "$holder" != "$$" ]; then
    rails__die "refusing to release lock $lock held by pid '$holder' (this process is $$)"
  fi
  rails__sys rm -rf "$lock"
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
