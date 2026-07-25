# Autonomous drill loop

A deterministic harness that runs the Sanctuary egress-gate drill ladder over
and over, unattended, and captures everything it sees. No model runs inside the
loop: it is bash plus expect, so it needs no API credential and nothing about it
depends on a login session staying alive. Intelligence enters afterwards,
reading the artifacts in the morning.

The job it exists to do: find defect layer N+1 at 3am, have the failing capture
sitting in front of a fix session by breakfast, and burn the fix back through
the loop the following night.

## The rails are the product

This harness escalates to root under a NOPASSWD sudoers grant, and it has been
reviewed UNSOUND twice. Both rounds are worth stating plainly, because the
current design is a direct answer to the second one.

**Round 1.** A REJECTED `--storage` path armed the operator's real
`~/.sanctuary` fortress as root: the rail's rejection happened inside a command
substitution and killed only a subshell, the parent continued with an empty
storage value, and an empty `SANCTUARY_STORAGE_PATH` resolves to the real
default fortress. Class: *a rail rejection never reached the code that used the
value.*

**Round 2.** Three independent lenses, two UNSOUND verdicts, two working
exploits. `clean-markers` deleted a file inside a fortress as root through an
unchecked INTERMEDIATE symlink, with every rail passing. The accepted storage
directory could be swapped for a symlink to a fortress after validation and
before use, winning in 44 attempts. And a planted `hostname` on PATH made the
artifact print `WRAPPER=ACCEPT` on the operator's MacBook Air, the one machine
the design says is structurally unable to run it. Class: *a rail APPROVED a
value, and then the code used something else.*

Round 1 was fixed by getting five named call sites right. That is what left the
class open. So round 2 is fixed at the class level instead:

**The caller no longer supplies a path.** There is no `--storage` flag. The
caller supplies a `--run-id`, which cannot contain a slash, and the wrapper
composes the path itself under a base it compiled in. An attacker cannot race,
swap or symlink a value they never supply.

**The base is root-owned and not operator-writable.** Every component of
`/private/var/sanctuary-drill/<operator>/.sanctuary-loop-<run-id>` is created by
root, verified component by component before use, and cannot be created,
renamed or replaced by an unprivileged caller. This is what actually kills the
time-of-check-to-time-of-use class, rather than narrowing its window.

**Every privileged filesystem operation goes through ONE resolution
chokepoint.** `rails_assert_safe_subpath` walks every component and refuses any
symlink anywhere in the chain. `clean-markers`, `preflight.sh` and
`teardown-verify.sh` all use it; no verb walks a path by hand.

### And the host rail decides on hardware, not on a name

A live audit of the real machines (2026-07-25) killed the name-based allowlist
outright. Measured, not assumed:

| | `hostname -s` | `scutil HostName` | `scutil LocalHostName` | `scutil ComputerName` |
| --- | --- | --- | --- | --- |
| Mini1, the intended drill host | **`Mac`** | **unset** | `Agents-Mac-mini` | `Agent's Mac mini` |
| MBA, which must never run this | `Eriks-MacBook-Air` | unset | `Eriks-MacBook-Air` | `Erik's MacBook Air` |

Allowing Mini1 by short name means putting the literal string **`Mac`** on the
allowlist, and a large fraction of default-configured Macs answer exactly that.
An allowlist containing `Mac` is close to no allowlist at all: it silently turns
"fail closed on an unknown host" into "pass on many unknown hosts". And
`scutil --get HostName` is unset on the drill host, so any branch leaning on it
gets an empty string there.

Names are forgeable anyway. BLOCKER 2 was a planted `hostname` on PATH producing
`WRAPPER=ACCEPT` on the MacBook Air.

So the decision is the machine's **hardware UUID** (`IOPlatformUUID`, read from
`ioreg` by absolute path), the allowlist and the denylist live in the **same
identifier space** (a denylist keyed on names beside an allowlist keyed on
hardware would silently stop matching), and every unusable lookup is a REFUSAL
rather than a non-match. Names survive only as a deny-only belt: they can push
the rail toward refusal and never toward acceptance.

What is committed is the SHA-256 of the UUID, not the UUID. This is a public
repository; a fingerprint compares exactly, carries no raw machine identifier,
and does not reverse into one.

**`RAILS_HOST_ALLOW_FP` ships EMPTY**, so the wrapper currently refuses on every
machine. Mini1's and Mini2's fingerprints have not been measured; the audit
above observed names only and this work did not reach those machines. Empty is
the correct state, and it is the same posture the harness already took toward an
unknown host. To provision, on the drill host, once, alongside the sudoers
grant:

```sh
scripts/drill-loop/host-fingerprint.sh     # read-only; installs nothing
```

then paste the printed fingerprint into `RAILS_HOST_ALLOW_FP`, name the machine
in a comment, run `build-wrapper.sh --write-hash`, and get the diff re-reviewed.
That list is the entire host allowlist.

The ordering here stays deliberate: `lib/rails.sh` first, its battery second,
the loop on top only once the battery was green. A harness that runs beautifully
but can be talked into touching a real fortress is worth negative value.

### What it refuses

| Refusal | Enforced by |
| --- | --- |
| A caller-supplied storage path, at all | there is no `--storage` flag; the wrapper derives the path |
| A run id that is not a plain identifier | `rails_assert_run_id`: no slash, no traversal, no leading dot or dash |
| A storage path outside `<base>/<operator>/.sanctuary-loop-<id>` | `rails_assert_disposable_storage`, anchored on a root-owned directory |
| A base whose chain is not root-owned and non-writable | `rails_assert_trusted_dir_chain`, every component |
| A symlink ANYWHERE in a path a privileged verb walks | `rails_assert_safe_subpath`, the one chokepoint |
| Any known fortress path, checked before the allowlist | denylist, lexical and resolved |
| An empty storage value | the rail, the post-rail guard, and the guard before the one export |
| Any machine but a compiled-in drill host | `rails_assert_host_allowed`, decided on the HARDWARE FINGERPRINT, deny-first, fail closed |
| The operator's daily-driver MacBook, by hardware | its fingerprint is on the un-overridable denylist, in the same identifier space as the allowlist |
| The operator's daily-driver MacBook, under any of its names | a deny-only name belt on an aggressively normalized form |
| A machine that merely CLAIMS a drill host's name | there is no name allowlist; a name can only ever cause a refusal |
| A hardware lookup that is empty, errored or unparseable | refused, never treated as "not the MacBook, therefore fine" |
| A PATH-planted `hostname`, `stat`, `rm` or interpreter | absolute shebang, pinned PATH, `rails__sys` absolute resolution, `secure_path` |
| `--operator-account root`, by name and by uid | `rails_assert_non_root_account` |
| Acting for an account other than the sudo caller | `rails_assert_caller_binding` |
| A group- or world-accessible passphrase file | `rails_assert_secret_file_perms`, masked against 022 and 077. NO PRODUCTION CALLER today: `--passphrase-file` was validated root-run surface that reached no verb and is gone, so this is a tested library rail waiting for a consumer, not a refusal the harness currently makes |
| An agent account outside the compiled-in agent allowlist | `rails_assert_agent_account_allowed`; `--agent-account` is a SELECTION from a compiled-in list, not a value |
| An UPPERCASE run id, which aliases a lowercase one on case-insensitive APFS | `rails_assert_run_id`, lowercase-only, rejected rather than folded |
| A hardware lookup that HANGS | `rails__sys_timeout`; a timeout is a REJECT like every other unusable lookup |
| A driver observation made through a PATH-resolved tool | `rails_require_cmd` in every driver; a structural test forbids a bare command name in driver code |
| A check that could not OBSERVE, reported as clean | tri-state verdicts: `VERIFY=UNOBSERVED` / `PREFLIGHT=FAIL` are distinct from DIRTY and both stop the night |
| A skipped probe, summarized as a pass | `rails_probe_result`: exit status AND the battery's own `verified=yes` must agree |
| A verdict computed from something other than what it measured | the observation ledger: `report` takes the observation ids as a REQUIRED argument and refuses an empty basis, a basis belonging to another probe, or a basis that observed nothing. A refused verdict is `UNOBSERVED` + a counted HARNESS DEFECT + exit 4 |
| A PASS claiming a mechanism the request never used ("through the gate") | `rails_claim_mechanisms` + `rails_assert_claim_supported`: the mechanism words in a verdict text are checked against what its basis actually exercised |
| A through-gate probe that never traversed the gate | the `gate-port` wrapper verb + `measure_http <probe> gate`: the port comes from the gate daemon's own runtime state and the request is proxied to it. `direct` requests pass `--noproxy '*'`, so the two channels cannot be confused |
| A status code attributed to a gate generation that rotated away | `measure_http` re-reads port+generation after every through-gate request; a change makes the observation UNOBSERVABLE |
| An absent gate log read as a gate-blamed denial | per-stream `WRAPPER=GATE-LOG-READ key=<k> state=read\|absent`; `gate_log_since_says` takes the stream CLASS the pattern would live in and returns COULD-NOT-OBSERVE when it was not read |
| Interleaving a scheduled run with an interactive drill | `rails_lock_acquire`, atomic single-winner reclaim |
| Running a wrapper that does not match its reviewed hash | `rails_assert_wrapper_integrity` |

There is no environment variable, flag, or argument anywhere in this harness
that can add a host or widen the storage allowlist. The sudoers grant carries no
`env_keep`, so sudo's `env_reset` strips anything a caller might try to smuggle
in, and the privileged path always uses its compiled-in lists. A test asserts
that the assembled artifact contains no such override outside a comment.

One claim this file used to make and no longer does: that *nothing whatsoever*
could make the wrapper run on the MacBook. A planted file did, through PATH.
What is true after the fix is narrower and is stated in
`sudoers.d/sanctuary-drill`.

## Layout

```
scripts/drill-loop/
  README.md                     this file
  lib/rails.sh                  THE single rail source: pure functions, explicit arguments
  lib/probe.sh                  the rails driven through the exact call-site form production uses
  wrapper-main.sh               the privileged wrapper's body (definitions only, no entrypoint)
  build-wrapper.sh              assembles rails.sh + wrapper-main.sh into one self-contained artifact
  wrapper.sha256                committed hash of that artifact, for drift detection
  install-wrapper.sh            root install to /usr/local/sbin (DOCUMENTED, NOT RUN)
  sudoers.d/sanctuary-drill     the exact NOPASSWD grant, reviewable (NOT INSTALLED)
  selftest.sh                   the rail battery, standalone, no node required
  host-fingerprint.sh           print THIS machine's drill-host fingerprint (read-only)
  ai.sanctuary.drill-loop.plist nightly launchd job (DOCUMENTED, NOT LOADED)
  drivers/
    run-loop.sh                 the loop: sweep N | soak N | reboot K
    preflight.sh                every historical defect layer as a permanent check
    run-probe-battery.sh        the pre-declared probe ladder
    teardown-verify.sh          teardown, OBSERVED-state verification, retirement
  expect/arm-expect.exp         answers the arm confirmation over a pty -- and ONLY
                                that one exact prompt; an unrecognised (y/n) question
                                during a root-run, host-wide arm is a hard stop, never
                                an unattended "y"
```

### Why the wrapper is assembled rather than sourced

The installed wrapper runs as root. If it sourced `lib/rails.sh` out of the
repository at runtime, every write to the repository would be a root
code-execution primitive, and the "scoped" grant would not be scoped at all. But
duplicating the rails into two files is how whack-a-mole starts.

So there is exactly one rails source, and `build-wrapper.sh` concatenates it
with `wrapper-main.sh` into a single self-contained artifact whose hash is
committed. Before the driver uses the privileged wrapper it re-assembles from
the repo, hashes, and compares against both the committed hash and the installed
file. One check catches both "you edited the repo and forgot to reinstall" and
"someone edited the installed wrapper."

## Running the battery

```sh
scripts/drill-loop/selftest.sh          # standalone, on any machine, ~8 seconds
cd server && npx vitest run test/drill-loop/rails.test.ts
```

The standalone battery exists because the machine that actually matters is the
drill host, and the drill host does not run the TypeScript suite. Run it there
before any nightly loop and after any wrapper reinstall.

The two are no longer separate sets of cases that a README claims are the same.
The README used to say "Both run the same cases" while vitest had 59 and
`selftest.sh` had 52, differing in both directions. Now **vitest runs
`selftest.sh` as one of its own cases**, so the drill host and CI execute the
same file and drift between them is impossible. vitest adds cases on top that
need node (structural assertions on the assembled artifact, the TOCTOU race
harness), and `selftest.sh` composes its test wrapper from the real
`build-wrapper.sh --stdout` output rather than hand-concatenating the parts, so
the battery that runs on the drill host tests the SHIPPED header, including the
pinned PATH and `set -euo pipefail`.

Most rejection cases assert three things: a nonzero exit, no ACCEPT token in the
output, and the expected REASON. The reason half matters as much as the others.
A deny for the wrong reason is a failure, not a pass, and that is not pedantry:
the 2026-07-24 drill's negative probes all "passed" while the gate was
strangling every request for an unrelated cause, which hid a live defect for a
full day. A handful of wrapper-level cases assert the first two and name the
layer instead of a reason string; they say so where they are.

The happy path is asserted too. A rail that rejects everything is not sound, it
is broken, and it would sail through a suite that only checks rejections.

### Proven by mutation, not by assertion

The round-2 coverage review found that three of the four layers the PR body
called load-bearing could be DELETED with the suite still fully green, and that
the function deciding which directory the path rail anchored to was stubbed out
in both batteries. So every fix in this round was proven the same way that
review proved its findings: break the property, watch a named test go red,
restore it. The mutation table is in the PR body. What it covers, in short:

- both executed exploits, replayed end to end through the real verb;
- the TOCTOU race, replayed as a test;
- each of the four BLOCKER-defence layers, individually deleted;
- the shipped constants (base, PATH, shebang), individually changed;
- each false-green fix, individually reverted.

## Running the loop

```sh
scripts/drill-loop/drivers/run-loop.sh \
  --mode sweep --iterations 20 \
  --operator-account agentmac \
  --agent-account sanctuary-agent --agent-uid 503
```

`--agent-account` must be on `RAILS_AGENT_ACCOUNT_ALLOW`, which ships empty. It
is a SELECTION from a compiled-in list, not a value the caller supplies: it
decides which principal a root-run `protect --exclusive-egress` acts against, so
it gets the same treatment the storage path, the CLI path and the host got.

Modes: `sweep N` (the default, maximum forward progress), `soak N` (green-path
focus, for flake-rate and determinism counts), `reboot K` (reboot survival).
`--stop-at-first-divergence` exists for interactive debugging and is never
scheduled; a nightly loop that stops at the first bug wastes the night.

### Maximum forward progress

An iteration never halts at the first bug. Each ladder step declares its
preconditions; on a failure the iteration skips only the steps whose
preconditions are now unmeetable (no probing *through* a gate that never armed)
and still attempts every independent one. Findings downstream of a failure are
labeled `tainted-by:<step>`, so morning triage can separate primary bugs from
cascade artifacts. Post-failure state has misled diagnosis for entire sessions
before; an untainted finding is a bug, a tainted one is a lead.

Two exceptions stop the night outright, and they are safety rails rather than
bug-hunting policy:

1. **A teardown or verify-clean failure.** Continuing past a dirty teardown
   risks wedging the host, and every later iteration would be born tainted.
2. **Any safety-rail trip.** There is no "recover and continue" past a rail.

Verify-clean means OBSERVED state, never a return code: the registry entry is
gone, the pf anchor is clear, the markers are gone, the locks are gone, and the
agent's uid can reach the network again. `--unprotect-egress-gate` exiting 0 is
a claim, not evidence.

And a check that COULD NOT observe is not a clean check. The reviewed version
read a refused `sudo -n pfctl` as CLEAN, because a refused sudo, a pf error and
a genuinely empty anchor were all one empty string, on a grant the README itself
said did not exist. Every observation now fails CLOSED when it cannot be made,
and names which one it was. That is the 2026-06-24 "claimed all drills dry"
failure, and the whole point of automating drills is that it must not be
automated too.

### Output

Per iteration: an evidence bundle (console, gate state, audit excerpts, timings)
plus one `FINDINGS.jsonl` line carrying pass/fail per probe, the first
divergence, artifact paths, and any taint label.

## Install (operator, one time, drill host only)

Not done by this repository, and deliberately so.

```sh
# 0. FIRST, on the drill host: measure it and put it on the allowlist.
#    Read-only. Installs nothing, changes nothing, contacts nothing.
scripts/drill-loop/host-fingerprint.sh
#    ...paste the fingerprint into RAILS_HOST_ALLOW_FP in lib/rails.sh, name
#    the machine in a comment, put the drill agent account in
#    RAILS_AGENT_ACCOUNT_ALLOW in the same diff, then:
scripts/drill-loop/build-wrapper.sh --write-hash
#    ...and get that diff re-reviewed. It is the entire host allowlist.

sudo scripts/drill-loop/install-wrapper.sh
sudo visudo -f /etc/sudoers.d/sanctuary-drill   # paste sudoers.d/sanctuary-drill
sudo visudo -c
cp scripts/drill-loop/ai.sanctuary.drill-loop.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.sanctuary.drill-loop.plist
```

Step 0 is not optional: with an empty allowlist the wrapper refuses everywhere,
which is deliberate. `install-wrapper.sh` runs the same host rail the wrapper
does, so it cannot be installed onto the daily driver (whose hardware is on the
denylist), and it verifies the installed hash after writing.

## Known open items before the first unattended night

Stated here rather than discovered at 3am:

- **The as-agent probes still need a second sudo grant.** The NOPASSWD grant
  covers only `/usr/local/sbin/sanctuary-drill-wrapper`. The pf-anchor read, the
  registry read, the in-fortress marker/lock read and the gate-log read all go
  through wrapper verbs now and need nothing extra, but the probe battery and
  the teardown check still run `sudo -n -u <agent> curl`, which the grant does
  not cover. When it is missing the probe battery asks ONCE up front, reports
  every probe as SKIP with the reason, and exits NONZERO with `verified=no`, so
  the loop records the step as UNVERIFIED and never as a pass; and
  `teardown-verify.sh` reports "could not RUN the as-agent probe" as UNOBSERVED,
  which stops the night. **Widening the sudoers line to
  `NOPASSWD: /usr/bin/curl` or `(ALL) NOPASSWD: ALL` is not an acceptable
  resolution** and `sudoers.d/sanctuary-drill` records why; the supported
  answers are a grant for exactly `sudo -u <agent-account> /usr/bin/curl`, or a
  wrapper verb.
- **No drill AGENT ACCOUNT is on the allowlist yet, so every verb that takes an
  agent principal refuses.** `RAILS_AGENT_ACCOUNT_ALLOW` ships empty for the
  same reason `RAILS_HOST_ALLOW_FP` does. `--agent-account` was the one
  caller-supplied input that steers what root does to whom: it was checked for
  shape and non-rootness and then handed to a root-run
  `protect --exclusive-egress`, so the grant holder could point that at any
  non-root local account. Provision it in the same reviewed diff as the host
  fingerprint.
- **None of the drivers has ever run against a live gate.** `run-loop.sh`,
  `preflight.sh`, `run-probe-battery.sh` and `arm-expect.exp` carry zero
  runtime evidence against a real Sanctuary gate. `teardown-verify.sh` is the
  exception and only partly: its verify-clean logic is now driven end to end by
  the battery against a stubbed `sudo`, which is what makes the pf fail-closed
  behavior a test rather than an argument. The rails are the part that is
  proven.
- **`N2` is not implemented and is no longer claimed.** The battery's header
  used to declare eight probes and implement six, while a green night asserted
  "every probe passed for the right reason". `N2` (request with no token
  denied) belongs to the gate's fail-closed client-auth mode; this drill runs
  the advisory peer mode, where an ordinary curl carries no
  proxy-authorization header and the question is not meaningful. `P3` (a second
  arm over a live confined agent is refused and the gate survives) WAS a real
  gap and is now implemented. The loop's finding string is the battery's own
  `PROBE=SUMMARY` line, naming what ran and what was skipped.
- **CLOSED (round 3): the drivers now READ inside the fortress, as root.**
  `tightenStoragePermissions` chmods the fortress to 0700 on every server start
  and the fortress is root-owned, so `preflight.sh`'s stale-marker and
  zero-byte-lock checks and `teardown-verify.sh`'s marker and lock checks could
  not be made by an unprivileged driver after the first arm. All four read
  absence as good, so reporting them PASS was a false green; refusing to
  conclude was the honest stopgap. The real fix -- a wrapper verb reading those
  paths as root -- is now built (`fortress-state`), alongside `registry-state`
  for the root-owned 0600 pf-anchor registry and `gate-log` for the gate service
  account's 0700 log directory. Every one of those checks is TRI-STATE:
  OBSERVED-CLEAN, OBSERVED-DIRTY, or COULD-NOT-OBSERVE, and the third is a hard
  failure that is never folded into either of the others.
- **CLOSED (round 4): `gate-log` has one privileged-read chokepoint.** The
  gate logs live outside the disposable fortress, and the first repair handled
  that with call-site lstat checks before handing the mutable path to `tail`.
  That was still a root read substitution primitive. The wrapper now composes
  the exact product gate account, resolves every log and registry read through
  the same helper, descends directories with physical-cwd checks, opens the
  final file once, verifies the fd identity, and reads from that fd.
- **CLOSED (round 4): probe reasons are causally bounded.** The battery takes
  wrapper-issued log cursors before P1, N1 and N3, then reads only bytes
  appended after the request boundary. N3 also requires the current wrong-uid
  request to be denied; a 2xx/3xx response is a loud FAIL even if a stale
  `peer_uid_mismatch` token exists elsewhere.
- **CLOSED (round 6): the probes now REACH the gate, and a verdict cannot
  outrun its observation.** Rounds 1 to 5 each fixed a list and the next round
  found a new instance of the same class: **every probe's verdict was computed
  from something other than the thing it claimed to have measured.** The
  clearest instance was the request itself. The gate is an `HTTPS_PROXY`
  CONNECT proxy on `127.0.0.1:<gate_port>`, the pf anchor passes exactly that
  loopback destination for the agent uid, and there is no `rdr` anywhere, so a
  bare `curl` never traverses the gate; the harness had no way to learn the
  port at all, yet printed `RESULT=PASS ... reachable through the gate`, and
  `N3` could never see the `peer_uid_mismatch` it exists to observe.

  Two things changed rather than seven:

  1. **A wrapper verb, `gate-port`,** reads the gate daemon's own published
     runtime state as root and reports the port + generation it bound. The
     battery proxies to that port for every through-gate probe, re-reads it
     after each request, and records the observation UNOBSERVABLE if the
     generation rotated across it. `P2` (per-uid differential) is DIRECT and
     `N3` (wrong uid) is THROUGH THE GATE, which is also what resolves their
     old mutual contradiction.
  2. **An observation ledger.** Every act of looking at the world appends a
     record naming the probe that made it, the mechanism it used, and whether
     it observed anything. `report` takes the observation ids as a REQUIRED
     argument and refuses a PASS or FAIL whose basis is empty, belongs to
     another probe, observed nothing, or whose TEXT names a mechanism the basis
     never exercised. A refused verdict becomes `UNOBSERVED`, is counted as a
     HARNESS DEFECT, and the battery exits 4. Every emitted line carries the
     derived `basis=`, `observed=` and `channels=` fields, so a reader never has
     to trust the prose. Consequences that fall out rather than being patched:
     `--repeats 0` cannot produce a pass, `N3` cannot read `N1`'s status code,
     and an absent gate-daemon log is COULD-NOT-OBSERVE rather than a
     gate-blamed FAIL (the four log streams are no longer interchangeable).
- **No drill host is on the allowlist yet, so the wrapper refuses everywhere.**
  `RAILS_HOST_ALLOW_FP` is empty: Mini1's and Mini2's hardware fingerprints
  have not been measured, because doing so means running
  `host-fingerprint.sh` ON those machines and this work did not reach them.
  This supersedes the older "Mini2's local short hostname is unconfirmed" item,
  which the machine audit made moot: the drill host answers `hostname -s` with
  the literal string `Mac`, so no name-based list was ever going to work.
  Refusing everywhere is the correct failure mode until step 0 of the install
  is done.
- **The path rail is still check-then-use, and that is now sound for a stated
  reason rather than an accepted risk.** The rail validates a path and hands
  the string on; what changed is that no component of that path is writable by
  an unprivileged caller, so there is nothing to change between the two
  moments. The previous version of this section said the exposure was "bounded
  by the fact that the directory is operator-owned and the loop runs as the
  operator (so it is a self-attack, not a privilege boundary), and closing it
  properly needs `openat`-style file-descriptor handoff, which bash cannot
  express." **Both halves of that were wrong**, and a reviewer proved it: it IS
  a privilege boundary, because winning the race made ROOT open a real
  fortress, and the fix needed ownership, not `openat`. If
  `RAILS_DISPOSABLE_BASE` is ever moved back under an operator-writable
  directory, that finding comes back with it.

## Disposable fortresses

The loop mints `/private/var/sanctuary-drill/<operator>/.sanctuary-loop-<id>`
per iteration and RETIRES it at the end of that iteration, through the wrapper's
`retire` verb, which `teardown-verify.sh` calls after every observation has been
made. Early aborts after `kickstart-daemons`, `mint`, or `preflight` also call
the same `retire` verb before advancing or stopping; a failed early retire is
recorded as a dirty stop. (Round 3 found that nothing removed them at all while
this sentence claimed a nightly teardown, so they would have accumulated as
root-owned directories one per iteration forever, and teardown-verify's
"the whole disposable fortress is gone" branch was unreachable dead code that
read as a covered case.) These carry no recovery obligation
and are covered by one standing row in `FORTRESS_KEYS.md` rather than a row per
night. The loop never runs `nuke`, `rotate-master` or `reset-passphrase` against
anything, and the rails make a non-disposable target unreachable rather than
merely discouraged.

**Operational cost of the root-owned base, stated plainly.** The disposable
fortress is no longer in the operator's home and is no longer operator-owned.
The wrapper creates it root-owned at 0755, so the operator can read and traverse
it and cannot write into it; the Sanctuary CLI runs as root under the wrapper,
so the state it writes was root's either way. Evidence bundles still live under
the operator's home and are unaffected.

**And one consequence that a reviewer should hold this PR to.** The product's
`tightenStoragePermissions` (`server/src/storage/permissions.ts`) chmods the
whole fortress to **0700 on every server start**. Combined with a root-owned
fortress, that means the unprivileged drivers lose read access to it from the
first arm onward. That matters because `preflight.sh` and `teardown-verify.sh`
draw conclusions from ABSENCE ("no stale marker", "no lock left behind"), and a
directory you are not allowed to look into is indistinguishable from an empty
one. So both drivers now refuse to draw an absence conclusion they could not
observe: the storage rail's own resolution post-condition stops the run hard
when the fortress cannot be traversed at all, and an explicit
`storage-observable` check covers the traversable-but-unreadable case. **Neither
one reports clean.**

Reading those paths through a wrapper verb was named here as the real fix and is
now built: `fortress-state`, `registry-state` and `gate-log` read the root-owned
surfaces as root, through the same `rails_assert_safe_subpath` chokepoint the
privileged verbs use, and the drivers classify what comes back into
OBSERVED-CLEAN / OBSERVED-DIRTY / COULD-NOT-OBSERVE. The last of those is a hard
failure and is never folded into either of the others, because "the host is
dirty" and "this harness is blind" are different mornings.
