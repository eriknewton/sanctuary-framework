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

This harness escalates to root under a NOPASSWD sudoers grant. Its first version
was reviewed UNSOUND: a REJECTED `--storage` path armed the operator's real
`~/.sanctuary` fortress as root, because the rail's rejection happened inside a
command substitution and killed only a subshell. The parent continued with an
empty storage value, and an empty `SANCTUARY_STORAGE_PATH` resolves to the real
default fortress.

So the ordering here is deliberate. `lib/rails.sh` came first, its battery came
second, and the loop was built on top only once the battery was green. A harness
that runs beautifully but can be talked into touching a real fortress is worth
negative value.

### What it refuses

| Refusal | Enforced by |
| --- | --- |
| Any storage path outside `~/.sanctuary-loop-<stamp>` | `rails_assert_disposable_storage` allowlist |
| Any known fortress path, checked before the allowlist | denylist, lexical and resolved |
| An empty storage path, at two independent layers | the rail, and the wrapper's required-argument guard |
| A `.sanctuary-loop-*` that is a symlink | `[ -L ]` lstat, plus parent-chain resolution |
| Any host but a compiled-in drill host | `rails_assert_host_allowed`, deny-first, fail closed |
| The operator's daily-driver MacBook, unconditionally | denylist checked before the allowlist, no override exists |
| `--operator-account root`, by name and by uid | `rails_assert_non_root_account` |
| A group- or world-accessible passphrase file | `rails_assert_secret_file_perms`, masked against 022 and 077 |
| Interleaving a scheduled run with an interactive drill | `rails_lock_acquire`, atomic single-winner reclaim |
| Running a wrapper that does not match its reviewed hash | `rails_assert_wrapper_integrity` |

There is no environment variable, flag, or argument anywhere in this harness
that can add a host or widen the storage allowlist. The sudoers grant carries no
`env_keep`, so sudo's `env_reset` strips anything a caller might try to smuggle
in, and the privileged path always uses its compiled-in lists. A test asserts
that the assembled artifact contains no such override outside a comment.

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
  ai.sanctuary.drill-loop.plist nightly launchd job (DOCUMENTED, NOT LOADED)
  drivers/
    run-loop.sh                 the loop: sweep N | soak N | reboot K
    preflight.sh                every historical defect layer as a permanent check
    run-probe-battery.sh        the pre-declared probe ladder
    teardown-verify.sh          teardown plus OBSERVED-state verification
  expect/arm-expect.exp         answers the arm confirmation over a pty
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
scripts/drill-loop/selftest.sh          # standalone, on any machine, ~2 seconds
cd server && npx vitest run test/drill-loop/rails.test.ts
```

Both run the same cases. The standalone copy exists because the machine that
actually matters is the drill host, and the drill host does not run the
TypeScript suite. Run it there before any nightly loop and after any wrapper
reinstall.

Every rejection case asserts three things: a nonzero exit, no ACCEPT token in
the output, and the expected REASON. The reason half matters as much as the
others. A deny for the wrong reason is a failure, not a pass, and that is not
pedantry: the 2026-07-24 drill's negative probes all "passed" while the gate was
strangling every request for an unrelated cause, which hid a live defect for a
full day.

The happy path is asserted too. A rail that rejects everything is not sound, it
is broken, and it would sail through a suite that only checks rejections.

## Running the loop

```sh
scripts/drill-loop/drivers/run-loop.sh \
  --mode sweep --iterations 20 \
  --operator-account agentmac \
  --agent-account sanctuary-agent --agent-uid 503
```

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

### Output

Per iteration: an evidence bundle (console, gate state, audit excerpts, timings)
plus one `FINDINGS.jsonl` line carrying pass/fail per probe, the first
divergence, artifact paths, and any taint label.

## Install (operator, one time, drill host only)

Not done by this repository, and deliberately so.

```sh
sudo scripts/drill-loop/install-wrapper.sh
sudo visudo -f /etc/sudoers.d/sanctuary-drill   # paste sudoers.d/sanctuary-drill
sudo visudo -c
cp scripts/drill-loop/ai.sanctuary.drill-loop.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.sanctuary.drill-loop.plist
```

`install-wrapper.sh` runs the same host rail the wrapper does, so it cannot be
installed onto the daily driver, and it verifies the installed hash after
writing.

## Disposable fortresses

The loop mints `~/.sanctuary-loop-<stamp>-<n>` per iteration and tears it down
each night. These carry no recovery obligation and are covered by one standing
row in `FORTRESS_KEYS.md` rather than a row per night. The loop never runs
`nuke`, `rotate-master` or `reset-passphrase` against anything, and the rails
make a non-disposable target unreachable rather than merely discouraged.
