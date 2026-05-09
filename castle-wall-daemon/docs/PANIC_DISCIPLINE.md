# Panic-discipline framework

## What this is

Castle Layer 1 enforcement is the load-bearing security promise of the Castle
Architecture. The daemon must remain available under stress: a single
`unreachable!()` or unannotated `.unwrap()` in production code is a process
crash, and a process crash is an enforcement gap. This document defines the
panic-discipline framework: every `.unwrap()` or `.expect(...)` call in
non-test Rust source files inside `castle-wall-daemon/src/` must carry an
immediately preceding `// Safety:` comment naming the local invariant that
protects it. Test code is exempt: `unwrap`/`expect` are idiomatic in tests,
and converting a panicking test into a `Result`-propagating test makes
failures less informative without changing what is being tested.

The framework is enforced by `scripts/check-panic-discipline.py`, which the
Castle Wall Linux CI workflow runs on every PR and every push to `main`.

## Classification framework

For every production-code `.unwrap()` or `.expect(...)` call site, classify
it into one of three categories before merging:

### Category A. Safe invariant

The Option is `Some` or the Result is `Ok` because of a local invariant
established earlier in the same function or module. The panic is a bug-trap
that fires only if the invariant is broken (i.e., the program is corrupted in
memory or the standard library contract has changed). Add a `// Safety:`
comment naming the invariant. The annotation is the audit trail: the next
reader sees, in plain English, why the panic cannot fire under normal
operation.

Example shape (`castle-wall-daemon/src/manifest/store.rs:201`):

```rust
self.current = Some(next);
self.current_snapshot = Some(snapshot);
// Safety: `self.current = Some(next)` two lines above sets the option;
// there is no intervening mutation point on this single-threaded path,
// so the option is guaranteed to be Some at the read below.
Ok(self.current.as_ref().expect("current set above"))
```

### Category B. Needs `?`-operator propagation

The Option-or-Result can actually fail at runtime, but the function already
returns a `Result` (or could be promoted to one). Convert to `?`-operator
propagation. If the caller's error type does not yet accept the propagated
error, add a `From` impl. Add a regression test that triggers the failure
mode and confirms graceful error return rather than a panic.

### Category C. Needs explicit error variant

The Option-or-Result can fail at runtime, the function does not return a
`Result`, and the caller needs structured information about the failure (not
just an opaque error chain). Introduce a new variant on the relevant error
enum, convert the call site to return that variant, update callers to handle
it, and add regression tests.

## The Safety annotation contract

Format requirements:

* The comment block must begin with a line whose stripped form starts with
  `// Safety:` (capital S, colon, exact spelling). Doc comments (`///`,
  `//!`) are not honored.
* The comment block may be one line or many; the gate looks for the
  `Safety:` token within 20 lines of the call site, stopping at any blank
  line or any earlier unwrap/expect call.
* The annotation must name the invariant in plain English. References to
  earlier code lines are encouraged: "two lines above," "the if-block above,"
  "constructed by `<fn>` and not mutated since."

The gate is intentionally permissive about formatting (any `// Safety:` line
within the lookback window passes) so that PRs do not bikeshed on whitespace.
The substantive review work is the invariant proof, not the comment shape.

## Running the gate locally

```bash
# Pass / fail check
python3 castle-wall-daemon/scripts/check-panic-discipline.py

# Self-tests for the gate logic itself
python3 castle-wall-daemon/scripts/test_check_panic_discipline.py
```

Pass output:

```
Castle Wall daemon panic-discipline gate PASS: 5 annotated production-code site(s), 0 unannotated.
```

Fail output lists each unannotated site with file path, line number, and the
offending source line.

## What the gate does NOT do

* It does not parse Rust. It uses line-oriented heuristics that strip
  contents of double-quoted strings and `//` line comments before counting
  braces and matching call sites. Raw string literals (`r"..."`) and
  character literals (`'{'`, `'}'`) are not parsed; both are vanishingly
  rare in this daemon and not present anywhere today. If they appear later,
  the gate may need a true Rust parser (`syn`). This is a coordinator-level
  scope decision, not a build-time fix.
* It does not enforce Categories B or C. If a panic at runtime is the wrong
  semantic and a `Safety:` annotation papers over the design defect, only
  human review catches it. The gate is a structural floor, not a ceiling.
* It does not run on `castle-wall-daemon/tests/` (Cargo integration test
  crate by convention) or on inline `#[cfg(test)] mod` blocks.

## How this closes full-sweep #58

PR #138 (merge `71c4580`) classified the 5 production-code `unwrap`/`expect`
sites in `castle-wall-daemon/src/` and annotated each with a `// Safety:`
comment. The original full-sweep "219 sites" figure was inflated by inline
`#[cfg(test)] mod` blocks; production code in `src/` had only 5 real sites.
This gate is the structural floor that prevents future commits from
re-introducing unannotated production-code sites. Together, PR #138 and the
gate close finding #58.

## How this fits the Castle Architecture

Castle Layer 1 is the OS-level egress filter: netfilter rules, NFQUEUE
verdicts, cgroup binding, the kernel-side enforcement that even prompt-
injected agents cannot bypass. The daemon implements that layer in
userspace. Every panic is a crash; every crash is a window of zero
enforcement. Panic discipline preserves Castle Layer 1 availability under
stress without changing the enforcement contract.

This document is canonical for the framework. Future scope expansions
(extending the gate to other Rust crates, wiring it as a clippy lint,
adding a `cargo xtask` runner) are coordinator-level decisions and ship as
follow-on PRs, not as scope creep on this file.
