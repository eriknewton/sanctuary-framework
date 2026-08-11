# BUILD_RESULT — LD5 BP-DEADLINE-01

## Finding

`withBridgeAdmissionDeadline` / `withReputationAdmissionDeadline` / sentinel's
`withDeadline` wrapped the admission `fn()` in the deadline race BEFORE it was
chained onto each store's per-instance admission lock (`admissionQueue`). The
raw promise the lock advanced on WAS the deadline race, not `fn()` itself, so
the lock released to the next admission the instant the timer fired — even
though the underlying `fn()` (the quota check plus `storage.write`) kept
running detached. A caller that repeatedly scheduled "scan passes, write
hangs past the deadline, enqueue another admission, release the delayed write
later" could make every successive admission's quota check observe stale
(pre-write) headroom indefinitely, landing arbitrarily many writes past the
per-origin cap once released — not the "exactly one extra write, never
unbounded growth" bound the pre-fix comments claimed.

## Option chosen: A (keep the admission slot held until `fn()` truly settles)

Applied uniformly to all three stores, per the finding's preferred option:

- `admissionQueue` (the per-instance promise chain / lock) is now fed the
  RAW `fn`, never the deadline-wrapped closure. The lock only advances once
  `fn()` itself settles (resolves or rejects) — including its `storage.write`.
- The settlement deadline is applied ONLY to the promise the outer
  `runAdmissionExclusiveBounded` (bridge, reputation) / `runAdmissionExclusive`
  (sentinel) method returns to its own caller. A timeout now changes only
  what that CALLER is told; it can never advance the lock on `fn()`'s behalf.
- Consequence (intentional, documented in the corrected comments): a `fn()`
  that never settles at all (genuinely hung, not merely slow) now blocks that
  store's admission queue for every later admission until it does. This is
  the correct trade — the alternative (releasing the lock early) is the exact
  bypass being closed. Each individual caller still fails closed on its own
  deadline and the store's `pendingAdmissionWaiters` cap, so a hung storage
  backend degrades to "no new admissions succeed," never to a quota
  overshoot.

Why option A over B/C: the existing promise-chain shape (`admissionQueue.then(fn, fn)`
already existed) made A a small, surgical change — move the deadline wrap from
"before chaining" to "after chaining, on the already-chained promise" — with
no new synchronization primitive, no re-verify-at-commit duplication (option
B), and no `AbortSignal` plumbing through `StorageBackend` (option C, which
would also require a wider interface change across every backend
implementation for no correctness gain over A).

## Files changed

- `server/src/bridge/tools.ts` — `BridgeStore.runAdmissionExclusiveBounded`:
  chain raw `fn` via `runAdmissionExclusive`, apply
  `withBridgeAdmissionDeadline` to the already-chained promise. Corrected the
  doc comments describing this method and the deadline constant (previously
  claimed a hung call "cannot retain this lock").
- `server/src/reputation/reputation-store.ts` — same shape for
  `ReputationStore.runAdmissionExclusiveBounded`. Rewrote the "ACCEPTED
  RESIDUAL... exactly one extra write... never unbounded growth" paragraph
  (was wrong under repeated scheduling) and the deadline-constant's opening
  doc.
- `server/src/sentinel/sentinel-finding-store.ts` — `runAdmissionExclusive`
  itself combined chaining and deadline-wrapping in one method (a slightly
  different shape than bridge/reputation): fixed by chaining raw `fn` for the
  `admissionQueue` advance and applying `withDeadline` to the resulting `run`
  on return, instead of wrapping `fn` inside the `.then()` callbacks. Same
  corrections to the "ACCEPTED RESIDUAL... exactly ONE extra write" paragraph
  and the `STORE_ADMISSION_DEADLINE_MS` doc.
- `server/test/security/ld5-bp-deadline-detached-write.test.ts` (new) — the
  adversarial fault-schedule tests (see below).
- `.test-baseline` (repo root — the instructions referenced `server/.test-baseline`,
  but the actual file the pre-commit hook and CI guard read lives at the repo
  root; there is no `server/.test-baseline`) — raised 13697 -> 13727.

All three stores were fixed. No store was left partially addressed.

## Tests

One new file, `server/test/security/ld5-bp-deadline-detached-write.test.ts`,
with one adversarial test per store (3 tests total, not a single shared
parametrized test — the three production APIs are different enough
(`bridge_commit` MCP tool handler vs `ReputationStore.record()` vs
`SentinelFindingStore.saveFinding()`) that a shared harness would have
obscured more than it saved):

- Each test wraps a `MemoryStorage` in a holdable proxy whose `write()` to
  the target namespace parks on a promise the test controls.
- Fires 5 waves (cap = 2) back-to-back without awaiting between them.
- Confirms only wave 0 reaches `storage.write` (asserts the queue depth stays
  at 1) even after TWO full `ADMISSION_DEADLINE_MS` advances — proving the
  lock is genuinely held, not released at the deadline.
- Drains the schedule (release → let the next wave run → release → ...) and
  asserts the store's real persisted count for the flooding origin never
  exceeds the cap.

**Mutation-proof verification performed**: stashed the three source fixes,
reran this test file — all 3 tests failed (the very first `pendingCount()`
assertion after the first deadline advance shows 2, not 1, confirming a
second wave's write raced ahead while the first was still detached). Restored
the fix; reran; all 3 pass. This confirms the tests actually catch the bug
this build closes, not just a rewritten-in-parallel duplicate of the fix
logic.

## Gate results (all in `server/`, foreground, from a clean tree)

1. `npm run typecheck` — clean (`tsc --noEmit` clean; tests/scripts
   diagnostics baseline unchanged at 987).
2. `npm run lint` — `eslint src/ --max-warnings 0` — zero warnings.
3. `npm test` (`vitest run`) — **953 test files passed (953)**,
   **13727 tests passed | 8 skipped (13735)**, 0 failed. Duration ~286s.

### Ambient flake encountered and resolved (not a regression)

The first full-suite run in this fresh worktree showed 12 failures, all in
`test/composition/composition-v1.test.ts`, all
`SidecarSpawnError: ... spawn /Users/.../sanctuary-ld5-bp-deadline/sidecars/concordia/.venv/bin/python ENOENT`.
This worktree's `sidecars/concordia/.venv` (gitignored, per-worktree Python
venv for the Concordia sidecar) simply did not exist yet — confirmed by
comparing against the main checkout, which has it. This is unrelated to this
build's diff (bridge/reputation/sentinel admission-lock stores; composition
uses a completely separate subsystem). Rebuilt the venv per
`sidecars/concordia/README.md`'s documented, hash-pinned procedure
(`python3.12 -m venv ... && pip install --require-hashes -r requirements.txt`),
reran `test/composition/composition-v1.test.ts` in isolation — 56/56 passed —
then reran the full suite, which came back fully green as reported above.

A second full-suite attempt separately hit a 10-minute wall-clock timeout
under heavy host load (`uptime` showed load average 14-22) with no test
failures logged before the cutoff; a third attempt completed cleanly in
~286s. Treated as transient host-load contention, not a code or test defect.

## Baseline

`.test-baseline` (repo root): **13697 -> 13727** (net-new: **+30** passing
tests — the pre-commit hook's own baseline-guard gate independently computed
and confirmed this exact delta when the commit ran, before I had it print
its own number).

## Residual / DEBT (honestly disclosed, not silently accepted)

- **A genuinely-hung (never-settling) `fn()` now blocks that store's whole
  admission queue indefinitely**, not just the calling admission. This is
  the deliberate trade the fix makes (see "Option chosen" above) — each
  individual caller still fails closed on its own deadline, so the
  user-visible effect is "no new admissions succeed against this store,"
  never a quota overshoot. Not a new capability-claim gap: the finding's own
  scope is bounded storage LATENCY past the deadline with eventual release,
  not literal infinite hangs, and a literally-hung storage backend is a
  separate, pre-existing availability concern outside this fix's scope.
- Cross-process concurrency (two separate server processes racing the same
  store) remains the pre-existing, separately-tracked accepted DEBT noted in
  each store's own doc (unchanged by this fix — this fix is about one
  process's own admission lock).
- No other stores in the codebase share this exact
  deadline-wraps-before-chaining shape as far as this build searched
  (`core/bounded-map.ts`'s `onEvict` timeout was checked and has a different
  shape — the timeout there bounds an audit call INSIDE the already-held
  lock and the enclosing `admitNewKey` explicitly returns/refuses on timeout
  rather than letting the lock advance past a still-running write; it was
  judged out of this finding's three-store scope and left untouched).
