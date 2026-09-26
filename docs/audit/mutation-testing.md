# Mutation testing

**Status:** scoped baseline only (decision A164, default D4, 2026-09-26). No CI job runs mutation testing yet; both tools below are operator-run. This doc explains how to run each tool, how to read its score, and the rule for using a score to justify removing a test. **The 2026-09-26 baseline did not produce a score; see Known limitation below before running this.**

## Known limitation (2026-09-26): the TypeScript baseline does not yet complete

The Stryker vitest runner executes every test file on a single worker so that a kill can be attributed to one mutant. Part of this suite's test isolation is only established under vitest's default multi-worker scheduling, so the initial dry run stops before any mutant is judged whenever the mutated modules' related tests include one of those files. This is a test-suite property, not a product defect, and it is tracked in the private register as `TEST-ISOLATION-SINGLE-WORKER-01`. Until that row closes, `npm run test:mutation` produces no score for any scope whose related tests reach the affected files; the tooling below is wired and proceeds normally once the dry run passes.


## Why mutation testing, and why scoped

A passing test suite and a coverage percentage both answer "did some test execute this line," never "would a test fail if this line were wrong." Mutation testing answers the second question: a tool changes one line of source at a time (flips a comparison, off-by-ones a bound, swaps a boolean) and reruns the tests that touch that line. A mutant that "survives" (no test failed) marks a line no test actually pins down, whatever the coverage report says.

The TypeScript server (`server/src`) is large, and a full-tree mutation run is a much longer investment than this pass makes. The scoped baseline below picks three representative modules (`server/src/core/encoding.ts`, `server/src/core/random.ts`, `server/src/storage/memory.ts`) to answer "does this tool tell us anything useful here" before committing to a wider run. Widening the `mutate` list in `server/stryker.config.mjs` is the natural next step; this doc and config are the harness for that, not the final scope.

## Running the TypeScript (Stryker) baseline

```
cd server
npm run test:mutation
```

This runs Stryker (`@stryker-mutator/core`) with the vitest runner against `server/stryker.config.mjs`. Key settings and why they matter:

- `coverageAnalysis: "perTest"` asks vitest which test files import each mutated file, so a mutant reruns only those files instead of the whole suite. Without this, mutation testing on even three modules would cost one full-suite run per mutant, which does not finish in any bounded window.
- `concurrency: 4` bounds parallel test-runner workers. Raise it on a CI runner with more cores once this graduates past a scoped baseline; a laptop-class box thrashes above this.
- `mutate` is an explicit whitelist of the three scoped files, not a glob over `src/**`. Widen it deliberately, one directory at a time, so a first full run is diagnosable rather than an opaque multi-hour job.
- Reports land in `server/reports/mutation/` (HTML and JSON); Stryker's own working state is `server/.stryker-tmp/`. Both are gitignored; a report is a point-in-time artifact, not something to check in.

A run can be capped with `timeout <seconds> npm run test:mutation` for a bounded evaluation window (the 2026-09-26 baseline used `timeout 2700`, 45 minutes). If the cap is hit mid-run, Stryker's incremental log (`server/.stryker-tmp/incremental.json`) still holds every mutant judged before the cutoff; report the judged count and per-mutant elapsed time, not a score, since an interrupted run is not a completed baseline.

## Reading a mutation score

Stryker reports a percentage: `killed / (killed + survived + timeout)`, ignoring mutants it could not test. A **killed** mutant means some test failed when the tool inserted a specific bug, which is the outcome you want. A **survived** mutant means every test still passed with that bug present, so no test in the suite would catch that specific mistake. A **timeout** counts as killed for scoring purposes but usually means the mutant introduced an infinite loop or a hang, not that a test asserted the right thing; treat a large timeout count as a signal to look at the mutated code, not as free credit.

A survived mutant is not automatically a defect to fix. Some survive because the mutated behavior is genuinely unobservable from the test's vantage point (dead code, a log-only branch, a constant that has no behavioral effect at the boundary tested). Others survive because a real gap exists: a boundary condition, an error path, or a return value nothing asserts on. Read each surviving mutant's diff before deciding which case it is.

## Test-pruning rule

**A test may be removed only when the mutation score on every module it imports is unchanged after the removal.** This is a manual check, not a mechanical gate. In practice: run the scoped baseline before removing a test, remove it, rerun the baseline over the same `mutate` list, and confirm no mutant that a test previously killed now survives. If the score on any imported module drops, the test was pinning something the remaining suite does not; keep it or replace it with a narrower assertion that restores the kill.

This rule exists because "this test looks redundant" and "this test is unnecessary" are different claims, and only a mutation-score comparison distinguishes them; visual redundancy (two tests that call the same function) says nothing about whether they kill the same mutants.

## Security-pin tests are never pruned

The pruning rule above governs which TESTS may be removed. It does not apply at all to the security regression pins: `test/security/**`, `test/structure/**`, `test/wrap/**`, `test/exit/**`, `test/core/**`, `test/disclosure/**`, `test/recovery/**`, and any file named `sec-0NN` or covering custody. Those files pin the must-never rules and drill-backed claims in `AGENTS.md`; removing one needs the underlying drill evidence re-established, not a mutation-score comparison. Source under mutation is the opposite case: enforcement and crypto modules are exactly where a surviving mutant is most valuable, so they are never excluded from a `mutate` list to protect a score.


## Rust (cargo-mutants) for castle-wall-daemon

`cargo-mutants` is not installed by this change; it is a heavier, security-sensitive install (it recompiles the crate under mutation and can execute mutated enforcement code paths) and is left as an explicit operator step rather than a project devDependency:

```
cargo install cargo-mutants
cd castle-wall-daemon
cargo mutants
```

The config `castle-wall-daemon/.cargo/mutants.toml` (read automatically from the crate root) excludes only the `tests/` directory from mutation and sets a minimum per-mutant timeout. Enforcement-path modules are mutated like any other source: a surviving mutant there is a finding, and the drill records in `docs/audit/` prove the shipped behavior on a host, which is a different question from whether the unit tests would catch a one-line mistake.

No CI job runs `cargo mutants` in this PR. It has not been run yet in this repo; run it locally per the steps above and record results in a dated `docs/audit/` file the same way other drills are recorded, rather than adding a mutation score claim here without evidence.
