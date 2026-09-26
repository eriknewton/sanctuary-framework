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

- Two settings bound the work per mutant, and they are different things. `vitest.related: true` (the runner's default, set explicitly in the config) limits each mutant's run to the test files whose import graph reaches the mutated file. `coverageAnalysis: "perTest"` then reruns only the tests whose recorded coverage actually executed the mutated line. Without either, a mutant would rerun everything the runner selects; without `related`, that selection would be the whole suite.
- `dryRunTimeoutMinutes: 30` bounds Stryker's initial unmutated run. The default is 5 minutes, and the related-test population for widely imported core modules on one vitest worker can exceed that; a dry-run abort produces no incremental file and no score, so this is the cap that decides whether a run starts at all.
- `concurrency: 4` bounds parallel test-runner workers. Raise it on a CI runner with more cores once this graduates past a scoped baseline; a laptop-class box thrashes above this.
- `mutate` is an explicit whitelist of the three scoped files, not a glob over `src/**`. Widen it deliberately, one directory at a time, so a first full run is diagnosable rather than an opaque multi-hour job.
- Reports land in `server/reports/mutation/` (HTML and JSON); Stryker's own working state is `server/.stryker-tmp/`. Both are gitignored; a report is a point-in-time artifact, not something to check in.

A run can be wrapped in `timeout <seconds> npm run test:mutation` for a bounded evaluation window (the 2026-09-26 baseline used `timeout 2700`, 45 minutes). That outer cap only matters once mutants are being judged: Stryker writes `server/.stryker-tmp/incremental.json` from mutant results (including on SIGTERM, when at least one mutant was judged), so an interrupted mutant phase leaves a judged count and per-mutant elapsed time to report. An abort during the dry run leaves nothing; the dry-run cap above is the one that governs that phase. Report counts, never a score, for any interrupted run.

## Reading a mutation score

Stryker reports two percentages. The headline mutation score is `(killed + timeout) / (killed + timeout + survived + noCoverage)`; the score on covered code drops `noCoverage` from the denominator. Mutants with a runtime or compile error are excluded from both. A **killed** mutant means some test failed when the tool inserted a specific bug, which is the outcome you want. A **survived** mutant means every test still passed with that bug present, so no test in the suite would catch that specific mistake. A **noCoverage** mutant sits on a line no selected test executed. A **timeout** is counted as detected in both formulas, but it usually means the mutant introduced a hang, not that a test asserted the right thing; for the pruning rule below a timeout is never treated as a kill.

A survived mutant is not automatically a defect to fix. Some survive because the mutated behavior is genuinely unobservable from the test's vantage point (dead code, a log-only branch, a constant that has no behavioral effect at the boundary tested). Others survive because a real gap exists: a boundary condition, an error path, or a return value nothing asserts on. Read each surviving mutant's diff before deciding which case it is.

## Test-pruning rule

**A test may be removed only when the set of killed mutants is unchanged after the removal, on every source module the test's import graph reaches.** A percentage is not the criterion, because a percentage can stay flat while the set moves. In practice: set the `mutate` list to every source module the candidate test imports, directly or transitively (`vitest related` in reverse: list the test's imports, then their imports, until no new `src/` file appears); run the baseline and keep the JSON report; remove the test; rerun over the same list; then compare the per-mutant status in the two JSON reports. Any mutant whose status moves from `Killed` to `Survived`, `Timeout` or `NoCoverage` means the test was pinning something the remaining suite does not: keep it, or replace it with a narrower assertion that restores the kill. A test that reaches a module outside the scope you are willing to mutate is not a pruning candidate. This is a manual procedure, not a mechanical gate; until a CI job runs it, a deletion PR cites the two report files in its record.

This rule exists because "this test looks redundant" and "this test is unnecessary" are different claims, and only a mutation-score comparison distinguishes them; visual redundancy (two tests that call the same function) says nothing about whether they kill the same mutants.

## Security-pin tests are never pruned

The pruning rule above governs which TESTS may be removed. It does not apply at all to the regression pins that back the must-never rules, the assurance matrix and the drill records. Under `server/test/`: `security`, `structure`, `wrap`, `exit`, `core`, `disclosure`, `recovery`, `castle-wall`, `egress-gate`, `policy-engine`, `principal-policy`, `privacy-enforcement`, `honeypot`, `fortress`, `drills`, `sentinel`, `keychain-linux-secret-service.test.ts`, `identity-signing-helpers.test.ts`, and the `release-*.test.ts` and `sign-release-manifest.test.ts` files. All of `castle-wall-daemon/tests/`. Any test whose name or describe block names custody, a passphrase, a signature, an approval tier, or an egress decision. Those files pin the must-never rules and drill-backed claims in `AGENTS.md`; removing one needs the underlying drill evidence re-established, not a mutation-score comparison. Source under mutation is the opposite case: enforcement and crypto modules are exactly where a surviving mutant is most valuable, so they are never excluded from a `mutate` list to protect a score.


## Rust (cargo-mutants) for castle-wall-daemon

`cargo-mutants` is not installed by this change; it is a heavier, security-sensitive install (it recompiles the crate under mutation and can execute mutated enforcement code paths) and is left as an explicit operator step rather than a project devDependency:

```
cargo install cargo-mutants
cd castle-wall-daemon
cargo mutants
```

The config `castle-wall-daemon/.cargo/mutants.toml` (read automatically from the crate root) excludes only the `tests/` directory from mutation and sets a minimum per-mutant timeout. Enforcement-path modules are mutated like any other source: a surviving mutant there is a finding, and the drill records in `docs/audit/` prove the shipped behavior on a host, which is a different question from whether the unit tests would catch a one-line mistake.

`cargo mutants` writes `mutants.out/` (and rotates the previous run to `mutants.out.old/`) inside the crate; both hold mutated enforcement source, test logs and a lock file naming the user and host, and both are gitignored. No CI job runs `cargo mutants` in this PR. It has not been run yet in this repo; run it locally per the steps above and record results in a dated `docs/audit/` file the same way other drills are recorded, rather than adding a mutation score claim here without evidence.
