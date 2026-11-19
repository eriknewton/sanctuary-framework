import { defineConfig } from "vitest/config";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const barrierModule = realpathSync(fileURLToPath(new URL("./src/storage/cross-process-lock.ts", import.meta.url)));
export const leaseGuardHookTimeoutMs = 10_000; // Preserve Vitest's default hook budget.

export default defineConfig({
  plugins: [{
    name: "test-master-write-lease-observer",
    enforce: "pre",
    transform(source, id) {
      if (id.split("?")[0] !== barrierModule) return;
      const declaration = "export async function acquireMasterWriteBarrier(";
      if (!source.includes(declaration)) throw new Error("Master-write lease acquisition chokepoint moved");
      const withoutDeclaration = source.replace(declaration, "");
      if (/\bacquireMasterWriteBarrier\s*\(/u.test(withoutDeclaration)) {
        throw new Error("Master-write lease acquisition has a same-module call");
      }
      // Observe the actual acquisition so partial mocks and module resets cannot bypass tracking.
      return source.replace(declaration, "async function acquireUnobservedMasterWriteBarrier(") + `
export async function acquireMasterWriteBarrier(...args: Parameters<typeof acquireUnobservedMasterWriteBarrier>) {
  const stack = new Error("Master-write lease acquired here").stack;
  const observe = globalThis[Symbol.for("sanctuary.test.master-write-lease-observer")];
  if (typeof observe !== "function") throw new Error("Master-write lease guard setup is missing");
  return observe(() => acquireUnobservedMasterWriteBarrier(...args), stack);
}
`;
    },
  }],
  test: {
    globals: true,
    hookTimeout: leaseGuardHookTimeoutMs,
    // Installs an in-memory credential store for every test so nothing ever
    // writes to the operator's real login keychain. See src/wrap/keychain-exec.ts.
    // Under a shared worker THREAD (the Stryker runner's `pool: 'threads',
    // maxWorkers: 1`) `os.homedir()` ignores a moved `process.env.HOME`, so the
    // per-test fortress redirection in test/helpers/temp-fortress.ts stops
    // isolating. The homedir-follows-env setup file makes `homedir()` follow the thread's
    // env, as it does in a process. See test/setup/homedir-follows-env.ts and
    // register row TEST-ISOLATION-SINGLE-WORKER-01.
    // git-env-scrub.ts stays FIRST: it clears the git redirect variables in scripts/git-redirect-env-keys.json
    // (GIT_DIR and friends that a git hook exports), so no test spawns git against the real repository
    // or config. Witness: test/structure/git-env-scrub.test.ts.
    setupFiles: ["./test/setup/git-env-scrub.ts", "./test/setup/keychain-fake.ts", "./test/setup/homedir-follows-env.ts", "./test/setup/master-write-leases.ts", "./test/setup/selector-roots-isolation.ts"],
    // aroundAll nesting: lease guard outermost, then selector setup, then the file's own hooks.
    // Teardown runs in reverse nesting order, after afterAll, beforeAll-returned cleanups and file-scoped fixtures.
    sequence: { setupFiles: "list", hooks: "stack" },
    // Leaves a marker directory at the package root for the whole run. setupFiles
    // covers this process and children inherit VITEST by default, but a child
    // spawned with `env: {}` has neither; the marker is what a scrubbed
    // environment cannot erase. See test/setup/test-run-marker.ts.
    // git-env-scrub.ts is FIRST here too: setupFiles run in workers only, so this entry clears the
    // main process (and the globalSetup modules after it). Witness: test/structure/git-env-scrub.test.ts.
    // The temp-root entry must match TEMP_ROOT_SETUP_ENTRY in test/structure/git-env-scrub.test.ts.
    // Vitest tears down in reverse order: temp cleanup follows marker teardown, so its errors cannot retain the marker.
    globalSetup: ["./test/setup/git-env-scrub.ts", "./test/setup/test-temp-roots.ts", "./test/setup/test-run-marker.ts", "./test/setup/selector-host-precondition.ts"],
    environment: "node",
    // No network egress from unit tests: the wrap-time pinned-version
    // resolvability probe (wrap/cli.ts) and the startup update check both
    // honor this documented zero-outbound knob. Tests that exercise the
    // probe itself either delete the var locally and point the probe at a
    // loopback server, or inject a stub via RunWrapDeps.
    env: { SANCTUARY_NO_UPDATE_CHECK: "1" },
    // CI's silent-test-file-drop detector (Gate 2b in
    // .github/workflows/test-baseline-guard.yml and .githooks/pre-commit, both
    // delegating to scripts/gate2b-check.sh) needs its "expected files" count
    // to track whatever this array (and test.exclude, dot, root, projects, or
    // any other resolution knob added here later) actually is at any given
    // moment. It gets that by asking vitest itself - `vitest list --filesOnly`
    // in server/scripts/count-vitest-test-files.mjs - rather than reading or
    // modeling this array, so there is nothing here to keep in sync and no
    // comment pin needed on this side for the RESOLUTION knobs: add a root, an
    // exclude, or an includeSource here and the detector follows automatically.
    // TWO SHAPES ARE THE EXCEPTION, and each refuses rather than miscounting.
    // OVERLAPPING projects (the same file resolved under more than one project,
    // which a real run executes more than once) refuse in the counter. And the
    // test INVOCATION itself is checked against a short allowlist of exact
    // strings in scripts/gate2b-check.sh, so anything other than the verified
    // invocation refuses there: not because those flags are all unsafe, but
    // because deciding safety by parsing that string was tried twice and
    // produced a parser that rejected a healthy flag while admitting an unsafe
    // one. The two refusals do NOT mean the same thing, and conflating them is
    // what would mislead the next reader: an overlapping project genuinely
    // changes what a run EXECUTES relative to what `vitest list` REPORTS, which
    // is the single assumption the detector rests on, while an unallowlisted
    // invocation refuses only because its safety is UNVERIFIED. A reporter flag
    // almost certainly changes nothing; it still refuses, because the allowlist
    // records what someone checked rather than what someone assumed. Adopting
    // either means updating scripts/gate2b-check.sh deliberately and
    // re-verifying scripts/gate2b-self-test.sh.
    // History: a hand-restated `find server/test` once missed the second root
    // below and let up to 14 dropped files pass undetected (2026-08-19); the
    // fix that followed re-modeled this array by hand instead of asking
    // vitest, which would have silently missed the NEXT config surface added
    // here too. See that script's header for the full account.
    include: ["test/**/*.test.ts", "../scripts/synthetic-coverage/test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/cli.ts"],
      // text -> human-readable summary in the terminal / CI log;
      // json-summary -> machine-readable totals for tooling;
      // lcov -> standard format for coverage viewers and uploaders.
      // No threshold is set here on purpose: coverage is a reported
      // signal, not yet a hard gate (a flaky threshold would block CI).
      reporter: ["text", "json-summary", "lcov"],
    },
    testTimeout: 30_000, // ZK proofs and crypto ops can be slow
  },
});
