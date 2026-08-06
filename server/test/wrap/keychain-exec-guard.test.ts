/**
 * The chokepoint that keeps tests off the operator's real login keychain.
 *
 * Regression origin (2026-08-04): the suite wrote ~61 entries per run into the
 * developer's real login keychain. Accumulation slowed keychain-dependent
 * tests; under vitest's parallel workers they hit the serialized keychain
 * daemon at once and tripped their timeouts, and the timed-out workers SURVIVED
 * the run and poisoned later ones. A suite that ran in 228s later failed to
 * finish inside 30 minutes with zero code change.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  decideKeychainExecution,
  execKeychain,
  setKeychainExec,
  type KeychainExec,
} from "../../src/wrap/keychain-exec.js";
import {
  getOrCreateKeychainCustodyKey,
  readKeychainCustodyKey,
} from "../../src/wrap/keychain-custody.js";
import { installInMemoryKeychainStore } from "../setup/keychain-fake.js";

const memoryStore = new Map<string, string>();
const memoryFake: KeychainExec = async (cmd, args, input) => {
  if (cmd === "security" && args[0] === "-i") {
    const m = /-s "([^"]+)" -w "([^"]*)"/.exec(input ?? "");
    if (m) memoryStore.set(m[1]!, m[2]!);
    return { stdout: "", stderr: "", code: 0 };
  }
  if (cmd === "security" && args[0] === "find-generic-password") {
    const i = args.indexOf("-s");
    const secret = i >= 0 ? memoryStore.get(args[i + 1]!) : undefined;
    return secret === undefined
      ? { stdout: "", stderr: "not found", code: 44 }
      : { stdout: `${secret}\n`, stderr: "", code: 0 };
  }
  return { stdout: "", stderr: "unsupported", code: 1 };
};

afterEach(() => {
  memoryStore.clear();
  installInMemoryKeychainStore();
});

describe("the credential CLI is UNREACHABLE from the suite", () => {
  /**
   * The decision is a pure function of two inputs, which is what makes the
   * property checkable rather than assertable. These cases used to work by
   * calling `setKeychainExec(null)` to drop the store and observe the refusal.
   * That capability is gone: `setKeychainExec` no longer accepts null and there
   * is no reset, so nothing in the suite can restore the spawn path. The truth
   * table below is how the refusal is verified now.
   */

  it("never yields spawn-real while under test, for ANY store state", () => {
    // The whole security property, as one assertion over the entire input space.
    for (const hasStore of [true, false]) {
      expect(decideKeychainExecution(hasStore, true)).not.toBe("spawn-real");
    }
  });

  it("refuses under test when no store is installed", () => {
    expect(decideKeychainExecution(false, true)).toBe("refuse-under-test");
  });

  it("uses the installed store under test", () => {
    expect(decideKeychainExecution(true, true)).toBe("installed-store");
  });

  it("spawns for real ONLY outside the test suite with no store installed", () => {
    // This is the branch scripts/real-backend-check.ts runs on: a plain node
    // process, where spawning the credential CLI is ordinary behavior.
    expect(decideKeychainExecution(false, false)).toBe("spawn-real");
  });

  it("prefers an injected store even outside tests, so production wiring is honored", () => {
    expect(decideKeychainExecution(true, false)).toBe("installed-store");
  });

  it("offers no way to un-set the store: setKeychainExec rejects null at the type level", () => {
    // A type-level guarantee is only worth something if something checks it, and
    // `npm run typecheck` is that something. This case pins the runtime half:
    // there is no reset export to reach for.
    const surface = readFileSync(
      fileURLToPath(new URL("../../src/wrap/keychain-exec.ts", import.meta.url)),
      "utf8"
    );
    expect(surface).not.toMatch(/export function resetKeychainExec/);
    expect(surface).toMatch(/export function setKeychainExec\(fn: KeychainExec\): void/);
  });

  it("routes through an installed store instead of spawning anything", async () => {
    setKeychainExec(memoryFake);
    const r = await execKeychain("security", ["-i"], 'add-generic-password -U -a "sanctuary" -s "svc-a" -w "sekret"\n');
    expect(r.code).toBe(0);
    const back = await execKeychain("security", ["find-generic-password", "-a", "sanctuary", "-s", "svc-a", "-w"]);
    expect(back.stdout.trim()).toBe("sekret");
  });
});

describe("the default in-memory store serves a real custody round-trip", () => {
  it("creates and reads back a custody key with NO exec injected and NO OS keyring touched", async () => {
    // The point of this case: it injects nothing. Before the fix, this exact
    // default path is what silently wrote into the operator's login keychain.
    // Now the global setup's in-memory store serves it, so the round-trip works
    // and nothing leaves the process.
    const created = await getOrCreateKeychainCustodyKey(
      "/tmp/sanctuary-keychain-exec-test",
      { home: "/tmp/sanctuary-keychain-exec-home", platformOverride: "darwin" }
    );
    expect(created).not.toBeNull();

    const readBack = await readKeychainCustodyKey(
      "/tmp/sanctuary-keychain-exec-test",
      { home: "/tmp/sanctuary-keychain-exec-home", platformOverride: "darwin" }
    );
    expect(readBack).not.toBeNull();
    expect(Array.from(readBack!)).toEqual(Array.from(created!));
  });
});

describe("the in-memory fake refuses what the real tool refuses", () => {
  /**
   * A test double that is MORE permissive than the tool it replaces teaches
   * tests a behavior production does not have. The specific shape that matters
   * here is the one this whole change exists to kill: answering "unlocked" for a
   * keychain the fake knows nothing about would make a dead or stale broker
   * keychain read as alive, and the suite would keep passing while proving
   * nothing. A refusal is an acceptable answer; a false success is not.
   */
  const PASSPHRASE = "fake-kc-passphrase";
  let dir: string;

  beforeEach(() => {
    installInMemoryKeychainStore();
    dir = mkdtempSync(join(tmpdir(), "sanctuary-fake-kc-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  async function createKeychain(path: string) {
    return execKeychain("/usr/bin/security", ["-i"], `create-keychain -p "${PASSPHRASE}" "${path}"\n`);
  }
  async function unlockKeychain(path: string, passphrase: string) {
    return execKeychain("/usr/bin/security", ["-i"], `unlock-keychain -p "${passphrase}" "${path}"\n`);
  }

  it("unlocks a keychain it created, with the right passphrase", async () => {
    const path = join(dir, "created.keychain-db");
    expect((await createKeychain(path)).code).toBe(0);
    expect((await unlockKeychain(path, PASSPHRASE)).code).toBe(0);
  });

  it("rejects the WRONG passphrase instead of waving it through", async () => {
    const path = join(dir, "created.keychain-db");
    await createKeychain(path);
    const result = await unlockKeychain(path, "not-the-passphrase");
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/passphrase you entered is not correct/);
  });

  it("REFUSES to unlock a file it did not create, rather than reporting success", async () => {
    // The regression this pins: an ordinary file that merely EXISTS used to
    // satisfy the unlock path, so a stale keychain looked unlocked.
    const path = join(dir, "not-a-keychain.keychain-db");
    writeFileSync(path, "this is not a keychain");
    const result = await unlockKeychain(path, PASSPHRASE);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/did not create/);
  });

  it("reports a missing keychain as not-found, distinct from refusing a foreign one", async () => {
    const result = await unlockKeychain(join(dir, "absent.keychain-db"), PASSPHRASE);
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/could not be found/);
  });

  it("REFUSES to dump a keychain it did not create, rather than reporting it empty", async () => {
    // An empty dump is the same lie in a different costume: "this keychain holds
    // no secrets" is a positive claim the fake cannot make about a foreign file.
    const path = join(dir, "foreign.keychain-db");
    writeFileSync(path, "");
    const result = await execKeychain("/usr/bin/security", ["dump-keychain", path]);
    expect(result.code).not.toBe(0);
    expect(result.stdout).toBe("");
  });

  it("REFUSES every NAMED-keychain verb for a file it did not create", async () => {
    // The gate found this class three times: unlock, then dump, then the
    // generic-password verbs. The refusal is now one check at the dispatch
    // point, so this case sweeps the whole verb surface rather than the two
    // that happened to be reported.
    const path = join(dir, "foreign.keychain-db");
    writeFileSync(path, "");
    const named: Array<[string, string[], string | undefined]> = [
      ["find-generic-password", ["find-generic-password", "-s", "svc", "-a", "acct", "-w", path], undefined],
      ["delete-generic-password", ["delete-generic-password", "-s", "svc", "-a", "acct", path], undefined],
      ["dump-keychain", ["dump-keychain", path], undefined],
      ["add-generic-password", ["-i"], `add-generic-password -s "svc" -a "acct" -w "v" "${path}"\n`],
      ["unlock-keychain", ["-i"], `unlock-keychain -p "${PASSPHRASE}" "${path}"\n`],
    ];
    for (const [label, args, input] of named) {
      const result = await execKeychain("/usr/bin/security", args, input);
      expect(result.code, `${label} must refuse a foreign keychain`).not.toBe(0);
      expect(result.stderr, `${label} must say why`).toMatch(/did not create/);
    }
  });

  it("still serves the DEFAULT keychain, which names no file and is the fake's own", async () => {
    // The refusal must not swallow the unnamed-keychain path that
    // wrap/keychain-custody.ts and wrap/passphrase.ts use; if it did, most of
    // the suite would break loudly, but a narrower version of this mistake
    // could break only one call site.
    const write = await execKeychain(
      "/usr/bin/security",
      ["-i"],
      'add-generic-password -U -a "sanctuary" -s "default-svc" -w "v"\n'
    );
    expect(write.code).toBe(0);
    const read = await execKeychain("/usr/bin/security", [
      "find-generic-password", "-a", "sanctuary", "-s", "default-svc", "-w",
    ]);
    expect(read.stdout.trim()).toBe("v");
  });

  it("refuses to create a keychain outside the temp root", async () => {
    const result = await createKeychain("/etc/sanctuary-should-never-exist.keychain-db");
    expect(result.code).not.toBe(0);
    expect(result.stderr).toMatch(/outside the temp root/);
    expect(existsSync("/etc/sanctuary-should-never-exist.keychain-db")).toBe(false);
  });
});

describe("nothing else in the tree spawns a credential CLI", () => {
  /**
   * The claim this PR makes is a COMPLETENESS claim: every credential-CLI spawn
   * goes through `execKeychain`. Four modules held their own `spawn` before;
   * routing three of them and leaving the fourth would make the claim false
   * while every test still passed. This is a source scan on purpose. It is a
   * lint over the whole tree, which is the one job a source scan is right for,
   * and it is the only mechanical way to catch a FIFTH call site that a future
   * change adds and no existing test reaches.
   */
  const srcRoot = fileURLToPath(new URL("../../src", import.meta.url));
  const CREDENTIAL_BINARIES = ["security", "secret-tool"];
  /** The chokepoint itself is the one module allowed to spawn. */
  const ALLOWED = ["wrap/keychain-exec.ts"];

  function walk(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) return walk(full);
      return entry.isFile() && full.endsWith(".ts") ? [full] : [];
    });
  }

  /**
   * Reaching a subprocess at all requires pulling in `node:child_process`.
   * Matching on that import rather than on a bare `exec(` call is what keeps
   * this precise: `keychain-custody.ts`, `passphrase.ts`, and
   * `cli/reset-passphrase.ts` all CALL something named `exec`, but it is the
   * injected executor that ends at the chokepoint, and flagging them would have
   * made this test noise everyone learns to edit around.
   */
  const IMPORTS_CHILD_PROCESS = /(?:from|import|require)\s*\(?\s*["']node:child_process["']/;

  it("no module outside the chokepoint spawns `security` or `secret-tool`", () => {
    const offenders: string[] = [];
    for (const file of walk(srcRoot)) {
      const relative = file.slice(srcRoot.length + 1);
      if (ALLOWED.includes(relative)) continue;
      const source = readFileSync(file, "utf8");
      if (!IMPORTS_CHILD_PROCESS.test(source)) continue;
      // A module may spawn plenty of other things (git, launchctl, pfctl);
      // only naming a credential binary in the same file is a bypass.
      if (
        CREDENTIAL_BINARIES.some((bin) =>
          new RegExp(`["'\`](?:/usr/bin/)?${bin}["'\`]`).test(source)
        )
      ) {
        offenders.push(relative);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("no code path in server/test can reach the real credential binary", () => {
  /**
   * The property, as a check rather than a claim. Three ways it could regress,
   * all swept here.
   *
   * SCOPE, stated honestly: this covers direct spawns and attempts to un-install
   * the store. A test that spawns the built CLI as a SUBPROCESS is covered by a
   * different mechanism, and the last case verifies it rather than assuming it:
   * the child inherits VITEST, so the chokepoint refuses inside the child too.
   * A test that deliberately scrubs the child env is governed by the AGENTS.md
   * rule requiring a per-run temporary keychain, which no scanner can enforce.
   */
  const testRoot = fileURLToPath(new URL("..", import.meta.url));

  /**
   * The bypass shape, as the conjunction of two signals. Both halves were
   * arrived at by planting the bypass and watching a weaker rule miss it:
   *
   *  - Keying on the callee name (`spawn|spawnSync|execFile`) missed a planted
   *    `import { spawnSync as plantedSpawn }` alias entirely. So the binary is
   *    matched in FIRST-ARGUMENT position instead, which no alias changes.
   *  - That alone flags `searchMessages("security")` in chat-v1.test.ts. So the
   *    file must ALSO import child_process, which is what reaching a subprocess
   *    actually requires.
   *
   * The conjunction clears both known false positives: chat-v1 imports no
   * child_process, and mcp-child/fortress-refusal.test.ts spawns the built CLI
   * but mentions "security" only after `!==`, inside an injected mock. A scanner
   * everyone learns to edit around protects nothing.
   */
  const CREDENTIAL_BINARY_AS_FIRST_ARG =
    /\(\s*["'`](?:\/usr\/bin\/)?(?:security|secret-tool)["'`]/;
  const IMPORTS_CHILD_PROCESS =
    /(?:from|import|require)\s*\(?\s*["']node:child_process["']/;

  /**
   * This file names the forbidden constructs in order to search for them, so it
   * would match itself. Excluded by exact path, and it is the guard under review
   * whenever it changes.
   */
  const SCANNER_ITSELF = "wrap/keychain-exec-guard.test.ts";

  function walkTests(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) return walkTests(full);
      return entry.isFile() && full.endsWith(".ts") ? [full] : [];
    });
  }

  const files = walkTests(testRoot)
    .map((file) => ({ relative: file.slice(testRoot.length), source: readFileSync(file, "utf8") }))
    .filter((f) => f.relative !== SCANNER_ITSELF);

  it("scans a non-trivial number of test files, so a broken walk cannot pass vacuously", () => {
    // An empty file list would make both cases below pass while checking nothing.
    expect(files.length).toBeGreaterThan(100);
  });

  /**
   * Only the setup file may touch the injection point at all. An allowlist on
   * the IDENTIFIER, rather than a pattern on the argument, is deliberate: a
   * planted `(setKeychainExec as unknown as (f: null) => void)(null)` slipped
   * straight past an argument-shaped check, and any future cast would too.
   * Matching the name catches every spelling.
   *
   * Tests that need bespoke credential behavior have a supported route that does
   * not touch this: nearly all of them already pass an `exec` through
   * KeychainCustodyOptions.
   */
  const MAY_INJECT = ["setup/keychain-fake.ts", SCANNER_ITSELF];

  it("finds no attempt to un-install or re-point the credential store", () => {
    const offenders = files
      .filter((f) => !MAY_INJECT.includes(f.relative))
      .filter(
        (f) =>
          /setKeychainExec/.test(f.source) ||
          /resetKeychainExec/.test(f.source) ||
          /SANCTUARY_TEST_ALLOW_REAL_KEYCHAIN/.test(f.source)
      )
      .map((f) => f.relative);
    expect(offenders).toEqual([]);
  });

  it("finds no test spawning a credential binary directly, bypassing the chokepoint", () => {
    // The chokepoint is only a chokepoint if nothing goes around it. A test that
    // spawns `secret-tool` itself reaches the operator's keyring no matter what
    // the installed store is doing.
    const offenders = files
      .filter(
        (f) => IMPORTS_CHILD_PROCESS.test(f.source) && CREDENTIAL_BINARY_AS_FIRST_ARG.test(f.source)
      )
      .map((f) => f.relative);
    expect(offenders).toEqual([]);
  });

  it("passes VITEST down to child processes spawned with the DEFAULT env", async () => {
    // Verified rather than asserted. This covers the common case only; the
    // scrubbed-env case below is the one that used to be open.
    const { spawnSync: spawnChild } = await import("node:child_process");
    const result = spawnChild(
      process.execPath,
      ["-e", "process.stdout.write(String(process.env.VITEST))"],
      { encoding: "utf8" }
    );
    expect(result.stdout).not.toBe("undefined");
  });

  it(
    "REFUSES inside a child spawned with `env: {}`, where no env signal survives",
    async () => {
      /**
       * The hole this closes. `underTest()` used to be purely env-derived, so a
       * child spawned with a scrubbed environment saw no VITEST, loaded no
       * vitest setup, had no store installed, and got `spawn-real`: the real
       * credential binary against the operator's own keychain. That is the
       * mechanism behind the tens of thousands of `sanctuary-*` artifacts found
       * in the login keychain.
       *
       * The fix is a marker FILE at the package root, which `env: {}` cannot
       * erase. This case runs the real thing: a child, genuinely scrubbed,
       * importing the same module, attempting a genuine credential read.
       */
      const { spawnSync: spawnChild } = await import("node:child_process");
      const serverDir = fileURLToPath(new URL("../..", import.meta.url));
      const fixture = fileURLToPath(
        new URL("../fixtures/scrubbed-env-child.ts", import.meta.url)
      );

      const result = spawnChild(process.execPath, ["--import", "tsx", fixture], {
        // The whole point: nothing inherited. Not VITEST, not NODE_ENV, not HOME.
        env: {},
        cwd: serverDir,
        encoding: "utf8",
        timeout: 60_000,
      });

      // Assert the postcondition, not the exit code: the child prints exactly
      // which branch it took, so "REFUSED" cannot be confused with a child that
      // failed to start.
      expect(result.stdout, `child stderr: ${result.stderr}`).toBe("REFUSED");
    },
    90_000
  );
});
