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
  execKeychain,
  setKeychainExec,
  ALLOW_REAL_KEYCHAIN_ENV,
  type KeychainExec,
} from "../../src/wrap/keychain-exec.js";
import {
  getOrCreateKeychainCustodyKey,
  readKeychainCustodyKey,
} from "../../src/wrap/keychain-custody.js";
import { installInMemoryKeychainStore } from "../setup/keychain-fake.js";
import {
  credentialStoreIsInstalled,
  enterRealBackendMode,
  probeDisposableCiRunner,
  shouldSkipRealBackend,
  type RealBackendProbe,
} from "../support/real-backend-guard.js";

/**
 * The global setup file (test/setup/keychain-fake.ts) installs the in-memory
 * store for every test. These cases deliberately remove it to prove the guard
 * underneath, so each one restores it.
 */
function withNoStore<T>(fn: () => T): T {
  // Capture nothing: the setup file re-installs per worker, and afterEach below
  // restores a working fake so later tests in this file are unaffected.
  setKeychainExec(null);
  try {
    return fn();
  } finally {
    setKeychainExec(memoryFake);
  }
}

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

// Cleared on BOTH sides of every case. Clearing only afterwards would leave the
// refusal cases below at the mercy of the ambient environment: a CI job that
// exported the opt-in would make them pass while asserting nothing, which is
// the same fail-open shape this whole chokepoint exists to prevent.
beforeEach(() => {
  delete process.env[ALLOW_REAL_KEYCHAIN_ENV];
});

afterEach(() => {
  delete process.env[ALLOW_REAL_KEYCHAIN_ENV];
  memoryStore.clear();
});

describe("keychain exec chokepoint", () => {
  it("REFUSES to spawn the real credential CLI from a test with no store installed", async () => {
    const attempt = withNoStore(() =>
      execKeychain("security", ["find-generic-password", "-a", "sanctuary", "-s", "probe", "-w"])
    );
    await expect(attempt).rejects.toThrow(/Refusing to run 'security' against the real OS credential store/);
  });

  it("names the remedy in the refusal so a new call site is fixable without archaeology", async () => {
    const attempt = withNoStore(() => execKeychain("security", ["-i"], "add-generic-password\n"));
    await expect(attempt).rejects.toThrow(/in-memory store|setKeychainExec/);
  });

  it("still refuses for the Linux Secret Service path, not just macOS", async () => {
    const attempt = withNoStore(() => execKeychain("secret-tool", ["store", "--label", "x"], "secret"));
    await expect(attempt).rejects.toThrow(/Refusing to run 'secret-tool'/);
  });

  it("allows the real CLI only when a test EXPLICITLY opts in", async () => {
    process.env[ALLOW_REAL_KEYCHAIN_ENV] = "1";
    // Proves the guard consults the opt-in. A command that cannot touch any
    // credential store is used so the test never writes anywhere real.
    const result = await withNoStore(() => execKeychain("/usr/bin/true", []));
    expect(result.code).toBe(0);
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

/**
 * The in-memory store is installed for EVERY test file, which is wrong for
 * exactly one of them: the Linux real-backend integration test exists to
 * exercise the genuine `secret-tool` shell-out. Served by the store it keeps
 * passing while proving nothing, and its degrade case actively lies, because an
 * in-memory store answers the same whether or not D-Bus is reachable.
 *
 * These cases used to grep that file for strings like
 * `SANCTUARY_TEST_DISPOSABLE_KEYRING`. That check would have passed if the
 * condition were ORed instead of ANDed, checked after the store was already
 * removed, or read into a variable nobody used. The predicate is now a callable
 * in `test/support/real-backend-guard.ts` and what follows exercises it.
 */
describe("the real-backend skip predicate (truth table, not substrings)", () => {
  const qualifies: RealBackendProbe = {
    isLinux: true,
    hasSecretTool: true,
    hasDbus: true,
    onDisposableCiRunner: true,
  };

  beforeEach(() => {
    // Order-independence: an earlier case in this file swaps the injected store
    // out, and the refusal case below asserts the store is STILL serving after
    // a refusal. Without this, that assertion would depend on which cases ran
    // first, which is how a test starts passing for the wrong reason.
    installInMemoryKeychainStore();
  });

  it("runs when every condition holds", () => {
    expect(shouldSkipRealBackend(qualifies)).toBe(false);
  });

  for (const condition of [
    "isLinux",
    "hasSecretTool",
    "hasDbus",
    "onDisposableCiRunner",
  ] as const) {
    it(`skips when ${condition} is false, so the four conditions are ANDed`, () => {
      expect(shouldSkipRealBackend({ ...qualifies, [condition]: false })).toBe(true);
    });
  }

  it("REFUSES to remove the credential store when the run does not qualify", async () => {
    expect(() =>
      enterRealBackendMode({ ...qualifies, onDisposableCiRunner: false })
    ).toThrow(/refusing to remove the in-memory credential store/);
    // The refusal is only worth anything if the store is still serving after it.
    expect(await credentialStoreIsInstalled()).toBe(true);
  });

  it("leaves the opt-in env var untouched when it refuses", () => {
    expect(() => enterRealBackendMode({ ...qualifies, isLinux: false })).toThrow();
    expect(process.env[ALLOW_REAL_KEYCHAIN_ENV]).toBeUndefined();
  });
});

describe("the real-backend suite is CI-only, and says so", () => {
  /**
   * The gate no longer tries to PROVE a keyring disposable; three attempts at
   * that each shipped a proof weaker than its claim (a bare env var, a nonce
   * round trip that only proved the service answered, and a socket-path shape
   * test that a developer's own `dbus-launch` satisfies). It now identifies the
   * one execution context that is disposable by construction, and the tests
   * below pin exactly that and nothing more.
   */

  it("runs on an ephemeral GitHub-hosted runner", () => {
    expect(
      probeDisposableCiRunner({ githubActions: "true", runnerEnvironment: "github-hosted" })
        .disposable
    ).toBe(true);
  });

  it("tolerates RUNNER_ENVIRONMENT being absent, because it is checked negatively", () => {
    // Deliberate: requiring it positively would turn an unverified assumption
    // about the runner image into a red CI.
    expect(
      probeDisposableCiRunner({ githubActions: "true", runnerEnvironment: undefined }).disposable
    ).toBe(true);
  });

  it("refuses a developer machine, which is every machine that is not CI", () => {
    const verdict = probeDisposableCiRunner({
      githubActions: undefined,
      runnerEnvironment: undefined,
    });
    expect(verdict.disposable).toBe(false);
    expect(verdict.reason).toMatch(/CI-only/);
  });

  it("refuses a self-hosted runner, whose machine outlives the job", () => {
    const verdict = probeDisposableCiRunner({
      githubActions: "true",
      runnerEnvironment: "self-hosted",
    });
    expect(verdict.disposable).toBe(false);
    expect(verdict.reason).toMatch(/outlives the job/);
  });

  it("requires the exact string \"true\", not any truthy value", () => {
    for (const value of ["1", "TRUE", "yes", ""]) {
      expect(
        probeDisposableCiRunner({ githubActions: value, runnerEnvironment: undefined }).disposable
      ).toBe(false);
    }
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

describe("the one file that opts out routes through the guarded entry point", () => {
  /**
   * The single remaining source assertion in this file, and it is here because
   * nothing executable can prove a NEGATIVE about another file: that it does not
   * reach past the guard and call `setKeychainExec(null)` itself. Everything
   * else about the opt-out is exercised as behavior above.
   */
  const source = readFileSync(
    fileURLToPath(
      new URL("../keychain-linux-real-backend-integration.test.ts", import.meta.url)
    ),
    "utf8"
  );

  it("removes the store only via enterRealBackendMode, never directly", () => {
    expect(source).toContain("enterRealBackendMode(");
    expect(source).not.toContain("setKeychainExec(");
  });

  it("puts the store back afterwards so the removal cannot outlive that file", () => {
    expect(source).toContain("leaveRealBackendMode(");
  });

  it("declares a case count the CI zero-test guard can hold it to", () => {
    // `.github/workflows/keychain-linux-real-backend.yml` requires the run to
    // report EXACTLY this many passing tests. Without the exact number, a
    // summary of `Tests 1 passed | 4 skipped` satisfies a "some tests passed"
    // grep while most real-backend assertions have vanished.
    //
    // Failure mode this catches: someone adds a case to the integration file
    // and the workflow's expectation silently no longer covers it. Adding a
    // case now fails HERE, in ordinary CI on every platform, until the declared
    // count is bumped.
    const declared = readFileSync(
      fileURLToPath(
        new URL(
          "../keychain-linux-real-backend-integration.expected-cases",
          import.meta.url
        )
      ),
      "utf8"
    ).trim();
    const actual = source.match(/^\s*it\(/gm)?.length ?? 0;
    expect(actual).toBe(Number(declared));
  });
});
