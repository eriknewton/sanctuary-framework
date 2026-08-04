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

import { describe, it, expect, afterEach } from "vitest";

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
