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
import ts from "typescript";

import {
  decideKeychainExecution,
  execKeychain,
  latchUnderTest,
  setKeychainExec,
  type KeychainExec,
} from "../../src/wrap/keychain-exec.js";
import {
  getOrCreateKeychainCustodyKey,
  readKeychainCustodyKey,
  RecoveryKeyKeychainStoreError,
  storeRecoveryKeyInKeychain,
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

function makeCustodyExec(options: {
  writeFails?: boolean;
  readBackOverride?: string;
} = {}): KeychainExec {
  let stored: string | undefined;
  return async (cmd, args, input) => {
    if (cmd !== "security") {
      return { stdout: "", stderr: "unsupported", code: 1 };
    }
    if (args[0] === "-i") {
      if (options.writeFails) {
        return { stdout: "", stderr: "write failed", code: 1 };
      }
      stored = /-w "([A-Za-z0-9_-]+)"/.exec(input ?? "")?.[1];
      return { stdout: "", stderr: "", code: stored === undefined ? 1 : 0 };
    }
    if (args[0] === "find-generic-password") {
      const value = stored === undefined ? undefined : (options.readBackOverride ?? stored);
      return value === undefined
        ? { stdout: "", stderr: "not found", code: 44 }
        : { stdout: `${value}\n`, stderr: "", code: 0 };
    }
    return { stdout: "", stderr: "unsupported", code: 1 };
  };
}

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
    let readBack: Uint8Array | null = null;
    try {
      expect(created).not.toBeNull();
      readBack = await readKeychainCustodyKey(
        "/tmp/sanctuary-keychain-exec-test",
        { home: "/tmp/sanctuary-keychain-exec-home", platformOverride: "darwin" }
      );
      expect(readBack).not.toBeNull();
      expect(Array.from(readBack!)).toEqual(Array.from(created!));
    } finally {
      // Both public reads transfer ownership to this test.
      created?.fill(0);
      readBack?.fill(0);
    }
  });
});

describe("keychain custody secret-buffer ownership", () => {
  const storagePath = "/tmp/sanctuary-keychain-zeroization";
  const baseOptions = {
    home: "/tmp/sanctuary-keychain-zeroization-home",
    platformOverride: "darwin" as const,
  };

  it("scrubs a generated custody key when the keychain write fails", async () => {
    let generated: Uint8Array | undefined;
    const result = await getOrCreateKeychainCustodyKey(storagePath, {
      ...baseOptions,
      exec: makeCustodyExec({ writeFails: true }),
      __testObserveSecretBuffer: (label, buffer) => {
        if (label === "generated-custody-key") generated = buffer;
      },
    });

    expect(result).toBeNull();
    expect(generated).toBeDefined();
    expect([...generated!].every((byte) => byte === 0)).toBe(true);
  });

  it("scrubs both generated and decoded copies after a mismatched custody readback", async () => {
    const observed = new Map<string, Uint8Array>();
    const mismatch = Buffer.alloc(32, 0xa5).toString("base64url");
    const result = await getOrCreateKeychainCustodyKey(storagePath, {
      ...baseOptions,
      exec: makeCustodyExec({ readBackOverride: mismatch }),
      __testObserveSecretBuffer: (label, buffer) => observed.set(label, buffer),
    });

    expect(result).toBeNull();
    expect([...observed.keys()]).toEqual([
      "generated-custody-key",
      "custody-key-readback",
    ]);
    for (const buffer of observed.values()) {
      expect([...buffer].every((byte) => byte === 0)).toBe(true);
    }
  });

  it("transfers only the generated custody key and scrubs the successful readback copy", async () => {
    const observed = new Map<string, Uint8Array>();
    const result = await getOrCreateKeychainCustodyKey(storagePath, {
      ...baseOptions,
      exec: makeCustodyExec(),
      __testObserveSecretBuffer: (label, buffer) => observed.set(label, buffer),
    });

    try {
      expect(result).not.toBeNull();
      expect(result).toBe(observed.get("generated-custody-key"));
      expect([...result!].some((byte) => byte !== 0)).toBe(true);
      const readBack = observed.get("custody-key-readback");
      expect(readBack).toBeDefined();
      expect([...readBack!].every((byte) => byte === 0)).toBe(true);
    } finally {
      result?.fill(0);
    }
  });

  it("always scrubs decoded recovery material and its success or mismatch readback", async () => {
    const recoveryKey = Buffer.alloc(32, 0x5c).toString("base64url");
    for (const mismatch of [false, true]) {
      const observed = new Map<string, Uint8Array>();
      const exec = makeCustodyExec(
        mismatch
          ? { readBackOverride: Buffer.alloc(32, 0xa6).toString("base64url") }
          : {},
      );
      const operation = storeRecoveryKeyInKeychain(storagePath, recoveryKey, {
        ...baseOptions,
        exec,
        __testObserveSecretBuffer: (label, buffer) => observed.set(label, buffer),
      });

      if (mismatch) {
        await expect(operation).rejects.toBeInstanceOf(RecoveryKeyKeychainStoreError);
      } else {
        await expect(operation).resolves.toMatchObject({ service: expect.any(String) });
      }
      expect([...observed.keys()]).toEqual([
        "decoded-recovery-key",
        "recovery-key-readback",
      ]);
      for (const buffer of observed.values()) {
        expect([...buffer].every((byte) => byte === 0)).toBe(true);
      }
    }
  });

  it("scrubs decoded recovery material when the keychain write fails", async () => {
    const recoveryKey = Buffer.alloc(32, 0x6d).toString("base64url");
    let decoded: Uint8Array | undefined;
    const operation = storeRecoveryKeyInKeychain(storagePath, recoveryKey, {
      ...baseOptions,
      exec: makeCustodyExec({ writeFails: true }),
      __testObserveSecretBuffer: (label, buffer) => {
        if (label === "decoded-recovery-key") decoded = buffer;
      },
    });

    await expect(operation).rejects.toBeInstanceOf(RecoveryKeyKeychainStoreError);
    expect(decoded).toBeDefined();
    expect([...decoded!].every((byte) => byte === 0)).toBe(true);
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

  const CHILD_PROCESS_EXECUTORS = new Set([
    "spawn",
    "spawnSync",
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
  ]);

  function directlySpawnsCredentialBinary(source: string, file: string): boolean {
    const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
    const directBindings = new Set<string>();
    const namespaces = new Set<string>();

    for (const statement of parsed.statements) {
      if (!ts.isImportDeclaration(statement)) continue;
      if (!ts.isStringLiteral(statement.moduleSpecifier)) continue;
      if (statement.moduleSpecifier.text !== "node:child_process") continue;
      const clause = statement.importClause;
      if (!clause?.namedBindings) continue;
      if (ts.isNamespaceImport(clause.namedBindings)) {
        namespaces.add(clause.namedBindings.name.text);
        continue;
      }
      for (const binding of clause.namedBindings.elements) {
        const imported = binding.propertyName?.text ?? binding.name.text;
        if (CHILD_PROCESS_EXECUTORS.has(imported)) {
          directBindings.add(binding.name.text);
        }
      }
    }

    let found = false;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        const isChildProcessCall =
          (ts.isIdentifier(callee) && directBindings.has(callee.text)) ||
          (ts.isPropertyAccessExpression(callee) &&
            ts.isIdentifier(callee.expression) &&
            namespaces.has(callee.expression.text) &&
            CHILD_PROCESS_EXECUTORS.has(callee.name.text));
        const target = node.arguments[0];
        if (
          isChildProcessCall &&
          target &&
          (ts.isStringLiteral(target) || ts.isNoSubstitutionTemplateLiteral(target)) &&
          CREDENTIAL_BINARIES.some((bin) =>
            target.text === bin || target.text === `/usr/bin/${bin}`
          )
        ) {
          found = true;
          return;
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
    return found;
  }

  it("no module outside the chokepoint spawns `security` or `secret-tool`", () => {
    const offenders: string[] = [];
    for (const file of walk(srcRoot)) {
      const relative = file.slice(srcRoot.length + 1);
      if (ALLOWED.includes(relative)) continue;
      const source = readFileSync(file, "utf8");
      // A module may spawn plenty of other things (git, launchctl, a Node
      // wipe worker) and separately name a credential CLI for an injected
      // executor. Flag the dangerous operation itself: a child-process API
      // whose target is the credential binary. Aliased and namespace imports
      // are both resolved so moving the bypass behind an import rename does
      // not evade the gate.
      if (directlySpawnsCredentialBinary(source, relative)) {
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

  it("stays under test after the marker disappears (latch, pure form)", () => {
    // THE RACE, as a state transition. Global teardown deletes the marker while
    // a child that started during the suite is still alive; that child must not
    // be reclassified as production when it finally makes its first call.
    expect(latchUnderTest(true, false)).toBe(true);
    // And the reverse must still work: a process that started just BEFORE the
    // marker appeared has to be able to observe it later, which is why a false
    // reading is never cached.
    expect(latchUnderTest(false, true)).toBe(true);
    expect(latchUnderTest(true, true)).toBe(true);
    expect(latchUnderTest(false, false)).toBe(false);
  });

  /**
   * Run a probe against an ISOLATED copy of the chokepoint, in a child spawned
   * with `env: {}`.
   *
   * Isolated on purpose: these probes create and delete a marker, and doing that
   * to the real one mid-suite would change the answer for other vitest workers
   * running in parallel. The module is COPIED from src at run time, so the probe
   * can never drift from what production does.
   */
  async function runIsolatedProbe(opts: {
    markerPresentAtImport: boolean;
    /** Statements run after import, before the first credential call. */
    betweenImportAndCall: string[];
  }): Promise<{ stdout: string; stderr: string }> {
    const { spawnSync: spawnChild } = await import("node:child_process");
    const serverDir = fileURLToPath(new URL("../..", import.meta.url));
    const probeDir = mkdtempSync(join(tmpdir(), "sanctuary-latch-probe-"));
    try {
      for (const file of ["keychain-exec.ts", "exec-result.ts"]) {
        writeFileSync(
          join(probeDir, file),
          readFileSync(join(serverDir, "src", "wrap", file), "utf8")
        );
      }
      writeFileSync(
        join(probeDir, "package.json"),
        JSON.stringify({ name: "latch-probe", type: "module", private: true })
      );
      if (opts.markerPresentAtImport) {
        writeFileSync(join(probeDir, ".sanctuary-test-run"), "probe");
      }
      writeFileSync(
        join(probeDir, "probe.ts"),
        [
          'import { rmSync, writeFileSync } from "node:fs";',
          'import { fileURLToPath } from "node:url";',
          'const marker = fileURLToPath(new URL("./.sanctuary-test-run", import.meta.url));',
          'void rmSync; void writeFileSync; void marker;',
          // The import is where the latch initializes.
          'import { execKeychain } from "./keychain-exec.js";',
          ...opts.betweenImportAndCall,
          "try {",
          '  await execKeychain("security", ["find-generic-password", "-s", "sanctuary-latch-probe-never-exists", "-a", "sanctuary", "-w"]);',
          '  process.stdout.write("SPAWNED_REAL");',
          "} catch (err) {",
          "  const message = (err as Error).message;",
          '  process.stdout.write(message.includes("Refusing to run") ? "REFUSED" : `OTHER:${message}`);',
          "}",
          "",
        ].join("\n")
      );

      const result = spawnChild(
        process.execPath,
        ["--import", "tsx", join(probeDir, "probe.ts")],
        { env: {}, cwd: serverDir, encoding: "utf8", timeout: 60_000 }
      );
      return { stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
    } finally {
      rmSync(probeDir, { recursive: true, force: true });
    }
  }

  it(
    "REFUSES in a child whose marker is deleted BEFORE its first credential call",
    async () => {
      // THE RACE. The child imports while the marker exists (latching), then
      // deletes it to simulate global teardown, then makes its first call. A
      // lazily-evaluated check answers "production" here; the latch does not.
      // The synchronous `env: {}` case below cannot cover this, because
      // spawnSync means that child always calls while the marker still exists.
      const { stdout, stderr } = await runIsolatedProbe({
        markerPresentAtImport: true,
        betweenImportAndCall: ["rmSync(marker, { force: true });"],
      });
      expect(stdout, `child stderr: ${stderr}`).toBe("REFUSED");
    },
    90_000
  );

  it(
    "still observes a marker that appears AFTER import, because no negative is cached",
    async () => {
      // The mirror property, and it was uncovered: caching the negative passed
      // every test. A process that starts moments BEFORE the marker appears must
      // still be able to see it, otherwise it latches "production" for the whole
      // run. Here the child imports with NO marker, then one appears.
      const { stdout, stderr } = await runIsolatedProbe({
        markerPresentAtImport: false,
        betweenImportAndCall: ['writeFileSync(marker, "appeared after import");'],
      });
      expect(stdout, `child stderr: ${stderr}`).toBe("REFUSED");
    },
    90_000
  );

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

describe("the production credential subprocess is bounded", () => {
  async function runBoundedSpawnProbe(
    helperScript: string,
    extraProbeLines: string[] = [],
  ): Promise<{ stdout: string; stderr: string; status: number | null }> {
    const { spawnSync: spawnChild } = await import("node:child_process");
    const serverDir = fileURLToPath(new URL("../..", import.meta.url));
    const probeDir = mkdtempSync(join(tmpdir(), "sanctuary-keychain-bound-"));
    try {
      let source = readFileSync(
        join(serverDir, "src", "wrap", "keychain-exec.ts"),
        "utf8",
      );
      source = source
        .replace(
          "const KEYCHAIN_PROCESS_TIMEOUT_MS = 15_000;",
          "const KEYCHAIN_PROCESS_TIMEOUT_MS = 500;",
        )
        .replace(
          "const KEYCHAIN_PROCESS_MAX_OUTPUT_BYTES = 64 * 1024;",
          "const KEYCHAIN_PROCESS_MAX_OUTPUT_BYTES = 1024;",
        )
        .replace(
          "const KEYCHAIN_PROCESS_TERM_GRACE_MS = 250;",
          "const KEYCHAIN_PROCESS_TERM_GRACE_MS = 100;",
        );
      writeFileSync(join(probeDir, "keychain-exec.ts"), source);
      writeFileSync(
        join(probeDir, "exec-result.ts"),
        readFileSync(join(serverDir, "src", "wrap", "exec-result.ts"), "utf8"),
      );
      writeFileSync(
        join(probeDir, "package.json"),
        JSON.stringify({ name: "bounded-keychain-probe", type: "module", private: true }),
      );
      writeFileSync(
        join(probeDir, "probe.ts"),
        [
          'import { execKeychain } from "./keychain-exec.js";',
          "let message = '';",
          "try {",
          `  await execKeychain(process.execPath, ["-e", ${JSON.stringify(helperScript)}]);`,
          "  message = 'RESOLVED';",
          "} catch (error) {",
          "  message = (error as Error).message;",
          "}",
          ...extraProbeLines,
          'process.stdout.write(message);',
          "",
        ].join("\n"),
      );
      const result = spawnChild(
        process.execPath,
        ["--import", "tsx", join(probeDir, "probe.ts")],
        { env: {}, cwd: serverDir, encoding: "utf8", timeout: 10_000 },
      );
      return {
        stdout: result.stdout ?? "",
        stderr: result.stderr ?? "",
        status: result.status,
      };
    } finally {
      rmSync(probeDir, { recursive: true, force: true });
    }
  }

  it("rejects output exhaustion before retaining unbounded helper output", async () => {
    const result = await runBoundedSpawnProbe(
      'process.stdout.write("x".repeat(4096)); setTimeout(() => process.exit(0), 3000);',
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("credential helper exceeded output limit");
    expect(result.stdout).not.toContain("xxxx");
  });

  it.skipIf(process.platform === "win32")(
    "times out and TERM-to-KILLs the helper process group",
    async () => {
    const pidFile = join(tmpdir(), `sanctuary-keychain-child-${process.pid}-${Date.now()}.pid`);
    const descendant =
      'process.on("SIGTERM", () => {}); setTimeout(() => process.exit(0), 3000);';
    const helper = [
      'const { spawn } = require("node:child_process");',
      'const { writeFileSync } = require("node:fs");',
      `const child = spawn(process.execPath, ["-e", ${JSON.stringify(descendant)}], { stdio: "ignore" });`,
      `writeFileSync(${JSON.stringify(pidFile)}, String(child.pid));`,
      'process.on("SIGTERM", () => {});',
      'setTimeout(() => process.exit(0), 3000);',
    ].join("\n");
    const result = await runBoundedSpawnProbe(helper, [
      'await new Promise((resolve) => setTimeout(resolve, 750));',
      `const { readFileSync } = await import("node:fs");`,
      `const descendantPid = Number(readFileSync(${JSON.stringify(pidFile)}, "utf8"));`,
      "let descendantGone = false;",
      "try { process.kill(descendantPid, 0); } catch { descendantGone = true; }",
      "message += descendantGone ? ':group-gone' : ':descendant-alive';",
    ]);
    if (existsSync(pidFile)) {
      const remainingPid = Number(readFileSync(pidFile, "utf8"));
      try {
        process.kill(remainingPid, "SIGKILL");
      } catch {
        // Expected: the production helper already killed the whole group.
      }
    }
    rmSync(pidFile, { force: true });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("credential helper timed out:group-gone");
    },
  );
});

describe("no test may spawn a child with a scrubbed environment", () => {
  /**
   * The one pattern that reopens the credential hole, refused at the authoring
   * point.
   *
   * WHY THIS EXISTS EVEN THOUGH THERE ARE ZERO VIOLATIONS TODAY. The sentinel in
   * keychain-exec.ts covers every child that loads the module while the marker
   * exists, which is every child any current test spawns. What it cannot cover
   * is a child that starts during the suite and first loads the module AFTER
   * global teardown. No test does that now, and this rule is what keeps one from
   * being added: a scrubbed env is the only way to get there, so the rule is
   * trivially satisfied today and costs nothing to keep.
   *
   * SCOPE, deliberately narrow. It looks ONLY at call sites whose callee is a
   * binding imported from node:child_process, and only at the `env` property of
   * an object-literal argument to those calls. It is not a style gate: an `env`
   * key anywhere else is invisible to it, which is why the ten in-process
   * `env: {}` parameters elsewhere in the suite (runNodesCommand and friends)
   * are correctly ignored.
   *
   * A child that inherits (no `env` at all, or one spreading `process.env`)
   * carries VITEST and is already covered.
   */
  const testRoot = fileURLToPath(new URL("..", import.meta.url));

  /** Names bound to a child_process import, including aliases and namespaces. */
  function childProcessBindings(sf: ts.SourceFile): Set<string> {
    const names = new Set<string>();
    const isChildProcess = (text: string): boolean =>
      text === "node:child_process" || text === "child_process";

    const visit = (node: ts.Node): void => {
      if (
        ts.isImportDeclaration(node) &&
        ts.isStringLiteral(node.moduleSpecifier) &&
        isChildProcess(node.moduleSpecifier.text)
      ) {
        const clause = node.importClause;
        if (clause?.name) names.add(clause.name.text);
        const bindings = clause?.namedBindings;
        if (bindings && ts.isNamedImports(bindings)) {
          // `spawnSync as plantedSpawn` binds the LOCAL name, which is what a
          // callee-name check has to match. An earlier text-based rule missed
          // exactly this.
          for (const element of bindings.elements) names.add(element.name.text);
        }
        if (bindings && ts.isNamespaceImport(bindings)) names.add(bindings.name.text);
      }
      // `const { spawnSync: x } = await import("node:child_process")`
      if (
        ts.isVariableDeclaration(node) &&
        node.initializer !== undefined &&
        /import\s*\(\s*["']node:child_process["']\s*\)/.test(node.initializer.getText(sf))
      ) {
        if (ts.isObjectBindingPattern(node.name)) {
          for (const element of node.name.elements) {
            if (ts.isIdentifier(element.name)) names.add(element.name.text);
          }
        } else if (ts.isIdentifier(node.name)) {
          names.add(node.name.text);
        }
      }
      node.forEachChild(visit);
    };
    visit(sf);
    return names;
  }

  /**
   * An env argument is safe when it inherits the parent environment (so VITEST
   * reaches the child) or explicitly propagates the test-run signal.
   */
  const INHERITS_OR_PROPAGATES = /process\.env|VITEST|SANCTUARY_TEST_RUN/;

  /**
   * Text to judge an `env` value by. An identifier is resolved to its
   * declaration in the same file, so `const env = { ...process.env }` reads as
   * safe while `const env = {}` does not. Unresolvable identifiers return the
   * bare name, which fails the check: a value this cannot see is treated as
   * scrubbed, not assumed safe.
   */
  function envValueText(expr: ts.Expression, sf: ts.SourceFile): string {
    if (!ts.isIdentifier(expr)) return expr.getText(sf);
    let resolved: string | null = null;
    const find = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.name.text === expr.text &&
        node.initializer !== undefined
      ) {
        resolved = node.initializer.getText(sf);
      }
      node.forEachChild(find);
    };
    find(sf);
    return resolved ?? expr.text;
  }

  function scrubbedEnvSpawns(sf: ts.SourceFile): number[] {
    const spawners = childProcessBindings(sf);
    if (spawners.size === 0) return [];
    const lines: number[] = [];

    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const callee = node.expression;
        const isSpawn =
          (ts.isIdentifier(callee) && spawners.has(callee.text)) ||
          (ts.isPropertyAccessExpression(callee) &&
            ts.isIdentifier(callee.expression) &&
            spawners.has(callee.expression.text));
        if (isSpawn) {
          for (const arg of node.arguments) {
            if (!ts.isObjectLiteralExpression(arg)) continue;
            for (const prop of arg.properties) {
              // BOTH object-literal spellings. `{ env: x }` is a
              // PropertyAssignment; `{ env }` is a ShorthandPropertyAssignment
              // and is a different AST node, so handling only the first left the
              // shorthand form walking straight through the tripwire. Same
              // "covers the forms you thought of" shape as the aliased import.
              let value: ts.Expression | undefined;
              if (
                ts.isPropertyAssignment(prop) &&
                prop.name.getText(sf).replace(/["']/g, "") === "env"
              ) {
                value = prop.initializer;
              } else if (
                ts.isShorthandPropertyAssignment(prop) &&
                prop.name.text === "env"
              ) {
                value = prop.name;
              }
              if (value === undefined) continue;
              if (!INHERITS_OR_PROPAGATES.test(envValueText(value, sf))) {
                lines.push(sf.getLineAndCharacterOfPosition(prop.getStart(sf)).line + 1);
              }
            }
          }
        }
      }
      node.forEachChild(visit);
    };
    visit(sf);
    return lines;
  }

  /**
   * Parse diagnostics from `ts.createSourceFile`. A file the scanner cannot
   * fully parse contributes zero violations, which is indistinguishable from a
   * clean file: absence of evidence reading as a pass, the same shape this whole
   * change exists to remove. So a parse error fails the check by name.
   */
  function parseErrors(sf: ts.SourceFile): number {
    const withDiagnostics = sf as unknown as { parseDiagnostics?: readonly ts.Diagnostic[] };
    return withDiagnostics.parseDiagnostics?.length ?? 0;
  }

  function walkTests(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) return walkTests(full);
      return entry.isFile() && full.endsWith(".ts") ? [full] : [];
    });
  }

  /**
   * This file is the exception, and it has to be: the isolated probes above
   * spawn with `env: {}` ON PURPOSE, because that is the condition being proven
   * safe. They run against a copied module in a temp package, never the suite's
   * own marker.
   */
  const SCANNER_ITSELF_ABS = fileURLToPath(import.meta.url);

  const scanned = walkTests(testRoot).filter((f) => f !== SCANNER_ITSELF_ABS);

  it("scans the test tree, so a broken walk cannot pass vacuously", () => {
    expect(scanned.length).toBeGreaterThan(100);
  });

  it("parses every test file, so an unreadable one cannot pass as clean", () => {
    const unparseable: string[] = [];
    for (const file of scanned) {
      const sf = ts.createSourceFile(
        file,
        readFileSync(file, "utf8"),
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TS
      );
      if (parseErrors(sf) > 0) unparseable.push(file.slice(testRoot.length));
    }
    expect(unparseable).toEqual([]);
  });

  it("finds no child spawned with an environment that drops VITEST", () => {
    const violations: string[] = [];
    for (const file of scanned) {
      const source = readFileSync(file, "utf8");
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
      // A file that did not parse is reported by the case above; counting its
      // (necessarily zero) violations here would launder the failure into a pass.
      if (parseErrors(sf) > 0) continue;
      for (const line of scrubbedEnvSpawns(sf)) {
        violations.push(`${file.slice(testRoot.length)}:${line}`);
      }
    }
    expect(violations).toEqual([]);
  });
});
