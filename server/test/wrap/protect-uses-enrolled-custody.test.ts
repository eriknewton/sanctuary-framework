// fail-before-exempt: combined-tree seam only: the probe literal gained the stagedRecoveryFile field and the castle-wall mock became a partial (importOriginal) mock so init.ts loads; the behaviour this file proves shipped in #1391 and is unchanged by this PR
/**
 * Rung 1 primary journey: `init` -> `install` -> the EXACT emitted `protect`
 * argv, end to end, with no credential supplied anywhere.
 *
 * Capability under test: the credential `init` enrolls is the credential
 * `protect` uses, and the install planner's `custody_access` describes the argv
 * it is about to emit rather than the fortress in the abstract. Register:
 * defect.a73-install-emitted-protect-fails-custody-establishment,
 * defect.a73-install-reports-complete-on-unopenable-fortress.
 *
 * WHAT EACH TEST ACTUALLY IS, so the file's claim matches its contents: ONE
 * test runs the planner's emitted argv VERBATIM (`--fortress <path>` included)
 * through the CLI's own top-level dispatcher, which is the only way to prove
 * the tokens BEFORE the subcommand are honored; the other `protect` tests
 * reconstruct the flag tail after `protect` and call `runWrap` directly, so
 * they can inject dashboard and local-intelligence seams. `export-passphrase`
 * calls its own verb entry point.
 *
 * Every keyring read and write here goes through the wrap keychain chokepoint,
 * which the suite serves from the in-memory store (test/setup/keychain-fake.ts):
 * no `security` / `secret-tool` subprocess runs, and the operator's login
 * keychain and real `~/.sanctuary` are never touched.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const castleWallMocks = vi.hoisted(() => ({
  runProvisionPin: vi.fn(async () => 0),
  startMacOSCastleWallDaemon: vi.fn(async () => ({ stop: async () => {} })),
}));

// Partial mock: only the pin provisioning verb is stubbed. init.ts also imports
// the pin path constant and the read-only host/extension observers from this
// module, and those must be the real ones (the tests here run with
// SANCTUARY_INIT_NO_PIN, so the observers are never consulted, but a bare
// factory would make the module fail to load at all).
vi.mock("../../src/cli/castle-wall.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/cli/castle-wall.js")>();
  return {
    ...actual,
    runProvisionPin: castleWallMocks.runProvisionPin,
  };
});

vi.mock("../../src/castle-wall/runtime/index.js", () => ({
  startMacOSCastleWallDaemon: castleWallMocks.startMacOSCastleWallDaemon,
  isLinuxProducerSignedActivationRequested: () => false,
}));

// The verbatim-argv run goes through the CLI's real dependency wiring, which
// starts the ONE main dashboard in process. Stub the dashboard boot rather than
// the wiring: what that test proves is the credential the dispatched argv
// establishes custody with, and a real HTTP listener would add a bound port to
// every run of this file.
vi.mock("../../src/dashboard-standalone.js", () => ({
  startStandaloneDashboard: vi.fn(async () => {}),
}));

import { parseWrapArgs, runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";
import { runInit } from "../../src/wrap/init.js";
import {
  buildAgentInstallPlan,
  probeCustodyAccess,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { runExportPassphrase } from "../../src/cli/export-passphrase.js";
import { readStoredPassphrase } from "../../src/wrap/passphrase.js";
import { readKeychainCustodyKey } from "../../src/wrap/keychain-custody.js";
import { unlockExistingMasterReadOnly } from "../../src/core/master-custody.js";
import {
  getPlatformPaths,
  hasExistingWrapMetaStrict,
} from "../../src/wrap/config-reader.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { toBase64url } from "../../src/core/encoding.js";

const ENV_KEYS = [
  "HOME",
  "SANCTUARY_STORAGE_PATH",
  "SANCTUARY_FORTRESS_PATH",
  "SANCTUARY_PASSPHRASE",
  "SANCTUARY_RECOVERY_KEY",
  "SANCTUARY_INIT_NO_PIN",
] as const;

type EnvKey = (typeof ENV_KEYS)[number];

/** Thrown in place of a real `process.exit` so a refusal is observable. */
class ProcessExit extends Error {
  constructor(readonly code: number) {
    super(`process.exit(${String(code)})`);
  }
}

function baseProbe(over: Partial<InstallProbeResult>): InstallProbeResult {
  return {
    cooperativeWrap: "absent",
    persistentCli: "present",
    persistentCliPath: "/usr/local/bin/sanctuary",
    persistentCliVersion: "1.0.0",
    packageManagerPath: "/usr/bin/npm",
    existingCustody: "present",
    custodyAccess: "usable",
    custodyMutation: "available",
    recoveryFactor: "present",
    nodePath: "/usr/bin/node",
    castleWallApp: "not-applicable",
    castleWallBuildSha: null,
    systemExtension: "not-applicable",
    bootService: "not-applicable",
    contentFilter: "not-applicable",
    enforcement: "not-applicable",
    trustAnchor: "not-applicable",
    operatorTwin: "not-applicable",
    stagedRecoveryFile: "absent",
    ...over,
  };
}

/**
 * The `protect` flags out of an emitted `next_action.argv`. The argv is
 * `[<node> <cli> --fortress <path> protect <flags...>]`; everything before
 * `protect` is the CLI's own dispatch, which `runWrap` does not parse.
 */
function protectFlagsFrom(argv: readonly string[]): string[] {
  const index = argv.indexOf("protect");
  expect(index).toBeGreaterThan(-1);
  return [...argv.slice(index + 1)];
}

describe("protect uses the custody factor init enrolled", () => {
  let home: string;
  let fortress: string;
  let originalEnv: Record<EnvKey, string | undefined>;
  let originalStdinIsTTY: boolean | undefined;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "a73-protect-custody-"));
    fortress = join(home, "sanctuary-daily");
    originalEnv = Object.fromEntries(
      ENV_KEYS.map((key) => [key, process.env[key]]),
    ) as Record<EnvKey, string | undefined>;
    originalStdinIsTTY = process.stdin.isTTY;
    // init's interactive branch (the one that enrolls the OS-keyring custody
    // factor) requires a TTY. protect stays non-interactive regardless, because
    // every run here passes --no-open.
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: true,
    });
    process.env.HOME = home;
    for (const key of ENV_KEYS) {
      if (key !== "HOME") delete process.env[key];
    }
    castleWallMocks.runProvisionPin.mockClear();
    castleWallMocks.runProvisionPin.mockResolvedValue(0);
    castleWallMocks.startMacOSCastleWallDaemon.mockClear();
    castleWallMocks.startMacOSCastleWallDaemon.mockResolvedValue({
      stop: async () => {},
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(console, "info").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(process.stderr, "write").mockImplementation(
      (() => true) as typeof process.stderr.write,
    );
    vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new ProcessExit(code ?? 0);
    }) as never);
  });

  afterEach(async () => {
    for (const key of ENV_KEYS) {
      const value = originalEnv[key];
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: originalStdinIsTTY,
    });
    vi.restoreAllMocks();
    await rm(home, { recursive: true, force: true });
  });

  /** `sanctuary init` on the documented interactive path: enrolls an OS-keyring custody factor and no passphrase. */
  async function initFortress(): Promise<string> {
    const result = await runInit(
      {
        fortress,
        noPin: true,
        noIdentity: true,
        // Answered up front so the local-intelligence step never reaches its
        // TTY prompt; this test is about custody, not model provisioning.
        provisionLocalIntelligence: false,
        recoveryOut: join(home, "recovery-key.txt"),
      },
      {
        provisionPin: vi.fn(async () => 0),
        // Local intelligence is out of scope here and would otherwise reach a
        // real Ollama runtime and a TTY prompt.
        runLocalIntelligenceSetup: vi.fn(async () => ({
          kind: "not-requested" as const,
        })),
        // Drives the attended re-entry step without a terminal; init still
        // takes the INTERACTIVE branch, which is the one that enrolls the
        // OS-keyring custody factor.
        verifyRecoveryKeyReentry: vi.fn(async () => {}),
      },
    );
    return result.fortressPath;
  }

  function wrapDeps(): RunWrapDeps {
    return {
      startDashboard: async () =>
        ({
          url: "http://127.0.0.1:3501",
          port: 3501,
          host: "127.0.0.1",
          mode: "co-located",
          stop: async () => {},
          createSessionUrl: () => "http://127.0.0.1:3501/v1.1",
          setV11Bindings: () => {},
          setV11LoopbackAutoAuth: () => {},
          updateSources: () => {},
        }) as never,
      openBrowser: async () => {},
      // Same reason as init's seam: local intelligence would reach a real
      // model runtime and a TTY prompt, and it is not what this file proves.
      runLocalIntelligenceSetup: (async () => ({
        kind: "not-requested" as const,
      })) as never,
      installClaudeCodeAllowlist: async () => ({
        installedAt: join(home, ".claude", "settings.json"),
        alreadyPresent: true,
        added: [],
      }),
    };
  }

  it("runs the exact emitted protect argv with no credential and reuses the enrolled factor", async () => {
    await initFortress();

    // Before the fix this reported `usable` from the fortress while the argv it
    // emitted could not use any of it. It now runs the SAME resolver the argv
    // will run, restricted to the host-local sources the argv can reach.
    const observed = await probeCustodyAccess(fortress, process.platform);
    expect(observed.custodyAccess).toBe("usable");

    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress,
      platform: process.platform,
      observed: baseProbe(observed),
    });
    const argv = plan.next_action?.argv;
    expect(argv).toBeDefined();
    // The contract forbids adding a credential, so the emitted argv must carry
    // none: this is exactly why the resolver run above excluded ambient env.
    expect(argv!.join(" ")).not.toContain("--passphrase");

    const options = parseWrapArgs(protectFlagsFrom(argv!));
    const enrolledBefore = await readKeychainCustodyKey(fortress);
    expect(enrolledBefore).not.toBeNull();

    // Before the fix this printed "Generated and stored passphrase" and then
    // exited 2 with "Custody Establishment Failed".
    await runWrap({ ...options, fortress, protectCommand: true }, wrapDeps());

    // No new keychain passphrase item was minted for this fortress: the run
    // used the factor `init` had already enrolled.
    expect(await readStoredPassphrase({ storagePath: fortress })).toBeNull();
    const enrolledAfter = await readKeychainCustodyKey(fortress);
    expect(toBase64url(enrolledAfter!)).toBe(toBase64url(enrolledBefore!));

    // And that factor still opens the fortress protect just wrote to.
    const storage = new FilesystemStorage(join(fortress, "state"));
    const master = await unlockExistingMasterReadOnly(storage, {
      keychainKey: enrolledAfter!,
      storagePathHint: fortress,
    });
    expect(master.length).toBe(32);
    master.fill(0);
    enrolledBefore!.fill(0);
    enrolledAfter!.fill(0);
  }, 120_000);

  it("runs the planner's emitted argv VERBATIM through the CLI's top-level dispatcher", async () => {
    await initFortress();
    const observed = await probeCustodyAccess(fortress, process.platform);
    const plan = buildAgentInstallPlan({
      profile: "memory",
      harness: "claude-code",
      fortress,
      platform: process.platform,
      observed: baseProbe(observed),
    });
    const argv = plan.next_action?.argv;
    expect(argv).toBeDefined();
    // The tokens BEFORE the subcommand are the part only the top-level
    // dispatcher parses, and the part a `runWrap`-level test cannot exercise:
    // `--fortress <path>` here is what points the whole run at this fortress.
    expect(argv!.slice(2, 5)).toEqual(["--fortress", fortress, "protect"]);
    expect(argv!.join(" ")).not.toContain("--passphrase");

    const enrolledBefore = await readKeychainCustodyKey(fortress);
    expect(enrolledBefore).not.toBeNull();

    // `init`'s enrolment needed a TTY; the emitted protect run is the agent's,
    // and it is non-interactive.
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: false,
    });
    const originalArgv = process.argv;
    process.argv = [...argv!];
    try {
      // Importing the entry point RUNS it against `process.argv`, which is the
      // only input the dispatcher takes; the exported promise is that
      // dispatch's completion. Before the fix this exited 2 with "Custody
      // Establishment Failed" after minting a passphrase it could not use.
      const entry = await import("../../src/cli.js");
      await entry.cliEntryInvocation;
    } finally {
      process.argv = originalArgv;
    }

    // The dispatch really performed the wrap: the harness config now carries
    // Sanctuary's wrap marker. Without this the rest of the assertions would
    // also hold for a run that dispatched nowhere.
    const wrapped = await Promise.all(
      getPlatformPaths()["claude-code"].map((path) =>
        hasExistingWrapMetaStrict(path),
      ),
    );
    expect(wrapped).toContain(true);

    // No new keychain passphrase item was minted for this fortress, and the
    // factor `init` enrolled is unchanged and still opens the fortress.
    expect(await readStoredPassphrase({ storagePath: fortress })).toBeNull();
    const enrolledAfter = await readKeychainCustodyKey(fortress);
    expect(enrolledAfter).not.toBeNull();
    expect(toBase64url(enrolledAfter!)).toBe(toBase64url(enrolledBefore!));

    const master = await unlockExistingMasterReadOnly(
      new FilesystemStorage(join(fortress, "state")),
      { keychainKey: enrolledAfter!, storagePathHint: fortress },
    );
    expect(master.length).toBe(32);
    master.fill(0);
    enrolledBefore!.fill(0);
    enrolledAfter!.fill(0);
  }, 120_000);

  it("SANCTUARY_RECOVERY_KEY unlocks protect", async () => {
    await initFortress();
    const { readFile } = await import("node:fs/promises");
    const recoveryFile = await readFile(join(home, "recovery-key.txt"), "utf-8");
    const recoveryKey = recoveryFile
      .split("\n")
      .map((line) => line.trim())
      .find((line) => /^[A-Za-z0-9_-]{43}$/.test(line));
    expect(recoveryKey).toBeDefined();
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKey!;

    // The old chain never read this variable, while its own failure message
    // told the operator to supply it.
    await runWrap(
      {
        claudeCode: true,
        noOpen: true,
        agentGuided: true,
        provisionAgentAccount: false,
        fortress,
        protectCommand: true,
      },
      wrapDeps(),
    );
    expect(await readStoredPassphrase({ storagePath: fortress })).toBeNull();
  }, 120_000);

  it("export-passphrase returns the enrolled factor after init", async () => {
    await initFortress();
    process.env.SANCTUARY_STORAGE_PATH = fortress;
    const written: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);

    // Before the fix this printed "No stored passphrase found. Run `sanctuary
    // wrap` first." on a fortress whose custody was fine.
    await runExportPassphrase(["--yes"]);

    const enrolled = await readKeychainCustodyKey(fortress);
    expect(enrolled).not.toBeNull();
    expect(written.join("").trim()).toBe(toBase64url(enrolled!));

    // The fallback branch prints the factor WITH its machine-resident bound.
    // Both branches are asserted because the help promises the ordering, and a
    // verb whose help and code disagree is what item 5 of this fix closed.
    const notices = vi
      .mocked(console.error)
      .mock.calls.map((call) => String(call[0]))
      .join("\n");
    expect(notices).toContain(
      "OS-keyring custody factor for this fortress on this host",
    );
    enrolled!.fill(0);
  }, 120_000);

  it("mints and succeeds on an empty fortress directory that still holds a leftover custody item", async () => {
    // The state `protect` lands in after a failed `init`, or after the operator
    // removed the fortress directory and left the keyring item behind. Before
    // the fix the resolver returned that leftover as `resolved` (no envelope
    // existed to disprove it), so `protect` never reached the mint branch and
    // `establishWrapCustody` refused: `firstRun` will not create custody from a
    // keychain credential. The run died on a directory that only needed minting.
    const { mkdir } = await import("node:fs/promises");
    const { getOrCreateKeychainCustodyKey } = await import(
      "../../src/wrap/keychain-custody.js"
    );
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    const leftover = await getOrCreateKeychainCustodyKey(fortress);
    expect(leftover).not.toBeNull();
    leftover!.fill(0);

    // Deliberately NOT `--agent-guided`: on macOS that path refuses a first
    // custody ceremony outright ("first macOS custody is a human action"),
    // which is a separate and correct gate this test must not route around.
    // Both shapes reach the same `resolveProtectCredential`, so leaving the
    // flag off keeps the assertion about the resolver and keeps the test
    // platform-stable.
    await runWrap(
      {
        claudeCode: true,
        noOpen: true,
        provisionAgentAccount: false,
        fortress,
        protectCommand: true,
      },
      wrapDeps(),
    );

    // It minted, and the credential it minted is the one that opens the
    // fortress it just wrote — the pairing the A73 blocker broke.
    const minted = await readStoredPassphrase({ storagePath: fortress });
    expect(minted).not.toBeNull();
    const master = await unlockExistingMasterReadOnly(
      new FilesystemStorage(join(fortress, "state")),
      { passphrase: minted!.value, storagePathHint: fortress },
    );
    expect(master.length).toBe(32);
    master.fill(0);
  }, 120_000);

  it("export-passphrase prints the stored passphrase, not the custody factor, when both unlock", async () => {
    // Both host-local factors open this fortress. The unlocking verbs rank the
    // custody factor first (it is the one `init` leaves behind), but this verb
    // is a BACKUP: the custody factor is 32 raw bytes no SANCTUARY_PASSPHRASE
    // consumer accepts, so inheriting that order printed an unusable credential
    // while the help promised the passphrase. Before the fix stdout carried
    // base64url of the custody key.
    const { mkdir } = await import("node:fs/promises");
    const { getOrCreateKeychainCustodyKey } = await import(
      "../../src/wrap/keychain-custody.js"
    );
    const { establishMaster, wrapMasterWithPassphrase, writeCustodyEnvelope } =
      await import("../../src/core/master-custody.js");
    const { persistUserProvidedPassphrase } = await import(
      "../../src/wrap/passphrase.js"
    );
    const BOTH_FACTORS_PASSPHRASE = "export-order-passphrase-not-a-real-secret";

    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(fortress, "state"));
    const custodyKey = await getOrCreateKeychainCustodyKey(fortress);
    expect(custodyKey).not.toBeNull();
    const established = await establishMaster({
      storage,
      keychainKey: custodyKey!,
      firstRun: { installMode: "interactive", mintRecoveryKey: false },
      storagePathHint: fortress,
    });
    // Enroll a SECOND wrap of the same master, so the envelope genuinely opens
    // under either factor; a passphrase that did not unlock would be rejected
    // by the resolver and would not discriminate the two orders.
    await writeCustodyEnvelope(
      storage,
      {
        ...established.envelope!,
        wraps: [
          ...established.envelope!.wraps,
          await wrapMasterWithPassphrase(
            established.masterKey,
            BOTH_FACTORS_PASSPHRASE,
            { verified: true },
          ),
        ],
      },
      established.masterKey,
    );
    established.masterKey.fill(0);
    await persistUserProvidedPassphrase(BOTH_FACTORS_PASSPHRASE, {
      storagePath: fortress,
    });

    process.env.SANCTUARY_STORAGE_PATH = fortress;
    const written: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);

    await runExportPassphrase(["--yes"]);

    expect(written.join("").trim()).toBe(BOTH_FACTORS_PASSPHRASE);
    expect(written.join("")).not.toContain(toBase64url(custodyKey!));
    custodyKey!.fill(0);
  }, 120_000);

  it("export-passphrase prints the enrolled custody factor, not a stale stored passphrase, when only the custody factor unlocks", async () => {
    // A stored passphrase item is PRESENT on this host (a leftover from a
    // replaced fortress instance, or a stale write) but was never added as a
    // wrap on THIS envelope, so it does not unlock it; only the enrolled
    // custody factor does. The verb's stored-first call
    // (`resolveHostLocal(["stored-passphrase"])`) must actually verify the
    // candidate against the envelope, not just observe that a keyring item
    // exists, or it would resolve on the stale value and print an unusable
    // credential while the help promises "when one unlocks this fortress."
    const { mkdir } = await import("node:fs/promises");
    const { getOrCreateKeychainCustodyKey } = await import(
      "../../src/wrap/keychain-custody.js"
    );
    const { establishMaster } = await import("../../src/core/master-custody.js");
    const { persistUserProvidedPassphrase } = await import(
      "../../src/wrap/passphrase.js"
    );
    const STALE_PASSPHRASE = "stale-leftover-passphrase-not-a-real-secret";

    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    const storage = new FilesystemStorage(join(fortress, "state"));
    const custodyKey = await getOrCreateKeychainCustodyKey(fortress);
    expect(custodyKey).not.toBeNull();
    const established = await establishMaster({
      storage,
      keychainKey: custodyKey!,
      firstRun: { installMode: "interactive", mintRecoveryKey: false },
      storagePathHint: fortress,
    });
    established.masterKey.fill(0);
    // Deliberately NOT added as a wrap on `established.envelope`: this
    // passphrase is present on the host but proves nothing about this
    // envelope.
    await persistUserProvidedPassphrase(STALE_PASSPHRASE, {
      storagePath: fortress,
    });

    process.env.SANCTUARY_STORAGE_PATH = fortress;
    const written: string[] = [];
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);

    await runExportPassphrase(["--yes"]);

    // The enrolled factor, never the stale passphrase, and the
    // machine-resident warning fires because a keychain key was printed.
    expect(written.join("").trim()).toBe(toBase64url(custodyKey!));
    expect(written.join("")).not.toContain(STALE_PASSPHRASE);
    const notices = vi
      .mocked(console.error)
      .mock.calls.map((call) => String(call[0]))
      .join("\n");
    expect(notices).toContain(
      "OS-keyring custody factor for this fortress on this host",
    );
    custodyKey!.fill(0);
  }, 120_000);

  it("refuses instead of minting when no host-local factor opens the fortress", async () => {
    // An envelope this host holds no credential for: the one thing protect must
    // NOT do is mint a fresh passphrase and then fail to unlock with it, which
    // is the A73 blocker verbatim.
    const { mkdir } = await import("node:fs/promises");
    const { establishMaster } = await import("../../src/core/master-custody.js");
    await mkdir(join(fortress, "state"), { recursive: true, mode: 0o700 });
    const seeded = await establishMaster({
      storage: new FilesystemStorage(join(fortress, "state")),
      passphrase: "a-credential-this-host-does-not-store",
      firstRun: { installMode: "headless", mintRecoveryKey: true },
      storagePathHint: fortress,
    });
    seeded.masterKey.fill(0);

    await expect(
      runWrap(
        {
          claudeCode: true,
          noOpen: true,
          agentGuided: true,
          provisionAgentAccount: false,
          fortress,
          protectCommand: true,
        },
        wrapDeps(),
      ),
    ).rejects.toBeInstanceOf(ProcessExit);
    // Nothing was minted over the existing envelope.
    expect(await readStoredPassphrase({ storagePath: fortress })).toBeNull();
  }, 120_000);
});
