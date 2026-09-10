// fail-before-exempt: fixture-only edit. The shared InstallProbeResult fixture gains the additive vaultProvision observation with the neutral "unknown" value; no assertion changed. The behavior it feeds is proven in test/cli/install.test.ts.
/**
 * Capability under test (AGENTS.md rule 4, wired consumer): the credential
 * `sanctuary init` enrols is the credential every stage of the install
 * contract uses, end to end. This runs `init`, then the install planner, then
 * the EXACT `protect` argv that planner emits, and lets that run start the
 * REAL standalone dashboard, with no credential supplied at any stage. The
 * dashboard then answers an authenticated HTTP request, which is the operator-
 * visible form of "the fortress opened".
 *
 * Register: defect.dashboard-boot-ignores-enrolled-keyring-custody-factor.
 *
 * Why the dashboard closure is REAL here and stubbed in
 * `protect-uses-enrolled-custody.test.ts`: that file proves what `protect`
 * itself establishes custody with, so it mocks the dashboard away. This file
 * proves the other half, the boot `protect` starts.
 *
 * Every keyring read and write here goes through the wrap keychain chokepoint,
 * which the suite serves from the in-memory store (test/setup/keychain-fake.ts):
 * no `security` / `secret-tool` subprocess runs, and the operator's login
 * keychain and real `~/.sanctuary` are never touched.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
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

// NOTE: `src/dashboard-standalone.js` is deliberately NOT mocked here. It is
// the module under test.

import { parseWrapArgs, runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";
import { runInit } from "../../src/wrap/init.js";
import {
  buildAgentInstallPlan,
  probeCustodyAccess,
  type InstallProbeResult,
} from "../../src/cli/install.js";
import { startStandaloneDashboard } from "../../src/dashboard-standalone.js";
import type { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { readKeychainCustodyKey } from "../../src/wrap/keychain-custody.js";
import { readStoredPassphrase } from "../../src/wrap/passphrase.js";
import { getPlatformPaths } from "../../src/wrap/config-reader.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomTestPort } from "../util/port-collision-retry.js";

const ENV_KEYS = [
  "HOME",
  "SANCTUARY_STORAGE_PATH",
  "SANCTUARY_FORTRESS_PATH",
  "SANCTUARY_PASSPHRASE",
  "SANCTUARY_RECOVERY_KEY",
  "SANCTUARY_INIT_NO_PIN",
] as const;

type EnvKey = (typeof ENV_KEYS)[number];

/** Explicit operator token, so the HTTP assertion below can authenticate. */
const DASHBOARD_TOKEN = "protect-contract-dashboard-token-not-a-secret";

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
    // Base fixture: this vault carries no wall claim, which is not a claim of
    // protection either. Tests that need one set it explicitly.
    vaultProvision: "unknown",
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

describe("the install-emitted protect argv boots the real dashboard", () => {
  let home: string;
  let fortress: string;
  let originalEnv: Record<EnvKey, string | undefined>;
  let originalStdinIsTTY: boolean | undefined;
  let started: DashboardApprovalChannel[];
  /** Every port `ensureMainDashboardForWrap` asked the starter to bind. */
  let requestedPorts: number[];
  /** Every port the starter actually bound, in start order. */
  let boundPorts: number[];

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "a73-protect-dashboard-"));
    fortress = join(home, "sanctuary-daily");
    started = [];
    requestedPorts = [];
    boundPorts = [];
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
    for (const dashboard of started) {
      await dashboard.stop().catch(() => undefined);
    }
    started = [];
    requestedPorts = [];
    boundPorts = [];
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
  async function initFortress(): Promise<void> {
    await runInit(
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
        // OS-keyring custody factor. The PROMPT is stubbed, the CHECK is not:
        // re-entry is what promotes the minted recovery wrap to `verified`,
        // and a fixture that skips it leaves the fortress below the
        // two-verified-factor custody floor — a different refusal from the
        // one this file is about, arriving at the same boot.
        verifyRecoveryKeyReentry: (async (args: {
          check: (entered: string) => Promise<boolean>;
        }) => {
          const disclosed = await readFile(
            join(home, "recovery-key.txt"),
            "utf-8",
          );
          const recoveryKey = disclosed
            .split("\n")
            .map((line) => line.trim())
            .find((line) => /^[A-Za-z0-9_-]{43}$/.test(line));
          if (recoveryKey === undefined) {
            throw new Error("fixture: no recovery key in the disclosure file");
          }
          expect(await args.check(recoveryKey)).toBe(true);
        }) as never,
      },
    );
  }

  /**
   * The PRODUCTION dashboard seam (`RunWrapDeps.startOwnedDashboard`), wired
   * the way `src/cli.ts` wires it: a closure over the real
   * `startStandaloneDashboard` that binds EXACTLY the port
   * `ensureMainDashboardForWrap` asked for. Binding a port of the closure's own
   * choosing instead would make the test blind to the contract production
   * depends on — `ensureMainDashboardForWrap` walks `requestedPort + i` on
   * EADDRINUSE and reports the port it believes was bound, so a starter that
   * silently binds elsewhere would emit a URL nothing is listening on and the
   * test would still pass.
   *
   * The test-shaped deviations are the requested port itself (seeded through
   * `options.port` to an ephemeral value, since the production default is a
   * fixed port two CI workers would collide on), an ephemeral distress port,
   * and an explicit auth token so the HTTP assertion can authenticate. None of
   * the three is an input to credential resolution.
   */
  function wrapDeps(): RunWrapDeps {
    return {
      startOwnedDashboard: async ({ storagePath, port, passphrase }) => {
        requestedPorts.push(port);
        const dashboard = await startStandaloneDashboard({
          storagePath,
          port,
          host: "127.0.0.1",
          distressPort: 0,
          authToken: DASHBOARD_TOKEN,
          ...(passphrase !== undefined ? { passphrase } : {}),
          mintAuthTokenIfAbsent: true,
        });
        started.push(dashboard);
        boundPorts.push(port);
        return { url: `http://127.0.0.1:${port}`, port };
      },
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

  it("runs the emitted argv to completion, dashboard included, and writes no secret into the wrapped config", async () => {
    await initFortress();

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
    // The contract forbids adding a credential, so the argv the planner emits
    // carries none and the dashboard it starts inherits none.
    const flags = protectFlagsFrom(argv!);
    expect(flags).not.toContain("--passphrase");
    // The planner's REAL emission, asserted flag-for-flag rather than by
    // substring over the joined string: `--no-open` is what keeps this run
    // non-interactive, and `--no-provision-agent-account` is what keeps it
    // from reaching agent-account provisioning. A test that ran a flag set the
    // planner does not emit would prove nothing about the shipped contract,
    // and `toContain` on the joined string cannot tell `--no-open` apart from
    // a hypothetical `--no-open-browser`.
    expect(flags).toContain("--claude-code");
    expect(flags).toContain("--agent-guided");
    expect(flags).toContain("--no-open");
    expect(flags).toContain("--no-provision-agent-account");

    const enrolled = await readKeychainCustodyKey(fortress);
    expect(enrolled).not.toBeNull();

    // Before the fix this reached the dashboard boot and threw "cannot unlock
    // this fortress ... with the available factors", naming only the
    // sanctuary-passphrase service: `protect` opened the fortress with the
    // enrolled factor and the dashboard it started refused the same fortress.
    const options = parseWrapArgs(flags);
    // `resolveDashboardPort` returns this verbatim, so it becomes the
    // `requestedPort` `ensureMainDashboardForWrap` hands the starter.
    const requestedPort = randomTestPort();
    await runWrap(
      { ...options, fortress, protectCommand: true, port: requestedPort },
      wrapDeps(),
    );

    // Exit 0: the run completed and never reached a refusal path (every
    // `process.exit` in this suite throws `ProcessExit`, so arriving here is
    // the assertion), and the dashboard really booted.
    expect(started.length).toBe(1);
    expect(started[0]!.isParked()).toBe(false);

    // The starter bound the port it was ASKED for, on the first attempt: no
    // walk, so the URL `ensureMainDashboardForWrap` reports is the URL that is
    // listening.
    expect(requestedPorts).toEqual([requestedPort]);
    expect(boundPorts).toEqual([requestedPort]);

    // The fortress really OPENED, over HTTP, on the port the contract emitted.
    // `isParked()` is the boot's own account of itself; a protected route
    // answering 200 needs the master-key-derived dependencies to have been
    // wired and served, which is the thing the operator actually gets.
    const res = await fetch(
      `http://127.0.0.1:${String(requestedPort)}/api/status`,
      { headers: { Authorization: `Bearer ${DASHBOARD_TOKEN}` } },
    );
    expect(res.status).toBe(200);

    // The fortress was opened by the factor `init` enrolled, not by a mint.
    expect(await readStoredPassphrase({ storagePath: fortress })).toBeNull();

    // No secret in anything the wrap wrote to the harness config.
    const enrolledEncoded = toBase64url(enrolled!);
    for (const path of getPlatformPaths()["claude-code"]) {
      const contents = await readFile(path, "utf-8").catch(() => null);
      if (contents === null) continue;
      expect(contents).not.toContain(enrolledEncoded);
      expect(contents).not.toContain("SANCTUARY_PASSPHRASE");
      expect(contents).not.toContain("SANCTUARY_RECOVERY_KEY");
    }
    enrolled!.fill(0);
  }, 180_000);
});
