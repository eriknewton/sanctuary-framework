import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  access,
  mkdtemp,
  readFile,
  rm,
  stat,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const castleWallMocks = vi.hoisted(() => ({
  runProvisionPin: vi.fn(async () => 0),
  startMacOSCastleWallDaemon: vi.fn(async () => ({
    stop: async () => {},
  })),
}));

vi.mock("../../src/cli/castle-wall.js", () => ({
  runProvisionPin: castleWallMocks.runProvisionPin,
}));

vi.mock("../../src/castle-wall/runtime/index.js", () => ({
  startMacOSCastleWallDaemon: castleWallMocks.startMacOSCastleWallDaemon,
  // Opt-in producer-signed Linux activation is OFF by default (mirrors the real
  // `isLinuxProducerSignedActivationRequested`, which reads false without the
  // explicit env flag). On Linux CI this keeps the wrap flow on the macOS-daemon
  // channel basis the assertions below expect, instead of routing into the
  // Linux activation gate.
  isLinuxProducerSignedActivationRequested: () => false,
}));

import {
  runWrap,
  type DashboardStarter,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";
import { runInit, type RunInitDeps } from "../../src/wrap/init.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import type { ExecResult } from "../../src/wrap/passphrase.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { toBase64url } from "../../src/core/encoding.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  loadPrincipalPolicy,
  parsePolicy,
} from "../../src/principal-policy/loader.js";
import { readPersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";
import { RECOVERY_KEY_FILENAME } from "../../src/wrap/recovery-key-disclosure.js";

const WRAP_PASSPHRASE = "fresh-install-wrap-passphrase";
const INIT_PASSPHRASE = "fresh-install-init-passphrase";

const ENV_KEYS = [
  "HOME",
  "SANCTUARY_STORAGE_PATH",
  "SANCTUARY_FORTRESS_PATH",
  "SANCTUARY_PASSPHRASE",
  "SANCTUARY_RECOVERY_OUT",
  "SANCTUARY_INIT_NO_PIN",
] as const;

type EnvKey = (typeof ENV_KEYS)[number];

function restoreEnv(key: EnvKey, value: string | undefined): void {
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

function extractRecoveryKey(fileContent: string): string {
  const keyLine = fileContent
    .split("\n")
    .map((line) => line.trim())
    .find((line) => /^[A-Za-z0-9_-]{43}$/.test(line));
  if (!keyLine) throw new Error("recovery key not found");
  return keyLine;
}

function makeLinuxRecoveryKeychain(): NonNullable<RunInitDeps["recoveryKeychain"]> {
  const stored = new Map<string, string>();
  return {
    home: "/tmp/sanctuary-fresh-install-smoke-home",
    platformOverride: "linux",
    exec: async (
      cmd: string,
      args: string[],
      input?: string,
    ): Promise<ExecResult> => {
      if (cmd !== "secret-tool") {
        return { stdout: "", stderr: "unexpected command", code: 1 };
      }
      const service = args[args.indexOf("service") + 1] ?? "";
      if (args[0] === "store" && input) {
        stored.set(service, input.trim());
        return { stdout: "", stderr: "", code: 0 };
      }
      if (args[0] === "lookup") {
        const value = stored.get(service);
        return value
          ? { stdout: `${value}\n`, stderr: "", code: 0 }
          : { stdout: "", stderr: "not found", code: 1 };
      }
      return { stdout: "", stderr: "unexpected args", code: 1 };
    },
  };
}

async function expectMissing(path: string): Promise<void> {
  await expect(access(path)).rejects.toThrow();
}

async function expectFortressDirectory(path: string): Promise<void> {
  const fortress = await stat(path);
  expect(fortress.isDirectory()).toBe(true);
  expect(fortress.mode & 0o777).toBe(0o700);
  const state = await stat(join(path, "state"));
  expect(state.isDirectory()).toBe(true);
}

async function expectDefaultPolicy(path: string): Promise<void> {
  // This mirrors first MCP/dashboard boot: loadPrincipalPolicy is the real
  // provisioning path for a missing principal-policy.yaml.
  const policy = await loadPrincipalPolicy(path);
  const policyPath = join(path, "principal-policy.yaml");
  const raw = await readFile(policyPath, "utf-8");
  const parsed = parsePolicy(raw);

  expect(policy.tier1_always_approve).toContain("state_export");
  expect(policy.tier3_always_allow).toContain("state_read");
  expect(parsed.approval_channel.type).toBe("stderr");
  expect(parsed.approval_channel.timeout_seconds).toBe(300);
}

async function expectAuditChain(
  storage: FilesystemStorage,
  masterKey: Uint8Array,
  expectedOps: string[],
): Promise<void> {
  const auditLog = new AuditLog(storage, masterKey);
  const audit = await auditLog.query({ limit: 100 });
  expect(audit.total).toBeGreaterThanOrEqual(expectedOps.length);
  expect(audit.integrity_findings).toEqual([]);
  expect(audit.entries.map((entry) => entry.operation)).toEqual(
    expect.arrayContaining(expectedOps),
  );
}

describe("fresh-install onboarding smoke", () => {
  let tmpHome: string;
  let originalEnv: Record<EnvKey, string | undefined>;
  let originalStdinIsTTY: boolean | undefined;

  beforeEach(async () => {
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-fresh-install-smoke-"));
    originalEnv = Object.fromEntries(
      ENV_KEYS.map((key) => [key, process.env[key]]),
    ) as Record<EnvKey, string | undefined>;
    originalStdinIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: false,
    });
    process.env.HOME = tmpHome;
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_FORTRESS_PATH;
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_OUT;
    delete process.env.SANCTUARY_INIT_NO_PIN;

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
  });

  afterEach(async () => {
    for (const key of ENV_KEYS) restoreEnv(key, originalEnv[key]);
    Object.defineProperty(process.stdin, "isTTY", {
      configurable: true,
      value: originalStdinIsTTY,
    });
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  it("wraps a fresh Claude Code install into a ready fortress without external services", async () => {
    const fortressPath = join(tmpHome, ".sanctuary-wrap");
    await expectMissing(fortressPath);

    const openedUrls: string[] = [];
    const startCalls: Parameters<DashboardStarter>[0][] = [];
    const assignedPort = 46321;
    const sessionUrl = `http://127.0.0.1:${assignedPort}/v1.1?session=fresh-install`;
    let v11BindingsSet = false;
    let loopbackAutoAuth: boolean | undefined;

    const dashboard = {
      url: `http://127.0.0.1:${assignedPort}`,
      port: assignedPort,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
      createSessionUrl: () => sessionUrl,
      setV11Bindings: () => {
        v11BindingsSet = true;
      },
      setV11LoopbackAutoAuth: (enabled: boolean) => {
        loopbackAutoAuth = enabled;
      },
      updateSources: () => {},
    } as unknown as DashboardHandle;

    const deps: RunWrapDeps = {
      startDashboard: async (opts) => {
        startCalls.push(opts);
        return dashboard;
      },
      openBrowser: async (url) => {
        openedUrls.push(url);
      },
      resolvePassphrase: async () => ({
        value: WRAP_PASSPHRASE,
        location: "fixture-keychain",
        source: "generated",
      }),
      installClaudeCodeAllowlist: async () => ({
        installedAt: join(tmpHome, ".claude", "settings.json"),
        alreadyPresent: true,
        added: [],
      }),
    };

    await runWrap({ claudeCode: true, fortress: fortressPath }, deps);

    await expectFortressDirectory(fortressPath);
    await expectDefaultPolicy(fortressPath);

    const claudeConfig = JSON.parse(
      await readFile(join(tmpHome, ".claude.json"), "utf-8"),
    ) as {
      mcpServers?: Record<
        string,
        { command?: string; args?: string[]; env?: Record<string, string> }
      >;
    };
    expect(claudeConfig.mcpServers?.sanctuary?.command).toBe("npx");
    expect(claudeConfig.mcpServers?.sanctuary?.env?.SANCTUARY_FORTRESS_PATH).toBe(
      fortressPath,
    );

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const unlocked = await establishMaster({
      storage,
      passphrase: WRAP_PASSPHRASE,
      storagePathHint: fortressPath,
    });
    try {
      expect(unlocked.origin).toBe("envelope");
      expect(unlocked.masterKey).toHaveLength(32);
      expect(unlocked.envelope?.wraps.map((wrap) => wrap.type)).toEqual(
        expect.arrayContaining(["passphrase", "recovery-key"]),
      );

      const identityMgr = new IdentityManager(storage, unlocked.masterKey);
      const identityLoad = await identityMgr.load();
      expect(identityLoad).toEqual({ total: 1, loaded: 1, failed: 0 });
      expect(identityMgr.list()).toMatchObject([
        { label: "default", key_protection: "passphrase" },
      ]);

      await expectAuditChain(storage, unlocked.masterKey, [
        "custody_envelope_created",
        "custody_headless_install",
        "custody_wrap_added",
        "identity_create",
      ]);
    } finally {
      unlocked.masterKey.fill(0);
    }

    const agents = readPersistedLocalAgents(fortressPath);
    expect(agents).toHaveLength(1);
    expect(agents[0]?.harness).toBe("claude_code");

    expect(startCalls).toHaveLength(1);
    expect(startCalls[0]).toMatchObject({
      port: 3501,
      mode: "co-located",
    });
    expect(startCalls[0]?.authToken).toMatch(/^[A-Za-z0-9_-]+$/);
    // Dashboard-fold PR-4 (ratified decision 1): the wrap path no longer
    // decorates a wrap-owned server handle. The browser opens the ensured
    // dashboard's plain URL (the ONE main dashboard authenticates its own
    // clients — loopback auto-auth after unlock lives in ITS boot path), and
    // wrap performs no v1.1-binding or loopback-auto-auth wiring on any
    // handle: the main dashboard builds its own bindings at boot.
    expect(openedUrls).toEqual([`http://127.0.0.1:${assignedPort}`]);
    expect(v11BindingsSet).toBe(false);
    expect(loopbackAutoAuth).toBeUndefined();
    expect(castleWallMocks.runProvisionPin).toHaveBeenCalledWith(
      [],
      expect.objectContaining({
        env: expect.objectContaining({
          SANCTUARY_STORAGE_PATH: fortressPath,
          SANCTUARY_PASSPHRASE: WRAP_PASSPHRASE,
        }),
      }),
    );
    expect(castleWallMocks.startMacOSCastleWallDaemon).toHaveBeenCalledWith(
      expect.objectContaining({ fortressPath }),
    );
  });

  it("initializes a headless no-confirm fortress into a resolvable ready state", async () => {
    const fortressPath = join(tmpHome, ".sanctuary-init");
    process.env.SANCTUARY_PASSPHRASE = INIT_PASSPHRASE;
    await expectMissing(fortressPath);

    const result = await runInit(
      {
        fortress: fortressPath,
        noConfirm: true,
        noPin: true,
      },
      {
        recoveryKeychain: makeLinuxRecoveryKeychain(),
        provisionPin: vi.fn(async () => 0),
      },
    );

    expect(result.fortressPath).toBe(fortressPath);
    expect(result.recoveryKeyDisclosurePath).toBe(
      join(fortressPath, RECOVERY_KEY_FILENAME),
    );
    await expectFortressDirectory(fortressPath);
    await expectDefaultPolicy(fortressPath);

    const recoveryFile = await readFile(result.recoveryKeyDisclosurePath, "utf-8");
    expect(recoveryFile).toContain("Recovery key:");
    const recoveryKey = extractRecoveryKey(recoveryFile);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const byRecovery = await establishMaster({
      storage,
      recoveryKey,
      storagePathHint: fortressPath,
    });
    const byPassphrase = await establishMaster({
      storage,
      passphrase: INIT_PASSPHRASE,
      storagePathHint: fortressPath,
    });
    try {
      expect(byRecovery.origin).toBe("envelope");
      expect(byPassphrase.origin).toBe("envelope");
      expect(toBase64url(byRecovery.masterKey)).toBe(
        toBase64url(byPassphrase.masterKey),
      );
      expect(byRecovery.envelope?.install_mode).toBe("headless");
      expect(byRecovery.envelope?.wraps.map((wrap) => wrap.type)).toEqual(
        expect.arrayContaining(["recovery-key", "passphrase"]),
      );

      await expectAuditChain(storage, byRecovery.masterKey, [
        "custody_envelope_created",
        "custody_headless_install",
        "castle_pin_provision_skipped",
      ]);
    } finally {
      byRecovery.masterKey.fill(0);
      byPassphrase.masterKey.fill(0);
    }
  });
});
