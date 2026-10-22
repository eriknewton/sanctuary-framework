/**
 * Real wrapper browser effects stay isolated under test and CI signals.
 * Injected openers remain observable without invoking the operator's browser.
 */
import { EventEmitter } from "node:events";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createTempFortress, type TempFortress } from "../helpers/temp-fortress.js";

const opener = vi.hoisted(() => ({ spawn: vi.fn() }));
vi.mock("node:child_process", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:child_process")>(),
  spawn: opener.spawn,
}));

import {
  __resetProcessShutdownStateForTest,
  runWrap,
  type RunWrapDeps,
} from "../../src/wrap/cli.js";

const DASHBOARD_URL = "http://127.0.0.1:3501";
const TEST_SIGNALS = ["VITEST", "VITEST_WORKER_ID", "NODE_ENV", "CI"] as const;

// Custody cleanup can also spawn a Linux scaffold reaper. This contract is
// specifically the OS browser boundary; every child remains mocked above.
function browserSpawnCalls() {
  return opener.spawn.mock.calls.filter(([command]) =>
    command === "open" || command === "cmd" || command === "xdg-open");
}

describe("wrapper default browser isolation", () => {
  let fortress: TempFortress;
  let configPath: string;
  let startOwnedDashboard: NonNullable<RunWrapDeps["startOwnedDashboard"]>;

  beforeEach(async () => {
    fortress = await createTempFortress("bo");
    vi.stubEnv("SANCTUARY_FORTRESS_PATH", undefined);
    vi.stubEnv("SANCTUARY_RECOVERY_KEY", undefined);
    vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", undefined);
    for (const signal of TEST_SIGNALS) vi.stubEnv(signal, undefined);
    configPath = join(fortress.home, "agent.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: { demo: { command: "node", args: ["demo.js"] } },
    }));
    startOwnedDashboard = vi.fn(async () => ({ url: DASHBOARD_URL, port: 3501 }));
    // No child is ever started, including on the unguarded source: emulate only
    // the spawn event/unref contract that the real browser opener consumes.
    opener.spawn.mockReset();
    opener.spawn.mockImplementation(() => {
      const child = Object.assign(new EventEmitter(), { unref: vi.fn() });
      queueMicrotask(() => child.emit("spawn"));
      return child;
    });
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    vi.unstubAllEnvs();
    __resetProcessShutdownStateForTest();
    vi.restoreAllMocks();
    await fortress.cleanup();
  });

  function deps(): RunWrapDeps {
    return {
      startOwnedDashboard,
      probeDashboardHealth: async () => false,
      resolvePassphrase: async () => ({
        value: "browser-isolation-fixture-passphrase",
        location: "test-memory-store",
        source: "stored-passphrase",
      }),
      checkPinResolvability: async () => "resolvable",
      runAutoProvisionForWrap: async () => ({ ran: false }),
    };
  }

  it.each([
    ["VITEST", "true"],
    ["NODE_ENV", "test"],
    ["CI", "1"],
  ] as const)("refuses an OS opener with only %s=%s", async (signal, value) => {
    vi.stubEnv(signal, value);
    await runWrap({ wrap: configPath }, deps());
    expect(startOwnedDashboard).toHaveBeenCalledOnce();
    expect(browserSpawnCalls()).toEqual([]);
  });

  it("preserves an injected opener under test signals", async () => {
    vi.stubEnv("VITEST", "true");
    const openBrowser = vi.fn(async () => {});
    await runWrap({ wrap: configPath }, { ...deps(), openBrowser });
    expect(openBrowser).toHaveBeenCalledExactlyOnceWith(DASHBOARD_URL);
    expect(browserSpawnCalls()).toEqual([]);
  });

  it("preserves --no-open without relying on a test signal", async () => {
    await runWrap({ wrap: configPath, noOpen: true }, deps());
    expect(startOwnedDashboard).toHaveBeenCalledOnce();
    expect(browserSpawnCalls()).toEqual([]);
  });

  it("routes ordinary production opening to the mocked OS process", async () => {
    await runWrap({ wrap: configPath }, deps());
    const command = process.platform === "darwin" ? "open"
      : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", DASHBOARD_URL] : [DASHBOARD_URL];
    expect(browserSpawnCalls()).toEqual([[command, args, {
      stdio: "ignore", detached: true,
    }]]);
  });
});
