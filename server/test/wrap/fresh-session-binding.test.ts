/** Automatic default binding requires this invocation's directory creation and identity seed. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { runInit, type InitOptions } from "../../src/wrap/init.js";
import { runWrap, __processShutdownCleanupCountForTest } from "../../src/wrap/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import * as config from "../../src/config.js";
import { createTempHome, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

let home: Awaited<ReturnType<typeof createTempHome>>;
let fortress: string;
beforeEach(async () => {
  home = await createTempHome("fresh-session-binding");
  fortress = home.defaultFortressPath;
  vi.stubEnv("SANCTUARY_PASSPHRASE", TEST_PASSPHRASE);
  vi.stubEnv("SANCTUARY_INIT_NO_IDENTITY", undefined);
});
afterEach(async () => { vi.restoreAllMocks(); vi.unstubAllEnvs(); await home.cleanup(); });
async function flag() {
  try { return JSON.parse(await readFile(join(fortress, "sanctuary.json"), "utf8")).session_binding; }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
}
const init = (options: InitOptions = {}) => runInit({ fortress, noConfirm: true, ...options }, { provisionPin: async () => 0 });

it("init that creates the directory writes the flag", async () => {
  await init();
  expect(await flag()).toEqual({ sole_identity: true });
});

it("init on an existing empty fortress (made with --no-identity) does not", async () => {
  await init({ noIdentity: true, recoveryOut: join(home.home, "first-recovery.txt") });
  expect(await flag()).toBeUndefined();
  await init({ force: true, recoveryOut: join(home.home, "second-recovery.txt") });
  expect(await flag()).toBeUndefined();
});

it("init --force over an existing directory does not", async () => {
  await mkdir(fortress, { recursive: true });
  await init({ force: true });
  expect(await flag()).toBeUndefined();
});

it("init on a pre-existing empty directory does not write the flag", async () => {
  await mkdir(fortress, { recursive: true });
  await init();
  expect(await flag()).toBeUndefined();
});

it("the fortress-creating call reports an existing directory as not fresh", async () => {
  const token = await config.createFreshFortress(fortress);
  expect(token).toBeDefined();
  expect(await config.createFreshFortress(fortress)).toBeUndefined();
  await config.writeSoleBindingForFreshFortress(token!, join(fortress, "sanctuary.json"));
  expect(await flag()).toEqual({ sole_identity: true });
});

it("creation evidence belongs to its own directory", async () => {
  const token = await config.createFreshFortress(fortress);
  const other = join(home.home, "other");
  await mkdir(other);
  await expect(config.writeSoleBindingForFreshFortress(token!, join(other, "sanctuary.json"))).rejects.toThrow("does not match");
});

it("a seed failure leaves default binding off", async () => {
  await expect(runInit({ fortress, noConfirm: true }, {
    provisionPin: async () => 0,
    beforeDurableMutation: label => { if (label === "operator-identity") throw new Error("seed unavailable"); },
  })).rejects.toThrow();
  expect(await flag()).toBeUndefined();
});

it("wrap on an existing empty fortress does not", async () => {
  await mkdir(fortress, { recursive: true });
  await runWrap({ claudeCode: true, noOpen: true, noDashboard: true }, {
    startDashboard: async () => ({ url: "http://127.0.0.1:0", port: 0, host: "127.0.0.1", mode: "co-located", stop: async () => {} }) as unknown as DashboardHandle,
    resolvePassphrase: async () => ({ value: TEST_PASSPHRASE, location: "test-keychain", source: "generated" }),
    openBrowser: async () => {},
  });
  expect(await flag()).toBeUndefined();
});

it.each([true, false])("wrap that creates its directory writes the flag (no dashboard: %s)", async noDashboard => {
  await runWrap({ claudeCode: true, noOpen: true, noDashboard }, {
    startDashboard: async () => ({ url: "http://127.0.0.1:0", port: 0, host: "127.0.0.1", mode: "co-located", stop: async () => {} }) as unknown as DashboardHandle,
    resolvePassphrase: async () => ({ value: TEST_PASSPHRASE, location: "test-keychain", source: "generated" }),
    openBrowser: async () => {},
  });
  expect(await flag()).toEqual({ sole_identity: true });
});

it("a parent created by the fortress call also proves freshness", async () => {
  const nested = join(home.home, "new-parent", "fortress");
  const token = await config.createFreshFortress(nested);
  expect(token).toBeDefined();
  await config.writeSoleBindingForFreshFortress(token!, join(nested, "sanctuary.json"));
  expect(JSON.parse(await readFile(join(nested, "sanctuary.json"), "utf8")).session_binding).toEqual({ sole_identity: true });
});

it("an identity audit failure leaves default binding off", async () => {
  await expect(runInit({ fortress, noConfirm: true }, {
    provisionPin: async () => 0,
    beforeDurableMutation: label => { if (label === "audit-identity-seeded") throw new Error("audit unavailable"); },
  })).rejects.toThrow();
  expect(await flag()).toBeUndefined();
});

it("wrap with a pre-resolved credential prints the explicit enable command", async () => {
  const stderr = vi.spyOn(console, "error");
  await runWrap({ claudeCode: true, noOpen: true, noDashboard: true,
    agentGuided: true, protectCommand: true, provisionAgentAccount: false }, {
    osPlatform: () => "linux",
    startDashboard: async () => ({ url: "http://127.0.0.1:0", port: 0, host: "127.0.0.1", mode: "co-located", stop: async () => {} }) as unknown as DashboardHandle,
    resolvePassphrase: async () => ({ value: TEST_PASSPHRASE, location: "test-keychain", source: "generated" }),
    openBrowser: async () => {},
  });
  expect(await flag()).toBeUndefined();
  expect(stderr.mock.calls.flat().join("\n")).toContain("sanctuary session-binding enable --fortress");
});

const enableCommand = "sanctuary session-binding enable --fortress";
const wrapDeps = {
  startDashboard: async () => ({ url: "http://127.0.0.1:0", port: 0, host: "127.0.0.1", mode: "co-located", stop: async () => {} }) as unknown as DashboardHandle,
  resolvePassphrase: async () => ({ value: TEST_PASSPHRASE, location: "test-keychain", source: "generated" as const }),
  openBrowser: async () => {},
};

it.each([
  ["--no-identity", async () => init({ noIdentity: true })],
  ["a pre-existing directory", async () => { await mkdir(fortress, { recursive: true }); await init(); }],
] as const)("init that leaves default binding off after %s prints the enable command", async (_case, run) => {
  const stderr = vi.spyOn(console, "error");
  await run();
  expect(await flag()).toBeUndefined();
  expect(stderr.mock.calls.flat().join("\n")).toContain(enableCommand);
});

it("init that writes the flag prints no enable command", async () => {
  const stderr = vi.spyOn(console, "error");
  await init();
  expect(await flag()).toEqual({ sole_identity: true });
  expect(stderr.mock.calls.flat().join("\n")).not.toContain(enableCommand);
});

it("a failed flag write at init completes init, leaves binding off and says so", async () => {
  const stderr = vi.spyOn(console, "error");
  vi.spyOn(config, "writeSoleBindingForFreshFortress").mockRejectedValue(new Error("config writer unavailable"));
  await expect(init()).resolves.toBeDefined();
  expect(await flag()).toBeUndefined();
  const text = stderr.mock.calls.flat().join("\n");
  expect(text).toContain("default session binding not enabled at init time (config writer unavailable)");
  expect(text).toContain(enableCommand);
});

it.each([true, false])("a failed flag write at wrap is reported apart from the identity seed (no dashboard: %s)", async noDashboard => {
  const stderr = vi.spyOn(console, "error");
  vi.spyOn(config, "writeSoleBindingForFreshFortress").mockRejectedValue(new Error("config writer unavailable"));
  await runWrap({ claudeCode: true, noOpen: true, noDashboard }, wrapDeps);
  expect(await flag()).toBeUndefined();
  const text = stderr.mock.calls.flat().join("\n");
  expect(text).toContain("default session binding not enabled at wrap time (config writer unavailable)");
  expect(text).toContain(enableCommand);
  expect(text).not.toContain("default identity not created at wrap time");
});

it("a failed flag write at wrap still unregisters the no-dashboard audit flush", async () => {
  vi.spyOn(config, "writeSoleBindingForFreshFortress").mockRejectedValue(new Error("config writer unavailable"));
  const cleanupsBefore = __processShutdownCleanupCountForTest();
  await runWrap({ claudeCode: true, noOpen: true, noDashboard: true }, wrapDeps);
  expect(__processShutdownCleanupCountForTest()).toBe(cleanupsBefore);
});
