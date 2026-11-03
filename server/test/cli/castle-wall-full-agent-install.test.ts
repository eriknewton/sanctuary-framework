/** Attended LaunchAgent commands use injected host and credential boundaries. Job 996. */
import * as fs from "node:fs";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { StoredPassphraseObservation } from "../../src/wrap/passphrase.js";
import { CASTLE_WALL_BOOT_LABEL, type ExecFileResult } from "../../src/cli/castle-wall-boot.js";
const agentPath = "../../src/cli/castle-wall-full-agent.js";
const statePath = "../../src/cli/castle-wall-full-agent-state.js";
const api = await import(agentPath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent.js") | null;
const state = await import(statePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent-state.js") | null;
const roots: string[] = [];
beforeEach(() => { expect(api, "LaunchAgent commands are shipped").not.toBeNull(); expect(state).not.toBeNull(); });
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void) { this.text += String(chunk); callback(); }
}
function fixture() {
  const root = fs.mkdtempSync("/tmp/j996-install-"); roots.push(root);
  const home = join(root, "home"), fortress = join(root, "fortress"), cli = join(root, "cli.js");
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(fortress, { mode: 0o700 }); fs.writeFileSync(cli, "// fixture entry\n");
  let bootLoaded = false;
  let pid: number | null = 1234; // Fixed fake launchd process identity; never signalled.
  const exec = vi.fn((_command: string, args: string[]): ExecFileResult => {
    if (args[0] === "print" && args[1] === `system/${CASTLE_WALL_BOOT_LABEL}`) {
      return bootLoaded ? { code: 0, stdout: "state = running\npid = 111\n", stderr: "" } : { code: 113, stdout: "", stderr: "Could not find service" };
    }
    if (args[0] === "print") return { code: 0, stdout: pid === null ? "state = exited\n" : `state = running\npid = ${pid}\n`, stderr: "" };
    return { code: 0, stdout: "", stderr: "" };
  });
  const observe = vi.fn(async (): Promise<StoredPassphraseObservation> => ({ status: "found", result: { value: "fixture credential", source: "keychain", location: "fixture" }, keyringUnreachable: false }));
  const sleep = vi.fn(async (_ms: number) => {});
  const out = new Capture(), err = new Capture();
  const io = { ...fs };
  const write = vi.spyOn(io, "writeFileSync");
  const ctx: import("../../src/cli/castle-wall-full-agent.js").FullAgentCommandContext = {
    home, env: { HOME: home, SANCTUARY_STORAGE_PATH: fortress }, platform: "darwin", euid: 501,
    isTTY: true, cliPath: cli, execPath: process.execPath, out, err, fs: io,
    execFileFn: exec, observePassphrase: observe, sleep,
  };
  return { root, home, fortress, cli, out, err, ctx, exec, observe, sleep, write, setBoot: (value: boolean) => { bootLoaded = value; }, setPid: (value: number | null) => { pid = value; } };
}

describe("full agent attended commands", () => {
  it.each(["root", "boot-loaded", "missing-credential", "no-tty"])("refuses install for %s", async reason => {
    const f = fixture();
    if (reason === "root") f.ctx.euid = 0;
    if (reason === "boot-loaded") f.setBoot(true);
    if (reason === "missing-credential") f.observe.mockResolvedValue({ status: "absent", keyringUnreachable: false });
    if (reason === "no-tty") f.ctx.isTTY = false;
    expect(await api!.runInstallFull([], f.ctx)).not.toBe(0);
    expect(f.write).not.toHaveBeenCalled();
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "bootstrap")).toBe(false);
    if (reason === "boot-loaded") expect(f.err.text).toContain(`sudo launchctl bootout system/${CASTLE_WALL_BOOT_LABEL}`);
  });

  it("writes a 0644 plist, bootstraps gui uid, and observes one pid beyond throttle", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx), f.err.text).toBe(0);
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    expect(fs.statSync(plist).mode & 0o777).toBe(0o644);
    expect(api!.fullAgentLaunchAgentWellFormed(fs.readFileSync(plist, "utf8"))).toBe(true);
    expect(f.exec).toHaveBeenCalledWith("launchctl", ["bootstrap", "gui/501", plist]);
    expect(f.observe).toHaveBeenCalledWith({ storagePath: f.fortress, home: f.home, readOnly: true, platformOverride: "darwin" });
    expect(f.sleep.mock.calls.reduce((sum, [ms]) => sum + ms, 0)).toBeGreaterThan(api!.FULL_AGENT_THROTTLE_INTERVAL_S * 1000);
  });

  it("does not certify a restarting pid as stable", async () => {
    const f = fixture();
    f.sleep.mockImplementation(async () => { f.setPid(5678); }); // Different fake process after the first sample.
    expect(await api!.runInstallFull([], f.ctx)).toBe(1);
  });

  it("uninstall and reset require yes, and reset additionally requires a TTY", async () => {
    const f = fixture();
    expect(await api!.runUninstallFull([], f.ctx)).toBe(2);
    expect(await api!.runResetFull([], f.ctx)).toBe(2);
    f.ctx.isTTY = false;
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(2);
    expect(f.exec).not.toHaveBeenCalled();
  });

  it("uninstalls the registered user job and its plist", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    expect(await api!.runUninstallFull(["--yes"], f.ctx)).toBe(0);
    expect(f.exec).toHaveBeenCalledWith("launchctl", ["bootout", `gui/501/${api!.FULL_AGENT_LABEL}`]);
    expect(fs.existsSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`))).toBe(false);
  });

  it("resets a stopped latch before kickstart and status is never green for pid zero or a latch", async () => {
    const f = fixture();
    const store = new state!.FullAgentStateStore(f.fortress);
    for (let i = 0; i <= state!.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    f.setPid(null);
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => {
      if (args[0] === "kickstart") expect(store.read()?.state).toBe("state_STOPPED_CLEAN");
      return original(command, args);
    });
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(0);
    expect(f.exec).toHaveBeenCalledWith("launchctl", ["kickstart", `gui/501/${api!.FULL_AGENT_LABEL}`]);
    store.admit();
    f.setPid(0); expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    f.setPid(1234); expect(await api!.runFullStatus([], f.ctx)).toBe(0);
  });
});
