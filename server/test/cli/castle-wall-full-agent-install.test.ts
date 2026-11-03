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
function fixture(fortressName = "fortress") {
  const root = fs.mkdtempSync("/tmp/j996-install-"); roots.push(root);
  const home = join(root, "home"), fortress = join(root, fortressName), cli = join(root, "cli.js");
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(fortress, { mode: 0o700 }); fs.writeFileSync(cli, "// fixture entry\n");
  let bootLoaded = false;
  let fullLoaded = false;
  let loadedFortress: string | null = fortress;
  let pid: number | null = 1234; // Fixed fake launchd process identity; never signalled.
  const exec = vi.fn((_command: string, args: string[]): ExecFileResult => {
    if (args[0] === "print" && args[1] === `system/${CASTLE_WALL_BOOT_LABEL}`) {
      return bootLoaded ? { code: 0, stdout: "state = running\npid = 111\n", stderr: "" } : { code: 113, stdout: "", stderr: "Could not find service" };
    }
    if (args[0] === "print") return fullLoaded ? { code: 0, stdout: `gui/501/${api!.FULL_AGENT_LABEL} = {\n` +
      (pid === null ? "state = exited\n" : `state = running\npid = ${pid}\n`) +
      `arguments = {\n${process.execPath}\n${cli}\ncastle-wall\ndaemon\n${loadedFortress === null ? "" : `--fortress\n${JSON.stringify(loadedFortress)}\n`}--launch-agent\n}\n}\n`, stderr: "" } :
      { code: 113, stdout: "", stderr: "Could not find service" };
    if (args[0] === "bootstrap") fullLoaded = true;
    if (args[0] === "bootout") fullLoaded = false;
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
  return { setLoaded: (value: boolean) => { fullLoaded = value; }, io, setLoadedFortress: (value: string | null) => { loadedFortress = value; }, root, home, fortress, cli, out, err, ctx, exec, observe, sleep, write, setBoot: (value: boolean) => { bootLoaded = value; }, setPid: (value: number | null) => { pid = value; } };
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

  it.each(["plist", "loaded", "missing-plist", "missing-loaded", "both-other"])("status binds matching fortress and refuses %s mismatch", async source => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    new state!.FullAgentStateStore(f.fortress).admit();
    expect(await api!.runFullStatus([], f.ctx)).toBe(0);
    const alias = join(f.root, "alias"); fs.symlinkSync(f.fortress, alias);
    expect(await api!.runFullStatus(["--fortress", alias], f.ctx)).toBe(0);
    const other = join(f.root, "other");
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    if (source === "plist" || source === "both-other") fs.writeFileSync(plist, api!.generateFullAgentPlist([process.execPath, f.cli, "castle-wall", "daemon", "--fortress", other, "--launch-agent"]));
    if (source === "loaded" || source === "both-other") f.setLoadedFortress(other);
    if (source === "missing-plist") fs.unlinkSync(plist);
    if (source === "missing-loaded") f.setLoadedFortress(null);
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.err.text).toContain("the installed full LaunchAgent serves a different fortress");
  });

  it.each(["plist", "loaded"])("reset checks %s fortress binding before counter writes or kickstart", async source => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const store = new state!.FullAgentStateStore(f.fortress);
    for (let i = 0; i <= state!.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    const before = store.read();
    f.setPid(null);
    const other = join(f.root, "other");
    if (source === "loaded") f.setLoadedFortress(other);
    else fs.writeFileSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`), api!.generateFullAgentPlist([process.execPath, f.cli, "castle-wall", "daemon", "--fortress", other, "--launch-agent"]));
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(store.read()).toEqual(before);
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "kickstart")).toBe(false);
    expect(f.err.text).toContain("the installed full LaunchAgent serves a different fortress");
  });

  it.each([false, true])("bootstrap failure removes plist with loaded=%s", async loaded => {
    const f = fixture();
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => {
      if (args[0] === "bootstrap") { f.setLoaded(loaded); return { code: 1, stdout: "", stderr: "fixture bootstrap failure" }; }
      if (!loaded && args[0] === "print" && args[1] !== `system/${CASTLE_WALL_BOOT_LABEL}`) return { code: 113, stdout: "", stderr: "Could not find service" };
      return original(command, args);
    });
    expect(await api!.runInstallFull([], f.ctx)).toBe(1);
    expect(fs.existsSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`))).toBe(false);
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "bootout")).toBe(loaded);
    const bootstrapIndex = f.exec.mock.calls.findIndex(([, args]) => args[0] === "bootstrap");
    const rollbackCommands = f.exec.mock.calls.slice(bootstrapIndex + 1).map(([, args]) => args[0]);
    expect(rollbackCommands).toEqual(loaded ? ["print", "bootout", "print"] : ["print", "print"]);
  });

  it("stable-pid failure boots out before removing plist", async () => {
    const f = fixture();
    f.sleep.mockImplementation(async () => { f.setPid(5678); }); // Different fixture pid at the second sample.
    const original = f.exec.getMockImplementation()!;
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    f.exec.mockImplementation((command, args) => {
      if (args[0] === "bootout") expect(fs.existsSync(plist)).toBe(true);
      return original(command, args);
    });
    expect(await api!.runInstallFull([], f.ctx)).toBe(1);
    expect(f.exec).toHaveBeenCalledWith("launchctl", ["bootout", `gui/501/${api!.FULL_AGENT_LABEL}`]);
    expect(fs.existsSync(plist)).toBe(false);
  });

  it("uninstall succeeds when not loaded and removes the plist idempotently", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    f.exec.mockReturnValue({ code: 113, stdout: "", stderr: "Could not find service" });
    expect(await api!.runUninstallFull(["--yes"], f.ctx)).toBe(0);
    expect(fs.existsSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`))).toBe(false);
    expect(await api!.runUninstallFull(["--yes"], f.ctx)).toBe(0);
  });
  it.each(["corrupt", "state_RUNNING", "state_LATCHED", "temp", "absent", "state_STOPPED_CLEAN"])("reset recovers %s in unload-remove-bootstrap order", async kind => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const store = new state!.FullAgentStateStore(f.fortress, { now: () => 1_000_000 });
    if (kind !== "absent") store.admit();
    if (kind === "corrupt") fs.writeFileSync(store.path, "{");
    if (kind === "state_LATCHED") for (let i = 0; i < state!.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    if (kind === "state_STOPPED_CLEAN") store.stoppedClean();
    if (kind === "state_LATCHED") expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    f.setPid(0); expect(await api!.runFullStatus([], f.ctx)).toBe(1); f.setPid(1234);
    if (kind === "temp") fs.writeFileSync(join(store.directory, ".full-agent.tmp"), "unfinished", { mode: 0o600 });
    const events: string[] = [];
    f.ctx.stateStore = () => new state!.FullAgentStateStore(f.fortress, { fs: { ...fs, unlinkSync: path => {
      events.push(String(path).endsWith(".tmp") ? "remove-temp" : "remove-record");
      fs.unlinkSync(path);
    } } });
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => {
      const result = original(command, args);
      if (args[0] === "bootout" || args[0] === "bootstrap") events.push(args[0]);
      if (args[0] === "print" && result.code !== 0) events.push("unloaded");
      return result;
    });
    expect(await api!.runResetFull(["--yes"], f.ctx), f.err.text).toBe(0);
    expect(events).toEqual(["bootout", "unloaded", "remove-record", "remove-temp", "bootstrap"]);
    expect(store.read()).toBeNull();
    expect(fs.existsSync(join(store.directory, ".full-agent.tmp"))).toBe(false);
    events.length = 0;
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(0);
    expect(events).toEqual(["bootout", "unloaded", "remove-record", "remove-temp", "bootstrap"]);
  });

  it("reset refuses a still-loaded job without removing either state file", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const store = new state!.FullAgentStateStore(f.fortress); store.admit();
    const before = fs.readFileSync(store.path);
    const temp = join(store.directory, ".full-agent.tmp"); fs.writeFileSync(temp, "unfinished", { mode: 0o600 });
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => args[0] === "bootout" ? { code: 0, stdout: "", stderr: "" } : original(command, args));
    f.exec.mockClear();
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(f.err.text).toContain("still loaded");
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "bootout")).toBe(true);
    expect(f.exec.mock.calls.filter(([, args]) => args[0] === "print").length).toBeGreaterThan(1);
    expect(fs.readFileSync(store.path)).toEqual(before);
    expect(fs.readFileSync(temp, "utf8")).toBe("unfinished");
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "bootstrap")).toBe(false);
  });

  it("a second reset after fsync failure succeeds from the unloaded state", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const store = new state!.FullAgentStateStore(f.fortress); store.admit();
    let fail = true;
    f.ctx.stateStore = () => new state!.FullAgentStateStore(f.fortress, { fs: { ...fs, fsyncSync: fd => {
      if (fail) { fail = false; throw new Error("fixture fsync failed"); }
      fs.fsyncSync(fd);
    } } });
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(store.read()).toBeNull();
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(0);
    expect(store.read()).toBeNull();
  });

  it.each(['pid = 1234', 'with spaces pid = 1234', 'with "quotes" pid = 1234'])("status ignores argument pid text in %s", async name => {
    const f = fixture(name);
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    new state!.FullAgentStateStore(f.fortress).admit();
    expect(await api!.runFullStatus([], f.ctx)).toBe(0);
    f.setPid(null);
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.out.text).toContain("pid=none");
    expect(f.err.text).not.toContain("different fortress");
  });

  it("status ignores pid fields in nested launchctl dictionaries", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    new state!.FullAgentStateStore(f.fortress).admit(); f.setPid(null);
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => {
      const result = original(command, args);
      result.stdout = result.stdout.replace("state = exited", "state = exited\nresource = {\npid = 1234\nchild = {\npid = 5678\n}\n}");
      return result;
    });
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.out.text).toContain("pid=none");
  });

  it("relative fortress requests refuse binding", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    new state!.FullAgentStateStore(f.fortress).admit();
    const relative = (await import("node:path")).relative(process.cwd(), f.fortress);
    expect(await api!.runFullStatus(["--fortress", relative], f.ctx)).toBe(1);
    expect(await api!.runResetFull(["--yes", "--fortress", relative], f.ctx)).toBe(1);
    f.setLoadedFortress(relative);
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
  });

  it("rollback reports a distinct exit if bootout leaves the job loaded and removes plist", async () => {
    const f = fixture();
    f.sleep.mockImplementation(async () => { f.setPid(5678); });
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => args[0] === "bootout" ? { code: 0, stdout: "", stderr: "" } : original(command, args));
    expect(await api!.runInstallFull([], f.ctx)).toBe(3);
    expect(f.err.text).toContain("rollback incomplete: the job is still loaded; run uninstall-full");
    expect(fs.existsSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`))).toBe(false);
  });

  it("install refuses an already loaded job without changing its plist or job", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    const before = fs.readFileSync(plist); const inode = fs.statSync(plist).ino;
    f.exec.mockClear(); f.write.mockClear(); f.observe.mockClear();
    expect(await api!.runInstallFull([], f.ctx)).toBe(1);
    expect(f.err.text).toContain("already installed; run uninstall-full first");
    expect(f.write).not.toHaveBeenCalled(); expect(f.observe).not.toHaveBeenCalled();
    expect(fs.readFileSync(plist)).toEqual(before); expect(fs.statSync(plist).ino).toBe(inode);
    expect(f.exec.mock.calls.every(([, args]) => args[0] === "print")).toBe(true);
  });

});
