/** Attended LaunchAgent commands use injected host and credential boundaries. Job 996. */
import * as fs from "node:fs";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isOwnerTrustedExecutable } from "../../src/cli/castle-wall-signer-client-path.js";
import type { StoredPassphraseObservation } from "../../src/wrap/passphrase.js";
import { CASTLE_WALL_BOOT_LABEL, type ExecFileResult } from "../../src/cli/castle-wall-boot.js";
import { livenessFortressId } from "../../src/cli/castle-wall-liveness-status.js";
import { resolveStableRuntime, STABLE_RUNTIME_REFUSAL_EXIT_CODE } from "../../src/cli/stable-runtime-path.js";
const agentPath = "../../src/cli/castle-wall-full-agent.js";
const statePath = "../../src/cli/castle-wall-full-agent-state.js";
const api = await import(agentPath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent.js") | null;
const state = await import(statePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent-state.js") | null;
const roots: string[] = [];
beforeEach(() => { expect(api, "LaunchAgent commands are shipped").not.toBeNull(); expect(state).not.toBeNull(); });
afterEach(() => { for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true }); });
// Mode, inode and bytes come from one open descriptor, so every assertion describes the same file even if the path is replaced in between.
function snapshot(path: string): { stat: fs.Stats; bytes: Buffer } {
  const fd = fs.openSync(path, "r");
  try { return { stat: fs.fstatSync(fd), bytes: fs.readFileSync(fd) }; } finally { fs.closeSync(fd); }
}
class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void) { this.text += String(chunk); callback(); }
}
function fixture(fortressName = "fortress") {
  const root = fs.mkdtempSync("/tmp/j996-install-"); roots.push(root);
  const home = join(root, "home"), fortress = join(root, fortressName), cli = join(root, "cli.js");
  fs.mkdirSync(home, { mode: 0o700 }); fs.mkdirSync(fortress, { mode: 0o700 }); fs.writeFileSync(cli, "// fixture entry\n");
  const signer = join(root, "signer-client");
  fs.writeFileSync(signer, "#!/bin/sh\nexit 0\n", { mode: 0o700 }); // Owner-only executable fixture.
  let bootLoaded = false;
  let fullLoaded = false;
  let loadedFortress: string | null = fortress;
  let pid: number | null = 1234; // Fixed fake launchd process identity; never signalled.
  const exec = vi.fn((_command: string, args: string[]): ExecFileResult => {
    if (args[0] === "print" && args[1] === `system/${CASTLE_WALL_BOOT_LABEL}`) {
      return bootLoaded ? { code: 0, stdout: `system/${CASTLE_WALL_BOOT_LABEL} = {\nstate = running\npid = 111\n}\n`, stderr: "" } : { code: 113, stdout: "", stderr: "Could not find service" };
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
    signerClientCandidates: [signer],
    // Stable runtime selection has its own suite; this fixture's temp CLI is accepted as the validated lexical path.
    stableRuntime: () => ({ ok: true, node: process.execPath, cli, nodeVersion: process.versions.node }),
  };
  return { setLoaded: (value: boolean) => { fullLoaded = value; }, io, setLoadedFortress: (value: string | null) => { loadedFortress = value; }, root, home, fortress, cli, signer, out, err, ctx, exec, observe, sleep, write, setBoot: (value: boolean) => { bootLoaded = value; }, setPid: (value: number | null) => { pid = value; } };
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
    const installed = snapshot(plist);
    expect(installed.stat.mode & 0o777).toBe(0o644);
    expect(api!.fullAgentLaunchAgentWellFormed(installed.bytes.toString("utf8"))).toBe(true);
    expect(f.exec).toHaveBeenCalledWith("launchctl", ["bootstrap", "gui/501", plist]);
    expect(f.observe).toHaveBeenCalledWith({ storagePath: f.fortress, home: f.home, readOnly: true, platformOverride: "darwin" });
    expect(f.sleep.mock.calls.reduce((sum, [ms]) => sum + ms, 0)).toBeGreaterThan(api!.FULL_AGENT_THROTTLE_INTERVAL_S * 1000);
  });

  it("install writes the golden plist shape and reports an owner-trusted signer", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx), f.err.text).toBe(0);
    const installed = fs.readFileSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`), "utf8");
    const golden = fs.readFileSync(new URL("./fixtures/castle-wall-full-agent.golden.plist", import.meta.url), "utf8")
      .replaceAll("/usr/local/bin/node", process.execPath)
      .replaceAll("/opt/sanctuary/cli.js", f.cli)
      .replaceAll("/Users/operator/Fortress", f.fortress)
      .replace("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", [...new Set([process.execPath.slice(0, process.execPath.lastIndexOf("/")), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])].join(":"));
    expect(installed).toBe(golden);
    const environment = /<key>EnvironmentVariables<\/key>\s*<dict>([\s\S]*?)<\/dict>/.exec(installed)![1]!;
    expect([...environment.matchAll(/<key>(.*?)<\/key>/g)].map(match => match[1])).toEqual(["PATH"]);
    expect(f.out.text).toContain(`install-full checkpoint signer: ${f.signer}`);
    expect(await isOwnerTrustedExecutable(f.signer, process.getuid?.bind(process), f.ctx.env)).toBe(true);
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
    // A bound running job with no liveness records exits 1 under wall-only exits; the binding still succeeds with no refusal.
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    const alias = join(f.root, "alias"); fs.symlinkSync(f.fortress, alias);
    expect(await api!.runFullStatus(["--fortress", alias], f.ctx)).toBe(1);
    expect(f.out.text).toMatch(/Full LaunchAgent state=state_RUNNING charges=\d+ pid=1234\n/);
    expect(f.err.text).toBe("");
    const other = join(f.root, "other");
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    if (source === "plist" || source === "both-other") fs.writeFileSync(plist, api!.generateFullAgentPlist([process.execPath, f.cli, "castle-wall", "daemon", "--fortress", other, "--launch-agent"]));
    if (source === "loaded" || source === "both-other") f.setLoadedFortress(other);
    if (source === "missing-plist") fs.unlinkSync(plist);
    if (source === "missing-loaded") f.setLoadedFortress(null);
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.err.text).toContain(source === "missing-plist" ? "plist is absent" : source === "missing-loaded" ? "fortress binding is unavailable" : "the installed full LaunchAgent serves a different fortress");
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
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.out.text).toMatch(/Full LaunchAgent state=state_RUNNING charges=\d+ pid=1234\n/);
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
    expect(f.err.text).toContain("rollback incomplete: the job was not confirmed unloaded or its plist was not removed; run full-status, then uninstall-full");
    expect(fs.existsSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`))).toBe(false);
  });

  it("install refuses an already loaded job without changing its plist or job", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    const { bytes: before, stat: { ino: inode } } = snapshot(plist);
    f.exec.mockClear(); f.write.mockClear(); f.observe.mockClear();
    expect(await api!.runInstallFull([], f.ctx)).toBe(1);
    expect(f.err.text).toContain("already installed; run uninstall-full first");
    expect(f.write).not.toHaveBeenCalled(); expect(f.observe).not.toHaveBeenCalled();
    const after = snapshot(plist); expect(after.bytes).toEqual(before); expect(after.stat.ino).toBe(inode);
    expect(f.exec.mock.calls.every(([, args]) => args[0] === "print")).toBe(true);
  });

  it.each(["payload", "signal", "null-status", "spawn-error", "service-block", "malformed-success"])("E1a E1b reset refuses INDETERMINATE %s", async kind => {
    const f = fixture("not found");
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const store = new state!.FullAgentStateStore(f.fortress); store.admit();
    const before = fs.readFileSync(store.path);
    const loaded = f.exec("launchctl", ["print", `gui/501/${api!.FULL_AGENT_LABEL}`]);
    f.ctx.execFileFn = vi.fn(() => ({
      code: kind === "null-status" ? null : kind === "payload" ? 1 : kind === "malformed-success" ? 0 : 113,
      stdout: kind === "payload" || kind === "service-block" ? loaded.stdout : kind === "malformed-success" ? "incomplete" : "",
      stderr: "Could not find service",
      signal: kind === "signal" ? "SIGTERM" as const : null,
      error: kind === "spawn-error" ? new Error("fixture spawn error") : undefined,
    }));
    f.exec.mockClear();
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(f.err.text).toContain("INDETERMINATE");
    expect(f.err.text).not.toContain("different fortress");
    expect(fs.readFileSync(store.path)).toEqual(before);
    expect(f.exec).not.toHaveBeenCalled();
  });

  it("E1c status 113 with empty stdout and stderr is UNLOADED", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const store = new state!.FullAgentStateStore(f.fortress); store.admit();
    f.setLoaded(false);
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => {
      const result = original(command, args);
      return result.code === 113 ? { ...result, stderr: "" } : result;
    });
    f.exec.mockClear();
    expect(await api!.runResetFull(["--yes"], f.ctx), f.err.text).toBe(0);
    expect(store.read()).toBeNull();
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "bootout")).toBe(false);
    expect(f.exec.mock.calls.some(([, args]) => args[0] === "bootstrap")).toBe(true);
  });

  it("E3a absent plist resets a latched counter without bootstrap or reading either name", async () => {
    const f = fixture();
    const store = new state!.FullAgentStateStore(f.fortress);
    for (let i = 0; i <= state!.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    expect(store.read()?.state).toBe("state_LATCHED");
    const temp = join(store.directory, ".full-agent.tmp");
    fs.writeFileSync(temp, "unfinished", { mode: 0o600 }); // Owner-only temporary accounting.
    const read = vi.fn(() => { throw new Error("reset must not read supervision contents"); });
    f.ctx.stateStore = () => new state!.FullAgentStateStore(f.fortress, { fs: { ...fs, readSync: read } });
    expect(await api!.runResetFull(["--yes", "--fortress", f.fortress], f.ctx), f.err.text).toBe(0);
    expect(f.out.text).toBe(`Counter reset at ${store.directory}. No full LaunchAgent is installed; run install-full to start it.\n`);
    expect(fs.existsSync(store.path)).toBe(false);
    expect(fs.existsSync(temp)).toBe(false);
    expect(read).not.toHaveBeenCalled();
    expect(f.exec.mock.calls.every(([, args]) => args[0] === "print")).toBe(true);
  });

  it("E3b malformed plist has its own refusal", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    fs.writeFileSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`), "malformed");
    f.setLoaded(false); f.exec.mockClear();
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(f.err.text).toBe("Full LaunchAgent plist is malformed.\n");
    expect(f.exec.mock.calls.every(([, args]) => args[0] === "print")).toBe(true);
  });

  it("E3c absent plist, fortress mismatch and indeterminate state have distinct refusals", async () => {
    const f = fixture(); expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    const plist = join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`);
    const saved = fs.readFileSync(plist);
    fs.unlinkSync(plist);
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(f.err.text).toBe("Full LaunchAgent plist is absent.\n");
    f.err.text = ""; fs.writeFileSync(plist, saved);
    f.setLoadedFortress(join(f.root, "other"));
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(f.err.text).toBe("the installed full LaunchAgent serves a different fortress\n");
    f.err.text = "";
    f.exec.mockReturnValue({ code: 1, stdout: "", stderr: "fixture unknown failure" });
    expect(await api!.runResetFull(["--yes"], f.ctx)).toBe(1);
    expect(f.err.text).toBe("Full LaunchAgent job state is INDETERMINATE.\n");
  });

});

type LivenessPatch = { op: "set" | "add" | "delete"; path: string; value?: unknown };
const LIVENESS_STATES = JSON.parse(fs.readFileSync(join(__dirname, "..", "castle-wall", "liveness", "fixtures", "states.json"), "utf8")) as { base: Record<string, any>; rows: Array<{ name: string; patches: LivenessPatch[] }> };
const LIVENESS_UID = process.getuid?.() ?? 0;
/** Write the fixture's liveness records into a fortress, re-subjected to it, and inject the matching reader clock into the command context. */
function withLiveness(f: ReturnType<typeof fixture>, patches: readonly LivenessPatch[], files: readonly string[] = ["daemon", "observer", "config"]) {
  const input = structuredClone(LIVENESS_STATES.base);
  for (const patch of patches) {
    const keys = patch.path.split(".");
    const last = keys.pop()!;
    let target = input;
    for (const key of keys) target = target[key];
    if (patch.op === "delete") delete target[last];
    else if (patch.op === "add") target[last] += patch.value as number;
    else target[last] = structuredClone(patch.value);
  }
  fs.mkdirSync(join(f.fortress, "liveness"), { mode: 0o700 });
  for (const name of files) {
    if (input[name].status !== "present") continue;
    const value = input[name].value;
    if (value.subject) Object.assign(value.subject, { fortress_id: livenessFortressId(f.fortress), operator_uid: LIVENESS_UID });
    fs.writeFileSync(join(f.fortress, "liveness", `${name}.json`), JSON.stringify(value), { mode: 0o600 });
  }
  f.ctx.liveness = { getuid: () => LIVENESS_UID, now: () => input.nowMs, hostClock: { read: async () => input.host, uptimeMs: () => input.host.uptimeMs } };
}
const livenessRow = (name: string) => LIVENESS_STATES.rows.find(row => row.name === name)!.patches;
function livenessSnapshot(fortress: string): Record<string, { bytes: string; mode: number }> {
  const dir = join(fortress, "liveness");
  const files: Record<string, { bytes: string; mode: number }> = { ".": { bytes: "", mode: fs.statSync(dir).mode } };
  for (const name of fs.readdirSync(dir).sort()) files[name] = { bytes: fs.readFileSync(join(dir, name), "base64"), mode: fs.statSync(join(dir, name)).mode };
  return files;
}
function treeListing(root: string): string[] {
  const entries: string[] = [];
  const walk = (dir: string) => { for (const name of fs.readdirSync(dir).sort()) { const path = join(dir, name); const info = fs.lstatSync(path); entries.push(`${path}:${info.mode}:${info.size}:${info.mtimeMs}`); if (info.isDirectory()) walk(path); } };
  walk(root);
  return entries;
}

describe("full-status wall-only exit", () => {
  async function installedAndRunning() {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    new state!.FullAgentStateStore(f.fortress).admit();
    f.out.text = "";
    return f;
  }

  it("a running pid with wall OK and agent DOWN exits 0, keeping the supervision line byte-identical", async () => {
    const f = await installedAndRunning();
    withLiveness(f, livenessRow("agent down process missing"));
    expect(await api!.runFullStatus([], f.ctx), f.err.text).toBe(0);
    expect(f.out.text).toMatch(/^Full LaunchAgent state=state_RUNNING charges=\d+ pid=1234\nLiveness wall: wall_OK_IDLE \(none\)\nLiveness agent: agent_DOWN \(agent_process_missing\)\n/);
  });

  it("wall DOWN with agent OK exits 1", async () => {
    const f = await installedAndRunning();
    withLiveness(f, [{ op: "delete", path: "daemon.value.raw.hooks.emission_tick" }]);
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.out.text).toContain("Liveness wall: wall_DOWN (evidence_incomplete)");
    expect(f.out.text).toMatch(/^Liveness agent: agent_OK_/m);
  });

  it("pid alive alone is never exit 0: state_RUNNING, bound pid 1234 and no liveness records exits 1", async () => {
    const f = await installedAndRunning();
    f.ctx.liveness = { getuid: () => LIVENESS_UID, hostClock: { read: async () => ({ ok: false }), uptimeMs: () => LIVENESS_STATES.base.host.uptimeMs } };
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.out.text).toMatch(/^Full LaunchAgent state=state_RUNNING charges=\d+ pid=1234\n/);
    expect(f.out.text).not.toMatch(/^Liveness wall: wall_OK_/m);
  });

  it("a fresh daemon.json with observer.json absent exits 1", async () => {
    const f = await installedAndRunning();
    withLiveness(f, [], ["daemon", "config"]);
    expect(await api!.runFullStatus([], f.ctx)).toBe(1);
    expect(f.out.text).toMatch(/^Liveness wall: wall_DOWN \([^)]*observer_missing/m);
  });

  it("full-status leaves every liveness file byte-identical and mode-identical", async () => {
    const f = await installedAndRunning();
    withLiveness(f, []);
    fs.chmodSync(join(f.fortress, "liveness", "config.json"), 0o640);
    const before = livenessSnapshot(f.fortress);
    await api!.runFullStatus([], f.ctx);
    expect(livenessSnapshot(f.fortress)).toEqual(before);
  });
});

describe("install-full stable runtime preflight", () => {
  const refusal = () => ({ ok: false as const, reason: "no stable Node candidate resolves to the running Node" });

  it("an unstable runtime exits 78 before the credential lookup, any launchctl call and any write", async () => {
    const f = fixture();
    f.ctx.stableRuntime = refusal;
    expect(await api!.runInstallFull([], f.ctx)).toBe(STABLE_RUNTIME_REFUSAL_EXIT_CODE);
    expect(f.observe).not.toHaveBeenCalled();
    expect(f.write).not.toHaveBeenCalled();
    expect(f.exec).not.toHaveBeenCalled();
    expect(fs.existsSync(join(f.home, "Library"))).toBe(false);
    expect(f.err.text).toContain("install-full refused an unstable runtime");
  });

  it("--preflight with a loaded old service and the boot daemon loaded validates, mutates nothing and reads no credential", async () => {
    const f = fixture();
    expect(await api!.runInstallFull([], f.ctx)).toBe(0);
    f.setBoot(true);
    f.ctx.isTTY = false;
    f.exec.mockClear(); f.write.mockClear(); f.observe.mockClear();
    const before = treeListing(f.root);
    expect(await api!.runInstallFull(["--preflight"], f.ctx), f.err.text).toBe(0);
    expect(f.out.text).toContain(`install-full preflight valid: node=${process.execPath} cli=${f.cli} signer=${f.signer}`);
    f.ctx.stableRuntime = refusal;
    expect(await api!.runInstallFull(["--preflight"], f.ctx)).toBe(STABLE_RUNTIME_REFUSAL_EXIT_CODE);
    expect(treeListing(f.root)).toEqual(before);
    expect(f.exec).not.toHaveBeenCalled();
    expect(f.write).not.toHaveBeenCalled();
    expect(f.observe).not.toHaveBeenCalled();
  });

  it.each([{ argv: [] }, { argv: ["--preflight"] }])("missing signer refuses before credentials, launchctl or writes: $argv", async ({ argv }) => {
    const f = fixture();
    f.ctx.signerClientCandidates = [join(f.root, "absent-signer")];
    const before = treeListing(f.root);
    expect(await api!.runInstallFull(argv, f.ctx)).toBe(STABLE_RUNTIME_REFUSAL_EXIT_CODE);
    expect(f.err.text).toContain("install-full preflight refused: signer client unavailable");
    expect(f.err.text).toContain("install or approve the Castle Wall host app");
    expect(f.observe).not.toHaveBeenCalled();
    expect(f.exec).not.toHaveBeenCalled();
    expect(f.write).not.toHaveBeenCalled();
    expect(treeListing(f.root)).toEqual(before);
  });

  it("--preflight keeps the unsupported-host refusal", async () => {
    const f = fixture();
    f.ctx.platform = "linux";
    expect(await api!.runInstallFull(["--preflight"], f.ctx)).toBe(1);
    f.ctx.platform = "darwin"; f.ctx.euid = 0;
    expect(await api!.runInstallFull(["--preflight"], f.ctx)).toBe(1);
  });

  it("a Cellar execPath with an opt alias saves the lexical alias in the plist, never the Cellar realpath", async () => {
    const f = fixture();
    const prefix = join(f.root, "prefix");
    const keg = join(prefix, "Cellar", "node", "22.11.0", "bin");
    fs.mkdirSync(keg, { recursive: true, mode: 0o755 });
    fs.writeFileSync(join(keg, "node"), "#!/bin/sh\n", { mode: 0o755 });
    fs.mkdirSync(join(prefix, "opt"), { mode: 0o755 });
    fs.symlinkSync(join("..", "Cellar", "node", "22.11.0"), join(prefix, "opt", "node"));
    const pkg = join(prefix, "lib", "node_modules", "@sanctuary-framework", "mcp-server");
    fs.mkdirSync(join(pkg, "dist"), { recursive: true, mode: 0o755 });
    fs.writeFileSync(join(pkg, "dist", "cli.js"), "// fixture entry\n", { mode: 0o644 });
    fs.writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: "@sanctuary-framework/mcp-server", engines: { node: ">=20" } }), { mode: 0o644 });
    const optNode = join(prefix, "opt", "node", "bin", "node");
    const cli = join(pkg, "dist", "cli.js");
    f.ctx.execPath = join(keg, "node");
    f.ctx.cliPath = cli;
    // The fixture files are owned by whoever runs the suite, so custody is checked against that uid, not the fixture's 501.
    // Failure mode: with the fixture uid the test passes only on a Mac whose operator is uid 501 and refuses on every Linux box.
    f.ctx.stableRuntime = running => resolveStableRuntime({ ...running, operatorUid: process.getuid!(), nodeCandidates: [optNode], cliCandidates: [cli], tempRoots: [], runningNodeVersion: "22.11.0" });
    // The fake launchd reports the arguments it was bootstrapped with, read back from the written plist.
    const original = f.exec.getMockImplementation()!;
    f.exec.mockImplementation((command, args) => {
      const result = original(command, args);
      return args[0] === "print" && args[1] === `gui/501/${api!.FULL_AGENT_LABEL}` ? { ...result, stdout: result.stdout.replace(`${process.execPath}\n${f.cli}`, `${optNode}\n${cli}`) } : result;
    });
    expect(await api!.runInstallFull([], f.ctx), f.err.text).toBe(0);
    const plist = fs.readFileSync(join(f.home, "Library", "LaunchAgents", `${api!.FULL_AGENT_LABEL}.plist`), "utf8");
    expect(plist).toContain(`<string>${optNode}</string>`);
    expect(plist).not.toContain("Cellar");
    fs.unlinkSync(join(prefix, "opt", "node"));
    const second = fixture();
    second.ctx.execPath = join(keg, "node"); second.ctx.cliPath = cli; second.ctx.stableRuntime = f.ctx.stableRuntime;
    expect(await api!.runInstallFull([], second.ctx)).toBe(STABLE_RUNTIME_REFUSAL_EXIT_CODE);
    expect(second.observe).not.toHaveBeenCalled();
    expect(second.write).not.toHaveBeenCalled();
  });
});
