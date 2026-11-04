/** The production full-daemon graph requires its exact opt-in fence. Job 996. */
import { mkdir, mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runDaemon, runProvisionPin, type CastleWallCommandContext } from "../../src/cli/castle-wall.js";
import { __testSetAuditWriterUidForRole } from "../../src/operational/audit-log.js";
import * as split from "../../src/operational/audit-store-split.js";
import * as passphrases from "../../src/wrap/passphrase.js";
import type { MacOSCastleWallDaemonInput } from "../../src/castle-wall/runtime/macos-daemon.js";
import { initializeTestCustody } from "../helpers/custody-fixture.js";
const statePath = "../../src/cli/castle-wall-full-agent-state.js";
const agentPath = "../../src/cli/castle-wall-full-agent.js";
const state = await import(statePath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent-state.js") | null;
const agent = await import(agentPath).catch(() => null) as typeof import("../../src/cli/castle-wall-full-agent.js") | null;
let root: string;
class Capture extends Writable {
  text = "";
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void) { this.text += String(chunk); callback(); }
}
beforeEach(async () => {
  expect(state, "full daemon fence is shipped").not.toBeNull(); expect(agent).not.toBeNull();
  root = await mkdtemp("/tmp/j996-wire-");
  await mkdir(join(root, "home"), { mode: 0o700 });
  vi.stubEnv("HOME", join(root, "home"));
  vi.stubEnv("SANCTUARY_CUSTODY_LOCK_ROOT", join(root, "locks"));
});
afterEach(async () => {
  __testSetAuditWriterUidForRole("root_daemon", undefined);
  vi.restoreAllMocks(); vi.unstubAllEnvs();
  if (root) await rm(root, { recursive: true, force: true });
});
const PASSPHRASE = "public-job996-fixture-passphrase";
async function prepared() {
  await initializeTestCustody(root, { passphrase: PASSPHRASE });
  expect(await runProvisionPin(["--fortress", root], {
    out: new Capture(), err: new Capture(),
    env: { HOME: join(root, "home"), SANCTUARY_PASSPHRASE: PASSPHRASE },
    globalPinnedPublicKeyPath: join(root, "global-pin"),
  })).toBe(0);
}
function context(uid: number) {
  let captured: MacOSCastleWallDaemonInput | undefined;
  const err = new Capture();
  const ctx: CastleWallCommandContext = {
    out: new Capture(), err, platform: "darwin", getuid: () => uid, getppid: () => 1,
    fullAgentExecFileFn: vi.fn((_command, _args) => ({ code: 0, stdout: `gui/${uid}/${agent!.FULL_AGENT_LABEL} = {\npid = ${process.pid}\narguments = {\n--launch-agent\n}\n}\n`, stderr: "" })),
    env: { HOME: join(root, "home"), SANCTUARY_STORAGE_PATH: root, SANCTUARY_PASSPHRASE: PASSPHRASE, SANCTUARY_CASTLE_LOCAL_SIGN: "1", SANCTUARY_TRANSPARENCY_INTERVAL: "off" },
    fullDaemonStart: async input => { captured = input; throw new Error("fixture captured before daemon start"); },
  };
  return { ctx, err, captured: () => captured };
}
describe("full daemon fence production wiring", () => {
  it.each([501, 0])("uid %s reaches the production consumer with the exact daemon fence", async uid => {
    await prepared();
    __testSetAuditWriterUidForRole("root_daemon", 0);
    const f = context(uid);
    expect(await runDaemon(["--fortress", root], f.ctx)).toBe(1);
    expect(f.captured(), f.err.text).toBeDefined();
    expect(f.captured()!.auditLog.processExitFence).toBe(state!.WALL_DAEMON_AUDIT_EXIT_FENCE);
  });

  it("rendered ProgramArguments run the real daemon admission and create its counter", async () => {
    await prepared();
    const args = [process.execPath, "/opt/sanctuary/cli.js", "castle-wall", "daemon", "--fortress", root, "--launch-agent"];
    const plist = agent!.generateFullAgentPlist(args);
    const array = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist)![1]!;
    const rendered = [...array.matchAll(/<string>(.*?)<\/string>/g)].map(match => match[1]!);
    const f = context(501);
    f.ctx.getppid = () => 501;
    expect(await runDaemon(rendered.slice(4), f.ctx)).toBe(2);
    await expect(stat(join(root, "supervision"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(f.captured()).toBeUndefined();
    expect(f.err.text).toContain("requires a launchd-spawned process");
    f.ctx.getppid = () => 1;
    expect(await runDaemon(rendered.slice(4), f.ctx)).toBe(1);
    expect(f.captured()!.auditLog.processExitFence).toBe(state!.WALL_DAEMON_AUDIT_EXIT_FENCE);
    expect(JSON.parse(await readFile(join(root, "supervision", "full-agent.json"), "utf8")).state).toBe("state_RUNNING");
  });

  it("E2b matching launchd pid admits through the production observation", async () => {
    await prepared();
    const f = context(501); // Fixture operator uid, never used for host execution.
    expect(await runDaemon(["--fortress", root, "--launch-agent"], f.ctx)).toBe(1);
    expect(f.captured(), f.err.text).toBeDefined();
    expect(f.ctx.fullAgentExecFileFn).toHaveBeenCalledWith("launchctl", ["print", `gui/501/${agent!.FULL_AGENT_LABEL}`]);
    expect(new state!.FullAgentStateStore(root).read()?.state).toBe("state_RUNNING");
  });

  it.each(["different pid", "no pid", "INDETERMINATE", "spawn failure", "thrown spawn failure"])("E2a E2c refuses %s before supervision access", async reason => {
    const f = context(501); // Fixture operator uid.
    const record = (pid: string) => `gui/501/${agent!.FULL_AGENT_LABEL} = {\n${pid}\narguments = {\n--launch-agent\n}\n}\n`;
    f.ctx.fullAgentExecFileFn = vi.fn(() => {
      if (reason === "thrown spawn failure") throw new Error("fixture spawn failure");
      return {
        code: reason === "INDETERMINATE" ? 1 : reason === "spawn failure" ? null : 0,
        stdout: record(reason === "different pid" ? `pid = ${process.pid + 1}` : ""), // Adjacent pid differs from this process.
        stderr: "",
        error: reason === "spawn failure" ? new Error("fixture spawn failure") : undefined,
      };
    });
    expect(await runDaemon(["--fortress", root, "--launch-agent"], f.ctx)).toBe(2);
    expect(f.err.text).toContain(reason.replace("thrown ", ""));
    await expect(stat(join(root, "supervision"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(f.captured()).toBeUndefined();
  });

  it("startup assertion refuses an unfenced root log before the start seam", async () => {
    await prepared();
    __testSetAuditWriterUidForRole("root_daemon", 0);
    const original = split.createDaemonAuditLog;
    vi.spyOn(split, "createDaemonAuditLog").mockImplementation((storage, key, config) => original(storage, key, { ...config, processExitFence: undefined }));
    const f = context(0);
    expect(await runDaemon(["--fortress", root], f.ctx)).toBe(1);
    expect(f.captured()).toBeUndefined();
    expect(f.err.text).toContain("audit exit fence is missing");
  });

  it("records a clean stop only after the production daemon session releases", async () => {
    await prepared();
    const f = context(501);
    const stopped = vi.fn(async () => {});
    f.ctx.fullDaemonStart = async () => ({ socketPath: join(root, "fixture.sock"), stop: stopped });
    const signals = ["SIGINT", "SIGTERM"] as const;
    const before = new Map<NodeJS.Signals, Set<unknown>>(signals.map(signal => [signal, new Set(process.rawListeners(signal))]));
    const run = runDaemon(["--fortress", root, "--launch-agent"], f.ctx);
    const POLL_MS = 10;
    const WAIT_MS = 5000; // Five seconds for the post-start signal handlers to be installed.
    try {
      let listener: ((signal: "SIGTERM") => void) | undefined;
      for (let elapsed = 0; elapsed < WAIT_MS; elapsed += POLL_MS) {
        listener = process.rawListeners("SIGTERM").find(candidate => !before.get("SIGTERM")!.has(candidate));
        if (listener) break;
        await new Promise(resolveWait => setTimeout(resolveWait, POLL_MS));
      }
      expect(listener, f.err.text).toBeDefined();
      listener!("SIGTERM");
      expect(await run).toBe(0);
      expect(stopped).toHaveBeenCalledTimes(1);
      expect(new state!.FullAgentStateStore(root).read()?.state).toBe("state_STOPPED_CLEAN");
    } finally {
      for (const signal of signals) {
        for (const listener of process.rawListeners(signal)) {
          if (!before.get(signal)!.has(listener)) {
            Reflect.apply(listener, process, [signal]);
            process.removeListener(signal, listener);
          }
        }
      }
      await run;
    }
  });

  it("latched admission returns zero before credential lookup or daemon startup", async () => {
    const store = new state!.FullAgentStateStore(root);
    for (let i = 0; i <= state!.FULL_AGENT_CRASH_BUDGET; i++) store.admit();
    const credential = vi.spyOn(passphrases, "getOrCreatePassphrase");
    const f = context(501); delete f.ctx.env!.SANCTUARY_PASSPHRASE;
    expect(await runDaemon(["--fortress", root, "--launch-agent"], f.ctx)).toBe(0);
    expect(credential).not.toHaveBeenCalled(); expect(f.captured()).toBeUndefined();
    expect(store.read()?.state).toBe("state_LATCHED");
  });

  it("refuses launch-agent plus safe-mode before any counter admission", async () => {
    const f = context(501);
    expect(await runDaemon(["--fortress", root, "--launch-agent", "--safe-mode"], f.ctx)).toBe(2);
    await expect(stat(join(root, "supervision"))).rejects.toMatchObject({ code: "ENOENT" });
    expect(f.captured()).toBeUndefined();
  });
});
