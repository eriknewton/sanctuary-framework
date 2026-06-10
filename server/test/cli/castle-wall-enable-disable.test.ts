import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  parseCastleWallArgs,
  runDisable,
  runEnable,
  type HostAppInvoker,
} from "../../src/cli/castle-wall.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

function reportLine(action: string, state: string, ok: boolean, error?: string): string {
  return JSON.stringify({ action, error, ok, state }) + "\n";
}

function makeInvoker(
  responses: Record<string, { stdout: string; exitCode: number; stderr?: string }>,
): { invoke: HostAppInvoker; calls: string[][] } {
  const calls: string[][] = [];
  const invoke: HostAppInvoker = async (binaryPath, args) => {
    calls.push([binaryPath, ...args]);
    const action = args[1]!;
    const response = responses[action];
    if (!response) throw new Error(`unexpected headless action: ${action}`);
    return {
      stdout: response.stdout,
      stderr: response.stderr ?? "",
      exitCode: response.exitCode,
    };
  };
  return { invoke, calls };
}

describe("castle-wall enable/disable CLI verbs", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFixture() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-arm-"));
    tempDirs.push(fortressPath);
    const hostAppPath = join(fortressPath, "CastleWallHostApp");
    await writeFile(hostAppPath, "#!/bin/sh\n", { mode: 0o755 });
    const recoveryKey = toBase64url(generateRandomKey());
    const env = {
      SANCTUARY_STORAGE_PATH: fortressPath,
      SANCTUARY_RECOVERY_KEY: recoveryKey,
    };
    return { fortressPath, hostAppPath, env, recoveryKey };
  }

  it("enable refuses when no daemon is reachable", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable([], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => false,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(err.text()).toContain("deny-all");
    expect(calls).toHaveLength(0);
  });

  it("enable --force bypasses the daemon gate and verifies via status", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--force"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => {
        throw new Error("probe must not run under --force");
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    expect(calls).toEqual([
      [hostAppPath, "--headless", "enable"],
      [hostAppPath, "--headless", "status"],
    ]);
  });

  it("enable writes an operator_decision audit entry corroborating the arm", async () => {
    const { fortressPath, hostAppPath, env, recoveryKey } = await makeFixture();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
    });
    expect(code).toBe(0);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const auditLog = new AuditLog(storage, fromBase64url(recoveryKey));
    const query = await auditLog.query({ layer: "l1", limit: 100 });
    const entry = query.entries.find((e) => e.operation === "operator_decision");
    expect(entry).toBeDefined();
    expect(entry?.details).toMatchObject({
      source: "castle-wall-cli",
      action: "enable",
      verified_state: "enabled",
      forced: false,
    });
  });

  it("enable surfaces the one-time GUI consent with exit code 3", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: {
        stdout: reportLine("enable", "needs_user_approval", false, "consent missing"),
        exitCode: 3,
      },
    });

    const code = await runEnable([], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
    });

    expect(code).toBe(3);
    expect(err.text()).toContain("one-time macOS content-filter consent");
    expect(err.text()).toContain("launch");
  });

  it("disable is unconditional: runs even when the daemon is down", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });

    const code = await runDisable([], {
      out,
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => {
        throw new Error("disable must never consult the daemon probe");
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall disarmed");
    expect(calls.map((c) => c[2])).toEqual(["disable", "status"]);
  });

  it("fails when post-change verification disagrees with the mutation report", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--force"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("post-change verification");
  });

  it("errors usefully when the host app binary is missing", async () => {
    const { fortressPath, env } = await makeFixture();
    const err = new CaptureStream();

    const code = await runDisable([], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [join(fortressPath, "does-not-exist")],
      hostAppInvoke: makeInvoker({}).invoke,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("Castle Wall app not found");
    expect(err.text()).toContain("SANCTUARY_CASTLE_HOSTAPP");
  });

  it("fails loud when SANCTUARY_CASTLE_HOSTAPP points at a missing binary", async () => {
    const { fortressPath, env } = await makeFixture();
    const err = new CaptureStream();

    const code = await runDisable([], {
      out: new CaptureStream(),
      err,
      env: { ...env, SANCTUARY_CASTLE_HOSTAPP: join(fortressPath, "nope") },
      platform: "darwin",
      hostAppInvoke: makeInvoker({}).invoke,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("SANCTUARY_CASTLE_HOSTAPP is set but");
  });

  it("disarm succeeds with a warning when the audit log cannot be written", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });

    const code = await runDisable([], {
      out,
      err,
      // 8 bytes instead of 32: resolveMasterKey throws, audit append degrades.
      env: { ...env, SANCTUARY_RECOVERY_KEY: toBase64url(new Uint8Array(8)) },
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall disarmed");
    expect(err.text()).toContain("audit entry could not be written");
  });

  it("is macOS-only", async () => {
    const err = new CaptureStream();
    const code = await runEnable([], {
      out: new CaptureStream(),
      err,
      env: {},
      platform: "linux",
    });
    expect(code).toBe(1);
    expect(err.text()).toContain("macOS-only");
  });

  it("parseCastleWallArgs understands --force", () => {
    expect(parseCastleWallArgs(["--force"]).force).toBe(true);
    expect(parseCastleWallArgs([]).force).toBeUndefined();
  });
});
