import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { parseFrame } from "../../src/castle-wall/ipc/framing.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  CASTLE_WALL_HEADLESS_CONTRACT_VERSION,
  makeLaunchServicesHostAppInvoke,
  parseCastleWallArgs,
  runDisable,
  runEnable,
  type HostAppInvoker,
  type OpenRunner,
} from "../../src/cli/castle-wall.js";
import {
  bootServiceInstalled,
  renderBootLaunchDaemonPlist,
} from "../../src/cli/castle-wall-boot.js";

const TEST_BUILD_SHA = "test-build-sha";

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

function reportLine(
  action: string,
  state: string,
  ok: boolean,
  error?: string,
  build = {
    git_sha: TEST_BUILD_SHA,
    headless_contract_version: CASTLE_WALL_HEADLESS_CONTRACT_VERSION,
  },
): string {
  return JSON.stringify({ action, build, error, ok, state }) + "\n";
}

function legacyReportLine(
  action: string,
  state: string,
  ok: boolean,
  error?: string,
): string {
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

async function waitFor(predicate: () => boolean, timeoutMs = 500): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error("timed out waiting for condition");
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
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
      SANCTUARY_CASTLE_BUILD_SHA: TEST_BUILD_SHA,
    };
    return { fortressPath, hostAppPath, env, recoveryKey };
  }

  function makeBootPlist(fortressPath: string): string {
    return renderBootLaunchDaemonPlist({
      programArguments: [
        "/usr/local/bin/node",
        "/opt/sanctuary/dist/cli.js",
        "castle-wall",
        "daemon",
        "--safe-mode",
        "--launchd",
      ],
      fortressPath,
      signerClientPath: "/Applications/Castle Wall.app/Contents/MacOS/castle-wall-signer-client",
    });
  }

  it("enable refuses when no daemon is reachable", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(["--no-ttl"], {
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

  it("enable refuses when no persistent boot service is installed (#450 item 5 composition guard)", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    // Daemon is reachable NOW (passes the first gate), but no boot service is
    // installed: arming would brick on the next reboot. The guard must refuse.
    const code = await runEnable(["--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceInstalledProbe: async () => false,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("no persistent Castle Wall boot service is installed");
    expect(err.text()).toContain("install-boot");
    // Never reaches the host app: nothing armed.
    expect(calls).toHaveLength(0);
  });

  it("enable refuses when the installed boot service targets a different fortress", async () => {
    const { fortressPath: fortressA, hostAppPath, env } = await makeFixture();
    const fortressB = await mkdtemp(join(tmpdir(), "sanctuary-cw-arm-b-"));
    tempDirs.push(fortressB);
    const plistPath = join(fortressA, "boot.plist");
    await writeFile(plistPath, makeBootPlist(fortressA));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(["--fortress", fortressB, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceInstalledProbe: (expectedFortressPath) =>
        bootServiceInstalled(plistPath, expectedFortressPath),
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("targets a different fortress");
    expect(err.text()).toContain(fortressB);
    expect(calls).toHaveLength(0);
  });

  it("enable accepts a boot service that targets the armed fortress", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const out = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out,
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceInstalledProbe: (expectedFortressPath) =>
        bootServiceInstalled(plistPath, expectedFortressPath),
      sysextProbe: async () => "[activated enabled]",
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
  });

  it("enable accepts a boot service that targets the default fortress", async () => {
    const defaultFortressPath = join(homedir(), ".sanctuary");
    const plistDir = await mkdtemp(join(tmpdir(), "sanctuary-cw-default-boot-"));
    tempDirs.push(plistDir);
    const plistPath = join(plistDir, "boot.plist");
    await writeFile(plistPath, makeBootPlist(defaultFortressPath));
    const err = new CaptureStream();

    const code = await runEnable([], {
      out: new CaptureStream(),
      err,
      env: {},
      platform: "darwin",
      daemonProbe: async () => true,
      bootServiceInstalledProbe: (expectedFortressPath) =>
        bootServiceInstalled(plistPath, expectedFortressPath),
    });

    expect(code).toBe(2);
    expect(err.text()).toContain("requires either --ttl");
    expect(err.text()).not.toContain("no persistent Castle Wall boot service");
    expect(err.text()).not.toContain("targets a different fortress");
  });

  it("enable --force bypasses the boot-service composition guard (#450 item 5)", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--force", "--no-ttl"], {
      out,
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      bootServiceInstalledProbe: async () => {
        throw new Error("boot-service probe must not run under --force");
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
  });

  it("enable --force bypasses the daemon gate and verifies via status", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--force", "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      daemonProbe: async () => {
        throw new Error("probe must not run under --force");
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    expect(calls).toEqual([
      [hostAppPath, "--headless", "enable", "--no-ttl"],
      [hostAppPath, "--headless", "status"],
    ]);
  });

  it("enable writes a wall_armed audit entry corroborating the arm", async () => {
    const { fortressPath, hostAppPath, env, recoveryKey } = await makeFixture();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--no-ttl"], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      daemonProbe: async () => true,
      bootServiceInstalledProbe: async () => true,
    });
    expect(code).toBe(0);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const auditLog = new AuditLog(storage, fromBase64url(recoveryKey));
    const query = await auditLog.query({ layer: "l1", limit: 100 });
    const entry = query.entries.find((e) => e.operation === "wall_armed");
    expect(entry).toBeDefined();
    expect(entry?.details).toMatchObject({
      source: "castle-wall-cli",
      action: "enable",
      verified_state: "enabled",
      forced: false,
    });
  });

  it("disable writes a wall_disarmed audit entry corroborating the disarm", async () => {
    const { fortressPath, hostAppPath, env, recoveryKey } = await makeFixture();
    const { invoke } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });

    const code = await runDisable([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
    });
    expect(code).toBe(0);

    const storage = new FilesystemStorage(join(fortressPath, "state"));
    const auditLog = new AuditLog(storage, fromBase64url(recoveryKey));
    const query = await auditLog.query({ layer: "l1", limit: 100 });
    const entry = query.entries.find((e) => e.operation === "wall_disarmed");
    expect(entry).toBeDefined();
    expect(entry?.details).toMatchObject({
      source: "castle-wall-cli",
      action: "disable",
      verified_state: "disabled",
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

    const code = await runEnable(["--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      daemonProbe: async () => true,
      bootServiceInstalledProbe: async () => true,
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

  it("disable sends a revoke-flagged lease before claiming fail-open recovery", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const received: Array<Record<string, unknown>> = [];
    const socketPath = join(fortressPath, "castle.sock");
    const server: Server = createServer((socket) => {
      let buffer = Buffer.alloc(0);
      socket.on("data", (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        const parsed = parseFrame(buffer);
        if (parsed.kind !== "complete") return;
        buffer = buffer.subarray(parsed.consumedBytes);
        const envelope = JSON.parse(parsed.body) as { params?: Record<string, unknown> };
        received.push(envelope.params ?? {});
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      // port-discipline: ignore - Unix domain socket path, not a TCP port.
      server.listen(socketPath, resolve);
    });

    const invoke: HostAppInvoker = async (_binaryPath, args) => {
      if (args[1] === "disable") {
        await waitFor(() => received.length > 0);
        expect(received[0]).toMatchObject({
          type: "arm_lease",
          armed: false,
          revoked: true,
          ttl_seconds: null,
        });
        return {
          stdout: reportLine("disable", "enabled", false, "NE save timed out"),
          stderr: "",
          exitCode: 1,
        };
      }
      throw new Error(`unexpected headless action: ${args[1]}`);
    };

    try {
      const code = await runDisable([], {
        out,
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
      });

      expect(code).toBe(0);
      expect(err.text()).toContain("fail-open path is active");
      expect(out.text()).toContain("provider dead-man lease revoked");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("fails when post-change verification disagrees with the mutation report", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--force", "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("post-change verification");
  });

  it("fails loud when the deployed app omits the headless build identity", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: legacyReportLine("enable", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--force", "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("did not report a headless build identity");
    expect(err.text()).toContain("rebuild + redeploy");
  });

  it("fails loud when the deployed app build does not match the CLI build", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: {
        stdout: reportLine("enable", "enabled", true, undefined, {
          git_sha: "stale-app-sha",
          headless_contract_version: CASTLE_WALL_HEADLESS_CONTRACT_VERSION,
        }),
        exitCode: 0,
      },
    });

    const code = await runEnable(["--force", "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("deployed app stale-app-sha != CLI test-build-sha");
    expect(err.text()).toContain("rebuild + redeploy");
  });

  it("disarm treats an inconclusive post-change verification as success (dead-man lever)", async () => {
    // On macOS Tahoe the corroborating status re-read spawns a SECOND
    // LaunchServices app instance that can time out / yield no parseable report
    // even though the disarm already took effect. That inconclusive
    // corroboration must NOT flip a genuine recovery into a reported failure.
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: "host app produced no report\n", exitCode: 4 },
    });

    const code = await runDisable([], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall disarmed");
    expect(out.text()).toContain("corroboration pending");
    expect(err.text()).toContain("inconclusive");
  });

  it("disarm fails loud when verification affirmatively shows the wall still enabled", async () => {
    // Distinct from an inconclusive read: a positive 'enabled' corroboration
    // means the disarm did not stick, so we must NOT hand back a false recovery
    // assurance (CLAUDE.md invariant 5).
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runDisable([], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("still shows the wall ENABLED");
    expect(out.text()).not.toContain("Castle Wall disarmed");
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
    const code = await runEnable(["--no-ttl"], {
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

  it("enable requires an explicit dead-man TTL mode", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable([], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceInstalledProbe: async () => true,
      sysextProbe: async () => "[activated enabled]",
    });

    expect(code).toBe(2);
    expect(err.text()).toContain("requires either --ttl");
    expect(calls).toHaveLength(0);
  });

  it("parseCastleWallArgs understands ttl modes", () => {
    expect(parseCastleWallArgs(["--ttl", "30s"]).ttlSeconds).toBe(30);
    expect(parseCastleWallArgs(["--ttl=5m"]).ttlSeconds).toBe(300);
    expect(parseCastleWallArgs(["--no-ttl"]).noTtl).toBe(true);
  });

  it("enable returns distinct exit 4 + toggle guidance when the sysext is activated-but-disabled", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(["--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceInstalledProbe: async () => true,
      sysextProbe: async () => "[activated disabled]",
    });

    expect(code).toBe(4);
    expect(err.text()).toContain("system extension is installed but toggled OFF");
    expect(err.text()).toContain("Network Extensions");
    // Never reaches the host app: nothing to arm over a disabled extension.
    expect(calls).toHaveLength(0);
  });

  it("disable ignores a disabled sysext (stays the unconditional dead-man lever)", async () => {
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
      sysextProbe: async () => {
        throw new Error("disable must never consult the sysext probe");
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall disarmed");
    expect(calls.map((c) => c[2])).toEqual(["disable", "status"]);
  });

  it("defaults to the LaunchServices invoker (routes arm through `open`) when none is injected", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const openArgs: string[][] = [];
    const reportPath = join(tmpdir(), "sanctuary-cw-default-report.json");

    // No hostAppInvoke: exercises the real default (LaunchServices) path,
    // but with the `open` runner + report path stubbed so no process spawns.
    const code = await runEnable(["--force", "--no-ttl"], {
      out,
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      sysextProbe: async () => "[activated enabled]",
      reportPathFactory: () => reportPath,
      runningAppController: {
        isRunning: async () => false,
        terminate: async () => true,
      },
      openRunner: async (command, args) => {
        openArgs.push([command, ...args]);
        // Simulate the host app writing its report, keyed off the action arg.
        const action = args[args.indexOf("--headless") + 1]!;
        const state = action === "status" ? "enabled" : "enabled";
        await writeFile(reportPath, reportLine(action, state, true));
        return { stdout: "", stderr: "", exitCode: 0 };
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    // Both the mutation and the post-change verification routed through `open`.
    expect(openArgs).toHaveLength(2);
    expect(openArgs[0]).toEqual([
      "open",
      "-n",
      "-W",
      hostAppPath, // no `.app` in the temp fixture path → bundle resolves to the binary
      "--args",
      "--headless",
      "enable",
      "--no-ttl",
      `--report-file=${reportPath}`,
    ]);
    expect(openArgs[1]!.slice(-2)).toEqual(["status", `--report-file=${reportPath}`]);
  });
});

describe("makeLaunchServicesHostAppInvoke", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function tmp(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cw-ls-"));
    tempDirs.push(dir);
    return dir;
  }

  const APP_BINARY =
    "/Applications/Sanctuary-CastleWall.app/Contents/MacOS/CastleWallHostApp";

  const notRunning = {
    isRunning: async () => false,
    terminate: async () => true,
  };

  it("resolves the .app bundle, round-trips the report file, and derives exit 0", async () => {
    const dir = await tmp();
    const reportPath = join(dir, "report.json");
    let captured: string[] = [];
    const openRunner: OpenRunner = async (_command, args) => {
      captured = args;
      await writeFile(reportPath, reportLine("enable", "enabled", true));
      return { stdout: "", stderr: "", exitCode: 0 };
    };

    const invoke = makeLaunchServicesHostAppInvoke({
      timeoutMs: 1000,
      openRunner,
      reportPathFactory: () => reportPath,
      runningAppController: notRunning,
    });
    const result = await invoke(APP_BINARY, ["--headless", "enable"]);

    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout.trim()).state).toBe("enabled");
    expect(captured).toEqual([
      "-n",
      "-W",
      "/Applications/Sanctuary-CastleWall.app",
      "--args",
      "--headless",
      "enable",
      `--report-file=${reportPath}`,
    ]);
    // The temp report file is cleaned up after the round-trip.
    await expect(readFile(reportPath, "utf8")).rejects.toThrow();
  });

  it("fail-closes (exit 1) when the host app writes no report file", async () => {
    const dir = await tmp();
    const reportPath = join(dir, "missing.json");
    const invoke = makeLaunchServicesHostAppInvoke({
      timeoutMs: 1000,
      reportPathFactory: () => reportPath,
      runningAppController: notRunning,
      openRunner: async () => ({ stdout: "", stderr: "boom", exitCode: 0 }),
    });

    const result = await invoke(APP_BINARY, ["--headless", "enable"]);
    expect(result.exitCode).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("no report");
    expect(result.stderr).toContain("Network Extensions");
  });

  it("fail-closes (exit 1) when the report file is unparseable", async () => {
    const dir = await tmp();
    const reportPath = join(dir, "garbage.json");
    const invoke = makeLaunchServicesHostAppInvoke({
      timeoutMs: 1000,
      reportPathFactory: () => reportPath,
      runningAppController: notRunning,
      openRunner: async () => {
        await writeFile(reportPath, "not json at all\n");
        return { stdout: "", stderr: "", exitCode: 0 };
      },
    });

    const result = await invoke(APP_BINARY, ["--headless", "enable"]);
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain("unparseable");
  });

  it("maps a needs_user_approval report to exit 3", async () => {
    const dir = await tmp();
    const reportPath = join(dir, "approval.json");
    const invoke = makeLaunchServicesHostAppInvoke({
      timeoutMs: 1000,
      reportPathFactory: () => reportPath,
      runningAppController: notRunning,
      openRunner: async () => {
        await writeFile(
          reportPath,
          reportLine("enable", "needs_user_approval", false, "consent missing"),
        );
        return { stdout: "", stderr: "", exitCode: 3 };
      },
    });

    const result = await invoke(APP_BINARY, ["--headless", "enable"]);
    expect(result.exitCode).toBe(3);
  });

  it("maps an ok:false report to exit 1", async () => {
    const dir = await tmp();
    const reportPath = join(dir, "fail.json");
    const invoke = makeLaunchServicesHostAppInvoke({
      timeoutMs: 1000,
      reportPathFactory: () => reportPath,
      runningAppController: notRunning,
      openRunner: async () => {
        await writeFile(
          reportPath,
          reportLine("enable", "unknown", false, "saveToPreferences failed"),
        );
        return { stdout: "", stderr: "", exitCode: 1 };
      },
    });

    const result = await invoke(APP_BINARY, ["--headless", "enable"]);
    expect(result.exitCode).toBe(1);
  });

  it("terminates an already-running GUI app before blocking LaunchServices mode", async () => {
    const dir = await tmp();
    const reportPath = join(dir, "report.json");
    const events: string[] = [];
    const invoke = makeLaunchServicesHostAppInvoke({
      timeoutMs: 1000,
      reportPathFactory: () => reportPath,
      runningAppController: {
        isRunning: async () => {
          events.push("probe");
          return events.length === 1;
        },
        terminate: async (processName) => {
          events.push(`terminate:${processName}`);
          return true;
        },
      },
      openRunner: async () => {
        events.push("open");
        await writeFile(reportPath, reportLine("enable", "enabled", true));
        return { stdout: "", stderr: "", exitCode: 0 };
      },
    });

    const result = await invoke(APP_BINARY, ["--headless", "enable"]);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toContain("already running");
    expect(result.stderr).toContain("relaunching headlessly");
    expect(events).toEqual(["probe", "terminate:CastleWallHostApp", "open"]);
  });
});
