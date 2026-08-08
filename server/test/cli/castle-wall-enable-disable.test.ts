import { afterEach, describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import { parseFrame } from "../../src/castle-wall/ipc/framing.js";
import { createTempHome } from "../helpers/temp-fortress.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { generateRandomKey } from "../../src/core/random.js";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  CASTLE_WALL_HEADLESS_CONTRACT_VERSION,
  formatEnforcementAvailabilityStatus,
  makeLaunchServicesHostAppInvoke,
  parseCastleWallArgs,
  runDisable,
  runEnable as runEnableRaw,
  type CastleWallCommandContext,
  type HostAppInvoker,
  type OpenRunner,
} from "../../src/cli/castle-wall.js";
import type { ResolvedEnforcementAvailability } from "../../src/castle-wall/runtime/enforcement-availability.js";
import {
  CASTLE_WALL_BOOT_LABEL,
  bootServiceInstalled,
  bootServiceReady,
  renderBootLaunchDaemonPlist,
} from "../../src/cli/castle-wall-boot.js";

const TEST_BUILD_SHA = "test-build-sha";

const TEST_OPERATOR_UID = String(process.getuid?.() ?? 501);
const TEST_OPERATOR_GID = String(process.getgid?.() ?? 20);

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

function availability(
  overrides: Partial<ResolvedEnforcementAvailability> = {},
): ResolvedEnforcementAvailability {
  return {
    status: "live",
    reason: "ok",
    observed_at: "2026-08-02T00:00:00.000Z",
    freshness_window_ms: 30_000,
    active_connection_count: 1,
    ...overrides,
  };
}

function runEnable(
  argv: string[],
  ctx: CastleWallCommandContext = {},
): Promise<number> {
  return runEnableRaw(argv, {
    enforcementAvailabilityQuery: async () => availability(),
    ...ctx,
  });
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

  function makeBootServiceReadyProbe(
    plistPath: string,
    loadedFortressPath: string,
    opts: { disabled?: boolean; running?: boolean } = {},
  ): (expectedFortressPath?: string) => Promise<boolean> {
    const disabled = opts.disabled ?? false;
    const running = opts.running ?? true;
    const execFileFn = (cmd: string, args: string[]) => {
      if (cmd === "launchctl" && args[0] === "print-disabled") {
        return {
          code: 0,
          stdout: `disabled services = {\n\t"${CASTLE_WALL_BOOT_LABEL}" => ${disabled ? "disabled" : "enabled"}\n}\n`,
          stderr: "",
        };
      }
      if (cmd === "launchctl" && args[0] === "print") {
        return running
          ? {
              code: 0,
              stdout:
                "\tstate = running\n" +
                "\tpid = 4242\n" +
                "\tenvironment = {\n" +
                `\t\tSANCTUARY_STORAGE_PATH => ${loadedFortressPath}\n` +
                "\t}\n",
              stderr: "",
            }
          : { code: 113, stdout: "", stderr: "Could not find service" };
      }
      return { code: 1, stdout: "", stderr: `unexpected command: ${cmd}` };
    };
    return (expectedFortressPath?: string) =>
      bootServiceReady(plistPath, expectedFortressPath, execFileFn, async () => {});
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
      bootServiceReadyProbe: async () => false,
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
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressA),
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
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      // This test targets the boot-service guard, not the descriptor guard.
      agentOriginDescriptorProbe: async () => true,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    expect(out.text()).toContain(
      "verified via host-app status, system extension state, and enforcement availability",
    );
  });

  it("enable does not claim content filter enabled while the sysext waits for user approval", async () => {
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
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated waiting for user]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
    });

    expect(code).toBe(0);
    expect(out.text()).not.toContain("content filter enabled");
    expect(out.text()).toContain("waiting for user approval");
    expect(out.text()).toContain("System Settings");
  });

  it("enable does not claim content filter enabled when sysext state is unreadable", async () => {
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
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => {
        throw new Error("systemextensionsctl unavailable");
      },
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
    });

    expect(code).toBe(0);
    expect(out.text()).not.toContain("content filter enabled");
    expect(out.text()).toContain("system extension state could not be read");
    expect(out.text()).toContain("System Settings");
  });

  it("enable refuses the verified claim when the shared availability verdict is heartbeat_stopped", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
      enforcementAvailabilityQuery: async () =>
        availability({
          status: "non_green",
          reason: "lease:heartbeat_stopped",
        }),
    });

    expect(code).toBe(1);
    expect(out.text()).not.toContain("verified via host-app status and system extension state");
    expect(err.text()).toContain(
      "Enforcement availability: non_green (lease:heartbeat_stopped",
    );
    expect(err.text()).toContain(
      "sudo launchctl kickstart -k system/ai.sanctuaryprotocol.castle-wall.daemon",
    );
  });

  it("enable refusal renders the same arm_lease_missing availability verdict as status", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });
    const sharedVerdict = availability({
      status: "non_green",
      reason: "lease:arm_lease_missing",
      observed_at: "2026-08-02T01:02:03.000Z",
      active_connection_count: 2,
    });
    let queries = 0;

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
      enforcementAvailabilityQuery: async () => {
        queries += 1;
        return sharedVerdict;
      },
    });

    expect(code).toBe(1);
    expect(queries).toBe(1);
    expect(out.text()).not.toContain("content filter enabled");
    expect(err.text()).toContain(formatEnforcementAvailabilityStatus(sharedVerdict));
    expect(err.text()).toContain(
      "sudo launchctl kickstart -k system/ai.sanctuaryprotocol.castle-wall.daemon",
    );
  });

  it("enable fails closed when the availability verdict cannot be read", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
      enforcementAvailabilityQuery: async () => {
        throw new Error("malformed enforcement availability response");
      },
    });

    expect(code).toBe(1);
    expect(out.text()).not.toContain("content filter enabled");
    expect(err.text()).toContain(
      "Enforcement availability: undetermined (availability_query_failed:malformed enforcement availability response",
    );
    expect(err.text()).toContain("Treat the wall as not enforcing");
  });

  it("enable refuses when the matching boot service is disabled", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(fortressPath));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath, {
        disabled: true,
      }),
      bootServiceInstalledProbe: (expectedFortressPath) =>
        bootServiceInstalled(plistPath, expectedFortressPath),
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("installed but not ready/enabled/loaded");
    expect(calls).toHaveLength(0);
  });

  it("enable refuses when the matching boot service is not loaded", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(fortressPath));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath, {
        running: false,
      }),
      bootServiceInstalledProbe: (expectedFortressPath) =>
        bootServiceInstalled(plistPath, expectedFortressPath),
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("installed but not ready/enabled/loaded");
    expect(calls).toHaveLength(0);
  });

  it("enable REFUSES when no agent-origin descriptor is set and no --force (#877 boot-cut guard)", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => false,
    });

    // Refuses like the sibling brick-guards; nothing is armed.
    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(err.text()).toContain("boot-cut");
    expect(err.text()).toContain("configure-origin");
    expect(err.text()).toContain("--force");
    expect(calls).toHaveLength(0);
  });

  it("enable does NOT warn about the descriptor when a valid one is set", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    expect(err.text()).not.toContain("no agent-origin descriptor");
  });

  it("enable --force arms agent-only despite no descriptor, with a loud warning", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    // --force is the intentional agent-only lockdown escape hatch: it bypasses
    // the daemon + boot-service brick guards AND the descriptor refuse, but the
    // descriptor warning must still fire and the arm must proceed.
    const code = await runEnable(["--force", "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => false,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    expect(err.text()).toContain("no agent-origin descriptor");
    // The arm actually reached the host app (proved it was not refused).
    expect(calls.length).toBeGreaterThan(0);
  });

  it("enable's DEFAULT descriptor probe REFUSES when the on-disk descriptor is absent (real read path)", async () => {
    // No agentOriginDescriptorProbe injected: exercises the production
    // defaultAgentOriginDescriptorPresent read+validate path against a fortress
    // with no policy/egress/agent-origin.json on disk.
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(calls).toHaveLength(0);
  });

  it("enable's DEFAULT descriptor probe stays silent when a valid descriptor is on disk (real read path)", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    // Write a structurally valid uid-mode descriptor where the real probe reads.
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });
    await writeFile(
      join(fortressPath, "policy", "egress", "agent-origin.json"),
      JSON.stringify({ mode: "uid", agent_uid: 502, system_uid_allow_ceiling: 500 }),
    );
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
    });

    expect(code).toBe(0);
    expect(err.text()).not.toContain("no agent-origin descriptor");
  });

  // --- Build 3: `enable --agent-uid=<uid> [--ceiling=<uid>]` one-command arm ---
  // Folds `configure-origin uid` into `enable` via the shared
  // `writeAgentOriginDescriptor` chokepoint. These tests exercise the fold
  // directly through `runEnable`; they inject `platform: "darwin"` (a plain
  // string, not a real OS check) so they run identically on Linux CI.

  it("enable --agent-uid writes a valid descriptor then proceeds to arm", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const out = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=502"],
      {
        out,
        err: new CaptureStream(),
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
        // No agentOriginDescriptorProbe override: exercises the REAL
        // read-back path, proving the descriptor this command just wrote
        // satisfies the very guard that follows it.
      },
    );

    expect(code).toBe(0);
    expect(out.text()).toContain("Agent origin configured: mode=uid agent_uid=502 ceiling=500");
    expect(out.text()).toContain("Castle Wall armed");

    const raw = await readFile(
      join(fortressPath, "policy", "egress", "agent-origin.json"),
      "utf8",
    );
    expect(JSON.parse(raw)).toEqual({
      mode: "uid",
      agent_uid: 502,
      system_uid_allow_ceiling: 500,
    });
  });

  it("enable --agent-uid honors --ceiling", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    // agent_uid must be >= ceiling (the floor invariant), so use 650/600.
    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=650", "--ceiling=600"],
      {
        out: new CaptureStream(),
        err: new CaptureStream(),
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(0);
    const raw = await readFile(
      join(fortressPath, "policy", "egress", "agent-origin.json"),
      "utf8",
    );
    expect(JSON.parse(raw).system_uid_allow_ceiling).toBe(600);
  });

  it("enable --agent-uid rejects a malformed uid fail-closed and does NOT arm", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=not-a-number"],
      {
        out: new CaptureStream(),
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(err.text()).toContain("not-a-number");
    expect(err.text()).toContain("plain positive integer");
    expect(calls).toHaveLength(0);

    // No half-built descriptor was written to disk (fail-closed: validate
    // before write, never a partially-trusted candidate on disk).
    await expect(
      readFile(join(fortressPath, "policy", "egress", "agent-origin.json"), "utf8"),
    ).rejects.toThrow();
  });

  it("enable --agent-uid=0 is REFUSED (root can never be the confined agent) and does NOT arm", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=0", "--ceiling=0"],
      {
        out: new CaptureStream(),
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(calls).toHaveLength(0);
    await expect(
      readFile(join(fortressPath, "policy", "egress", "agent-origin.json"), "utf8"),
    ).rejects.toThrow();
  });

  it("enable --agent-uid below --ceiling is REFUSED and does NOT arm", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=100", "--ceiling=500"],
      {
        out: new CaptureStream(),
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(calls).toHaveLength(0);
  });

  it("enable --agent-uid EQUAL to --ceiling is accepted (boundary) and arms", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });
    const out = new CaptureStream();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=500", "--ceiling=500"],
      {
        out,
        err: new CaptureStream(),
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    const raw = await readFile(
      join(fortressPath, "policy", "egress", "agent-origin.json"),
      "utf8",
    );
    expect(JSON.parse(raw)).toEqual({
      mode: "uid",
      agent_uid: 500,
      system_uid_allow_ceiling: 500,
    });
  });

  it("enable rejects a truncation-prone --agent-uid (501abc) fail-closed, NOT silently 501", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=501abc"],
      {
        out: new CaptureStream(),
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("plain positive integer");
    expect(calls).toHaveLength(0);
    await expect(
      readFile(join(fortressPath, "policy", "egress", "agent-origin.json"), "utf8"),
    ).rejects.toThrow();
  });

  it("enable rejects a truncation-prone --ceiling (500abc) fail-closed and does NOT arm", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=502", "--ceiling=500abc"],
      {
        out: new CaptureStream(),
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        // These tests are not about the no-egress brick guard; report one
        // agent-matchable allow rule so the guard stays out of the way (the
        // guard's own behavior has dedicated tests below).
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("--ceiling");
    expect(calls).toHaveLength(0);
    await expect(
      readFile(join(fortressPath, "policy", "egress", "agent-origin.json"), "utf8"),
    ).rejects.toThrow();
  });

  it("enable with NO --agent-uid and no descriptor on disk still REFUSES unless --force (#884 floor preserved)", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    // No --agent-uid at all: the fold-in step must be a no-op, leaving the
    // pre-existing #884 hard-refuse floor completely unchanged.
    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      // Real read-back path (no override): no descriptor exists on disk.
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("Refusing to arm");
    expect(err.text()).toContain("no agent-origin descriptor is set");
    expect(calls).toHaveLength(0);
  });

  it("enable with NO --agent-uid and no descriptor on disk arms under --force (unchanged #884 escape hatch)", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });

    const code = await runEnable(["--fortress", fortressPath, "--force", "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
    expect(err.text()).toContain("no agent-origin descriptor");
    expect(calls.length).toBeGreaterThan(0);
  });

  it("enable accepts a boot service that targets the default fortress", async () => {
    // HOME is redirected (not SANCTUARY_STORAGE_PATH, which would defeat the
    // default-fortress branch under test) so "the default fortress" is a temp
    // path, never the operator's own.
    const tempHome = await createTempHome("sanctuary-cw-default-boot-home");
    try {
      const defaultFortressPath = tempHome.defaultFortressPath;
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
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, defaultFortressPath),
      });

      expect(code).toBe(2);
      expect(err.text()).toContain("requires either --ttl");
      expect(err.text()).not.toContain("no persistent Castle Wall boot service");
      expect(err.text()).not.toContain("targets a different fortress");
    } finally {
      await tempHome.cleanup();
    }
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
      egressAllowRuleCountProbe: async () => 1,
      bootServiceReadyProbe: async () => {
        throw new Error("boot-service probe must not run under --force");
      },
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
  });

  it("enable --agent-uid refuses a symlinked policy ancestor before writing outside", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const plistPath = join(fortressPath, "boot.plist");
    await writeFile(plistPath, makeBootPlist(`${fortressPath}/`));
    const outside = await mkdtemp(join(tmpdir(), "cw-agent-origin-outside-"));
    tempDirs.push(outside);
    await symlink(outside, join(fortressPath, "policy"));
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=502"],
      {
        out: new CaptureStream(),
        err,
        env: { ...env, SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID, SUDO_USER: "operator" },
        platform: "darwin",
        getuid: () => 0,
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fortressPath),
        sysextProbe: async () => "[activated enabled]",
        egressAllowRuleCountProbe: async () => 1,
      },
    );

    expect(code).toBe(1);
    expect(err.text()).toContain("refusing an owner-write through");
    await expect(readFile(join(outside, "egress", "agent-origin.json"), "utf8")).rejects.toThrow();
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

    const code = await runEnable(["--force", "--no-ttl"], {
      out,
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
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
      egressAllowRuleCountProbe: async () => 1,
      daemonProbe: async () => true,
      bootServiceReadyProbe: async () => true,
      // This test targets the audit trail, not the descriptor guard.
      agentOriginDescriptorProbe: async () => true,
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
      egressAllowRuleCountProbe: async () => 1,
      daemonProbe: async () => true,
      bootServiceReadyProbe: async () => true,
      // This test targets the one-time GUI consent, not the descriptor guard.
      agentOriginDescriptorProbe: async () => true,
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

  it.each([
    {
      label: "observed disabled",
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
      outcome: "corroborated_off",
    },
    {
      label: "status timed out",
      status: { stdout: "", stderr: "timeout", exitCode: 124 },
      outcome: "save_accepted_inconclusive",
    },
    {
      label: "status unparseable",
      status: { stdout: "not json\n", exitCode: 0 },
      outcome: "save_accepted_inconclusive",
    },
    {
      label: "status unknown",
      status: { stdout: reportLine("status", "unknown", true), exitCode: 0 },
      outcome: "save_accepted_inconclusive",
    },
  ] as const)("B1 disable outcome: $label", async ({ status, outcome }) => {
    const { hostAppPath, env } = await makeFixture();
    const observed: string[] = [];
    const { invoke } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status,
    });

    const code = await runDisable([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      onDisableNePreferenceOutcome: (value) => {
        observed.push(value);
      },
    });

    expect(code).toBe(0);
    expect(observed).toEqual([outcome]);
  });

  it("disable sends a revoke-flagged lease before claiming fail-open recovery", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const received: Array<Record<string, unknown>> = [];
    const outcomes: string[] = [];
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
        onDisableNePreferenceOutcome: (value) => {
          outcomes.push(value);
        },
      });

      expect(code).toBe(0);
      expect(err.text()).toContain("fail-open path is active");
      expect(out.text()).toContain("provider dead-man lease revoked");
      expect(outcomes).toEqual(["fail_open_deadman"]);
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
      egressAllowRuleCountProbe: async () => 1,
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
      egressAllowRuleCountProbe: async () => 1,
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
      egressAllowRuleCountProbe: async () => 1,
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

  it("trusts an operator-owned host app when running as root via sudo", async () => {
    const { hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const operatorUid = process.getuid?.();
    expect(operatorUid).toBeDefined();
    const { invoke, calls } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });

    const code = await runDisable([], {
      out,
      err,
      env: { ...env, SUDO_UID: String(operatorUid), SUDO_GID: TEST_OPERATOR_GID },
      platform: "darwin",
      getuid: () => 0,
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
    });

    expect(code).toBe(0);
    expect(calls[0]?.[0]).toBe(hostAppPath);
    expect(out.text()).toContain("Castle Wall disarmed");
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

  it("parseCastleWallArgs understands --agent-uid and --ceiling", () => {
    expect(parseCastleWallArgs(["--agent-uid=502"]).agentUid).toBe("502");
    expect(parseCastleWallArgs(["--agent-uid=502", "--ceiling=600"]).ceiling).toBe(
      "600",
    );
    expect(parseCastleWallArgs([]).agentUid).toBeUndefined();
    expect(parseCastleWallArgs([]).ceiling).toBeUndefined();
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
      bootServiceReadyProbe: async () => true,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
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
      bootServiceReadyProbe: async () => true,
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
      egressAllowRuleCountProbe: async () => 1,
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

  // ── Confined-agent egress (design 2026-07-10, section 5 layer 2): the
  //    standing no-egress brick guard on `enable` in uid mode ────────────────
  describe("no-egress brick guard (uid mode)", () => {
    async function writeUidDescriptor(fortressPath: string): Promise<void> {
      await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });
      await writeFile(
        join(fortressPath, "policy", "egress", "agent-origin.json"),
        JSON.stringify({ mode: "uid", agent_uid: 502, system_uid_allow_ceiling: 500 }),
      );
    }

    function guardCtx(
      fixture: { fortressPath: string; hostAppPath: string; env: Record<string, string> },
      plistPath: string,
      err: CaptureStream,
      invoke: HostAppInvoker,
      extras: Record<string, unknown> = {},
    ) {
      return {
        out: new CaptureStream(),
        err,
        env: fixture.env,
        platform: "darwin" as const,
        hostAppCandidates: [fixture.hostAppPath],
        hostAppInvoke: invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: makeBootServiceReadyProbe(plistPath, fixture.fortressPath),
        sysextProbe: async () => "[activated enabled]" as const,
        sudoPreflightProbe: async () => ({ ok: true, exitCode: 0 }),
        ...extras,
      };
    }

    it("REFUSES to arm a uid-mode wall with ZERO agent-matchable allow rules (real disk read: empty rules dir) and names --allow-no-egress", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const err = new CaptureStream();
      const { invoke, calls } = makeInvoker({});

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl"],
        guardCtx(fixture, plistPath, err, invoke),
      );

      expect(code).toBe(1);
      expect(err.text()).toContain("ZERO agent-matchable allow rules");
      expect(err.text()).toContain("--allow-no-egress");
      // The wall was NEVER armed (no host-app invoke at all).
      expect(calls).toHaveLength(0);
    });

    it("the refusal is AUDITED as egress_provision_refused (queryable proof the guard fired)", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const err = new CaptureStream();
      const { invoke } = makeInvoker({});

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl"],
        guardCtx(fixture, plistPath, err, invoke),
      );
      expect(code).toBe(1);

      const storage = new FilesystemStorage(join(fixture.fortressPath, "state"));
      const { establishMaster } = await import("../../src/core/master-custody.js");
      const { masterKey } = await establishMaster({
        storage,
        recoveryKey: fixture.env.SANCTUARY_RECOVERY_KEY!,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
        storagePathHint: fixture.fortressPath,
      });
      const auditLog = new AuditLog(storage, masterKey);
      const { entries } = await auditLog.query({ layer: "l1", limit: 100 });
      const refusal = entries.find((e) => e.operation === "egress_provision_refused");
      expect(refusal).toBeDefined();
      expect(refusal?.details).toMatchObject({
        guard: "no-egress-brick",
        agent_matchable_allow_rules: 0,
      });
    });

    it("--allow-no-egress refuses before arming when sudo preflight cannot run as the target uid and audits the guard", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const err = new CaptureStream();
      let preflightUid: number | undefined;
      const { invoke, calls } = makeInvoker({});

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl", "--allow-no-egress"],
        guardCtx(fixture, plistPath, err, invoke, {
          sudoPreflightProbe: async (uid: number) => {
            preflightUid = uid;
            return {
              ok: false,
              exitCode: 1,
              stderr: "sudo: a password is required",
              command: ["/usr/bin/sudo", "-n", "-u", "#502", "/usr/bin/true"],
            };
          },
        }),
      );

      expect(code).toBe(1);
      expect(preflightUid).toBe(502);
      expect(err.text()).toContain("non-interactive sudo credential");
      expect(err.text()).toContain("sudo -v");
      expect(err.text()).toContain("The wall was not armed");
      expect(err.text()).toContain("sudo: a password is required");
      expect(err.text()).not.toContain("disarm");
      expect(calls).toHaveLength(0);

      const storage = new FilesystemStorage(join(fixture.fortressPath, "state"));
      const { establishMaster } = await import("../../src/core/master-custody.js");
      const { masterKey } = await establishMaster({
        storage,
        recoveryKey: fixture.env.SANCTUARY_RECOVERY_KEY!,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
        storagePathHint: fixture.fortressPath,
      });
      const auditLog = new AuditLog(storage, masterKey);
      const { entries } = await auditLog.query({ layer: "l1", limit: 100 });
      const refusal = entries.find(
        (e) =>
          e.operation === "egress_provision_refused" &&
          (e.details as Record<string, unknown>).guard === "sudo-preflight",
      );
      expect(refusal?.details).toMatchObject({
        guard: "sudo-preflight",
        agent_uid: 502,
        exit_code: 1,
        disarm_outcome: "not-armed",
      });
    });

    it("--allow-no-egress refuses before arming when the quarantine uid cannot be resolved", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const err = new CaptureStream();
      const { invoke, calls } = makeInvoker({});

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl", "--allow-no-egress"],
        guardCtx(fixture, plistPath, err, invoke, {
          egressAllowRuleCountProbe: async () => {
            await writeFile(
              join(fixture.fortressPath, "policy", "egress", "agent-origin.json"),
              JSON.stringify({ mode: "uid", system_uid_allow_ceiling: 500 }),
            );
            return 0;
          },
          sudoPreflightProbe: async () => {
            throw new Error("preflight should not run without a resolved uid");
          },
        }),
      );

      expect(code).toBe(1);
      expect(err.text()).toContain("uid-mode agent-origin descriptor could not be resolved");
      expect(err.text()).toContain("The wall was not armed");
      expect(err.text()).not.toContain("disarm");
      expect(calls).toHaveLength(0);

      const storage = new FilesystemStorage(join(fixture.fortressPath, "state"));
      const { establishMaster } = await import("../../src/core/master-custody.js");
      const { masterKey } = await establishMaster({
        storage,
        recoveryKey: fixture.env.SANCTUARY_RECOVERY_KEY!,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
        storagePathHint: fixture.fortressPath,
      });
      const auditLog = new AuditLog(storage, masterKey);
      const { entries } = await auditLog.query({ layer: "l1", limit: 100 });
      const refusal = entries.find(
        (e) =>
          e.operation === "egress_provision_refused" &&
          (e.details as Record<string, unknown>).guard ===
            "deny-all-quarantine-uid-resolution",
      );
      expect(refusal?.details).toMatchObject({
        guard: "deny-all-quarantine-uid-resolution",
        observed: "unverified",
        disarm_outcome: "not-armed",
      });
    });

    it("--allow-no-egress overrides the guard (deliberate quarantine), warns loudly, arms, and the override is audited on wall_armed", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const err = new CaptureStream();
      const out = new CaptureStream();
      let probeInput: { agentUid: number; host: string; port: number } | undefined;
      let preflightUid: number | undefined;
      const events: string[] = [];
      const { invoke } = makeInvoker({
        enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
        status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
      });
      const trackingInvoke: HostAppInvoker = async (binaryPath, args) => {
        events.push(`invoke:${args[1]}`);
        return invoke(binaryPath, args);
      };

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl", "--allow-no-egress"],
        guardCtx(fixture, plistPath, err, invoke, {
          out,
          hostAppInvoke: trackingInvoke,
          sudoPreflightProbe: async (uid: number) => {
            preflightUid = uid;
            events.push(`preflight:${uid}`);
            return { ok: true, exitCode: 0 };
          },
          denyAllQuarantineProbe: async (input: { agentUid: number; host: string; port: number }) => {
            probeInput = input;
            events.push(`smoke:${input.agentUid}`);
            return {
              reachable: false,
              verified: true,
              exitCode: 28,
              stderr: "curl: (28) Operation timed out",
              command: ["/usr/bin/sudo", "-n", "-u", "#502", "/usr/bin/curl", "--noproxy", "*"],
            };
          },
        }),
      );

      expect(code).toBe(0);
      expect(err.text()).toContain("--allow-no-egress");
      expect(err.text()).toContain("deliberate quarantine");
      expect(out.text()).toContain("Deny-all quarantine smoke passed");
      expect(preflightUid).toBe(502);
      expect(probeInput).toMatchObject({ agentUid: 502, host: "example.com", port: 443 });
      expect(events).toEqual(["preflight:502", "invoke:enable", "invoke:status", "smoke:502"]);

      const storage = new FilesystemStorage(join(fixture.fortressPath, "state"));
      const { establishMaster } = await import("../../src/core/master-custody.js");
      const { masterKey } = await establishMaster({
        storage,
        recoveryKey: fixture.env.SANCTUARY_RECOVERY_KEY!,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
        storagePathHint: fixture.fortressPath,
      });
      const auditLog = new AuditLog(storage, masterKey);
      const { entries } = await auditLog.query({ layer: "l1", limit: 100 });
      const armed = entries.find((e) => e.operation === "wall_armed");
      expect(armed).toBeDefined();
      expect(armed?.details).toMatchObject({ allow_no_egress_override: true });
    });

    it("--allow-no-egress refuses the armed claim when the direct negative-control probe is reachable", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const out = new CaptureStream();
      const err = new CaptureStream();
      const { invoke } = makeInvoker({
        enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
        status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
      });

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl", "--allow-no-egress"],
        guardCtx(fixture, plistPath, err, invoke, {
          out,
          denyAllQuarantineProbe: async () => ({
            reachable: true,
            verified: true,
            exitCode: 0,
            command: [
              "/usr/bin/sudo",
              "-n",
              "-u",
              "#502",
              "/usr/bin/curl",
              "--noproxy",
              "*",
              "https://example.com:443/",
            ],
          }),
        }),
      );

      expect(code).toBe(1);
      expect(err.text()).toContain("deny-all quarantine smoke FAILED");
      expect(err.text()).toContain("uid 502 reached example.com:443");
      expect(err.text()).toContain("--noproxy");
      expect(out.text()).not.toContain("Castle Wall armed");

      const storage = new FilesystemStorage(join(fixture.fortressPath, "state"));
      const { establishMaster } = await import("../../src/core/master-custody.js");
      const { masterKey } = await establishMaster({
        storage,
        recoveryKey: fixture.env.SANCTUARY_RECOVERY_KEY!,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
        storagePathHint: fixture.fortressPath,
      });
      const auditLog = new AuditLog(storage, masterKey);
      const { entries } = await auditLog.query({ layer: "l1", limit: 100 });
      const refusal = entries.find(
        (e) =>
          e.operation === "egress_provision_refused" &&
          (e.details as Record<string, unknown>).guard === "deny-all-quarantine-smoke",
      );
      expect(refusal?.details).toMatchObject({
        observed: "reachable",
        agent_uid: 502,
        negative_control_host: "example.com",
      });
    });

    it("--allow-no-egress refuses the armed claim when the direct negative-control probe is inconclusive", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const out = new CaptureStream();
      const err = new CaptureStream();
      const { invoke } = makeInvoker({
        enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
        status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
      });

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl", "--allow-no-egress"],
        guardCtx(fixture, plistPath, err, invoke, {
          out,
          denyAllQuarantineProbe: async () => ({
            reachable: false,
            verified: false,
            exitCode: 1,
            stderr: "sudo: a password is required",
            command: ["/usr/bin/sudo", "-n", "-u", "#502", "/usr/bin/curl"],
          }),
        }),
      );

      expect(code).toBe(1);
      expect(err.text()).toContain("could not verify the direct as-uid path");
      expect(err.text()).toContain("sudo: a password is required");
      expect(out.text()).not.toContain("Castle Wall armed");
    });

    it("arms WITHOUT the override when an agent-matchable allow rule exists on disk (real countAgentMatchableAllowRules path)", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      // A real, valid allow rule in the rules dir.
      const rulesDir = join(fixture.fortressPath, "policy", "egress", "rules");
      await mkdir(rulesDir, { recursive: true });
      await writeFile(
        join(rulesDir, "provisioned-hermes-abc123def456.json"),
        JSON.stringify({
          id: "provisioned-hermes-abc123def456",
          schema_version: 1,
          created_at: "2026-07-10T00:00:00Z",
          match: { host: ["api.venice.ai"], port: [443], protocol: "tcp" },
          scope: {},
          disposition: "allow",
          derived: true,
        }),
      );
      const err = new CaptureStream();
      const { invoke } = makeInvoker({
        enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
        status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
      });

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl"],
        guardCtx(fixture, plistPath, err, invoke),
      );

      expect(code).toBe(0);
      expect(err.text()).not.toContain("ZERO agent-matchable allow rules");
    });

    it("deny-only and reserved-habeas rules do NOT satisfy the guard (they grant the agent nothing)", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await writeUidDescriptor(fixture.fortressPath);
      const rulesDir = join(fixture.fortressPath, "policy", "egress", "rules");
      await mkdir(rulesDir, { recursive: true });
      await writeFile(
        join(rulesDir, "deny-everything-extra.json"),
        JSON.stringify({
          id: "deny-everything-extra",
          schema_version: 1,
          created_at: "2026-07-10T00:00:00Z",
          match: { host: ["api.evil.example"], port: [443], protocol: "tcp" },
          scope: {},
          disposition: "deny",
        }),
      );
      await writeFile(
        join(rulesDir, "reserved_habeas_distress_webhook.json"),
        JSON.stringify({
          id: "reserved_habeas_distress_webhook",
          schema_version: 1,
          created_at: "2026-07-10T00:00:00Z",
          match: { host: ["hooks.example.com"], port: [443], protocol: "tcp" },
          scope: { agent_ids: ["sanctuary-distress-daemon"] },
          disposition: "allow",
        }),
      );
      const err = new CaptureStream();
      const { invoke, calls } = makeInvoker({});

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl"],
        guardCtx(fixture, plistPath, err, invoke),
      );

      expect(code).toBe(1);
      expect(err.text()).toContain("ZERO agent-matchable allow rules");
      expect(calls).toHaveLength(0);
    });

    it("the guard does NOT fire for a NAT-mode descriptor (uid-mode-only by design)", async () => {
      const fixture = await makeFixture();
      const plistPath = join(fixture.fortressPath, "boot.plist");
      await writeFile(plistPath, makeBootPlist(`${fixture.fortressPath}/`));
      await mkdir(join(fixture.fortressPath, "policy", "egress"), { recursive: true });
      await writeFile(
        join(fixture.fortressPath, "policy", "egress", "agent-origin.json"),
        JSON.stringify({
          mode: "nat",
          egress_helper_signing_id: "ai.sanctuaryprotocol.egress-helper",
          system_uid_allow_ceiling: 500,
        }),
      );
      const err = new CaptureStream();
      const { invoke } = makeInvoker({
        enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
        status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
      });

      const code = await runEnable(
        ["--fortress", fixture.fortressPath, "--no-ttl"],
        guardCtx(fixture, plistPath, err, invoke),
      );

      expect(code).toBe(0);
      expect(err.text()).not.toContain("ZERO agent-matchable allow rules");
    });
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

describe("fortress-ownership guards on arm/disarm (spec 2026-07-30)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFixture() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-custody-"));
    tempDirs.push(fortressPath);
    const hostAppPath = join(fortressPath, "CastleWallHostApp");
    await writeFile(hostAppPath, "#!/bin/sh\n", { mode: 0o755 });
    const env = {
      SANCTUARY_STORAGE_PATH: fortressPath,
      SANCTUARY_RECOVERY_KEY: toBase64url(generateRandomKey()),
      SANCTUARY_CASTLE_BUILD_SHA: TEST_BUILD_SHA,
    };
    return { fortressPath, hostAppPath, env };
  }

  it("enable refuses a root-owned fortress before any other gate, and --force does not override", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke, calls } = makeInvoker({});

    const code = await runEnable(["--no-ttl", "--force"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      // Every downstream gate would pass; only the custody guard refuses.
      daemonProbe: async () => true,
      bootServiceReadyProbe: async () => true,
      sysextProbe: async () => "[activated enabled]",
      agentOriginDescriptorProbe: async () => true,
      fortressOwnerUidProbe: async () => 0,
    });

    expect(code).toBe(1);
    expect(err.text()).toContain("owned by root");
    expect(err.text()).toContain("repair-custody");
    expect(err.text()).toContain("--force does not override");
    // Never reaches the host app: nothing armed.
    expect(calls).toHaveLength(0);
  });

  it("enable proceeds when the fortress is operator-owned or unstattable", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
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
      bootServiceReadyProbe: async () => true,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
      fortressOwnerUidProbe: async () => 501,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain("Castle Wall armed");
  });

  it("a sudo enable runs the custody-normalize chokepoint with the resolved operator", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const { invoke } = makeInvoker({
      enable: { stdout: reportLine("enable", "enabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "enabled", true), exitCode: 0 },
    });
    const normalizeCalls: { fortressPath: string; operator: { uid: number; gid: number } }[] = [];

    const code = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: { ...env, SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID, SUDO_USER: "operator" },
      platform: "darwin",
      getuid: () => 0,
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      daemonProbe: async () => true,
      bootServiceReadyProbe: async () => true,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      agentOriginDescriptorProbe: async () => true,
      fortressOwnerUidProbe: async () => 501,
      normalizeFortressCustody: async (input) => {
        normalizeCalls.push({ fortressPath: input.fortressPath, operator: input.operator });
        return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
      },
    });

    expect(code).toBe(0);
    expect(normalizeCalls).toEqual([
      { fortressPath, operator: { uid: Number(TEST_OPERATOR_UID), gid: Number(TEST_OPERATOR_GID) } },
    ]);
  });

  it("a sudo disable runs the chokepoint too; a non-root run never does", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const responses = {
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    };
    const sudoCalls: string[] = [];
    expect(
      await runDisable([], {
        out: new CaptureStream(),
        err: new CaptureStream(),
        env: { ...env, SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID, SUDO_USER: "operator" },
        platform: "darwin",
        getuid: () => 0,
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: makeInvoker(responses).invoke,
        normalizeFortressCustody: async (input) => {
          sudoCalls.push(input.fortressPath);
          return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
        },
      }),
    ).toBe(0);
    expect(sudoCalls).toEqual([fortressPath]);

    const nonRootCalls: string[] = [];
    expect(
      await runDisable([], {
        out: new CaptureStream(),
        err: new CaptureStream(),
        env,
        platform: "darwin",
        // The REAL uid, so the host-app owner-trust check passes on any
        // runner; hard-coding 501 made this pass only where the author's uid
        // happened to match.
        getuid: () => Number(TEST_OPERATOR_UID),
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: makeInvoker(responses).invoke,
        normalizeFortressCustody: async (input) => {
          nonRootCalls.push(input.fortressPath);
          return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
        },
      }),
    ).toBe(0);
    expect(nonRootCalls).toEqual([]);
  });

  it("normalizes on REFUSAL exits too, not just success (gate HIGH: the descriptor/lease writes precede them)", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const sudoEnv = { ...env, SUDO_UID: TEST_OPERATOR_UID, SUDO_GID: TEST_OPERATOR_GID, SUDO_USER: "operator" };
    await mkdir(join(fortressPath, "policy", "egress"), { recursive: true });

    // (a) `--agent-uid` writes the agent-origin descriptor as root, THEN the
    // no-egress guard refuses. The chokepoint must still run.
    const noEgressCalls: string[] = [];
    const noEgress = await runEnable(
      ["--fortress", fortressPath, "--no-ttl", "--agent-uid=550"],
      {
        out: new CaptureStream(),
        err: new CaptureStream(),
        env: sudoEnv,
        platform: "darwin",
        getuid: () => 0,
        hostAppCandidates: [hostAppPath],
        hostAppInvoke: makeInvoker({}).invoke,
        daemonProbe: async () => true,
        bootServiceReadyProbe: async () => true,
        sysextProbe: async () => "[activated enabled]",
        fortressOwnerUidProbe: async () => 501,
        egressAllowRuleCountProbe: async () => 0,
        normalizeFortressCustody: async (input) => {
          noEgressCalls.push(input.fortressPath);
          return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
        },
      },
    );
    expect(noEgress).toBe(1);
    expect(noEgressCalls).toEqual([fortressPath]);

    // (b) `disable` writes the lease-status file, then the host app fails.
    const disableCalls: string[] = [];
    const failed = await runDisable(["--fortress", fortressPath], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: sudoEnv,
      platform: "darwin",
      getuid: () => 0,
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: makeInvoker({
        disable: { stdout: "", exitCode: 1, stderr: "host app exploded" },
      }).invoke,
      normalizeFortressCustody: async (input) => {
        disableCalls.push(input.fortressPath);
        return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
      },
    });
    expect(failed).toBe(1);
    expect(disableCalls).toEqual([fortressPath]);

    // (c) the root-owned-fortress arm refusal itself still normalizes.
    const refusalCalls: string[] = [];
    const refused = await runEnable(["--fortress", fortressPath, "--no-ttl"], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env: sudoEnv,
      platform: "darwin",
      getuid: () => 0,
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: makeInvoker({}).invoke,
      fortressOwnerUidProbe: async () => 0,
      normalizeFortressCustody: async (input) => {
        refusalCalls.push(input.fortressPath);
        return { status: "changed", repaired: ["."], skips: [], vanished: [], failed: [] };
      },
    });
    expect(refused).toBe(1);
    expect(refusalCalls).toEqual([fortressPath]);
  });

  it("a root run without a resolvable operator refuses before mutation", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const { invoke } = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });
    const calls: string[] = [];

    const code = await runDisable(["--fortress", fortressPath], {
      out: new CaptureStream(),
      err,
      // SUDO_GID missing: the fail-closed identity chokepoint refuses, even
      // though enough SUDO context exists for host-app trust resolution.
      env: { ...env, SUDO_UID: TEST_OPERATOR_UID },
      platform: "darwin",
      getuid: () => 0,
      hostAppCandidates: [hostAppPath],
      hostAppInvoke: invoke,
      normalizeFortressCustody: async (input) => {
        calls.push(input.fortressPath);
        return { status: "clean", repaired: [], skips: [], vanished: [], failed: [] };
      },
    });

    expect(code).toBe(1);
    expect(calls).toEqual([]);
    expect(err.text()).toContain("Cannot resolve the non-root operator identity");
  });
});
