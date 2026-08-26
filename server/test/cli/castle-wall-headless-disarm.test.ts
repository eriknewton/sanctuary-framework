import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  CASTLE_WALL_HEADLESS_CONTRACT_VERSION,
  makeIdentityIndependentHostAppInvoke,
  requestSystemExtensionDeactivation,
  runDisable,
  runEnable,
  type HostAppInvoker,
  type OpenRunner,
} from "../../src/cli/castle-wall.js";
import { flattenDisarmDetail, runUninstallCommand, type UninstallOps } from "../../src/cli/uninstall.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url } from "../../src/core/encoding.js";

// D5 drill 2026-08-25 (Mini1, macOS 26.5.2): with zero console users there is
// no Aqua domain, so the LaunchServices disarm invoke (`open -n -W`) fails
// before the host app runs, while direct exec of the same signed binary works
// and disables the filter. These tests pin the session-aware fallback for the
// protection-DECREASING verbs (disable / deactivate-system-extension), the
// unchanged LaunchServices-primary behavior in GUI sessions and on the enable
// path, and the truthful failure + lease-ratchet disclosure.

const TEST_BUILD_SHA = "test-build-sha";

// Mirrors the hardware failure shape from the D5 drill gui-session-probe
// evidence: `open` cannot launch anything without an Aqua domain.
const DRILL_OPEN_FAILURE_STDERR =
  "LSOpenURLsWithCompletionHandler() failed with error -10826: " +
  "RBSRequestErrorDomain error 5 / OSLaunchdErrorDomain error 125: " +
  "Domain does not support specified action";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: unknown,
    _encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

function reportLine(action: string, state: string, ok: boolean, error?: string): string {
  return (
    JSON.stringify({
      action,
      build: {
        git_sha: TEST_BUILD_SHA,
        headless_contract_version: CASTLE_WALL_HEADLESS_CONTRACT_VERSION,
      },
      error,
      ok,
      state,
    }) + "\n"
  );
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

/**
 * OpenRunner double that records calls and fails the way the drill hardware
 * did. Every test passes SOME openRunner so that no run (including the
 * fail-before run against pre-fix source, where the new seams are unknown
 * properties) ever shells out to the real `open` on a developer Mac.
 */
function failingOpenRunner(): { runner: OpenRunner; calls: string[][] } {
  const calls: string[][] = [];
  const runner: OpenRunner = async (command, args) => {
    calls.push([command, ...args]);
    return { stdout: "", stderr: DRILL_OPEN_FAILURE_STDERR, exitCode: 1 };
  };
  return { runner, calls };
}

/**
 * OpenRunner double that emulates a WORKING LaunchServices round-trip: it
 * parses the action and the `--report-file=` path out of the `open` argv and
 * writes the corresponding host-app report there.
 */
function succeedingOpenRunner(
  reports: Record<string, string>,
): { runner: OpenRunner; calls: string[][] } {
  const calls: string[][] = [];
  const runner: OpenRunner = async (command, args) => {
    calls.push([command, ...args]);
    const headlessIdx = args.findIndex((arg) => arg === "--headless");
    const action = args[headlessIdx + 1]!;
    const reportArg = args.find((arg) => arg.startsWith("--report-file="));
    if (!reportArg) throw new Error("open argv carried no --report-file");
    const report = reports[action];
    if (!report) throw new Error(`unexpected LaunchServices action: ${action}`);
    await writeFile(reportArg.slice("--report-file=".length), report);
    return { stdout: "", stderr: "", exitCode: 0 };
  };
  return { runner, calls };
}

const notRunning = {
  isRunning: async () => false,
  terminate: async () => true,
};

function neverDirectInvoke(): { invoke: HostAppInvoker; calls: string[][] } {
  const calls: string[][] = [];
  const invoke: HostAppInvoker = async (binaryPath, args) => {
    calls.push([binaryPath, ...args]);
    throw new Error("direct-exec invoker must not be used on this path");
  };
  return { invoke, calls };
}

describe("headless (no-GUI-session) disarm fallback", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function makeFixture() {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-cw-headless-"));
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

  it("disable falls back to direct exec of the same signed binary when no GUI session exists", async () => {
    const { hostAppPath, env } = await makeFixture();
    const open = failingOpenRunner();
    const direct = makeInvoker({
      disable: { stdout: reportLine("disable", "disabled", true), exitCode: 0 },
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
    });
    const outcomes: string[] = [];

    const code = await runDisable([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      openRunner: open.runner,
      runningAppController: notRunning,
      sessionManagerNameProbe: async () => "Background",
      directHostAppInvoke: direct.invoke,
      onDisableNePreferenceOutcome: (outcome) => {
        outcomes.push(outcome);
      },
    });

    // Pre-fix behavior (reproduced on hardware): the LaunchServices invoke
    // fails with the no-Aqua-domain error, direct exec is never attempted, and
    // the run degrades to fail_open_deadman / a failed disable. Post-fix the
    // fallback direct-execs the same binary and the disarm corroborates off.
    expect(code).toBe(0);
    expect(outcomes).toEqual(["corroborated_off"]);
    expect(open.calls).toEqual([]);
    // Same resolved signed binary, same COMPLETE argv as the LaunchServices
    // path - including the host-app deadline; a partial argv assertion would
    // let the fallback silently drop or change a flag.
    expect(direct.calls).toEqual([
      [hostAppPath, "--headless", "disable", "--timeout=3"],
      [hostAppPath, "--headless", "status"],
    ]);
  });

  it.each([
    { label: "Aqua session", probeResult: "Aqua" as string | null },
    { label: "probe failure (fail-safe)", probeResult: null as string | null },
  ])("disable keeps LaunchServices primary: $label", async ({ probeResult }) => {
    const { hostAppPath, env } = await makeFixture();
    const open = succeedingOpenRunner({
      disable: reportLine("disable", "disabled", true),
      status: reportLine("status", "disabled", true),
    });
    const direct = neverDirectInvoke();
    const outcomes: string[] = [];

    const code = await runDisable([], {
      out: new CaptureStream(),
      err: new CaptureStream(),
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      openRunner: open.runner,
      runningAppController: notRunning,
      sessionManagerNameProbe: async () => probeResult,
      directHostAppInvoke: direct.invoke,
      onDisableNePreferenceOutcome: (outcome) => {
        outcomes.push(outcome);
      },
    });

    expect(code).toBe(0);
    expect(outcomes).toEqual(["corroborated_off"]);
    expect(direct.calls).toEqual([]);
    expect(open.calls.length).toBeGreaterThan(0);
  });

  it("names the underlying failure and disclosed lease ratchet when the fallback disable also fails", async () => {
    const { fortressPath, hostAppPath, env } = await makeFixture();
    const out = new CaptureStream();
    const err = new CaptureStream();
    const open = failingOpenRunner();
    const direct = makeInvoker({
      disable: {
        stdout: "",
        stderr:
          "NEFilterManager saveToPreferences failed: Domain=NEConfigurationErrorDomain Code=9",
        exitCode: 1,
      },
    });
    const outcomes: string[] = [];

    // A live lease socket makes the revoke deliverable, which is what routes
    // the failed disable into the fail_open_deadman disclosure branch. The
    // handler consumes data and the accepted sockets are tracked and destroyed
    // in teardown: server.close() only waits out existing connections, so an
    // unconsumed accepted socket left open by any client would hang the test
    // at teardown, not fail it.
    const socketPath = join(fortressPath, "castle.sock");
    const accepted: Array<{ destroy: () => void }> = [];
    const server: Server = createServer((socket) => {
      accepted.push(socket);
      socket.on("data", () => {});
      socket.on("error", () => {});
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      // port-discipline: ignore - Unix domain socket path, not a TCP port.
      server.listen(socketPath, resolve);
    });

    try {
      const code = await runDisable([], {
        out,
        err,
        env,
        platform: "darwin",
        hostAppCandidates: [hostAppPath],
        openRunner: open.runner,
        runningAppController: notRunning,
        sessionManagerNameProbe: async () => "Background",
        directHostAppInvoke: direct.invoke,
        onDisableNePreferenceOutcome: (outcome) => {
          outcomes.push(outcome);
        },
      });

      expect(code).toBe(0);
      expect(outcomes).toEqual(["fail_open_deadman"]);
      // The underlying invoke failure is named, not only the outcome label...
      expect(err.text()).toContain("NEConfigurationErrorDomain");
      // ...and the one-way lease ratchet is disclosed with its observed effect
      // (full deny for the protected uid) and its exit path.
      expect(err.text()).toContain(
        "the protected uid is fully denied until a later successful disable or re-enable",
      );
    } finally {
      for (const socket of accepted.splice(0)) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("system-extension deactivation falls back headlessly and surfaces the host app's real answer", async () => {
    const { hostAppPath, env } = await makeFixture();
    const open = failingOpenRunner();
    const direct = makeInvoker({
      status: { stdout: reportLine("status", "disabled", true), exitCode: 0 },
      "deactivate-system-extension": {
        stdout: reportLine(
          "deactivate-system-extension",
          "needs_user_approval",
          false,
          "OSSystemExtensionErrorDomain error 13: authorization required",
        ),
        exitCode: 3,
      },
    });

    const outcome = await requestSystemExtensionDeactivation({
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      openRunner: open.runner,
      runningAppController: notRunning,
      sessionManagerNameProbe: async () => "Background",
      directHostAppInvoke: direct.invoke,
    });

    // Pre-fix the LaunchServices launch fails before the request is even
    // submitted, so the operator sees an opaque launch failure instead of the
    // host app's honest authorization answer.
    expect(outcome).toEqual({
      kind: "needs-user-approval",
      detail: "OSSystemExtensionErrorDomain error 13: authorization required",
    });
    expect(open.calls).toEqual([]);
    // Complete call arrays: same signed binary and the full argv including the
    // deactivation deadline, not just the action names.
    expect(direct.calls).toEqual([
      [hostAppPath, "--headless", "status"],
      [hostAppPath, "--headless", "deactivate-system-extension", "--timeout=60"],
    ]);
  });

  it("enable stays LaunchServices-only even in a Background session (arm path untouched)", async () => {
    const { hostAppPath, env } = await makeFixture();
    const err = new CaptureStream();
    const open = failingOpenRunner();
    const direct = neverDirectInvoke();

    const code = await runEnable(["--force", "--no-ttl"], {
      out: new CaptureStream(),
      err,
      env,
      platform: "darwin",
      hostAppCandidates: [hostAppPath],
      openRunner: open.runner,
      runningAppController: notRunning,
      sessionManagerNameProbe: async () => "Background",
      directHostAppInvoke: direct.invoke,
      sysextProbe: async () => "[activated enabled]",
      egressAllowRuleCountProbe: async () => 1,
      daemonProbe: async () => true,
      bootServiceReadyProbe: async () => true,
      agentOriginDescriptorProbe: async () => true,
      enforcementAvailabilityQuery: async () => ({
        status: "live",
        reason: "ok",
        observed_at: "2026-08-25T00:00:00.000Z",
        freshness_window_ms: 30_000,
        active_connection_count: 1,
      }),
    });

    // The no-GUI fallback is scoped to the protection-DECREASING verbs (fix
    // spawn prompt 2026-08-25 scope rule 4): arming still requires the
    // LaunchServices transport and fails loud headlessly.
    expect(code).toBe(1);
    expect(open.calls.length).toBeGreaterThan(0);
    expect(direct.calls).toEqual([]);
    expect(err.text()).toContain("produced no report");
  });

  it("uninstall reports the underlying disable failure detail, not only the outcome label", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-uninstall-detail-"));
    tempDirs.push(fortressPath);
    const out = new CaptureStream();

    // Real disarm op (not an ops override): the disable verb fails at host-app
    // resolution, and the row must carry that underlying diagnosis through the
    // formerly-swallowed stderr.
    const missingHostApp = join(fortressPath, "no-such-CastleWallHostApp");
    const hermeticOps: Partial<UninstallOps> = {
      uninstallHarnessDaemon: async () => {},
      scrubProvisionedEgressRules: async () => ({ removedRuleIds: [], reloadOk: true }),
      bootServiceStatus: async () => "absent",
      uninstallBootService: async () => {},
      globalPinStatus: async () => "absent",
      systemExtensionStatus: async () => "absent",
      deactivateSystemExtension: async () => ({ kind: "request-completed" }),
    };

    const code = await runUninstallCommand({
      argv: ["--fortress", fortressPath],
      out,
      err: new CaptureStream(),
      env: {
        SANCTUARY_STORAGE_PATH: fortressPath,
        SANCTUARY_CASTLE_HOSTAPP: missingHostApp,
        SANCTUARY_CASTLE_BUILD_SHA: TEST_BUILD_SHA,
      },
      platform: "darwin",
      getuid: () => 501,
      ops: hermeticOps,
    });

    expect(code).toBe(1);
    expect(out.text()).toContain("failed: castle-wall");
    // The row names the underlying cause (here: the host-app resolution
    // refusal), not just an exit code or outcome label.
    expect(out.text()).toContain("does not point at a trusted executable");
  });
});

describe("identity-independent direct invoker", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
    delete process.env.SANCTUARY_CASTLE_BUILD_SHA;
  });

  it("strips SANCTUARY_CASTLE_BUILD_SHA from the child environment so the host app cannot echo the CLI's own expectation back", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-cw-envstrip-"));
    tempDirs.push(dir);
    const scriptPath = join(dir, "echo-env.sh");
    // The fixture reports the variable the REAL host app echoes back when
    // present (must match currentBuildGitSha in HeadlessFilterCLI.swift):
    // an inherited value here is exactly the self-attestation the invoker
    // exists to prevent.
    await writeFile(
      scriptPath,
      '#!/bin/sh\nprintf "sha=%s" "${SANCTUARY_CASTLE_BUILD_SHA:-ABSENT}"\n',
      { mode: 0o755 },
    );
    process.env.SANCTUARY_CASTLE_BUILD_SHA = "attacker-controlled-expectation";
    // Constructed AFTER the env var is set: the sanitized snapshot must still
    // exclude it.
    const invoke = makeIdentityIndependentHostAppInvoke(5_000);
    const result = await invoke(scriptPath, []);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toBe("sha=ABSENT");
  });
});

describe("disarm detail truncation", () => {
  const WARNING_LINE =
    "Warning: NE preference disable did not complete (LSOpenURLsWithCompletionHandler() failed with error -10826); " +
    "the authenticated dead-man lease was already revoked, so the protected uid is fully denied until a later successful disable or re-enable.";

  it("retains the disable warning and full-deny disclosure when long later output would otherwise evict them", () => {
    // The eviction shape the gate named: audit failure text and custody
    // normalization output FOLLOW the warning, so a plain keep-the-tail
    // truncation would drop the diagnosis.
    const trailing = Array.from(
      { length: 40 },
      (_, i) => `[castle-wall] audit chain append retry ${i}: producer unreachable at socket; will retry`,
    ).join("\n");
    const flat = flattenDisarmDetail(`${WARNING_LINE}\n${trailing}`);
    expect(flat).toContain("NE preference disable did not complete");
    expect(flat).toContain(
      "the protected uid is fully denied until a later successful disable or re-enable",
    );
    // Truncation is marked, never silent, and the tail is still represented.
    expect(flat).toContain("…");
    expect(flat).toContain("will retry");
  });

  it("keeps plain tail behavior when no priority line is present", () => {
    const longOther = Array.from({ length: 80 }, (_, i) => `line ${i}`).join("\n");
    const flat = flattenDisarmDetail(longOther);
    expect(flat.startsWith("…")).toBe(true);
    expect(flat).toContain("line 79");
  });
});
