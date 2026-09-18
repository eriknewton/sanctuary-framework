import { describe, expect, it } from "vitest";

import {
  DISARM_FLAG,
  LINUX_UPGRADE_ROUTE_A_STEPS,
  LINUX_UPGRADE_ROUTE_B_STEPS,
  PREFLIGHT_MANIFEST_FLAG,
  assertRouteHasNoSameBootStart,
  discoverInstalledLinuxFortressIds,
  executeLinuxUpgradeRoute,
  preflightManifestArgs,
  reportInstalledManifestAdmission,
  type UpgradeCommandResult,
  type UpgradeCommandRunner,
} from "../../../src/castle-wall/runtime/linux-upgrade-routes.js";
import { runDoctorChecks } from "../../../src/cli/doctor.js";

const NEW_BINARY = "/tmp/castle-wall-daemon.new";
const OLD_BINARY = "/usr/local/libexec/sanctuary/castle-wall-daemon";
const FORTRESS_ID = "a1b2c3d4e5f60718";

interface RecordedCommand {
  command: string;
  args: readonly string[];
}

/**
 * Injected runner. No real systemctl, no real daemon: the route's order is the
 * property under test, so the recorded argv IS the observation.
 */
function recordingRunner(
  outcomes: (cmd: RecordedCommand) => UpgradeCommandResult = () => ({
    code: 0,
    stdout: "",
    stderr: "",
  }),
): { runner: UpgradeCommandRunner; calls: RecordedCommand[] } {
  const calls: RecordedCommand[] = [];
  return {
    calls,
    runner: {
      run: async (command, args) => {
        const call = { command, args: [...args] };
        calls.push(call);
        return outcomes(call);
      },
    },
  };
}

describe("Linux upgrade routes", () => {
  it("route A runs preflight, stop, disarm, replace, start in that order", async () => {
    const { runner, calls } = recordingRunner();
    let replacedAfter = -1;
    const result = await executeLinuxUpgradeRoute({
      route: "disarm",
      newBinaryPath: NEW_BINARY,
      installedBinaryPath: OLD_BINARY,
      target: { kind: "fortress_id", fortressId: FORTRESS_ID },
      runner,
      replaceBinary: async () => {
        replacedAfter = calls.length;
      },
      systemctlBinary: "systemctl",
    });

    expect(result.outcome).toBe("completed");
    expect(result.completed_steps).toEqual([...LINUX_UPGRADE_ROUTE_A_STEPS]);
    expect(calls.map((c) => [c.command, ...c.args])).toEqual([
      [NEW_BINARY, PREFLIGHT_MANIFEST_FLAG, "--fortress-id", FORTRESS_ID],
      ["systemctl", "stop", "sanctuary-castle-wall.service"],
      [OLD_BINARY, DISARM_FLAG],
      ["systemctl", "start", "sanctuary-castle-wall.service"],
    ]);
    // The replacement sits between the disarm and the start, never before the stop.
    expect(replacedAfter).toBe(3);
  });

  it("route B ends at the reboot and executes no start in the old boot", async () => {
    const { runner, calls } = recordingRunner();
    const result = await executeLinuxUpgradeRoute({
      route: "reboot",
      newBinaryPath: NEW_BINARY,
      target: { kind: "fortress_id", fortressId: FORTRESS_ID },
      runner,
      replaceBinary: async () => {},
    });

    expect(result.outcome).toBe("completed");
    expect(result.planned_steps).toEqual([...LINUX_UPGRADE_ROUTE_B_STEPS]);
    expect(result.planned_steps).not.toContain("start_unit");
    expect(result.completed_steps).not.toContain("start_unit");
    // The route cannot execute a start: no invocation carries the start subcommand.
    expect(calls.some((c) => c.args.includes("start"))).toBe(false);
    expect(calls.map((c) => [c.command, ...c.args])).toEqual([
      [NEW_BINARY, PREFLIGHT_MANIFEST_FLAG, "--fortress-id", FORTRESS_ID],
      ["systemctl", "stop", "sanctuary-castle-wall.service"],
      ["systemctl", "reboot"],
    ]);
  });

  it("refuses a reboot route whose step list carries a start", () => {
    expect(() =>
      assertRouteHasNoSameBootStart("reboot", ["stop_unit", "start_unit"]),
    ).toThrow(/no start step/);
    expect(() =>
      assertRouteHasNoSameBootStart("disarm", [...LINUX_UPGRADE_ROUTE_A_STEPS]),
    ).not.toThrow();
  });

  it("a failing preflight aborts before any stop or replacement, with the text verbatim", async () => {
    const remediation =
      "castle-wall-daemon: preflight-manifest FAILED - reissue the manifest through the publisher";
    const { runner, calls } = recordingRunner((cmd) =>
      cmd.command === NEW_BINARY
        ? { code: 1, stdout: "", stderr: `${remediation}\n` }
        : { code: 0, stdout: "", stderr: "" },
    );
    let replaced = false;
    for (const route of ["disarm", "reboot"] as const) {
      const result = await executeLinuxUpgradeRoute({
        route,
        newBinaryPath: NEW_BINARY,
        installedBinaryPath: OLD_BINARY,
        target: { kind: "fortress_id", fortressId: FORTRESS_ID },
        runner,
        replaceBinary: async () => {
          replaced = true;
        },
      });
      expect(result.outcome).toBe("aborted");
      expect(result.completed_steps).toEqual([]);
      expect(result.abort?.step).toBe("preflight_manifest_new_binary");
      expect(result.abort?.exit_code).toBe(1);
      expect(result.abort?.output).toBe(remediation);
    }
    expect(replaced).toBe(false);
    expect(calls.every((c) => c.command === NEW_BINARY)).toBe(true);
    expect(calls.some((c) => c.args.includes("stop"))).toBe(false);
  });

  it("aborts at the disarm step without replacing the binary", async () => {
    const { runner } = recordingRunner((cmd) =>
      cmd.args.includes(DISARM_FLAG)
        ? { code: 2, stdout: "", stderr: "castle-wall-daemon: disarm refused, table is foreign" }
        : { code: 0, stdout: "", stderr: "" },
    );
    let replaced = false;
    const result = await executeLinuxUpgradeRoute({
      route: "disarm",
      newBinaryPath: NEW_BINARY,
      installedBinaryPath: OLD_BINARY,
      target: { kind: "fortress_id", fortressId: FORTRESS_ID },
      runner,
      replaceBinary: async () => {
        replaced = true;
      },
    });
    expect(result.outcome).toBe("aborted");
    expect(result.abort?.step).toBe("disarm_old_binary");
    expect(result.abort?.exit_code).toBe(2);
    expect(result.completed_steps).toEqual(["preflight_manifest_new_binary", "stop_unit"]);
    expect(replaced).toBe(false);
  });

  it("builds the verb argv in both documented forms and refuses a foreign fortress id", () => {
    expect(preflightManifestArgs({ kind: "fortress_id", fortressId: FORTRESS_ID })).toEqual([
      PREFLIGHT_MANIFEST_FLAG,
      "--fortress-id",
      FORTRESS_ID,
    ]);
    expect(
      preflightManifestArgs({
        kind: "explicit_paths",
        policyDir: "/var/lib/sanctuary/x/policy/egress",
        pinnedPublicKeyPath: "/var/lib/sanctuary/x/policy/egress/pinned.key",
      }),
    ).toEqual([
      PREFLIGHT_MANIFEST_FLAG,
      "--policy-dir",
      "/var/lib/sanctuary/x/policy/egress",
      "--pinned-public-key",
      "/var/lib/sanctuary/x/policy/egress/pinned.key",
    ]);
    expect(() =>
      preflightManifestArgs({ kind: "fortress_id", fortressId: "--policy-dir" }),
    ).toThrow(/hexadecimal/);
  });
});

describe("installed-manifest admission report", () => {
  it("reports an admitted manifest with the verb's own line", async () => {
    const { runner } = recordingRunner(() => ({
      code: 0,
      stdout: "castle-wall-daemon: preflight-manifest - this host admits the installed manifest\n",
      stderr: "",
    }));
    const report = await reportInstalledManifestAdmission({
      target: { kind: "fortress_id", fortressId: FORTRESS_ID },
      runner,
      binaryPath: OLD_BINARY,
    });
    expect(report).toEqual({
      probe: "ran",
      admitted: true,
      exit_code: 0,
      daemon_output:
        "castle-wall-daemon: preflight-manifest - this host admits the installed manifest",
    });
  });

  it("reports a refused manifest and never grades the uid values itself", async () => {
    const line =
      "castle-wall-daemon: preflight-manifest FAILED - gate uid is not attestable on this host; reissue the manifest through the publisher";
    const { runner } = recordingRunner(() => ({ code: 1, stdout: "", stderr: `${line}\n` }));
    const report = await reportInstalledManifestAdmission({
      target: { kind: "fortress_id", fortressId: FORTRESS_ID },
      runner,
      binaryPath: OLD_BINARY,
    });
    expect(report.probe).toBe("ran");
    expect(report.admitted).toBe(false);
    expect(report.exit_code).toBe(1);
    expect(report.daemon_output).toBe(line);
  });

  it("an absent binary and a failed spawn are never reported as admitted", async () => {
    const absent: UpgradeCommandRunner = {
      run: async () => {
        throw Object.assign(new Error("spawn ENOENT"), { code: "ENOENT" });
      },
    };
    const broken: UpgradeCommandRunner = {
      run: async () => {
        throw new Error("spawn EACCES");
      },
    };
    const target = { kind: "fortress_id", fortressId: FORTRESS_ID } as const;
    const absentReport = await reportInstalledManifestAdmission({ target, runner: absent });
    expect(absentReport.probe).toBe("binary_absent");
    expect(absentReport.admitted).toBe(false);
    const brokenReport = await reportInstalledManifestAdmission({ target, runner: broken });
    expect(brokenReport.probe).toBe("unavailable");
    expect(brokenReport.admitted).toBe(false);
  });

  it("returns only canonical fortress ids, and none when the state root is unreadable", async () => {
    const ids = await discoverInstalledLinuxFortressIds(
      async () => ["a1b2c3d4e5f60718", "not a fortress", "../escape", "b1b2c3d4"],
      "/var/lib/sanctuary",
    );
    expect(ids).toEqual(["a1b2c3d4e5f60718", "b1b2c3d4"]);
    const none = await discoverInstalledLinuxFortressIds(async () => {
      throw new Error("EACCES");
    });
    expect(none).toEqual([]);
  });
});

describe("doctor reports the installed manifest's admission", () => {
  const storagePath = "/tmp/doctor-admission-fortress";

  it("warns with the daemon's line when this host refuses the installed manifest", async () => {
    const line =
      "castle-wall-daemon: preflight-manifest FAILED - reissue the manifest through the publisher";
    const checks = await runDoctorChecks({
      env: {},
      storagePath,
      platform: "linux",
      manifestAdmission: {
        readDir: async () => [FORTRESS_ID],
        runner: { run: async () => ({ code: 1, stdout: "", stderr: line }) },
      },
    });
    const check = checks.find((c) => c.name === "castle wall manifest admission");
    expect(check?.status).toBe("WARN");
    expect(check?.message).toContain(line);
    expect(check?.hint).toContain("reissue the manifest through the publisher");
  });

  it("reports OK when the verb admits it, and n/a when no state is installed", async () => {
    const admitted = await runDoctorChecks({
      env: {},
      storagePath,
      platform: "linux",
      manifestAdmission: {
        readDir: async () => [FORTRESS_ID],
        runner: { run: async () => ({ code: 0, stdout: "admitted", stderr: "" }) },
      },
    });
    expect(admitted.find((c) => c.name === "castle wall manifest admission")?.status).toBe("OK");

    const noState = await runDoctorChecks({
      env: {},
      storagePath,
      platform: "linux",
      manifestAdmission: {
        readDir: async () => [],
        runner: {
          run: async () => {
            throw new Error("the runner must not be reached with no installed state");
          },
        },
      },
    });
    const check = noState.find((c) => c.name === "castle wall manifest admission");
    expect(check?.status).toBe("OK");
    expect(check?.message).toContain("no installed Linux Castle Wall state");
  });
});
