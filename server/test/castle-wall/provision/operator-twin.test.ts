import { afterEach, describe, expect, it } from "vitest";
import { link, lstat, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  restoreOperatorTwinStandDown,
  standDownOperatorTwinLaunchAgent,
  type OperatorTwinDescriptor,
  type OperatorTwinStandDownOps,
  type OperatorTwinStandDownSnapshot,
} from "../../../src/castle-wall/provision/operator-twin.js";
import {
  OPERATOR_TWIN_PLIST_MAX_BYTES,
  operatorTwinStandDownOpsForProvision,
  verifyOperatorTwinPlistForRestore,
} from "../../../src/wrap/auto-provision.js";

const TEST_OPERATOR_UID = typeof process.getuid === "function" ? process.getuid() : 501;

const DESCRIPTOR: OperatorTwinDescriptor = {
  domain: "gui/501",
  label: "ai.hermes.gateway",
  plistPath: "/Users/operator/Library/LaunchAgents/ai.hermes.gateway.plist",
};
// 2 = a planted second directory entry proves restore refuses multi-entry plists.
const MULTI_ENTRY_LINK_COUNT = 2;

interface TwinHost {
  ops: OperatorTwinStandDownOps;
  calls: string[];
  files: Map<string, string>;
  notices: string[];
  disabled: boolean;
  loaded: boolean;
  running: boolean;
}

function makeTwinHost(
  overrides: Partial<Pick<TwinHost, "disabled" | "loaded" | "running">> = {},
  descriptor: OperatorTwinDescriptor = DESCRIPTOR,
): TwinHost {
  const host: TwinHost = {
    calls: [],
    files: new Map([[descriptor.plistPath, "<plist>before</plist>"]]),
    notices: [],
    disabled: overrides.disabled ?? false,
    loaded: overrides.loaded ?? true,
    running: overrides.running ?? true,
    ops: undefined as unknown as OperatorTwinStandDownOps,
  };
  host.ops = {
    async readFile(path) {
      host.calls.push(`read ${path}`);
      return host.files.get(path);
    },
    async verifyPlistForRestore(path, expectedContent) {
      host.calls.push(`verify ${path}`);
      return host.files.get(path) === expectedContent
        ? { ok: true }
        : { ok: false, problem: "restore_problem: operator plist bytes changed before restore" };
    },
    async runLaunchctl(args) {
      host.calls.push(`launchctl ${args.join(" ")}`);
      const verb = args[0];
      if (verb === "print-disabled") {
        return {
          code: 0,
          stdout: host.disabled ? `"${descriptor.label}" => disabled\n` : "",
          stderr: "",
        };
      }
      if (verb === "print") {
        return host.loaded
          ? { code: 0, stdout: host.running ? "\tpid = 4242\n" : "", stderr: "" }
          : { code: 3, stdout: "", stderr: "No such process" };
      }
      if (verb === "disable") {
        host.disabled = true;
        return { code: 0, stdout: "", stderr: "" };
      }
      if (verb === "enable") {
        host.disabled = false;
        return { code: 0, stdout: "", stderr: "" };
      }
      if (verb === "bootout") {
        host.loaded = false;
        host.running = false;
        return { code: 0, stdout: "", stderr: "" };
      }
      if (verb === "bootstrap") {
        host.loaded = true;
        return { code: 0, stdout: "", stderr: "" };
      }
      if (verb === "kickstart") {
        host.loaded = true;
        host.running = true;
        return { code: 0, stdout: "", stderr: "" };
      }
      return { code: 64, stdout: "", stderr: `unexpected launchctl verb ${verb ?? ""}` };
    },
    sleepMs: async () => undefined,
    notify(message) {
      host.notices.push(message);
    },
  };
  return host;
}

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function makeTempDescriptor(): Promise<OperatorTwinDescriptor> {
  const root = await mkdtemp(join(tmpdir(), "sanctuary-operator-twin-"));
  tempRoots.push(root);
  const launchAgents = join(root, "Library", "LaunchAgents");
  await mkdir(launchAgents, { recursive: true });
  return {
    domain: `gui/${TEST_OPERATOR_UID}`,
    label: "ai.hermes.gateway",
    plistPath: join(launchAgents, "ai.hermes.gateway.plist"),
  };
}

function snapshotFor(descriptor: OperatorTwinDescriptor): OperatorTwinStandDownSnapshot {
  return {
    plistPath: descriptor.plistPath,
    priorPlistBytes: "<plist>before</plist>",
    domain: descriptor.domain,
    label: descriptor.label,
    serviceName: `${descriptor.domain}/${descriptor.label}`,
    disabledBefore: false,
    wasLoaded: true,
    wasRunning: true,
    preexistingTwinModified: true,
  };
}

async function makeFifo(path: string): Promise<void> {
  const { execFile } = await import("node:child_process");
  await new Promise<void>((resolve, reject) => {
    execFile("/usr/bin/mkfifo", [path], (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function installFsOps(host: TwinHost): void {
  host.ops.readFile = async (path) => {
    host.calls.push(`read ${path}`);
    try {
      return await readFile(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw err;
    }
  };
  host.ops.verifyPlistForRestore = async (path, expectedContent) => {
    host.calls.push(`verify ${path}`);
    return await verifyOperatorTwinPlistForRestore(path, expectedContent, TEST_OPERATOR_UID);
  };
}

describe("operator twin stand-down", () => {
  it("snapshots the operator LaunchAgent and disables before bootout", async () => {
    const host = makeTwinHost();
    const snapshot = await standDownOperatorTwinLaunchAgent(DESCRIPTOR, host.ops);

    expect(snapshot).toMatchObject({
      plistPath: DESCRIPTOR.plistPath,
      priorPlistBytes: "<plist>before</plist>",
      domain: "gui/501",
      label: "ai.hermes.gateway",
      serviceName: "gui/501/ai.hermes.gateway",
      disabledBefore: false,
      wasLoaded: true,
      wasRunning: true,
      preexistingTwinModified: true,
    });
    expect(host.disabled).toBe(true);
    expect(host.loaded).toBe(false);
    expect(host.running).toBe(false);

    const disableAt = host.calls.indexOf("launchctl disable gui/501/ai.hermes.gateway");
    const bootoutAt = host.calls.indexOf(`launchctl bootout gui/501 ${DESCRIPTOR.plistPath}`);
    expect(disableAt).toBeGreaterThanOrEqual(0);
    expect(bootoutAt).toBeGreaterThanOrEqual(0);
    expect(disableAt).toBeLessThan(bootoutAt);
  });

  it("fails loud when settled launchd status still reports the unconfined twin running", async () => {
    const host = makeTwinHost();
    host.ops.runLaunchctl = async (args) => {
      host.calls.push(`launchctl ${args.join(" ")}`);
      if (args[0] === "print-disabled") {
        return {
          code: 0,
          stdout: host.disabled ? `"${DESCRIPTOR.label}" => disabled\n` : "",
          stderr: "",
        };
      }
      if (args[0] === "print") {
        return { code: 0, stdout: "\tpid = 4242\n", stderr: "" };
      }
      if (args[0] === "disable") {
        host.disabled = true;
        return { code: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "enable") {
        host.disabled = false;
        return { code: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "bootout") {
        return { code: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "bootstrap" || args[0] === "kickstart") {
        return { code: 0, stdout: "", stderr: "" };
      }
      return { code: 64, stdout: "", stderr: "unexpected" };
    };

    await expect(standDownOperatorTwinLaunchAgent(DESCRIPTOR, host.ops)).rejects.toThrow(
      /STILL RUNNING.*unconfined twin/,
    );
  });

  it("restores loaded state, running state, and disabled override without changing existing plist bytes", async () => {
    const host = makeTwinHost({ disabled: true, loaded: false, running: false });
    const snapshot: OperatorTwinStandDownSnapshot = {
      plistPath: DESCRIPTOR.plistPath,
      priorPlistBytes: "<plist>before</plist>",
      domain: DESCRIPTOR.domain,
      label: DESCRIPTOR.label,
      serviceName: "gui/501/ai.hermes.gateway",
      disabledBefore: true,
      wasLoaded: true,
      wasRunning: true,
      preexistingTwinModified: true,
    };

    const report = await restoreOperatorTwinStandDown(snapshot, host.ops);

    expect(report).toEqual({
      restored: true,
      plistRestored: true,
      disabledStateRestored: true,
      loadedStateRestored: true,
      runningStateRestored: true,
      problems: [],
    });
    expect(host.files.get(DESCRIPTOR.plistPath)).toBe("<plist>before</plist>");
    expect(host.disabled).toBe(true);
    expect(host.loaded).toBe(true);
    expect(host.running).toBe(true);
    expect(host.calls).not.toContain(`write ${DESCRIPTOR.plistPath}`);
    expect(host.calls).toContain("launchctl enable gui/501/ai.hermes.gateway");
    expect(host.calls).toContain(`launchctl bootstrap gui/501 ${DESCRIPTOR.plistPath}`);
    expect(host.calls).toContain("launchctl kickstart gui/501/ai.hermes.gateway");
    expect(host.calls).toContain("launchctl disable gui/501/ai.hermes.gateway");
  });

  it("reports a restore problem and keeps launchd stopped when the plist leaf is replaced by a non-regular file", async () => {
    const descriptor = await makeTempDescriptor();
    const host = makeTwinHost({ disabled: true, loaded: false, running: false }, descriptor);
    installFsOps(host);
    const outside = join(dirnameForTest(descriptor.plistPath), "outside.plist");
    await writeFile(outside, "<plist>outside</plist>", { mode: 0o644 });
    await symlink(outside, descriptor.plistPath);
    const ownerBefore = await stat(outside);

    const report = await restoreOperatorTwinStandDown(snapshotFor(descriptor), host.ops);

    expect(report.restored).toBe(false);
    expect(report.problems.some((problem) => problem.includes("restore_problem"))).toBe(true);
    expect(await readFile(outside, "utf8")).toBe("<plist>outside</plist>");
    expect((await stat(outside)).uid).toBe(ownerBefore.uid);
    expect(host.disabled).toBe(true);
    expect(host.loaded).toBe(false);
    expect(host.running).toBe(false);
    expect(host.calls).not.toContain(`launchctl enable ${descriptor.domain}/${descriptor.label}`);
    expect(host.calls).not.toContain(`launchctl bootstrap ${descriptor.domain} ${descriptor.plistPath}`);
    expect(host.calls).not.toContain(`launchctl kickstart ${descriptor.domain}/${descriptor.label}`);
  });

  it("reports a restore problem and keeps launchd stopped when the plist leaf has multiple directory entries", async () => {
    const descriptor = await makeTempDescriptor();
    const host = makeTwinHost({ disabled: true, loaded: false, running: false }, descriptor);
    installFsOps(host);
    const outside = join(dirnameForTest(descriptor.plistPath), "outside-hardlink.plist");
    await writeFile(outside, "<plist>outside</plist>", { mode: 0o644 });
    await link(outside, descriptor.plistPath);
    expect((await lstat(descriptor.plistPath)).nlink).toBe(MULTI_ENTRY_LINK_COUNT);
    const ownerBefore = await stat(outside);

    const report = await restoreOperatorTwinStandDown(snapshotFor(descriptor), host.ops);

    expect(report.restored).toBe(false);
    expect(report.problems.some((problem) => problem.includes("restore_problem"))).toBe(true);
    expect(await readFile(outside, "utf8")).toBe("<plist>outside</plist>");
    expect((await stat(outside)).uid).toBe(ownerBefore.uid);
    expect(host.disabled).toBe(true);
    expect(host.loaded).toBe(false);
    expect(host.running).toBe(false);
    expect(host.calls).not.toContain(`launchctl enable ${descriptor.domain}/${descriptor.label}`);
    expect(host.calls).not.toContain(`launchctl bootstrap ${descriptor.domain} ${descriptor.plistPath}`);
    expect(host.calls).not.toContain(`launchctl kickstart ${descriptor.domain}/${descriptor.label}`);
  });

  it("leaves a previously disabled loaded twin disabled when plist verification fails", async () => {
    const descriptor = await makeTempDescriptor();
    const host = makeTwinHost({ disabled: true, loaded: false, running: false }, descriptor);
    installFsOps(host);
    const outside = join(dirnameForTest(descriptor.plistPath), "disabled-outside.plist");
    await writeFile(outside, "<plist>outside</plist>", { mode: 0o644 });
    await symlink(outside, descriptor.plistPath);
    const snapshot = {
      ...snapshotFor(descriptor),
      disabledBefore: true,
    };

    const report = await restoreOperatorTwinStandDown(snapshot, host.ops);

    expect(report.restored).toBe(false);
    expect(report.problems.some((problem) => problem.includes("restore_problem"))).toBe(true);
    expect(host.disabled).toBe(true);
    expect(host.loaded).toBe(false);
    expect(host.running).toBe(false);
    expect(host.calls).not.toContain(`launchctl enable ${descriptor.domain}/${descriptor.label}`);
    expect(host.calls).not.toContain(`launchctl bootstrap ${descriptor.domain} ${descriptor.plistPath}`);
  });

  it("reports a restore problem when launchd state was owed but no plist snapshot exists", async () => {
    const host = makeTwinHost({ disabled: true, loaded: false, running: false });
    const snapshot: OperatorTwinStandDownSnapshot = {
      plistPath: DESCRIPTOR.plistPath,
      domain: DESCRIPTOR.domain,
      label: DESCRIPTOR.label,
      serviceName: "gui/501/ai.hermes.gateway",
      disabledBefore: false,
      wasLoaded: true,
      wasRunning: false,
      preexistingTwinModified: true,
    };

    const report = await restoreOperatorTwinStandDown(snapshot, host.ops);

    expect(report.restored).toBe(false);
    expect(report.problems).toContain(
      "restore_problem: launchd state was not restored because no operator plist snapshot was available",
    );
    expect(host.calls).not.toContain("launchctl enable gui/501/ai.hermes.gateway");
    expect(host.calls).not.toContain(`launchctl bootstrap gui/501 ${DESCRIPTOR.plistPath}`);
  });

  it("refuses a symlinked plist before launchd mutation when stand-down snapshots through the real helper", async () => {
    const descriptor = await makeTempDescriptor();
    const host = makeTwinHost({ disabled: false, loaded: true, running: true }, descriptor);
    const outside = join(dirnameForTest(descriptor.plistPath), "stand-down-linked.plist");
    await writeFile(outside, "<plist>before</plist>", { mode: 0o644 });
    await symlink(outside, descriptor.plistPath);
    host.ops = operatorTwinStandDownOpsForProvision({
      consoleOwnerUid: TEST_OPERATOR_UID,
      runLaunchctl: host.ops.runLaunchctl,
      sleepMs: host.ops.sleepMs,
      notify: host.ops.notify,
    });

    await expect(standDownOperatorTwinLaunchAgent(descriptor, host.ops)).rejects.toThrow(/stand_down_problem/);

    expect(host.calls).not.toContain(`launchctl disable ${descriptor.domain}/${descriptor.label}`);
    expect(host.calls).not.toContain(`launchctl bootout ${descriptor.domain} ${descriptor.plistPath}`);
  });

  it("refuses non-snapshotable plist shapes before launchd mutation during stand-down", async () => {
    const cases = [
      async (descriptor: OperatorTwinDescriptor) => {
        const outside = join(dirnameForTest(descriptor.plistPath), "snapshot-link-target.plist");
        await writeFile(outside, "<plist>before</plist>", { mode: 0o644 });
        await symlink(outside, descriptor.plistPath);
      },
      async (descriptor: OperatorTwinDescriptor) => {
        await makeFifo(descriptor.plistPath);
      },
      async (descriptor: OperatorTwinDescriptor) => {
        const outside = join(dirnameForTest(descriptor.plistPath), "snapshot-hardlink-target.plist");
        await writeFile(outside, "<plist>before</plist>", { mode: 0o644 });
        await link(outside, descriptor.plistPath);
      },
      async (descriptor: OperatorTwinDescriptor) => {
        await writeFile(descriptor.plistPath, "a".repeat(OPERATOR_TWIN_PLIST_MAX_BYTES + 1), { mode: 0o644 });
      },
    ];

    for (const arrange of cases) {
      const descriptor = await makeTempDescriptor();
      const host = makeTwinHost({ disabled: false, loaded: true, running: true }, descriptor);
      await arrange(descriptor);
      host.ops = operatorTwinStandDownOpsForProvision({
        consoleOwnerUid: TEST_OPERATOR_UID,
        runLaunchctl: host.ops.runLaunchctl,
        sleepMs: host.ops.sleepMs,
        notify: host.ops.notify,
      });

      await expect(standDownOperatorTwinLaunchAgent(descriptor, host.ops)).rejects.toThrow(/stand_down_problem/);
      expect(host.calls).not.toContain(`launchctl disable ${descriptor.domain}/${descriptor.label}`);
      expect(host.calls).not.toContain(`launchctl bootout ${descriptor.domain} ${descriptor.plistPath}`);
    }
  });
});

function dirnameForTest(path: string): string {
  return path.slice(0, path.lastIndexOf("/"));
}
