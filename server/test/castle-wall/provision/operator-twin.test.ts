import { describe, expect, it } from "vitest";

import {
  restoreOperatorTwinStandDown,
  standDownOperatorTwinLaunchAgent,
  type OperatorTwinDescriptor,
  type OperatorTwinStandDownOps,
  type OperatorTwinStandDownSnapshot,
} from "../../../src/castle-wall/provision/operator-twin.js";

const DESCRIPTOR: OperatorTwinDescriptor = {
  domain: "gui/501",
  label: "ai.hermes.gateway",
  plistPath: "/Users/operator/Library/LaunchAgents/ai.hermes.gateway.plist",
};

interface TwinHost {
  ops: OperatorTwinStandDownOps;
  calls: string[];
  files: Map<string, string>;
  notices: string[];
  disabled: boolean;
  loaded: boolean;
  running: boolean;
}

function makeTwinHost(overrides: Partial<Pick<TwinHost, "disabled" | "loaded" | "running">> = {}): TwinHost {
  const host: TwinHost = {
    calls: [],
    files: new Map([[DESCRIPTOR.plistPath, "<plist>before</plist>"]]),
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
    async writeFile(path, content) {
      host.calls.push(`write ${path}`);
      host.files.set(path, content);
    },
    async removeFile(path) {
      host.calls.push(`remove ${path}`);
      host.files.delete(path);
    },
    async runLaunchctl(args) {
      host.calls.push(`launchctl ${args.join(" ")}`);
      const verb = args[0];
      if (verb === "print-disabled") {
        return {
          code: 0,
          stdout: host.disabled ? `"${DESCRIPTOR.label}" => disabled\n` : "",
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

  it("restores plist bytes, loaded state, running state, and disabled override from the snapshot", async () => {
    const host = makeTwinHost({ disabled: true, loaded: false, running: false });
    host.files.set(DESCRIPTOR.plistPath, "<plist>mutated</plist>");
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
    expect(host.calls).toContain(`write ${DESCRIPTOR.plistPath}`);
    expect(host.calls).toContain("launchctl enable gui/501/ai.hermes.gateway");
    expect(host.calls).toContain(`launchctl bootstrap gui/501 ${DESCRIPTOR.plistPath}`);
    expect(host.calls).toContain("launchctl kickstart gui/501/ai.hermes.gateway");
    expect(host.calls).toContain("launchctl disable gui/501/ai.hermes.gateway");
  });
});
