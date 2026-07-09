/**
 * Tests for the agent-harness self-confinement LaunchDaemon plumbing
 * (Unified Protect Slice 4): fail-closed plist rendering (never root,
 * never a secret, absolute paths only), install/uninstall step execution
 * against injected ops, and fail-closed status parsing. Arming on a real
 * host is a console ceremony; drill acceptance is PENDING (see
 * docs/audit/unified-protect-enforcement-status.md).
 */

import { describe, it, expect } from "vitest";

import {
  AGENT_HARNESS_DAEMON_LABEL,
  AGENT_HARNESS_DAEMON_PLIST_PATH,
  HARNESS_FORBIDDEN_PLIST_ENV,
  renderAgentHarnessDaemonPlist,
  planAgentHarnessDaemonInstall,
  installAgentHarnessDaemon,
  uninstallAgentHarnessDaemon,
  agentHarnessDaemonStatus,
  type HarnessDaemonOps,
} from "../../src/egress-gate/harness-daemon.js";
import { FORBIDDEN_PLIST_ENV } from "../../src/cli/castle-wall-boot.js";

const BASE = {
  agentAccount: "sanctuary-agent",
  programArguments: ["/usr/local/bin/node", "/opt/sanctuary/harness.js"],
  fortressPath: "/Users/operator/.sanctuary",
};

function mockOps(overrides: Partial<HarnessDaemonOps> = {}): HarnessDaemonOps & {
  writes: Array<{ path: string; content: string; mode: number }>;
  removals: string[];
  launchctl: string[][];
} {
  const writes: Array<{ path: string; content: string; mode: number }> = [];
  const removals: string[] = [];
  const launchctl: string[][] = [];
  let installed = false;
  return {
    writes,
    removals,
    launchctl,
    writeFile(path, content, mode) {
      writes.push({ path, content, mode });
      return Promise.resolve();
    },
    removeFile(path) {
      removals.push(path);
      return Promise.resolve();
    },
    runLaunchctl(args) {
      launchctl.push([...args]);
      if (args[0] === "print") {
        return installed
          ? Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n\tstate = running\n}\n`,
              stderr: "",
            })
          : Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
      }
      if (args[0] === "bootstrap") {
        installed = true;
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
      if (args[0] === "bootout") {
        const wasInstalled = installed;
        installed = false;
        return Promise.resolve(
          wasInstalled
            ? { code: 0, stdout: "", stderr: "" }
            : { code: 3, stdout: "", stderr: "No such service" },
        );
      }
      return Promise.resolve({ code: 0, stdout: "", stderr: "" });
    },
    sleepMs: async () => {},
    ...overrides,
  };
}

describe("egress-gate/harness-daemon", () => {
  describe("renderAgentHarnessDaemonPlist (fail-closed rendering)", () => {
    it("renders UserName, label, argv, env, and RunAtLoad/KeepAlive", () => {
      const plist = renderAgentHarnessDaemonPlist(BASE);
      expect(plist).toContain("<key>UserName</key>");
      expect(plist).toContain("<string>sanctuary-agent</string>");
      expect(plist).toContain(`<string>${AGENT_HARNESS_DAEMON_LABEL}</string>`);
      expect(plist).toContain("<string>/usr/local/bin/node</string>");
      expect(plist).toContain("<key>SANCTUARY_STORAGE_PATH</key>");
      expect(plist).toContain("<key>RunAtLoad</key>");
      expect(plist).toContain("<key>KeepAlive</key>");
      expect(plist).toContain("<true/>");
    });

    it.each(["root", "_root", "daemon", "wheel"])(
      "refuses to render a daemon running as privileged account %s",
      (account) => {
        expect(() =>
          renderAgentHarnessDaemonPlist({ ...BASE, agentAccount: account }),
        ).toThrow(/Refusing to render/);
      },
    );

    it.each([
      ["empty", ""],
      ["spaces", "sanctuary agent"],
      ["uppercase start", "Sanctuary"],
      ["plist markup", "a</string><key>x"],
      ["leading digit", "1agent"],
    ])("rejects unsafe account name (%s)", (_label, account) => {
      expect(() => renderAgentHarnessDaemonPlist({ ...BASE, agentAccount: account })).toThrow(
        /not a safe service-account name/,
      );
    });

    it("rejects a relative program path", () => {
      expect(() =>
        renderAgentHarnessDaemonPlist({ ...BASE, programArguments: ["node", "harness.js"] }),
      ).toThrow(/must be absolute/);
    });

    it("rejects empty programArguments", () => {
      expect(() => renderAgentHarnessDaemonPlist({ ...BASE, programArguments: [] })).toThrow(
        /must not be empty/,
      );
    });

    it("rejects control characters in arguments", () => {
      expect(() =>
        renderAgentHarnessDaemonPlist({
          ...BASE,
          programArguments: ["/usr/local/bin/node", "evil\x00arg"],
        }),
      ).toThrow(/control characters/);
    });

    it("refuses to embed a secret env name in the world-readable plist", () => {
      for (const name of HARNESS_FORBIDDEN_PLIST_ENV) {
        expect(() =>
          renderAgentHarnessDaemonPlist({ ...BASE, environment: { [name]: "hunter2" } }),
        ).toThrow(/Refusing to embed/);
      }
    });

    it("keeps the forbidden-env list in lockstep with cli/castle-wall-boot.ts", () => {
      expect([...HARNESS_FORBIDDEN_PLIST_ENV].sort()).toEqual([...FORBIDDEN_PLIST_ENV].sort());
    });

    it("xml-escapes argv content", () => {
      const plist = renderAgentHarnessDaemonPlist({
        ...BASE,
        programArguments: ["/usr/local/bin/node", "--flag=<&>"],
      });
      expect(plist).toContain("--flag=&lt;&amp;&gt;");
    });

    it("rejects a relative fortress path", () => {
      expect(() =>
        renderAgentHarnessDaemonPlist({ ...BASE, fortressPath: ".sanctuary" }),
      ).toThrow(/must be absolute/);
    });
  });

  describe("install / uninstall plumbing", () => {
    it("plans the canonical plist path and system-domain bootstrap", () => {
      const plan = planAgentHarnessDaemonInstall(BASE);
      expect(plan.plistPath).toBe(AGENT_HARNESS_DAEMON_PLIST_PATH);
      expect(plan.bootstrapArgs).toEqual(["bootstrap", "system", AGENT_HARNESS_DAEMON_PLIST_PATH]);
      expect(plan.plistContent).toContain("<key>UserName</key>");
    });

    it("writes the plist 0o644 then bootstraps (after the not-installed pre-check)", async () => {
      const ops = mockOps();
      await installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops);
      expect(ops.writes).toHaveLength(1);
      expect(ops.writes[0]!.path).toBe(AGENT_HARNESS_DAEMON_PLIST_PATH);
      expect(ops.writes[0]!.mode).toBe(0o644);
      expect(ops.launchctl).toEqual([
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["bootstrap", "system", AGENT_HARNESS_DAEMON_PLIST_PATH],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
      ]);
    });

    it("removes the just-written plist when a fresh-install bootstrap fails (no half-installed unit)", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
          }
          return Promise.resolve({ code: 5, stdout: "", stderr: "Bootstrap failed" });
        },
      });
      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/exited 5/);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    });

    it("refuses to write or bootstrap when launchctl status is unknown (preserve possible pre-existing daemon)", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({ code: 1, stdout: "", stderr: "ETIMEDOUT: launchctl print timed out" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });

      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/did not return a trustworthy status/);
      expect(ops.writes).toEqual([]);
      expect(ops.removals).toEqual([]);
    });

    it("re-install over an already-bootstrapped service refreshes the plist and never bootstraps or rolls back (boot persistence preserved)", async () => {
      // Regression: `launchctl bootstrap` exits non-zero when the service is
      // ALREADY bootstrapped (a routine ceremony re-run), so the old
      // write-then-rollback deleted the unit file a LIVE confined harness
      // depended on -- confinement silently lost at the next boot.
      const calls: string[][] = [];
      const ops = mockOps({
        runLaunchctl: (args) => {
          calls.push([...args]);
          if (args[0] === "print") {
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n}\n`,
              stderr: "",
            });
          }
          return Promise.resolve({
            code: 5,
            stdout: "",
            stderr: "Bootstrap failed: 5: Input/output error",
          });
        },
      });
      await installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops);
      // Plist bytes refreshed, no second bootstrap attempted, nothing removed.
      expect(ops.writes).toHaveLength(1);
      expect(calls).toEqual([
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
      ]);
      expect(ops.removals).toEqual([]);
    });

    it("bootstrap accepted but crash-looping harness does NOT report installed success", async () => {
      let printed = false;
      const calls: string[][] = [];
      const ops = mockOps({
        runLaunchctl: (args) => {
          calls.push([...args]);
          if (args[0] === "print" && !printed) {
            printed = true;
            return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
          }
          if (args[0] === "bootstrap") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "print") {
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
              stderr: "",
            });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });

      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/did not report a stable running pid/);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
      expect(calls.some((args) => args[0] === "bootout")).toBe(true);
    });

    it("never removes the plist when post-bootstrap-failure status is unknown", async () => {
      // The pre-check saw a genuinely absent service, but after bootstrap
      // failed launchctl itself became untrustworthy. Preserve the plist rather
      // than deleting the unit file for a possibly live service.
      let prints = 0;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            if (prints === 1) {
              return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
            }
            return Promise.resolve({ code: 1, stdout: "", stderr: "ETIMEDOUT: launchctl print timed out" });
          }
          return Promise.resolve({
            code: 5,
            stdout: "",
            stderr: "Bootstrap failed: 5: Input/output error",
          });
        },
      });
      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/exited 5/);
      expect(ops.removals).toEqual([]);
    });

    it("bootstrap accepted but unstable harness only removes plist after successful cleanup bootout", async () => {
      let prints = 0;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            if (prints === 1) {
              return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
            }
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
              stderr: "",
            });
          }
          if (args[0] === "bootstrap") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "bootout") {
            return Promise.resolve({ code: 5, stdout: "", stderr: "Input/output error" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });

      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/cleanup failed/);
      expect(ops.removals).toEqual([]);
    });

    it("requires every stability sample to report the same running pid", async () => {
      let prints = 0;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            if (prints === 1) {
              return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
            }
            if (prints === 3) {
              return Promise.resolve({
                code: 0,
                stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
                stderr: "",
              });
            }
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n}\n`,
              stderr: "",
            });
          }
          if (args[0] === "bootstrap") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "bootout") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });

      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/did not report a stable running pid/);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    });

    it("uninstall boots out then removes the plist (idempotent when not loaded)", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          void args;
          return Promise.resolve({ code: 3, stdout: "", stderr: "No such service" });
        },
      });
      await uninstallAgentHarnessDaemon(ops);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    });

    it("uninstall treats the textual not-loaded signature as benign regardless of exit code", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          void args;
          return Promise.resolve({
            code: 36,
            stdout: "",
            stderr: "Boot-out failed: 36: No such process",
          });
        },
      });
      await uninstallAgentHarnessDaemon(ops);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    });

    it("uninstall THROWS on a real bootout failure and leaves the plist in place (no silently-failed teardown)", async () => {
      // Regression: a stuck-but-loaded service (bootout fails, service still
      // running) must not report a successful teardown; removing the plist
      // anyway would leave a live confined harness with no unit file behind
      // it until reboot.
      const ops = mockOps({
        runLaunchctl: (args) => {
          void args;
          return Promise.resolve({
            code: 5,
            stdout: "",
            stderr: "Boot-out failed: 5: Input/output error",
          });
        },
      });
      await expect(uninstallAgentHarnessDaemon(ops)).rejects.toThrow(
        /bootout system\/.* exited 5/,
      );
      expect(ops.removals).toEqual([]);
    });
  });

  describe("agentHarnessDaemonStatus (fail-closed posture)", () => {
    it("reports running with a pid when launchd prints one", async () => {
      const ops = mockOps({
        runLaunchctl: () =>
          Promise.resolve({
            code: 0,
            stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n\tstate = running\n}\n`,
            stderr: "",
          }),
      });
      expect(await agentHarnessDaemonStatus(ops)).toEqual({
        known: true,
        installed: true,
        running: true,
        pid: 4242,
      });
    });

    it("reports installed-not-running when no pid is printed", async () => {
      const ops = mockOps({
        runLaunchctl: () =>
          Promise.resolve({
            code: 0,
            stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
            stderr: "",
          }),
      });
      expect(await agentHarnessDaemonStatus(ops)).toEqual({ known: true, installed: true, running: false });
    });

    it("reports known-not-installed on a launchctl not-loaded exit", async () => {
      const ops = mockOps({
        runLaunchctl: () =>
          Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" }),
      });
      expect(await agentHarnessDaemonStatus(ops)).toEqual({ known: true, installed: false, running: false });
    });

    it("reports unknown when launchctl itself fails (never guess absent or running)", async () => {
      const ops = mockOps({
        runLaunchctl: () => Promise.reject(new Error("spawn launchctl ENOENT")),
      });
      expect(await agentHarnessDaemonStatus(ops)).toEqual({ known: false, installed: false, running: false });
    });

    it("reports unknown on a non-not-loaded launchctl failure", async () => {
      const ops = mockOps({
        runLaunchctl: () =>
          Promise.resolve({ code: 1, stdout: "", stderr: "ETIMEDOUT: launchctl print timed out" }),
      });
      expect(await agentHarnessDaemonStatus(ops)).toEqual({ known: false, installed: false, running: false });
    });
  });
});
