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
  planCoarseHarnessDaemonInstall,
  harnessLaunchSpec,
  REQUIRED_HARNESS_LAUNCH_ENV,
  installAgentHarnessDaemon,
  uninstallAgentHarnessDaemon,
  agentHarnessDaemonStatus,
  kickstartAgentHarnessDaemon,
  setAgentHarnessJobDisabled,
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
  // A mini-host, not a stub-per-verb: the fix-round-3 install path branches on
  // whether the bytes it writes DIFFER from what is on disk, and the
  // enable/disable path reads launchd's override table back. Both are
  // meaningless against ops that forget what they were told.
  const disk = new Map<string, string>();
  let disabled = false;
  return {
    writes,
    removals,
    launchctl,
    writeFile(path, content, mode) {
      writes.push({ path, content, mode });
      disk.set(path, content);
      return Promise.resolve();
    },
    readFile(path) {
      return Promise.resolve(disk.get(path));
    },
    removeFile(path) {
      removals.push(path);
      disk.delete(path);
      return Promise.resolve();
    },
    runLaunchctl(args) {
      launchctl.push([...args]);
      if (args[0] === "print-disabled") {
        return Promise.resolve({
          code: 0,
          stdout: disabled ? `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n` : "",
          stderr: "",
        });
      }
      if (args[0] === "disable" || args[0] === "enable") {
        disabled = args[0] === "disable";
        return Promise.resolve({ code: 0, stdout: "", stderr: "" });
      }
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

    it("refuses a credentialed URL value even under an unblocked env name", () => {
      expect(() =>
        renderAgentHarnessDaemonPlist({
          ...BASE,
          environment: { AGENT_PROXY_URL: "http://sanctuary-gate:7.deadbeef@127.0.0.1:49152" },
        }),
      ).toThrow(/AGENT_PROXY_URL value containing URL credentials/);
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
        // Drill-D2 fix-round (F2): the coarse install CLEARS the persistent
        // launchd disable before writing. Without it, the recovery command the
        // abort render prints -- "re-run 'sanctuary protect --hermes'" -- could
        // not work on any host whose label the park had disabled.
        ["enable", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        // Fix-round 3: the enable is READ BACK against launchd's persistent
        // override table. A zero exit is not the state.
        ["print-disabled", "system"],
        ["bootstrap", "system", AGENT_HARNESS_DAEMON_PLIST_PATH],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
      ]);
    });

    // F2 (both gate lenses): the printed recovery path could not work. The
    // park sets a PERSISTENT `launchctl disable`; nothing on the coarse path
    // ever cleared it, so a recovery re-run bootstrapped a disabled label and
    // failed its own stable-pid check. Asserted as behaviour -- the enable is
    // issued, and it is issued BEFORE the plist write so a failed enable
    // leaves the operator's plist untouched.
    it("F2: clears a persistent launchd disable BEFORE writing the plist, so a recovery re-run can actually start the job", async () => {
      const order: string[] = [];
      const ops = mockOps({
        runLaunchctl: (args) => {
          order.push(`launchctl:${args[0]}`);
          if (args[0] === "print") {
            return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
        writeFile: () => {
          order.push("write");
          return Promise.resolve();
        },
      });
      await installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops).catch(() => undefined);
      expect(order).toContain("launchctl:enable");
      expect(order.indexOf("launchctl:enable")).toBeLessThan(order.indexOf("write"));
    });

    it("F2: a failing enable refuses the install outright rather than writing a plist for a job that cannot start", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
          }
          if (args[0] === "enable") {
            return Promise.resolve({ code: 9, stdout: "", stderr: "Operation not permitted" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });
      await expect(
        installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops),
      ).rejects.toThrow(/enable/);
      expect(ops.writes).toEqual([]);
    });

    it("waits for launchd to report the first pid after accepting bootstrap", async () => {
      let prints = 0;
      const calls: string[][] = [];
      const ops = mockOps({
        runLaunchctl: (args) => {
          calls.push([...args]);
          if (args[0] === "print") {
            prints += 1;
            if (prints === 1) {
              return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
            }
            if (prints <= 3) {
              return Promise.resolve({
                code: 0,
                stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
                stderr: "",
              });
            }
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n\tstate = running\n}\n`,
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

      await installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops);

      expect(ops.removals).toEqual([]);
      expect(calls.filter((args) => args[0] === "print")).toHaveLength(6);
      expect(calls.some((args) => args[0] === "bootout")).toBe(false);
    });

    it("removes the just-written plist when a fresh-install bootstrap fails (no half-installed unit)", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
          }
          // The disable-clearing enable succeeds; the BOOTSTRAP is what fails.
          if (args[0] === "enable") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "print-disabled") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
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
          if (args[0] === "enable") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "print-disabled") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          return Promise.resolve({
            code: 5,
            stdout: "",
            stderr: "Bootstrap failed: 5: Input/output error",
          });
        },
      });
      // The bytes on disk ALREADY match what this install writes -- the
      // genuine idempotent-re-run shape. (Fix-round 3 narrowed the no-reload
      // fast path to exactly this case; see the changed-bytes tests below.)
      const plan = planAgentHarnessDaemonInstall(BASE);
      await ops.writeFile(plan.plistPath, plan.plistContent, 0o644);
      ops.writes.length = 0;
      await installAgentHarnessDaemon(plan, ops);
      // Plist bytes refreshed, no second bootstrap attempted, nothing removed.
      expect(ops.writes).toHaveLength(1);
      expect(calls).toEqual([
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["enable", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print-disabled", "system"],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
        ["print", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
      ]);
      expect(ops.removals).toEqual([]);
    });

    // ROUND-3 REGRESSION (Claude finding 1). Writing a plist FILE does not
    // reload launchd. The pre-fix `existing.installed` branch wrote new bytes,
    // saw "a stable pid exists", and returned -- so the parked-install revert
    // could restore the operator's plist to DISK while launchd kept running
    // the confined barrier job, and the operator was told the harness was
    // running again. The pid observed has to belong to the unit we wrote.
    it("R3: an already-installed service whose plist bytes CHANGED is booted out and re-bootstrapped, not merely rewritten", async () => {
      const calls: string[][] = [];
      let loaded = true;
      const ops = mockOps({
        runLaunchctl: (args) => {
          calls.push([...args]);
          if (args[0] === "print") {
            return Promise.resolve(
              loaded
                ? {
                    code: 0,
                    stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n}\n`,
                    stderr: "",
                  }
                : { code: 113, stdout: "", stderr: "Could not find service" },
            );
          }
          if (args[0] === "bootout") {
            loaded = false;
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "bootstrap") {
            loaded = true;
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "print-disabled") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });
      // Disk holds a DIFFERENT unit (stand in for the parked barrier plist).
      await ops.writeFile(AGENT_HARNESS_DAEMON_PLIST_PATH, "<plist><!-- BARRIER --></plist>", 0o644);
      await installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops);
      const verbs = calls.map((c) => c[0]);
      expect(verbs).toContain("bootout");
      expect(verbs).toContain("bootstrap");
      // And in that order: the bootout precedes the bootstrap that loads the
      // bytes we wrote.
      expect(verbs.indexOf("bootout")).toBeLessThan(verbs.indexOf("bootstrap"));
      expect(ops.removals).toEqual([]);
    });

    it("R3: refuses when the plist changed and the old job will not stop -- rather than report an install whose unit was never loaded", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n}\n`,
              stderr: "",
            });
          }
          if (args[0] === "print-disabled") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          // bootout claims success; the job stays up. Exactly the shape the
          // shared not-loaded predicate's safety comment warns about.
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });
      await ops.writeFile(AGENT_HARNESS_DAEMON_PLIST_PATH, "<plist><!-- BARRIER --></plist>", 0o644);
      await expect(installAgentHarnessDaemon(planAgentHarnessDaemonInstall(BASE), ops)).rejects.toThrow(
        /STILL RUNNING after bootout; refusing to report an install whose new unit was never loaded/,
      );
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

    // NOTE on the `bootedOut` flag in the two mocks below (fix-round 2,
    // 2026-07-18): `uninstallAgentHarnessDaemon` now re-reads `launchctl print`
    // after its bootout and refuses to remove the plist over a job that is
    // still running. These mocks previously reported a live pid FOREVER, even
    // after a zero-exit bootout -- a host launchd cannot produce. Modelling the
    // bootout is what lets them keep testing what they are about (an unstable
    // install cleans its plist up) instead of accidentally testing the new
    // guard. The still-running case has its own test further down.
    it("requires every stability sample to report the same running pid", async () => {
      let prints = 0;
      let bootedOut = false;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            if (prints === 1) {
              return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
            }
            if (prints === 3 || bootedOut) {
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
            bootedOut = true;
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

    it("rejects a harness whose running pid changes between stability samples", async () => {
      let prints = 0;
      let bootedOut = false;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            if (prints === 1) {
              return Promise.resolve({ code: 113, stdout: "", stderr: "Could not find service" });
            }
            if (bootedOut) {
              return Promise.resolve({
                code: 0,
                stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
                stderr: "",
              });
            }
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = ${4241 + prints}\n}\n`,
              stderr: "",
            });
          }
          if (args[0] === "bootstrap") {
            return Promise.resolve({ code: 0, stdout: "", stderr: "" });
          }
          if (args[0] === "bootout") {
            bootedOut = true;
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

    // ------------------------------------------------------------------
    // FIX-ROUND 2 (2026-07-18). The shared `launchctlBootoutWasNotLoaded`
    // predicate justifies its generous match with "every caller re-reads
    // `launchctl print` afterwards and refuses if the job is still running."
    // The gate lens found that argument was FALSE at this function -- the
    // first site the comment names. These make it true, and keep it true.
    // ------------------------------------------------------------------

    it("uninstall REFUSES to remove the plist when the job is still running after a TOLERATED bootout", async () => {
      // The fail-open shape: the predicate says "already stopped" (so the
      // bootout error is swallowed), but launchd still reports a live pid.
      // Removing the plist here leaves a live confined harness with no unit
      // file behind it while the ceremony reports success.
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({
              code: 0,
              stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n\tstate = running\n}\n`,
              stderr: "",
            });
          }
          return Promise.resolve({ code: 1, stdout: "", stderr: "service not loaded" });
        },
      });
      await expect(uninstallAgentHarnessDaemon(ops)).rejects.toThrow(/STILL RUNNING after bootout/);
      expect(ops.removals).toEqual([]);
    });

    // ROUND-3 REGRESSION (Claude finding 2). The round-2 post-bootout check
    // was a SINGLE sample while its comment claimed it settled "exactly as the
    // parked install's stopped-settle assertion does" -- an assertion that
    // samples 20x250ms precisely because this branch learned on Mini1 that a
    // bootout's zero exit does not prove the process is reaped. One sample
    // turns a job one sample away from gone into a refusal, on stock
    // `sanctuary unprotect`, whose plist is KeepAlive: the harness comes back
    // at next boot after the user asked for it to be gone.
    it("R3: uninstall SETTLES -- a job that is still running on the first sample and gone on the second is torn down, not refused", async () => {
      let prints = 0;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            return Promise.resolve(
              prints === 1
                ? {
                    code: 0,
                    stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n\tstate = stopping\n}\n`,
                    stderr: "",
                  }
                : { code: 113, stdout: "", stderr: "Could not find service" },
            );
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });
      await uninstallAgentHarnessDaemon(ops);
      expect(prints).toBeGreaterThan(1);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    });

    // Finding 5: the EINPROGRESS asymmetry. The parked install tolerated and
    // settled on it; this site threw. One shared pair of predicates now, so
    // the two bootout sites behave the same way on the same launchd reply.
    it("R3: uninstall tolerates an EINPROGRESS bootout and settles rather than throwing on it", async () => {
      let prints = 0;
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            prints += 1;
            return Promise.resolve(
              prints === 1
                ? { code: 0, stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 77\n}\n`, stderr: "" }
                : { code: 113, stdout: "", stderr: "Could not find service" },
            );
          }
          if (args[0] === "bootout") {
            return Promise.resolve({ code: 36, stdout: "", stderr: "Boot-out failed: 36: Operation now in progress" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });
      await uninstallAgentHarnessDaemon(ops);
      expect(ops.removals).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    });

    it("uninstall REFUSES to remove the plist against an untrustworthy post-bootout status", async () => {
      const ops = mockOps({
        runLaunchctl: (args) => {
          if (args[0] === "print") {
            return Promise.resolve({ code: 1, stdout: "", stderr: "launchctl exploded" });
          }
          return Promise.resolve({ code: 0, stdout: "", stderr: "" });
        },
      });
      await expect(uninstallAgentHarnessDaemon(ops)).rejects.toThrow(/trustworthy status after bootout/);
      expect(ops.removals).toEqual([]);
    });
  });

  describe("kickstartAgentHarnessDaemon (no silent green-on-down; fix-round HIGH regression)", () => {
    const printRunning = {
      code: 0,
      stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tpid = 4242\n\tstate = running\n}\n`,
      stderr: "",
    };
    const printNotRunning = {
      code: 0,
      stdout: `system/${AGENT_HARNESS_DAEMON_LABEL} = {\n\tstate = not running\n}\n`,
      stderr: "",
    };

    it("succeeds only when the job reaches a stable running pid after kickstart", async () => {
      const ops = mockOps({
        runLaunchctl: (args) =>
          Promise.resolve(args[0] === "print" ? printRunning : { code: 0, stdout: "", stderr: "" }),
      });
      await expect(kickstartAgentHarnessDaemon(ops)).resolves.toBeUndefined();
    });

    it("throws when kickstart is ACCEPTED but the job never runs (a refusing wrapper is a failed start, not a green)", async () => {
      const ops = mockOps({
        runLaunchctl: (args) =>
          Promise.resolve(args[0] === "print" ? printNotRunning : { code: 0, stdout: "", stderr: "" }),
      });
      await expect(kickstartAgentHarnessDaemon(ops)).rejects.toThrow(/stable running pid/);
    });

    it("throws on a non-zero kickstart exit", async () => {
      const ops = mockOps({
        runLaunchctl: () => Promise.resolve({ code: 5, stdout: "", stderr: "Input/output error" }),
      });
      await expect(kickstartAgentHarnessDaemon(ops)).rejects.toThrow(/kickstart/);
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

// ROUND-3 (both lenses; Claude finding 3 / Codex non-blocking residual). Every
// caller wrote "confirmed disabled/enabled" around a function that read the
// `launchctl enable`/`disable` EXIT CODE and never re-read launchd's
// persistent override database. The codebase already had the readback
// (`print-disabled system`, what `verifyHarnessJobDisabled` uses), so the
// resolution is to OBSERVE, not to disclose a bound.
describe("setAgentHarnessJobDisabled reads the override database back (fix-round 3)", () => {
  function overrideOps(overrides: {
    disabledTable: boolean | "unreadable";
    verbCode?: number;
  }): HarnessDaemonOps & { launchctl: string[][] } {
    const launchctl: string[][] = [];
    return {
      launchctl,
      writeFile: async () => {},
      readFile: async () => undefined,
      removeFile: async () => {},
      runLaunchctl: (args) => {
        launchctl.push([...args]);
        if (args[0] === "print-disabled") {
          return overrides.disabledTable === "unreadable"
            ? Promise.resolve({ code: 5, stdout: "", stderr: "Bootstrap failed: 5" })
            : Promise.resolve({
                code: 0,
                stdout: overrides.disabledTable ? `\t"${AGENT_HARNESS_DAEMON_LABEL}" => disabled\n` : "",
                stderr: "",
              });
        }
        return Promise.resolve({ code: overrides.verbCode ?? 0, stdout: "", stderr: "" });
      },
      sleepMs: async () => {},
    };
  }

  it("refuses when the verb exits 0 but the override table disagrees", async () => {
    // The exact fail-open: `launchctl disable` returns 0, launchd's durable
    // override state is untouched, and the park is reported as asserted.
    const ops = overrideOps({ disabledTable: false });
    await expect(setAgentHarnessJobDisabled(ops, true)).rejects.toThrow(
      /still reports the job ENABLED; refusing to report the job disabled/,
    );
    expect(ops.launchctl.map((c) => c[0])).toContain("print-disabled");
  });

  it("refuses in the enable direction too", async () => {
    const ops = overrideOps({ disabledTable: true });
    await expect(setAgentHarnessJobDisabled(ops, false)).rejects.toThrow(
      /still reports the job DISABLED; refusing to report the job enabled/,
    );
  });

  it("refuses fail-closed when the override table cannot be read at all", async () => {
    // "I could not tell" must never pass for "it is set".
    const ops = overrideOps({ disabledTable: "unreadable" });
    await expect(setAgentHarnessJobDisabled(ops, true)).rejects.toThrow(
      /could not be read back .*; refusing to report the job disabled/,
    );
  });

  it("accepts when the verb exits 0 and the table agrees", async () => {
    await expect(setAgentHarnessJobDisabled(overrideOps({ disabledTable: true }), true)).resolves.toBeUndefined();
    await expect(setAgentHarnessJobDisabled(overrideOps({ disabledTable: false }), false)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// FIX F-HARNESSENV (HIGH, Mini1 confined-Hermes re-drill 2026-07-26)
// ---------------------------------------------------------------------------
describe("harnessLaunchSpec (the argv+environment chokepoint)", () => {
  const goodEnv = {
    HERMES_ACCEPT_HOOKS: "1",
    HOME: "/var/sanctuary-agents/sanctuary-hermes",
    PYTHONPATH: "/var/sanctuary-agents/sanctuary-hermes/.hermes/hermes-agent",
  };

  it("carries argv and environment as ONE frozen value", () => {
    const spec = harnessLaunchSpec({ programArguments: ["/opt/venv/bin/python", "-m", "x"], environment: goodEnv });
    expect(spec.programArguments).toEqual(["/opt/venv/bin/python", "-m", "x"]);
    expect(spec.environment).toEqual(goodEnv);
    expect(Object.isFrozen(spec)).toBe(true);
    expect(Object.isFrozen(spec.environment)).toBe(true);
  });

  it("REFUSES a launch missing any required environment name, naming the missing ones", () => {
    for (const missing of REQUIRED_HARNESS_LAUNCH_ENV) {
      const environment: Record<string, string> = { ...goodEnv };
      delete environment[missing];
      expect(() => harnessLaunchSpec({ programArguments: ["/opt/venv/bin/python"], environment })).toThrow(
        new RegExp(missing),
      );
    }
    // Present-but-empty is missing: an empty PYTHONPATH is the same failure as
    // no PYTHONPATH, and the drill's crash came from an unset one.
    expect(() =>
      harnessLaunchSpec({ programArguments: ["/opt/venv/bin/python"], environment: { ...goodEnv, PYTHONPATH: "" } }),
    ).toThrow(/PYTHONPATH/);
  });

  it("REFUSES an empty or relative argv (a LaunchDaemon does not search PATH)", () => {
    expect(() => harnessLaunchSpec({ programArguments: [], environment: goodEnv })).toThrow(/non-empty argv/);
    expect(() => harnessLaunchSpec({ programArguments: ["python"], environment: goodEnv })).toThrow(/ABSOLUTE/);
  });

  it("planCoarseHarnessDaemonInstall renders the environment (the degraded coarse RESTORE path)", () => {
    // The drill's coarse restore rendered the plain plist from a bare argv, so
    // the very step that puts the agent back the way it was produced a plist
    // the agent could not start under ("coarse harness start failed").
    const plan = planCoarseHarnessDaemonInstall({
      agentAccount: "sanctuary-hermes",
      harnessLaunch: harnessLaunchSpec({
        programArguments: ["/opt/venv/bin/python", "-m", "x"],
        environment: goodEnv,
      }),
      fortressPath: "/Users/operator/.sanctuary",
    });
    for (const [name, value] of Object.entries(goodEnv)) {
      expect(plan.plistContent).toContain(`<key>${name}</key>`);
      expect(plan.plistContent).toContain(`<string>${value}</string>`);
    }
    expect(plan.plistContent).toContain("<key>SANCTUARY_STORAGE_PATH</key>");
    // Still the PLAIN (coarse) form, not the barrier form.
    expect(plan.plistContent).toContain("<key>RunAtLoad</key>\n\t<true/>");
    expect(plan.plistContent).not.toContain("Disabled");
  });
});
