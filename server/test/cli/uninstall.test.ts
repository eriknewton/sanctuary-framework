import { describe, expect, it } from "vitest";
import { Writable } from "node:stream";

import { runUninstallCommand, type UninstallOps } from "../../src/cli/uninstall.js";
import { TOP_LEVEL_SUBCOMMANDS } from "../../src/cli/subcommands.js";

class Capture extends Writable {
  chunks: string[] = [];
  _write(chunk: Buffer | string, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

function ops(overrides: Partial<UninstallOps> = {}): UninstallOps {
  return {
    disarm: async () => "corroborated_off",
    uninstallHarnessDaemon: async () => {},
    scrubProvisionedEgressRules: async () => ({ removedRuleIds: ["provisioned-hermes-a"], reloadOk: true }),
    bootServiceStatus: async () => "absent",
    uninstallBootService: async () => {},
    globalPinStatus: async () => "absent",
    systemExtensionStatus: async () => "absent",
    deactivateSystemExtension: async () => ({ kind: "request-completed" }),
    ...overrides,
  };
}

describe("sanctuary uninstall", () => {
  it("is exposed as a top-level completion subcommand", () => {
    expect(TOP_LEVEL_SUBCOMMANDS).toContain("uninstall");
  });

  it("runs the reachable teardown and preserves operator data by default", async () => {
    const out = new Capture();
    const calls: string[] = [];
    const code = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out,
      err: new Capture(),
      platform: "linux",
      getuid: () => 501,
      ops: ops({
        disarm: async (fortressPath) => {
          calls.push(`disarm:${fortressPath}`);
          return "corroborated_off";
        },
        uninstallHarnessDaemon: async () => {
          calls.push("uninstall-daemon");
        },
        scrubProvisionedEgressRules: async (fortressPath, harnessId) => {
          calls.push(`scrub:${fortressPath}:${harnessId}`);
          return { removedRuleIds: ["provisioned-hermes-a", "provisioned-hermes-b"], reloadOk: true };
        },
      }),
    });

    expect(code).toBe(0);
    expect(calls).toEqual(["disarm:/tmp/fortress", "uninstall-daemon", "scrub:/tmp/fortress:hermes"]);
    expect(out.text()).toContain("installed footprint removed");
    expect(out.text()).toContain("skipped: castle-wall");
    expect(out.text()).toContain("2 provisioned rule file(s) removed");
    expect(out.text()).toContain("operator-data");
    expect(out.text()).toContain("remain at /tmp/fortress");
  });

  it("reports residue honestly when an installed boot service needs sudo", async () => {
    const out = new Capture();
    const code = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 501,
      ops: ops({
        bootServiceStatus: async () => "present",
        globalPinStatus: async () => "absent",
        systemExtensionStatus: async () => "present",
      }),
    });

    expect(code).toBe(1);
    expect(out.text()).toContain("completed with residue");
    expect(out.text()).toContain("cannot-remove: boot-service");
    expect(out.text()).toContain("requires sudo");
    expect(out.text()).toContain("cannot-remove: system-extension");
  });

  it("does not swallow teardown failures as clean uninstall", async () => {
    const out = new Capture();
    const code = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out,
      err: new Capture(),
      platform: "linux",
      getuid: () => 501,
      ops: ops({
        scrubProvisionedEgressRules: async () => {
          throw new Error("egress rule scrub left 1 provisioned rule file behind");
        },
      }),
    });

    expect(code).toBe(1);
    expect(out.text()).toContain("failed: scrub-egress-rules");
    expect(out.text()).toContain("egress rule scrub left 1 provisioned rule file behind");
    expect(out.text()).toContain("operator-data");
  });

  it("deactivates through the signed host and claims removal only after observed absence", async () => {
    const out = new Capture();
    const calls: string[] = [];
    let statusReads = 0;
    const code = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        disarm: async () => {
          calls.push("disarm");
          return "corroborated_off";
        },
        uninstallHarnessDaemon: async () => {
          calls.push("daemon");
        },
        scrubProvisionedEgressRules: async () => {
          calls.push("rules");
          return { removedRuleIds: [], reloadOk: true };
        },
        systemExtensionStatus: async () => {
          calls.push("sysext-status");
          statusReads++;
          return statusReads === 1 ? "present" : "absent";
        },
        deactivateSystemExtension: async () => {
          calls.push("deactivate");
          return { kind: "request-completed" };
        },
      }),
    });

    expect(code).toBe(0);
    expect(calls).toEqual([
      "disarm",
      "daemon",
      "rules",
      "sysext-status",
      "deactivate",
      "sysext-status",
    ]);
    expect(out.text()).toContain("removed: system-extension");
    expect(out.text()).toContain("observed absent");
  });

  it("surfaces the host app's remediation hint in the system-extension row on every outcome branch", async () => {
    // The deactivation verb never mutates; when it detects an app-version
    // skew it attaches a machine-readable remediation id. That hint must
    // reach the operator row on EVERY branch - success, failure, and the two
    // post-request probe branches (still-present and unreadable) - because
    // the row is the only place the operator learns why a rerun needs the
    // console.
    const remediationText =
      "remediation required (extension_version_skew_reregister_required)";

    const failedOut = new Capture();
    const failedCode = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out: failedOut,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        systemExtensionStatus: async () => "present",
        deactivateSystemExtension: async () => ({
          kind: "failed",
          detail: "OSSystemExtensionErrorDomain error 4.",
          error_domain: "OSSystemExtensionErrorDomain",
          error_code: 4,
          remediation: "extension_version_skew_reregister_required",
        }),
      }),
    });
    expect(failedCode).toBe(1);
    expect(failedOut.text()).toContain("OSSystemExtensionErrorDomain error 4.");
    expect(failedOut.text()).toContain(remediationText);
    expect(failedOut.text()).toContain("launch Sanctuary-CastleWall.app at the console");

    const removedOut = new Capture();
    let removedStatusReads = 0;
    const removedCode = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out: removedOut,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        systemExtensionStatus: async () => {
          removedStatusReads++;
          return removedStatusReads === 1 ? "present" : "absent";
        },
        deactivateSystemExtension: async () => ({
          kind: "request-completed",
          remediation: "extension_version_skew_reregister_required",
        }),
      }),
    });
    expect(removedCode).toBe(0);
    expect(removedOut.text()).toContain(remediationText);

    // request-completed but the extension is STILL PRESENT: the hint must
    // survive into this branch too, not only the clean ones.
    const stillPresentOut = new Capture();
    const stillPresentCode = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out: stillPresentOut,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        systemExtensionStatus: async () => "present",
        deactivateSystemExtension: async () => ({
          kind: "request-completed",
          remediation: "extension_version_skew_reregister_required",
        }),
      }),
    });
    expect(stillPresentCode).toBe(1);
    expect(stillPresentOut.text()).toContain("still present");
    expect(stillPresentOut.text()).toContain(remediationText);

    // request-completed but the post-request probe could not read state:
    // the unreadable branch keeps the hint as well.
    const unreadableOut = new Capture();
    let unreadableStatusReads = 0;
    const unreadableCode = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out: unreadableOut,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        systemExtensionStatus: async () => {
          unreadableStatusReads++;
          return unreadableStatusReads === 1 ? "present" : "unknown";
        },
        deactivateSystemExtension: async () => ({
          kind: "request-completed",
          remediation: "extension_version_skew_reregister_required",
        }),
      }),
    });
    expect(unreadableCode).toBe(1);
    expect(unreadableOut.text()).toContain("absence could not be observed");
    expect(unreadableOut.text()).toContain(remediationText);
  });

  it("keeps reboot-deferred deactivation non-clean until absence is observed", async () => {
    const out = new Capture();
    const code = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        systemExtensionStatus: async () => "present",
        deactivateSystemExtension: async () => ({ kind: "reboot-required" }),
      }),
    });

    expect(code).toBe(1);
    expect(out.text()).toContain("cannot-remove: system-extension");
    expect(out.text()).toContain("requires reboot");
  });

  it("does not remove supporting services when disarm is not positively observed", async () => {
    const out = new Capture();
    const calls: string[] = [];
    const code = await runUninstallCommand({
      argv: ["--fortress", "/tmp/fortress"],
      out,
      err: new Capture(),
      platform: "darwin",
      getuid: () => 0,
      ops: ops({
        disarm: async () => "save_accepted_inconclusive",
        uninstallHarnessDaemon: async () => {
          calls.push("daemon");
        },
        scrubProvisionedEgressRules: async () => {
          calls.push("rules");
          return { removedRuleIds: [], reloadOk: true };
        },
        systemExtensionStatus: async () => "present",
        deactivateSystemExtension: async () => {
          calls.push("deactivate");
          return { kind: "request-completed" };
        },
      }),
    });

    expect(code).toBe(1);
    expect(calls).toEqual([]);
    expect(out.text()).toContain("failed: castle-wall");
    expect(out.text()).toContain("kept because the content filter was not positively observed disabled");
    expect(out.text()).toContain("deactivation not requested");
  });

  it("refuses operator data deletion through the software uninstall verb", async () => {
    const out = new Capture();
    const err = new Capture();
    const code = await runUninstallCommand({
      argv: ["--remove-operator-data"],
      out,
      err,
      platform: "linux",
      ops: ops(),
    });

    expect(code).toBe(2);
    expect(err.text()).toContain("Refusing --remove-operator-data");
    expect(out.text()).toBe("");
  });

  it("prints help that names the preservation bound", async () => {
    const out = new Capture();
    const code = await runUninstallCommand({ argv: ["--help"], out, err: new Capture(), ops: ops() });

    expect(code).toBe(0);
    expect(out.text()).toContain("preserves the fortress state");
    expect(out.text()).toContain("never reports a clean uninstall");
  });
});
