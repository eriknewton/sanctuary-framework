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
    disarm: async () => {},
    uninstallHarnessDaemon: async () => {},
    scrubProvisionedEgressRules: async () => ({ removedRuleIds: ["provisioned-hermes-a"], reloadOk: true }),
    bootServiceStatus: async () => "absent",
    uninstallBootService: async () => {},
    globalPinStatus: async () => "absent",
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
