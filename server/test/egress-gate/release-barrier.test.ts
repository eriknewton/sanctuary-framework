/**
 * Release-barrier primitives (Unified Protect Slice 5 S5-5): hold-file
 * render/parse, argv digest, wrapper script invariants, barrier plist form,
 * and the parked install (never bootstraps; fails loud on a live harness).
 */

import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AGENT_HARNESS_DAEMON_LABEL,
  AGENT_HARNESS_DAEMON_PLIST_PATH,
  renderAgentHarnessDaemonPlist,
} from "../../src/egress-gate/harness-daemon.js";
import {
  AGENT_HARNESS_HOLD_DIR,
  HOLD_FILE_HEADER,
  PARKED_EXPECTED_GENERATION,
  RELEASE_EXEC_WRAPPER_SCRIPT,
  RELEASE_WRAPPER_REFUSAL_EXIT_CODE,
  ReleaseBarrierError,
  buildBarrierProgramArguments,
  computeHarnessArgvDigest,
  executeParkedHarnessInstall,
  holdFilePathForUid,
  parseHarnessReleaseHoldFile,
  planParkedHarnessInstall,
  releaseWrapperPath,
  renderHarnessReleaseHoldFile,
  renderReleaseExecWrapperScript,
  type HarnessReleaseHoldRecord,
  type ParkedInstallOps,
} from "../../src/egress-gate/release-barrier.js";

const RECORD: HarnessReleaseHoldRecord = {
  generation_id: 7,
  agent_uid: 503,
  harness_label: AGENT_HARNESS_DAEMON_LABEL,
  argv_digest: "a".repeat(64),
  boot_session_uuid: "1A2B3C4D-0000-4444-8888-ABCDEFABCDEF",
};

describe("hold-file paths", () => {
  it("builds the per-uid hold path under the root-owned dir", () => {
    expect(holdFilePathForUid(503)).toBe(`${AGENT_HARNESS_HOLD_DIR}/503.release`);
  });

  it("refuses non-positive and non-integer uids", () => {
    expect(() => holdFilePathForUid(0)).toThrow(ReleaseBarrierError);
    expect(() => holdFilePathForUid(-1)).toThrow(ReleaseBarrierError);
    expect(() => holdFilePathForUid(1.5)).toThrow(ReleaseBarrierError);
  });

  it("places the wrapper inside the hold dir", () => {
    expect(releaseWrapperPath()).toBe(`${AGENT_HARNESS_HOLD_DIR}/release-exec-wrapper.sh`);
  });
});

describe("computeHarnessArgvDigest", () => {
  it("matches the known NUL-separated sha256 vector", () => {
    // printf '%s\0' a b | shasum -a 256  ->  sha256 of "a\0b\0"
    const expected = "8fb20ef63ced4145fc2e983ffe597d1dcff39154c3bf21f0fa9dde6a0c50fdc9";
    expect(computeHarnessArgvDigest(["a", "b"])).toBe(expected);
  });

  it("is order- and boundary-sensitive (no concat ambiguity)", () => {
    expect(computeHarnessArgvDigest(["ab"])).not.toBe(computeHarnessArgvDigest(["a", "b"]));
    expect(computeHarnessArgvDigest(["a", "b"])).not.toBe(computeHarnessArgvDigest(["b", "a"]));
  });

  it("refuses an empty argv and NUL bytes inside arguments", () => {
    expect(() => computeHarnessArgvDigest([])).toThrow(ReleaseBarrierError);
    expect(() => computeHarnessArgvDigest(["a\0b"])).toThrow(ReleaseBarrierError);
  });
});

describe("hold-file render + strict parse", () => {
  it("round-trips a valid record", () => {
    const text = renderHarnessReleaseHoldFile(RECORD);
    expect(text.startsWith(`${HOLD_FILE_HEADER}\n`)).toBe(true);
    expect(parseHarnessReleaseHoldFile(text)).toEqual(RECORD);
  });

  it("render refuses a non-positive generation id", () => {
    expect(() => renderHarnessReleaseHoldFile({ ...RECORD, generation_id: 0 })).toThrow(ReleaseBarrierError);
    expect(() => renderHarnessReleaseHoldFile({ ...RECORD, generation_id: -3 })).toThrow(ReleaseBarrierError);
  });

  it("render refuses an unsafe label, malformed digest, and malformed boot uuid", () => {
    expect(() => renderHarnessReleaseHoldFile({ ...RECORD, harness_label: "bad label" })).toThrow(
      ReleaseBarrierError,
    );
    expect(() => renderHarnessReleaseHoldFile({ ...RECORD, argv_digest: "ZZ".repeat(32) })).toThrow(
      ReleaseBarrierError,
    );
    expect(() => renderHarnessReleaseHoldFile({ ...RECORD, argv_digest: "ab" })).toThrow(ReleaseBarrierError);
    expect(() => renderHarnessReleaseHoldFile({ ...RECORD, boot_session_uuid: "" })).toThrow(ReleaseBarrierError);
    expect(() =>
      renderHarnessReleaseHoldFile({ ...RECORD, boot_session_uuid: "uuid\nwith=newline" }),
    ).toThrow(ReleaseBarrierError);
  });

  it("parse refuses a wrong header", () => {
    const text = renderHarnessReleaseHoldFile(RECORD).replace("v1", "v2");
    expect(() => parseHarnessReleaseHoldFile(text)).toThrow(/header/);
  });

  it("parse refuses a duplicated key (never last-wins)", () => {
    const text = renderHarnessReleaseHoldFile(RECORD) + "generation_id=99\n";
    expect(() => parseHarnessReleaseHoldFile(text)).toThrow(/duplicated/);
  });

  it("parse refuses a missing key and an unknown key", () => {
    const missing = renderHarnessReleaseHoldFile(RECORD)
      .split("\n")
      .filter((l) => !l.startsWith("argv_digest="))
      .join("\n");
    expect(() => parseHarnessReleaseHoldFile(missing)).toThrow(/missing/);
    const unknown = renderHarnessReleaseHoldFile(RECORD) + "extra_key=1\n";
    expect(() => parseHarnessReleaseHoldFile(unknown)).toThrow(/unknown key/);
  });

  it("parse re-validates values (a tampered digest never parses)", () => {
    const text = renderHarnessReleaseHoldFile(RECORD).replace("a".repeat(64), "nothex");
    expect(() => parseHarnessReleaseHoldFile(text)).toThrow(ReleaseBarrierError);
  });

  it("parse is wrapper-equivalent on integers: refuses decimal, leading-zero, signed, and padded forms", () => {
    // Fix-round MED regression: the sh wrapper compares these fields as
    // STRINGS, so Number()-coercible non-canonical forms ("1.0", "007",
    // "+7", " 7") must be refused by the TS parser too -- otherwise the two
    // parsers disagree about the same file.
    const base = renderHarnessReleaseHoldFile(RECORD);
    for (const bad of ["1.0", "007", "+7", " 7", "7 ", "0x7", "7e0"]) {
      const genTampered = base.replace("generation_id=7", `generation_id=${bad}`);
      expect(() => parseHarnessReleaseHoldFile(genTampered)).toThrow(/canonical positive integer/);
    }
    for (const bad of ["503.0", "0503", "+503"]) {
      const uidTampered = base.replace("agent_uid=503", `agent_uid=${bad}`);
      expect(() => parseHarnessReleaseHoldFile(uidTampered)).toThrow(/canonical positive integer/);
    }
  });
});

describe("wrapper script (static content invariants)", () => {
  it("is fully static: renderReleaseExecWrapperScript returns the constant", () => {
    expect(renderReleaseExecWrapperScript()).toBe(RELEASE_EXEC_WRAPPER_SCRIPT);
  });

  it("execs the untouched argv and refuses with the documented exit code", () => {
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain('exec "$@"');
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain(`exit ${RELEASE_WRAPPER_REFUSAL_EXIT_CODE}`);
    // Exactly one exec and it is the LAST command line of the script.
    const lines = RELEASE_EXEC_WRAPPER_SCRIPT.trimEnd().split("\n");
    expect(lines[lines.length - 1]).toBe('exec "$@"');
  });

  it("binds the release to the current boot session and the argv digest", () => {
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain("kern.bootsessionuuid");
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain("printf '%s\\0' \"$@\"");
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain("/usr/bin/shasum -a 256");
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain(HOLD_FILE_HEADER);
  });

  it("refuses the parked sentinel generation", () => {
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain('[ "$EXPECTED_GENERATION" -gt 0 ]');
  });

  it("fails closed under sh strict mode", () => {
    expect(RELEASE_EXEC_WRAPPER_SCRIPT.startsWith("#!/bin/sh\n")).toBe(true);
    expect(RELEASE_EXEC_WRAPPER_SCRIPT).toContain("set -eu");
  });
});

describe("buildBarrierProgramArguments", () => {
  const base = {
    wrapperPath: "/var/db/sanctuary/agent-harness/release-exec-wrapper.sh",
    holdFilePath: "/var/db/sanctuary/agent-harness/503.release",
    expectedGenerationId: 7,
    harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
    harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
  };

  it("composes wrapper-first argv with the -- separator and untouched harness argv", () => {
    expect(buildBarrierProgramArguments(base)).toEqual([
      base.wrapperPath,
      base.holdFilePath,
      "7",
      AGENT_HARNESS_DAEMON_LABEL,
      "--",
      "/usr/local/bin/node",
      "/opt/harness.js",
    ]);
  });

  it("accepts the parked sentinel generation (rendered as 0)", () => {
    const argv = buildBarrierProgramArguments({ ...base, expectedGenerationId: PARKED_EXPECTED_GENERATION });
    expect(argv[2]).toBe("0");
  });

  it("refuses relative wrapper/hold paths, unsafe labels, negative generations, and a relative harness program", () => {
    expect(() => buildBarrierProgramArguments({ ...base, wrapperPath: "wrapper.sh" })).toThrow(ReleaseBarrierError);
    expect(() => buildBarrierProgramArguments({ ...base, holdFilePath: "503.release" })).toThrow(ReleaseBarrierError);
    expect(() => buildBarrierProgramArguments({ ...base, harnessLabel: "bad label" })).toThrow(ReleaseBarrierError);
    expect(() => buildBarrierProgramArguments({ ...base, expectedGenerationId: -1 })).toThrow(ReleaseBarrierError);
    expect(() => buildBarrierProgramArguments({ ...base, harnessArgv: ["node", "x.js"] })).toThrow(
      ReleaseBarrierError,
    );
    expect(() => buildBarrierProgramArguments({ ...base, harnessArgv: [] })).toThrow(ReleaseBarrierError);
  });
});

describe("barrier plist form", () => {
  const plan = planParkedHarnessInstall({
    agentAccount: "sanctuary-hermes",
    agentUid: 503,
    harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
    fortressPath: "/Users/op/.sanctuary",
  });

  it("renders Disabled=true, RunAtLoad=false, and Crashed-only KeepAlive", () => {
    expect(plan.plistContent).toContain("<key>Disabled</key>\n\t<true/>");
    expect(plan.plistContent).toContain("<key>RunAtLoad</key>\n\t<false/>");
    expect(plan.plistContent).toContain("<key>Crashed</key>\n\t\t<true/>");
    expect(plan.plistContent).not.toContain("<key>KeepAlive</key>\n\t<true/>");
  });

  it("NEVER renders a SuccessfulExit KeepAlive (launchd.plist(5): SuccessfulExit implies RunAtLoad=true, defeating the park, and restarts wrapper refusals in a loop)", () => {
    // Fix-round MED regression: the barrier form must use {Crashed:true},
    // which carries no RunAtLoad implication and does not restart a plain
    // non-zero exit (the wrapper's refusal exit 78).
    expect(plan.plistContent).not.toContain("SuccessfulExit");
  });

  it("routes ProgramArguments through the wrapper with the parked generation", () => {
    expect(plan.plistContent).toContain(`<string>${plan.wrapperPath}</string>`);
    expect(plan.plistContent).toContain(`<string>${plan.holdFilePath}</string>`);
    expect(plan.plistContent).toContain("<string>0</string>");
    expect(plan.plistContent).toContain("<string>--</string>");
    expect(plan.plistContent).toContain("<string>/opt/harness.js</string>");
  });

  it("release re-render embeds the committed generation id", () => {
    const released = planParkedHarnessInstall({
      agentAccount: "sanctuary-hermes",
      agentUid: 503,
      harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
      expectedGenerationId: 42,
    });
    expect(released.plistContent).toContain("<string>42</string>");
  });

  it("legacy render (no barrier options) is byte-identical to the pre-S5-5 form", () => {
    const legacy = renderAgentHarnessDaemonPlist({
      agentAccount: "sanctuary-hermes",
      programArguments: ["/usr/local/bin/node", "/opt/harness.js"],
    });
    expect(legacy).not.toContain("Disabled");
    expect(legacy).toContain("<key>RunAtLoad</key>\n\t<true/>");
    expect(legacy).toContain("<key>KeepAlive</key>\n\t<true/>");
    expect(legacy).not.toContain("SuccessfulExit");
  });

  it("plan refuses a root account and a non-positive uid (renderer validation still applies)", () => {
    expect(() =>
      planParkedHarnessInstall({ agentAccount: "root", agentUid: 503, harnessArgv: ["/x"] }),
    ).toThrow(/root/);
    expect(() =>
      planParkedHarnessInstall({ agentAccount: "sanctuary-hermes", agentUid: 0, harnessArgv: ["/x"] }),
    ).toThrow(ReleaseBarrierError);
  });

  it("targets the canonical plist path and label", () => {
    expect(plan.plistPath).toBe(AGENT_HARNESS_DAEMON_PLIST_PATH);
    expect(plan.harnessLabel).toBe(AGENT_HARNESS_DAEMON_LABEL);
  });
});

interface OpsLog {
  writes: Array<{ path: string; mode: number }>;
  removed: string[];
  launchctl: string[][];
}

function makeParkedOps(overrides?: {
  disableCode?: number;
  running?: boolean;
  known?: boolean;
}): { ops: ParkedInstallOps; log: OpsLog } {
  const log: OpsLog = { writes: [], removed: [], launchctl: [] };
  const ops: ParkedInstallOps = {
    async writeFile(path, _content, mode) {
      log.writes.push({ path, mode });
    },
    async removeFile(path) {
      log.removed.push(path);
    },
    async runLaunchctl(args) {
      log.launchctl.push([...args]);
      return { code: overrides?.disableCode ?? 0, stdout: "", stderr: "boom" };
    },
    async harnessStatus() {
      return {
        known: overrides?.known ?? true,
        installed: false,
        running: overrides?.running ?? false,
      };
    },
  };
  return { ops, log };
}

describe("executeParkedHarnessInstall", () => {
  const plan = planParkedHarnessInstall({
    agentAccount: "sanctuary-hermes",
    agentUid: 503,
    harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
  });

  it("writes wrapper 0755 + plist 0644, disables, removes any stale hold file, and NEVER bootstraps", async () => {
    const { ops, log } = makeParkedOps();
    await executeParkedHarnessInstall(plan, ops);
    expect(log.writes).toEqual([
      { path: plan.wrapperPath, mode: 0o755 },
      { path: plan.plistPath, mode: 0o644 },
    ]);
    expect(log.launchctl).toEqual([["disable", `system/${AGENT_HARNESS_DAEMON_LABEL}`]]);
    expect(log.removed).toEqual([plan.holdFilePath]);
    expect(log.launchctl.some((args) => args[0] === "bootstrap" || args[0] === "kickstart")).toBe(false);
  });

  it("fails loud when launchctl disable fails", async () => {
    const { ops } = makeParkedOps({ disableCode: 5 });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/disable/);
  });

  it("fails loud when the harness reports RUNNING after the park", async () => {
    const { ops } = makeParkedOps({ running: true });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/RUNNING/);
  });

  it("fails loud when the harness status is not trustworthy", async () => {
    const { ops } = makeParkedOps({ known: false });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/trustworthy/);
  });
});

/**
 * Live wrapper behavior, macOS only (the wrapper depends on
 * kern.bootsessionuuid and /usr/bin/shasum; Linux CI skips -- the Linux
 * authoritative gate covers the pure-TS surfaces above).
 */
const isDarwin = process.platform === "darwin";

function runSh(args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile("/bin/sh", args, { timeout: 20_000, encoding: "utf8" }, (error, stdout, stderr) => {
      const code = error ? ((error as NodeJS.ErrnoException).code as unknown as number) : 0;
      resolve({ code: typeof code === "number" ? code : 127, stdout, stderr });
    });
  });
}

async function currentBootSessionUuid(): Promise<string> {
  const r = await new Promise<{ out: string }>((resolve) => {
    execFile("/usr/sbin/sysctl", ["-n", "kern.bootsessionuuid"], { encoding: "utf8" }, (_e, stdout) =>
      resolve({ out: stdout.trim() }),
    );
  });
  return r.out;
}

describe.runIf(isDarwin)("wrapper script live behavior (macOS)", () => {
  it("refuses (78) on absent hold file, wrong generation, wrong digest, stale boot session; releases on full match", async () => {
    const dir = mkdtempSync(join(tmpdir(), "s5-5-wrapper-"));
    try {
      const wrapper = join(dir, "release-exec-wrapper.sh");
      writeFileSync(wrapper, RELEASE_EXEC_WRAPPER_SCRIPT);
      chmodSync(wrapper, 0o755);
      const hold = join(dir, "503.release");
      const bootUuid = await currentBootSessionUuid();
      expect(bootUuid.length).toBeGreaterThan(0);

      const argv = ["/bin/echo", "released-ok"];
      const digest = computeHarnessArgvDigest(argv);
      const uid = process.getuid ? process.getuid() : 0;
      const record: HarnessReleaseHoldRecord = {
        generation_id: 7,
        agent_uid: uid,
        harness_label: AGENT_HARNESS_DAEMON_LABEL,
        argv_digest: digest,
        boot_session_uuid: bootUuid,
      };
      const wrapperArgs = (gen: string) => [wrapper, hold, gen, AGENT_HARNESS_DAEMON_LABEL, "--", ...argv];

      // Absent hold file: refuse.
      let r = await runSh(wrapperArgs("7"));
      expect(r.code).toBe(RELEASE_WRAPPER_REFUSAL_EXIT_CODE);
      expect(r.stderr).toContain("hold file absent");

      // Parked sentinel generation: refuse even with a valid hold file.
      writeFileSync(hold, renderHarnessReleaseHoldFile(record));
      r = await runSh(wrapperArgs("0"));
      expect(r.code).toBe(RELEASE_WRAPPER_REFUSAL_EXIT_CODE);

      // Generation mismatch (stale plist): refuse.
      r = await runSh(wrapperArgs("8"));
      expect(r.code).toBe(RELEASE_WRAPPER_REFUSAL_EXIT_CODE);
      expect(r.stderr).toContain("does not match expected generation");

      // Digest mismatch (swapped argv): refuse.
      writeFileSync(
        hold,
        renderHarnessReleaseHoldFile({ ...record, argv_digest: computeHarnessArgvDigest(["/bin/echo", "other"]) }),
      );
      r = await runSh(wrapperArgs("7"));
      expect(r.code).toBe(RELEASE_WRAPPER_REFUSAL_EXIT_CODE);
      expect(r.stderr).toContain("argv digest mismatch");

      // Stale boot session (hold file from a previous boot): refuse.
      writeFileSync(
        hold,
        renderHarnessReleaseHoldFile({ ...record, boot_session_uuid: "00000000-0000-4000-8000-000000000000" }),
      );
      r = await runSh(wrapperArgs("7"));
      expect(r.code).toBe(RELEASE_WRAPPER_REFUSAL_EXIT_CODE);
      expect(r.stderr).toContain("previous boot session");

      // Full match: exec the harness argv (echo).
      writeFileSync(hold, renderHarnessReleaseHoldFile(record));
      r = await runSh(wrapperArgs("7"));
      expect(r.code).toBe(0);
      expect(r.stdout.trim()).toBe("released-ok");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("end to end: the PARKED plist's argv is refused, the re-rendered RELEASED plist's argv execs (fix-round HIGH regression)", async () => {
    // Pins the P1 finding: a release MUST re-render the plist with the
    // committed generation. The exact ProgramArguments a plist would hand
    // launchd are extracted from BOTH plist forms and run through the real
    // wrapper: the parked form (generation 0) must refuse even with a fully
    // valid hold file on disk; only the released re-render execs.
    const dir = mkdtempSync(join(tmpdir(), "s5-5-e2e-"));
    try {
      const harnessArgv = ["/bin/echo", "released-ok"];
      const agentUid = process.getuid ? process.getuid() : 0;
      const planOptions = {
        agentAccount: "sanctuary-hermes",
        agentUid,
        harnessArgv,
        holdDir: dir,
      };
      const parkedPlan = planParkedHarnessInstall(planOptions);
      const committedPlan = planParkedHarnessInstall({ ...planOptions, expectedGenerationId: 7 });

      // Install the wrapper exactly as executeParkedHarnessInstall would.
      writeFileSync(parkedPlan.wrapperPath, parkedPlan.wrapperContent);
      chmodSync(parkedPlan.wrapperPath, 0o755);

      // A fully valid hold file for the committed generation is on disk.
      const bootUuid = await currentBootSessionUuid();
      writeFileSync(
        parkedPlan.holdFilePath,
        renderHarnessReleaseHoldFile({
          generation_id: 7,
          agent_uid: agentUid,
          harness_label: AGENT_HARNESS_DAEMON_LABEL,
          argv_digest: computeHarnessArgvDigest(harnessArgv),
          boot_session_uuid: bootUuid,
        }),
      );

      const extractProgramArguments = (plist: string): string[] => {
        const block = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist);
        expect(block).not.toBeNull();
        return [...block![1]!.matchAll(/<string>([\s\S]*?)<\/string>/g)].map((m) => m[1]!);
      };

      // Parked plist: wrapper refuses (generation 0) despite the valid hold file.
      const parkedArgv = extractProgramArguments(parkedPlan.plistContent);
      let r = await runSh(parkedArgv);
      expect(r.code).toBe(RELEASE_WRAPPER_REFUSAL_EXIT_CODE);
      expect(r.stderr).toContain("parked plist");

      // Released re-render: same wrapper, same hold file, execs the harness.
      const releasedArgv = extractProgramArguments(committedPlan.plistContent);
      r = await runSh(releasedArgv);
      expect(r.code).toBe(0);
      expect(r.stdout.trim()).toBe("released-ok");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
