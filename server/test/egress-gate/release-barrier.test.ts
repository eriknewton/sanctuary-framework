/**
 * Release-barrier primitives (Unified Protect Slice 5 S5-5): hold-file
 * render/parse, argv digest, wrapper script invariants, barrier plist form,
 * and the parked install (never bootstraps; fails loud on a live harness).
 *
 * S5-DRILL 2026-07-18 fix-round adds the two install-path defect classes the
 * mocked suite could not see: D1, the hold-directory chokepoint, covered
 * against a REAL filesystem with a directory that does not exist (a test that
 * only asserted "the mkdir op was called" would reproduce the original blind
 * spot); and D2, the parked-install stand-down, covered by asserting launchctl
 * call ORDER (disable strictly before bootout, both before the status
 * assertion) rather than mere presence.
 */

import { describe, it, expect } from "vitest";
import { execFile } from "node:child_process";
import {
  mkdtempSync,
  writeFileSync,
  chmodSync,
  rmSync,
  statSync,
  readFileSync,
  openSync,
  fstatSync,
  closeSync,
} from "node:fs";
import { chmod, mkdir, rm, writeFile as fsWriteFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ensureAgentHarnessHoldDir } from "../../src/egress-gate/arming-wiring.js";

import {
  AGENT_HARNESS_DAEMON_LABEL,
  AGENT_HARNESS_DAEMON_PLIST_PATH,
  renderAgentHarnessDaemonPlist,
} from "../../src/egress-gate/harness-daemon.js";
import {
  AGENT_HARNESS_HOLD_DIR,
  AGENT_HARNESS_HOLD_DIR_MODE,
  writeIntoHoldDir,
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
  revertParkedHarnessInstall,
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
  ensured: Array<{ path: string; mode: number }>;
  removed: string[];
  launchctl: string[][];
  notices: string[];
  /** Every side effect in the order it happened (cross-op-kind ordering). */
  sequence: string[];
  /**
   * THE HOST, not the call record (fix-round 2, 2026-07-18). The re-gate's
   * blocker survived a well-tested fix round because every assertion was about
   * which functions ran. These three fields are the state a real operator would
   * be left with, and the B1 tests below assert on THEM: the bytes on disk, the
   * persistent launchd disable, and whether the agent is running.
   */
  files: Map<string, string>;
  jobDisabled: boolean;
  jobRunning: boolean;
}

function makeParkedOps(overrides?: {
  disableCode?: number;
  bootoutCode?: number;
  bootoutStderr?: string;
  running?: boolean;
  known?: boolean;
  ensureHoldDirError?: string;
  /** Bytes the pre-existing harness plist holds, or undefined for a clean host. */
  priorPlist?: string;
  /** Status samples returned in order (later ones drive the settle loop). */
  statusSamples?: Array<{ known: boolean; installed: boolean; running: boolean }>;
  /** Make the revert's verified restart fail (it throws, as production's does). */
  restoreRunningHarnessError?: string;
}): { ops: ParkedInstallOps; log: OpsLog } {
  const log: OpsLog = {
    writes: [],
    ensured: [],
    removed: [],
    launchctl: [],
    notices: [],
    sequence: [],
    files: new Map(),
    jobDisabled: false,
    jobRunning: overrides?.statusSamples?.[0]?.running ?? overrides?.running ?? false,
  };
  if (overrides?.priorPlist !== undefined) {
    log.files.set(AGENT_HARNESS_DAEMON_PLIST_PATH, overrides.priorPlist);
  }
  let statusCall = 0;
  const ops: ParkedInstallOps = {
    async ensureHoldDir(path, mode) {
      log.ensured.push({ path, mode });
      log.sequence.push(`ensureHoldDir:${path}`);
      if (overrides?.ensureHoldDirError !== undefined) throw new Error(overrides.ensureHoldDirError);
    },
    async readFile(path) {
      log.sequence.push(`read:${path}`);
      return log.files.get(path);
    },
    async writeFile(path, content, mode) {
      log.writes.push({ path, mode });
      log.sequence.push(`write:${path}`);
      log.files.set(path, content);
    },
    async removeFile(path) {
      log.removed.push(path);
      log.sequence.push(`remove:${path}`);
      log.files.delete(path);
    },
    async restoreRunningHarness(plistContent) {
      log.sequence.push("restoreRunningHarness");
      if (overrides?.restoreRunningHarnessError !== undefined) {
        throw new Error(overrides.restoreRunningHarnessError);
      }
      // Production wires this to `installAgentHarnessDaemon`, which refuses
      // unless launchd reports a stable running pid -- so it resolving means
      // the plist is back AND the job is up. Model exactly that.
      log.files.set(AGENT_HARNESS_DAEMON_PLIST_PATH, plistContent);
      log.jobDisabled = false;
      log.jobRunning = true;
    },
    async clearJobDisable() {
      log.sequence.push("clearJobDisable");
      log.jobDisabled = false;
    },
    async runLaunchctl(args) {
      log.launchctl.push([...args]);
      log.sequence.push(`launchctl:${args.join(" ")}`);
      if (args[0] === "bootout") {
        const code = overrides?.bootoutCode ?? 0;
        if (code === 0) log.jobRunning = false;
        return { code, stdout: "", stderr: overrides?.bootoutStderr ?? "" };
      }
      const disableCode = overrides?.disableCode ?? 0;
      if (args[0] === "disable" && disableCode === 0) log.jobDisabled = true;
      return { code: disableCode, stdout: "", stderr: "boom" };
    },
    async harnessStatus() {
      log.sequence.push("harnessStatus");
      const samples = overrides?.statusSamples;
      if (samples !== undefined) {
        const sample = samples[Math.min(statusCall, samples.length - 1)]!;
        statusCall += 1;
        return sample;
      }
      statusCall += 1;
      return {
        known: overrides?.known ?? true,
        installed: false,
        running: overrides?.running ?? false,
      };
    },
    async sleepMs() {
      /* instant under test */
    },
    notify(message) {
      log.notices.push(message);
      log.sequence.push("notify");
    },
  };
  return { ops, log };
}

/** A plist the identity gate accepts: same service account as the plan. */
function priorPlistFor(account: string, programArgs: string[] = ["/usr/local/bin/node", "/opt/harness.js"]): string {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<plist version=\"1.0\"><dict>",
    "<key>UserName</key>",
    `<string>${account}</string>`,
    "<key>ProgramArguments</key>",
    "<array>",
    ...programArgs.map((a) => `<string>${a}</string>`),
    "</array>",
    "</dict></plist>",
  ].join("\n");
}

describe("executeParkedHarnessInstall", () => {
  const plan = planParkedHarnessInstall({
    agentAccount: "sanctuary-hermes",
    agentUid: 503,
    harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
  });

  it("writes wrapper 0755 + plist 0644, disables, stands down, removes any stale hold file, and NEVER bootstraps", async () => {
    const { ops, log } = makeParkedOps();
    await executeParkedHarnessInstall(plan, ops);
    expect(log.writes).toEqual([
      { path: plan.wrapperPath, mode: 0o755 },
      { path: plan.plistPath, mode: 0o644 },
    ]);
    expect(log.launchctl).toEqual([
      ["disable", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
      ["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`],
    ]);
    expect(log.removed).toEqual([plan.holdFilePath]);
    expect(log.launchctl.some((args) => args[0] === "bootstrap" || args[0] === "kickstart")).toBe(false);
  });

  it("fails loud when launchctl disable fails", async () => {
    const { ops } = makeParkedOps({ disableCode: 5 });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/disable/);
  });

  it("fails loud when the harness reports RUNNING after the park", async () => {
    const { ops } = makeParkedOps({
      // A running job ALWAYS has a plist on a real host; a running job without
      // one is refused up front by its own gate (see the F5 tests below), so
      // reaching the post-park assertion requires modelling the plist.
      priorPlist: priorPlistFor("sanctuary-hermes"),
      running: true,
    });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/RUNNING/);
  });

  it("fails loud when the harness status is not trustworthy", async () => {
    const { ops } = makeParkedOps({ known: false });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/trustworthy/);
  });

  // ------------------------------------------------------------------
  // Drill D1 (2026-07-18): the wrapper was written into a root-owned
  // directory nothing in a first-ever install creates, so every clean-host
  // arm died with ENOENT before any account existed.
  // ------------------------------------------------------------------

  it("D1: ensures the hold directory BEFORE writing the wrapper into it, root-owned 0755", async () => {
    const { ops, log } = makeParkedOps();
    await executeParkedHarnessInstall(plan, ops);
    expect(log.ensured).toEqual([{ path: AGENT_HARNESS_HOLD_DIR, mode: AGENT_HARNESS_HOLD_DIR_MODE }]);
    // ORDER, not merely presence: the ensure must precede the write it guards.
    expect(log.sequence.indexOf(`ensureHoldDir:${AGENT_HARNESS_HOLD_DIR}`)).toBeLessThan(
      log.sequence.indexOf(`write:${plan.wrapperPath}`),
    );
  });

  it("D1: refuses the whole parked install when the hold directory cannot be ensured", async () => {
    const { ops, log } = makeParkedOps({ ensureHoldDirError: "EACCES: read-only /var/db" });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/EACCES/);
    // Fail-closed: nothing was written and no launchctl state was touched.
    expect(log.writes).toEqual([]);
    expect(log.launchctl).toEqual([]);
  });

  it("D1: writeIntoHoldDir refuses a relative hold dir or a name that escapes it", async () => {
    const { ops } = makeParkedOps();
    await expect(writeIntoHoldDir(ops, "relative/dir", "x.sh", "x", 0o755)).rejects.toThrow(ReleaseBarrierError);
    await expect(writeIntoHoldDir(ops, "/", "x.sh", "x", 0o755)).rejects.toThrow(ReleaseBarrierError);
  });

  // The contract the gate lenses said the old signature did not have: the
  // directory ensured and the directory written into are the same value. The
  // old shape took a full path and ensured `dirname(path)`, so "ensure one
  // directory, write into another" was expressible and untested. These assert
  // the property (where the bytes land), not that a guard function was called.
  it("D1: writeIntoHoldDir writes into EXACTLY the directory it ensured", async () => {
    const { ops, log } = makeParkedOps();
    await writeIntoHoldDir(ops, "/var/db/sanctuary/agent-harness", "503.release", "body", 0o644);
    expect(log.ensured).toEqual([
      { path: "/var/db/sanctuary/agent-harness", mode: AGENT_HARNESS_HOLD_DIR_MODE },
    ]);
    expect(log.writes).toEqual([{ path: "/var/db/sanctuary/agent-harness/503.release", mode: 0o644 }]);
  });

  it("D1: writeIntoHoldDir cannot be steered out of the ensured directory by the file name", async () => {
    const { ops, log } = makeParkedOps();
    for (const escape of ["../elsewhere.sh", "sub/dir.sh", "..", ".", "", "a\\b"]) {
      await expect(
        writeIntoHoldDir(ops, "/var/db/sanctuary/agent-harness", escape, "body", 0o644),
      ).rejects.toThrow(ReleaseBarrierError);
    }
    // Fail-closed: not one of them even reached the ensure, let alone a write.
    expect(log.ensured).toEqual([]);
    expect(log.writes).toEqual([]);
  });

  // ------------------------------------------------------------------
  // Drill D2 (2026-07-18): `launchctl disable` does not stop an already
  // running job, so every upgrade host (pre-Slice-5 KeepAlive harness)
  // tripped the post-install RUNNING assertion and aborted the arm.
  // ------------------------------------------------------------------

  it("D2: disables BEFORE booting out, so nothing can re-bootstrap under the stand-down", async () => {
    const { ops, log } = makeParkedOps();
    await executeParkedHarnessInstall(plan, ops);
    const disableAt = log.sequence.indexOf(`launchctl:disable system/${AGENT_HARNESS_DAEMON_LABEL}`);
    const bootoutAt = log.sequence.indexOf(`launchctl:bootout system/${AGENT_HARNESS_DAEMON_LABEL}`);
    expect(disableAt).toBeGreaterThanOrEqual(0);
    expect(bootoutAt).toBeGreaterThanOrEqual(0);
    expect(disableAt).toBeLessThan(bootoutAt);
    // ...and both strictly before the assertion that reads the result. NOTE
    // `lastIndexOf`: there is now also a READ-ONLY status probe in the
    // preconditions phase, before any mutation (see the F1 tests below).
    expect(bootoutAt).toBeLessThan(log.sequence.lastIndexOf("harnessStatus"));
  });

  it("D2: a bootout that actually stopped a live job is announced, never silent", async () => {
    const { ops, log } = makeParkedOps({ bootoutCode: 0 });
    await executeParkedHarnessInstall(plan, ops);
    expect(log.notices).toHaveLength(1);
    expect(log.notices[0]).toMatch(/bootout/);
    expect(log.notices[0]).toContain(AGENT_HARNESS_DAEMON_LABEL);
  });

  it("D2: treats 'no such process' / 'could not find' bootout failures as already-stopped", async () => {
    for (const stderr of [
      "Boot-out failed: 3: No such process",
      "Could not find service “ai.sanctuaryprotocol.agent-harness”",
      "Boot-out failed: 113: Could not find specified service",
    ]) {
      const { ops, log } = makeParkedOps({ bootoutCode: 3, bootoutStderr: stderr });
      await expect(executeParkedHarnessInstall(plan, ops)).resolves.toMatchObject({
        preexistingJobModified: false,
      });
      // Nothing was stopped, so nothing is announced.
      expect(log.notices).toEqual([]);
    }
  });

  // FIX-ROUND F4: on a clean host NOTHING is loaded, so every first-ever
  // install depends on the not-loaded tolerance matching. The branch had a
  // NARROWER list than `harness-daemon.ts`'s for the same label -- a miss is a
  // D1-shaped clean-host blocker inside the D1 fix. One shared predicate now;
  // these are the shapes the narrower list dropped.
  it("D2/F4: tolerates every not-loaded shape the sibling teardown tolerates (clean host must not refuse)", async () => {
    const cases: Array<{ code: number; stderr: string }> = [
      { code: 3, stderr: "" }, // standalone ESRCH, no phrase at all
      { code: 113, stderr: "" }, // standalone "could not find specified service"
      { code: 1, stderr: "service not loaded" },
      { code: 1, stderr: "Service is not loaded" },
      { code: 1, stderr: "No such service" },
      { code: 1, stderr: "does not exist" },
    ];
    for (const { code, stderr } of cases) {
      const { ops } = makeParkedOps({ bootoutCode: code, bootoutStderr: stderr });
      await expect(
        executeParkedHarnessInstall(plan, ops),
        `bootout exit ${code} / ${JSON.stringify(stderr)} must read as already-stopped`,
      ).resolves.toBeDefined();
    }
  });

  it("D2/F4: EINPROGRESS settles instead of throwing, and the job is proven stopped before the install claims parked", async () => {
    // launchctl accepted the stop but the job is still running down. The old
    // code matched no tolerance and threw AFTER the plist was overwritten.
    const { ops, log } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes"),
      bootoutCode: 36,
      bootoutStderr: "Boot-out failed: 36: Operation now in progress",
      statusSamples: [
        { known: true, installed: true, running: true }, // pre-install probe
        { known: true, installed: true, running: true }, // still dying
        { known: true, installed: true, running: true },
        { known: true, installed: false, running: false }, // settled
      ],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).resolves.toBeDefined();
    // It genuinely waited rather than accepting the first sample.
    expect(log.sequence.filter((s) => s === "harnessStatus").length).toBeGreaterThan(2);
  });

  it("D2/F4: a job that NEVER stops still refuses -- settling delays the refusal, it does not remove it", async () => {
    const { ops } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes"),
      bootoutCode: 36,
      bootoutStderr: "Boot-out failed: 36: Operation now in progress",
      statusSamples: [{ known: true, installed: true, running: true }],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/RUNNING/);
  });

  it("D2: refuses when bootout fails for any OTHER reason (never a park it could not assert)", async () => {
    const { ops, log } = makeParkedOps({ bootoutCode: 1, bootoutStderr: "Operation not permitted" });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/stand down/);
    // Fail-closed: the stale hold file removal and the parked-status claim
    // never ran. Exactly ONE status call happened -- the read-only precondition
    // probe; the post-stand-down assertion was never reached.
    expect(log.removed).not.toContain(plan.holdFilePath);
    expect(log.sequence.filter((s) => s === "harnessStatus")).toHaveLength(1);
    // FIX-ROUND 2: and the clean host is CLEAN again. This run created the
    // parked plist and the disable from nothing, so undoing means removing
    // both -- not leaving a disabled label and a barrier plist for the next
    // run to trip over.
    expect(log.files.has(plan.plistPath)).toBe(false);
    expect(log.jobDisabled).toBe(false);
  });

  it("D2: STILL refuses when the job reports running after a successful stand-down", async () => {
    // The pre-existing fail-closed assertion is the last line of defense and
    // must survive the stand-down being added in front of it.
    const { ops, log } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes"),
      bootoutCode: 0,
      running: true,
    });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/RUNNING/);
    expect(log.launchctl).toContainEqual(["bootout", `system/${AGENT_HARNESS_DAEMON_LABEL}`]);
  });

  // ------------------------------------------------------------------
  // FIX-ROUND after the two-family gate (2026-07-18). The stand-down above is
  // DESTRUCTIVE: it stops the operator's live agent. Everything here is about
  // the two remedies in preference order -- refuse before mutating, and make
  // what cannot be reordered reversible.
  // ------------------------------------------------------------------

  it("F1: every refusable precondition is checked BEFORE anything is written or stopped", async () => {
    // Unknown launchd state. The old code overwrote the singleton plist and
    // issued disable/bootout, and only then asked whether launchd was
    // trustworthy -- i.e. it destroyed state it could not reason about.
    const { ops, log } = makeParkedOps({ known: false });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/BEFORE the parked install/);
    // The property, not the guard: nothing on this host changed.
    expect(log.writes).toEqual([]);
    expect(log.launchctl).toEqual([]);
    expect(log.removed).toEqual([]);
    expect(log.ensured).toEqual([]);
  });

  it("F1: refuses to stand down a singleton job that belongs to a DIFFERENT service account, changing nothing", async () => {
    const { ops, log } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-someone-else"),
      statusSamples: [{ known: true, installed: true, running: true }],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/sanctuary-someone-else/);
    expect(log.writes).toEqual([]);
    expect(log.launchctl).toEqual([]);
  });

  it("F1: accepts a pre-existing job that IS this run's account and reports it as modified", async () => {
    const { ops } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes"),
      statusSamples: [
        { known: true, installed: true, running: true },
        { known: true, installed: false, running: false },
      ],
    });
    const snapshot = await executeParkedHarnessInstall(plan, ops);
    // The honest signal: this is what an abort path keys its restore on, and
    // it is exactly what `bootstrappedThisRun: false` could not express.
    expect(snapshot.preexistingJobModified).toBe(true);
    expect(snapshot.wasRunning).toBe(true);
    expect(snapshot.priorPlistContent).toBe(priorPlistFor("sanctuary-hermes"));
  });

  it("F3: refuses to boot out an agent already running released under a committed generation", async () => {
    // Re-running a failed install is normal operator behaviour. A second
    // --exclusive-egress run used to stop a LIVE CONFINED agent at step 6 of
    // 11, before the run was committed to anything.
    const { ops, log } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes", [plan.wrapperPath, plan.holdFilePath, "7", plan.harnessLabel]),
      statusSamples: [{ known: true, installed: true, running: true }],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/ALREADY running/);
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/--repair-egress-gate/);
    expect(log.writes).toEqual([]);
    expect(log.launchctl).toEqual([]);
  });

  it("F3: a fine-grained plist whose job is NOT running is a parked leftover, not a live agent -- the install proceeds", async () => {
    const { ops } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes", [plan.wrapperPath, plan.holdFilePath, "0", plan.harnessLabel]),
      statusSamples: [{ known: true, installed: true, running: false }],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).resolves.toBeDefined();
  });

  it("F1: the stand-down notice states the abort behaviour instead of promising a restart that may never happen", async () => {
    const { ops, log } = makeParkedOps({
      priorPlist: priorPlistFor("sanctuary-hermes"),
      statusSamples: [
        { known: true, installed: true, running: true },
        { known: true, installed: false, running: false },
      ],
    });
    await executeParkedHarnessInstall(plan, ops);
    expect(log.notices).toHaveLength(1);
    const notice = log.notices[0]!;
    // The old wording asserted the barrier "starts it after the gate
    // generation commits" -- a promise nothing retracted on the abort paths.
    expect(notice).not.toMatch(/the release barrier starts it after/i);
    expect(notice).toMatch(/unless the exclusive-egress gate commits/i);
    expect(notice).toMatch(/put back the way it was/i);
    // FIX-ROUND 2: and it no longer states the restore as a guarantee. The
    // restore can still fail; the notice names that instead of implying it
    // cannot happen.
    expect(notice).toMatch(/if that restore does not succeed this run says so/i);
  });

  // ------------------------------------------------------------------
  // FIX-ROUND 2 (2026-07-18). Both gate families, independently: a
  // post-mutation failure stood the agent down and never restored it, because
  // the snapshot was returned only on the SUCCESS path. The notice above
  // promises restoration; these assert the host actually gets it.
  //
  // EVERY ASSERTION HERE IS ABOUT OBSERVED STATE -- the plist bytes on disk,
  // the persistent disable, whether the job is up. Round 1 was well-tested and
  // still shipped this defect precisely because its assertions were about
  // which functions got called.
  // ------------------------------------------------------------------

  const upgradeHostPlist = priorPlistFor("sanctuary-hermes");

  /** The upgrade host the Mini1 drill hit: pre-S5 KeepAlive harness, running. */
  function upgradeHostThatNeverStops() {
    return makeParkedOps({
      priorPlist: upgradeHostPlist,
      bootoutCode: 0,
      // The exact Mini1 condition: a KeepAlive job that restarts (or does not
      // die within the settle bound), so the stopped-settle assertion throws
      // AFTER the plist has been overwritten and the disable set.
      statusSamples: [{ known: true, installed: true, running: true }],
    });
  }

  it("B1: a post-mutation failure leaves the plist BYTES and the enable-state exactly as they were", async () => {
    const { ops, log } = upgradeHostThatNeverStops();
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/RUNNING/);
    // The three things the operator would find on the host afterwards.
    expect(log.files.get(plan.plistPath)).toBe(upgradeHostPlist);
    expect(log.jobDisabled).toBe(false);
    expect(log.jobRunning).toBe(true);
  });

  it("B1: the thrown error states the OBSERVED restore, and still carries the original failure", async () => {
    const { ops } = upgradeHostThatNeverStops();
    const err = await executeParkedHarnessInstall(plan, ops).catch((e: unknown) => e as Error);
    // The original refusal is not swallowed by the recovery.
    expect(err.message).toMatch(/reports RUNNING after a parked install/);
    expect(err.message).toMatch(/put back/i);
    expect(err.message).toMatch(/running again/i);
    // ...and it does NOT claim the agent is stopped, because it is not.
    expect(err.message).not.toMatch(/is STOPPED/);
  });

  it("B1: EVERY post-mutation throw site reverts, not just the assertion the drill happened to hit", async () => {
    // A snapshot that only survives one code path is not a recovery mechanism.
    // Drive each distinct failure AFTER the first write and assert the host is
    // unchanged in all of them.
    const cases: Array<{ name: string; overrides: Parameters<typeof makeParkedOps>[0] }> = [
      { name: "disable non-zero", overrides: { disableCode: 5 } },
      {
        name: "bootout unrecognized failure",
        overrides: { bootoutCode: 1, bootoutStderr: "Operation not permitted" },
      },
      {
        name: "status unknown after the park",
        overrides: {
          statusSamples: [
            { known: true, installed: true, running: true },
            { known: false, installed: false, running: false },
          ],
        },
      },
      {
        name: "job still running after the park",
        overrides: { statusSamples: [{ known: true, installed: true, running: true }] },
      },
    ];
    for (const { name, overrides } of cases) {
      const { ops, log } = makeParkedOps({ priorPlist: upgradeHostPlist, ...overrides });
      await expect(executeParkedHarnessInstall(plan, ops), name).rejects.toThrow();
      expect(log.files.get(plan.plistPath), `${name}: prior plist bytes`).toBe(upgradeHostPlist);
      expect(log.jobDisabled, `${name}: persistent disable`).toBe(false);
    }
  });

  it("B1: when the revert CANNOT restart the agent, the error says the agent is STOPPED", async () => {
    // The failure mode that must never be dressed up as a success.
    const { ops, log } = makeParkedOps({
      priorPlist: upgradeHostPlist,
      statusSamples: [{ known: true, installed: true, running: true }],
      restoreRunningHarnessError: "launchctl bootstrap exited 5: Input/output error",
    });
    const err = await executeParkedHarnessInstall(plan, ops).catch((e: unknown) => e as Error);
    expect(err.message).toMatch(/could NOT be put back/);
    expect(err.message).toMatch(/is STOPPED/);
    expect(err.message).toMatch(/sanctuary protect --hermes/);
    expect(err.message).not.toMatch(/put back: its previous plist is restored/);
    // The plist still goes back even though the restart did not, so the
    // operator is not left holding a barrier plist they cannot start.
    expect(log.files.get(plan.plistPath)).toBe(upgradeHostPlist);
  });

  it("B1: a clean-host post-mutation failure removes what THIS run created, and says so without claiming a rescue", async () => {
    const { ops, log } = makeParkedOps({ disableCode: 5 });
    const err = await executeParkedHarnessInstall(plan, ops).catch((e: unknown) => e as Error);
    expect(err.message).toMatch(/Nothing that existed before this run was modified/);
    expect(err.message).not.toMatch(/is STOPPED/);
    expect(log.files.has(plan.plistPath)).toBe(false);
    expect(log.jobDisabled).toBe(false);
  });

  it("F5: refuses a RUNNING job with no plist to restore it from -- a stand-down we could not undo", async () => {
    // Codex lens: launchd knows a running job, but nothing is at the plist
    // path. We can stop it and have nothing to start it with. The only
    // one-way door in this function, closed where closing it is free.
    const { ops, log } = makeParkedOps({
      statusSamples: [{ known: true, installed: true, running: true }],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).rejects.toThrow(/could not undo|cannot undo/i);
    // Read-only refusal: the host is untouched.
    expect(log.writes).toEqual([]);
    expect(log.launchctl).toEqual([]);
    expect(log.ensured).toEqual([]);
    expect(log.jobRunning).toBe(true);
  });

  it("F5: a job that is INSTALLED but not running with no plist is fine -- there is nothing to strand", async () => {
    const { ops } = makeParkedOps({
      statusSamples: [
        { known: true, installed: true, running: false },
        { known: true, installed: false, running: false },
      ],
    });
    await expect(executeParkedHarnessInstall(plan, ops)).resolves.toMatchObject({
      preexistingJobModified: true,
      wasRunning: false,
    });
  });
});

describe("revertParkedHarnessInstall (drill-D2 fix-round: the stand-down is reversible)", () => {
  interface RevertLog {
    restarted: string[];
    disableCleared: number;
    writes: Array<{ path: string; content: string }>;
    removed: string[];
  }

  function makeRevertOps(overrides?: { restartError?: string; writeError?: string }): {
    ops: Parameters<typeof revertParkedHarnessInstall>[1];
    log: RevertLog;
  } {
    const log: RevertLog = { restarted: [], disableCleared: 0, writes: [], removed: [] };
    // Backed by a real map (fix-round 3, 2026-07-19): `plistRestored` is now
    // READ BACK from disk rather than inferred from `writeFile` resolving, so
    // ops that forget what they were told can no longer assert the claim.
    const disk = new Map<string, string>();
    return {
      log,
      ops: {
        async restoreRunningHarness(plistContent) {
          if (overrides?.restartError !== undefined) throw new Error(overrides.restartError);
          log.restarted.push(plistContent);
          disk.set(AGENT_HARNESS_DAEMON_PLIST_PATH, plistContent);
        },
        async clearJobDisable() {
          log.disableCleared += 1;
        },
        async writeFile(path, content) {
          if (overrides?.writeError !== undefined) throw new Error(overrides.writeError);
          log.writes.push({ path, content });
          disk.set(path, content);
        },
        async readFile(path) {
          return disk.get(path);
        },
        async removeFile(path) {
          log.removed.push(path);
          disk.delete(path);
        },
      },
    };
  }

  const PRIOR = priorPlistFor("sanctuary-hermes");
  const runningSnapshot = {
    priorPlistContent: PRIOR,
    wasInstalled: true,
    wasRunning: true,
    preexistingJobModified: true,
    plistPath: AGENT_HARNESS_DAEMON_PLIST_PATH,
    harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
  };

  // ROUND-3. `plistRestored` used to be set because `writeFile` resolved --
  // disclosed as an "honest bound", which both lenses said was the wrong
  // resolution for something the ops could simply read back. A resolved write
  // is not a read: a truncating writer, a full filesystem, or a path that is
  // not the file we think it is all resolve.
  it("R3: a write that RESOLVES but does not land reports plistRestored:false and restored:false", async () => {
    const log: RevertLog = { restarted: [], disableCleared: 0, writes: [], removed: [] };
    const ops = {
      async restoreRunningHarness() {
        throw new Error("launchctl bootstrap exited 5");
      },
      async clearJobDisable() {
        log.disableCleared += 1;
      },
      async writeFile(path: string, content: string) {
        // Resolves. Writes nothing.
        log.writes.push({ path, content });
      },
      async readFile() {
        return undefined;
      },
      async removeFile(path: string) {
        log.removed.push(path);
      },
    };
    const result = await revertParkedHarnessInstall(runningSnapshot, ops);
    expect(result.plistRestored).toBe(false);
    expect(result.restored).toBe(false);
    expect(result.errors.join(" ")).toMatch(/does not match what was there before this run/);
  });

  it("R3: a clean-host revert whose removal silently leaves the file reports plistRestored:false", async () => {
    const ops = {
      async restoreRunningHarness() {},
      async clearJobDisable() {},
      async writeFile() {},
      async readFile() {
        return "<plist><!-- STILL HERE --></plist>";
      },
      async removeFile() {},
    };
    const result = await revertParkedHarnessInstall(
      { ...runningSnapshot, preexistingJobModified: false, wasRunning: false },
      ops,
    );
    expect(result.nothingToRevert).toBe(true);
    expect(result.plistRestored).toBe(false);
    expect(result.restored).toBe(false);
    expect(result.errors.join(" ")).toMatch(/STILL PRESENT after removing it/);
  });

  it("restores the operator's ORIGINAL plist bytes and restarts the agent that was running", async () => {
    const { ops, log } = makeRevertOps();
    const result = await revertParkedHarnessInstall(runningSnapshot, ops);
    expect(result).toMatchObject({ harnessRestarted: true, plistRestored: true, errors: [] });
    // The bytes that were there, not a re-rendered approximation of them.
    expect(log.restarted).toEqual([PRIOR]);
  });

  it("puts the plist back even when the RESTART fails, and says so rather than reporting success", async () => {
    const { ops, log } = makeRevertOps({ restartError: "launchctl bootstrap exited 5" });
    const result = await revertParkedHarnessInstall(runningSnapshot, ops);
    expect(result.harnessRestarted).toBe(false);
    expect(result.plistRestored).toBe(true);
    expect(result.errors.join(" ")).toMatch(/could NOT be restarted/);
    expect(log.writes).toEqual([{ path: AGENT_HARNESS_DAEMON_PLIST_PATH, content: PRIOR }]);
    // The park's PERSISTENT launchd disable is cleared, or the operator's own
    // recovery re-run would bootstrap a disabled label and fail.
    expect(log.disableCleared).toBeGreaterThan(0);
  });

  it("restores a pre-existing but STOPPED job's plist without starting something that was not running", async () => {
    const { ops, log } = makeRevertOps();
    const result = await revertParkedHarnessInstall(
      { ...runningSnapshot, wasRunning: false },
      ops,
    );
    expect(result.harnessRestarted).toBe(false);
    expect(log.restarted).toEqual([]);
    expect(log.writes).toEqual([{ path: AGENT_HARNESS_DAEMON_PLIST_PATH, content: PRIOR }]);
    expect(log.disableCleared).toBe(1);
  });

  it("on a CLEAN host removes the parked plist this run created and clears its disable, leaving no residue", async () => {
    const { ops, log } = makeRevertOps();
    const result = await revertParkedHarnessInstall(
      {
        wasInstalled: false,
        wasRunning: false,
        preexistingJobModified: false,
        plistPath: AGENT_HARNESS_DAEMON_PLIST_PATH,
        harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
      },
      ops,
    );
    expect(result.nothingToRevert).toBe(true);
    expect(log.removed).toEqual([AGENT_HARNESS_DAEMON_PLIST_PATH]);
    expect(log.disableCleared).toBe(1);
    expect(log.restarted).toEqual([]);
  });

  it("NEVER throws: a revert runs on an already-failing path, so it reports problems instead of replacing the real error", async () => {
    const { ops } = makeRevertOps({ restartError: "boom", writeError: "EROFS" });
    const result = await revertParkedHarnessInstall(runningSnapshot, ops);
    expect(result.plistRestored).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(2);
  });

  // ------------------------------------------------------------------
  // FIX-ROUND 2 (2026-07-18) -- B2, found independently by both lenses. The
  // production caller derived `restored` from `errors.length === 0`, which is a
  // statement about how QUIETLY the revert failed. `restored` is now derived
  // here, from observed state, and these are the two cases that separate the
  // two definitions.
  // ------------------------------------------------------------------

  it("B2: a job that was running and could NOT be restarted is NOT restored, however cleanly the plist went back", async () => {
    const { ops, log } = makeRevertOps({ restartError: "launchctl bootstrap exited 5" });
    const result = await revertParkedHarnessInstall(runningSnapshot, ops);
    // The plist genuinely IS back; that was never the question.
    expect(result.plistRestored).toBe(true);
    expect(log.writes).toEqual([{ path: AGENT_HARNESS_DAEMON_PLIST_PATH, content: PRIOR }]);
    // The verdict is about the AGENT, and the agent is down.
    expect(result.harnessRestarted).toBe(false);
    expect(result.wasRunning).toBe(true);
    expect(result.restored).toBe(false);
  });

  it("B2: a running job with NO captured prior plist reports a FAILED restore -- the exact silent case", async () => {
    // Both lenses constructed this: `wasRunning: true` with
    // `priorPlistContent: undefined` skips the restart branch rather than
    // failing it, so NOTHING throws and the error list stays empty. Under the
    // old rule that read as a successful restore while the operator's agent
    // sat stopped. (The install now refuses this host before mutating; the
    // revert must still be truthful about it -- defence in depth.)
    const { ops } = makeRevertOps();
    const result = await revertParkedHarnessInstall(
      { ...runningSnapshot, priorPlistContent: undefined },
      ops,
    );
    expect(result.harnessRestarted).toBe(false);
    expect(result.plistRestored).toBe(true);
    expect(result.restored).toBe(false);
    // Silence is not evidence: the absence of a complaint became a complaint.
    expect(result.errors.join(" ")).toMatch(/is STOPPED now/);
    expect(result.errors.join(" ")).toMatch(/no captured prior plist/);
  });

  it("B2: the restores that genuinely succeeded still report restored:true", async () => {
    const { ops } = makeRevertOps();
    // Was running, restart verified.
    await expect(revertParkedHarnessInstall(runningSnapshot, ops)).resolves.toMatchObject({
      restored: true,
      harnessRestarted: true,
      wasRunning: true,
    });
    // Was NOT running: correctly not restarted, and correctly restored.
    await expect(
      revertParkedHarnessInstall({ ...runningSnapshot, wasRunning: false }, ops),
    ).resolves.toMatchObject({ restored: true, harnessRestarted: false, wasRunning: false });
    // Clean host: nothing pre-existing to put back.
    await expect(
      revertParkedHarnessInstall(
        {
          wasInstalled: false,
          wasRunning: false,
          preexistingJobModified: false,
          plistPath: AGENT_HARNESS_DAEMON_PLIST_PATH,
          harnessLabel: AGENT_HARNESS_DAEMON_LABEL,
        },
        ops,
      ),
    ).resolves.toMatchObject({ restored: true, nothingToRevert: true });
  });
});

/**
 * Drill D1, REAL FILESYSTEM. The unit suite above proves the ops contract; it
 * would still have passed with a mocked `mkdir` that never ran. This exercises
 * the production ensure (`ensureAgentHarnessHoldDir`) against real `fs` with a
 * hold directory that DOES NOT EXIST -- the exact clean-host condition the
 * drill hit -- and asserts the wrapper file is on disk with the right mode
 * afterwards. Never touches /var/db; the hold dir is redirected into a tmpdir.
 *
 * `chown(0, 0)` is root-only, so the real ensure is used verbatim when the
 * suite runs as root and with the chown step relaxed otherwise; the mkdir +
 * explicit-chmod behavior under test is identical either way.
 */
describe("parked install against a REAL, NON-EXISTENT hold directory (drill D1)", () => {
  const runningAsRoot = typeof process.getuid === "function" && process.getuid() === 0;

  it("creates the missing hold directory and lands the wrapper 0755 inside it", async () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), "s5-d1-holddir-"));
    try {
      // Deliberately NOT created: this is the clean-host state. Asserted by
      // statSync THROWING rather than by an existsSync probe -- a
      // check-then-use pair over a path we later write is the file-system
      // race shape (CodeQL js/file-system-race), even inside a private tmpdir.
      const holdDir = join(tmpRoot, "var", "db", "sanctuary", "agent-harness");
      expect(() => statSync(holdDir)).toThrow(/ENOENT/);

      const realPlan = planParkedHarnessInstall({
        agentAccount: "sanctuary-hermes",
        agentUid: 503,
        harnessArgv: ["/usr/local/bin/node", "/opt/harness.js"],
        holdDir,
      });
      expect(realPlan.wrapperPath).toBe(join(holdDir, "release-exec-wrapper.sh"));

      const plistPath = join(tmpRoot, "agent-harness.plist");
      const launchctl: string[][] = [];
      await executeParkedHarnessInstall(
        { ...realPlan, plistPath },
        {
          ensureHoldDir: runningAsRoot
            ? ensureAgentHarnessHoldDir
            : async (path, mode) => {
                // Same shape as the production ensure minus the root-only
                // chown: mkdir -p (mode omitted, umask-masked) + EXPLICIT chmod.
                // The chown and the symlink refusal ARE covered, against the
                // production policy function, in the `applyRootOwnedDirEnsure`
                // suite in arming-wiring.test.ts -- this branch used to be the
                // only coverage, which meant deleting the production chown
                // changed no test.
                await mkdir(path, { recursive: true });
                await chmod(path, mode);
              },
          async readFile() {
            return undefined; // clean host: no pre-existing plist
          },
          async writeFile(path, content, mode) {
            await fsWriteFile(path, content, { mode });
            await chmod(path, mode);
          },
          async removeFile(path) {
            await rm(path, { force: true });
          },
          async runLaunchctl(args) {
            launchctl.push([...args]);
            return { code: 0, stdout: "", stderr: "" };
          },
          async harnessStatus() {
            return { known: true, installed: true, running: false };
          },
          notify() {
            /* captured by the unit suite; irrelevant here */
          },
        },
      );

      // The directory the drill found missing now exists, root-owned-shaped 0755.
      const holdDirStat = statSync(holdDir);
      expect(holdDirStat.isDirectory()).toBe(true);
      expect(holdDirStat.mode & 0o777).toBe(AGENT_HARNESS_HOLD_DIR_MODE);
      // ...and the wrapper is genuinely on disk inside it, executable. Mode
      // and content are read through ONE file descriptor (open -> fstat ->
      // read), so there is no path-resolved-twice window at all: separate
      // `statSync(p)` + `readFileSync(p)` calls are the check-then-use shape
      // CodeQL flags as js/file-system-race, and a single handle is the real
      // fix rather than a suppression. `openSync` throws if the install never
      // landed the wrapper, which is precisely the D1 failure mode.
      const wrapperFd = openSync(realPlan.wrapperPath, "r");
      try {
        const wrapperStat = fstatSync(wrapperFd);
        expect(wrapperStat.isFile()).toBe(true);
        expect(wrapperStat.mode & 0o777).toBe(0o755);
        expect(readFileSync(wrapperFd, "utf8")).toBe(RELEASE_EXEC_WRAPPER_SCRIPT);
      } finally {
        closeSync(wrapperFd);
      }
      expect(launchctl.map((a) => a[0])).toEqual(["disable", "bootout"]);
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
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
