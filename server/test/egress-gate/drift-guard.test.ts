/**
 * Tests for the transient-pf-rule drift guard (Unified Protect Slice 5 S5-6,
 * design MED-7): the diff of the RUNNING pf main ruleset against the
 * base-config-derived ruleset that the `--repair-egress-gate` verb consults
 * BEFORE any hook install. Every branch is driven through a mocked
 * PfCommandRunner + a temp base config; fail-closed = any pfctl or
 * filesystem failure THROWS (the repair caller refuses, never proceeds
 * blind).
 */

import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { diffTransientPfRules } from "../../src/egress-gate/drift-guard.js";
import { PF_ANCHOR_NAME, type PfCommandRunner } from "../../src/egress-gate/pf-anchor.js";

const EXPECTED_RULES = [
  "scrub-anchor \"com.apple/*\" all fragment reassemble",
  "nat-anchor \"com.apple/*\" all",
  "rdr-anchor \"com.apple/*\" all",
  "anchor \"com.apple/*\" all",
  "dummynet-anchor \"com.apple/*\" all",
];

const STOCK_MACOS_RUNNING_RULES = [
  "scrub-anchor \"com.apple/*\" all fragment reassemble",
  "nat-anchor \"com.apple/*\" all",
  "rdr-anchor \"com.apple/*\" all",
  "anchor \"com.apple/*\" all",
  "dummynet-anchor \"com.apple/*\" all",
];

const STOCK_MACOS_BASE_DERIVED_RULES = [
  "scrub-anchor \"/*\" all fragment reassemble",
  "nat-anchor \"/*\" all",
  "rdr-anchor \"/*\" all",
  "anchor \"/*\" all",
  "dummynet-anchor \"/*\" all",
  "anchor \"/*\" all",
  "anchor \"/*\" all",
];

const STOCK_MACOS_BASE_CONFIG = [
  'scrub-anchor "com.apple/*" all fragment reassemble',
  'nat-anchor "com.apple/*" all',
  'rdr-anchor "com.apple/*" all',
  'anchor "com.apple/*" all',
  'dummynet-anchor "com.apple/*" all',
  'load anchor "com.apple" from "/etc/pf.anchors/com.apple"',
  "",
].join("\n");

/** A runner whose -sr and -n -v -f outputs are scripted per test. */
function scriptedRunner(script: {
  runningRules?: string[];
  runningCode?: number;
  parseRules?: string[];
  parseCode?: number;
  parseStderr?: string;
}): PfCommandRunner & { calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    async run(command: string, args: readonly string[]) {
      calls.push([command, ...args]);
      if (args[0] === "-sr") {
        return {
          code: script.runningCode ?? 0,
          stdout: `${(script.runningRules ?? EXPECTED_RULES).join("\n")}\n`,
          stderr: script.runningCode !== undefined && script.runningCode !== 0 ? "pfctl: /dev/pf: Permission denied" : "",
        };
      }
      // The -n -v -f normalization pass.
      return {
        code: script.parseCode ?? 0,
        stdout: `${(script.parseRules ?? EXPECTED_RULES).join("\n")}\n`,
        stderr:
          script.parseStderr ??
          (script.parseCode !== undefined && script.parseCode !== 0 ? "pfctl: syntax error" : ""),
      };
    },
  };
}

describe("egress-gate/drift-guard diffTransientPfRules", () => {
  let dir: string;
  let mainConfPath: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "sanctuary-drift-guard-test-"));
    mainConfPath = join(dir, "pf.conf");
    await writeFile(mainConfPath, "# base config\nscrub-anchor \"com.apple/*\" all fragment reassemble\n");
  });

  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("clean ruleset: every running rule derivable from the base config -> no foreign rules", async () => {
    const runner = scriptedRunner({});
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([]);
    expect(diff.runningCount).toBe(EXPECTED_RULES.length);
    expect(diff.expectedCount).toBeGreaterThan(0);
  });

  it("MED-7: a transient third-party rule (VPN shape) in the running ruleset is reported FOREIGN", async () => {
    const vpnRule = "pass in quick on utun3 all flags S/SA keep state";
    const runner = scriptedRunner({ runningRules: [...EXPECTED_RULES, vpnRule] });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([vpnRule]);
  });

  it("the Sanctuary anchor-call rule is NEVER counted foreign (it is ours, whether or not the base config carries it)", async () => {
    const anchorCall = `anchor "${PF_ANCHOR_NAME}" on lo0 all`;
    const runner = scriptedRunner({ runningRules: [...EXPECTED_RULES, anchorCall] });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([]);
  });

  it("whitespace differences never manufacture a foreign rule (normalized set compare)", async () => {
    const runner = scriptedRunner({
      runningRules: ["  anchor   \"com.apple/*\"   all  "],
      parseRules: ["anchor \"com.apple/*\" all"],
    });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([]);
  });

  it("D5: stock macOS anchors compare equal against the real seven stripped-anchor lines", async () => {
    await writeFile(mainConfPath, STOCK_MACOS_BASE_CONFIG);
    const runner = scriptedRunner({
      runningRules: STOCK_MACOS_RUNNING_RULES,
      parseRules: STOCK_MACOS_BASE_DERIVED_RULES,
    });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([]);
    expect(diff.expectedCount).toBe(STOCK_MACOS_RUNNING_RULES.length);
    expect(diff.runningCount).toBe(STOCK_MACOS_RUNNING_RULES.length);
  });

  it("L1: expectedCount ignores pfctl normalization warnings written to stderr", async () => {
    await writeFile(mainConfPath, STOCK_MACOS_BASE_CONFIG);
    const runner = scriptedRunner({
      runningRules: STOCK_MACOS_RUNNING_RULES,
      parseRules: STOCK_MACOS_BASE_DERIVED_RULES,
      parseStderr: [
        "pfctl: Use of -f option, could result in flushing of rules",
        "present in the main ruleset",
        "pfctl: load anchors",
      ].join("\n"),
    });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([]);
    expect(diff.expectedCount).toBe(STOCK_MACOS_RUNNING_RULES.length);
    expect(diff.runningCount).toBe(STOCK_MACOS_RUNNING_RULES.length);
  });

  it("D5: a genuinely foreign transient anchor still refuses under the stock-anchor normalization", async () => {
    await writeFile(mainConfPath, STOCK_MACOS_BASE_CONFIG);
    const vpnRule = 'anchor "com.corp.vpn/*" on en0 all';
    const runner = scriptedRunner({
      runningRules: [...STOCK_MACOS_RUNNING_RULES, vpnRule],
      parseRules: STOCK_MACOS_BASE_DERIVED_RULES,
    });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([vpnRule]);
  });

  it('M1: a literal running anchor "/*" line remains the observed foreign rule', async () => {
    await writeFile(mainConfPath, STOCK_MACOS_BASE_CONFIG);
    const runningRule = 'anchor "/*" all';
    const runner = scriptedRunner({
      runningRules: [runningRule],
      parseRules: STOCK_MACOS_BASE_DERIVED_RULES,
    });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([runningRule]);
    expect(diff.runningCount).toBe(1);
  });

  it("M1: expected-side stripped-anchor expansion does not launder a new running suffix", async () => {
    await writeFile(mainConfPath, 'anchor "com.apple/*"\nanchor "com.corp.vpn/*" on en0\n');
    const runningRule = 'anchor "com.apple/*" on en0 all';
    const runner = scriptedRunner({
      runningRules: [runningRule],
      parseRules: ['anchor "/*" all', 'anchor "/*" on en0 all'],
    });
    const diff = await diffTransientPfRules(runner, { mainConfPath });
    expect(diff.foreign).toEqual([runningRule]);
  });

  it("fail-closed: pfctl -sr failure THROWS (never diff blind)", async () => {
    const runner = scriptedRunner({ runningCode: 1 });
    await expect(diffTransientPfRules(runner, { mainConfPath })).rejects.toThrow(/pfctl -sr exited 1/);
  });

  it("fail-closed: the expected-ruleset normalization (pfctl -n -v -f) failure THROWS", async () => {
    const runner = scriptedRunner({ parseCode: 1 });
    await expect(diffTransientPfRules(runner, { mainConfPath })).rejects.toThrow(
      /expected-ruleset normalization.*exited 1/,
    );
  });

  it("fail-closed: an unreadable base pf config THROWS (never assume an empty expected set)", async () => {
    const runner = scriptedRunner({});
    await expect(
      diffTransientPfRules(runner, { mainConfPath: join(dir, "does-not-exist.conf") }),
    ).rejects.toThrow(/cannot read base pf config/);
  });
});
