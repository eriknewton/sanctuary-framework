/**
 * Tests for the per-uid pf loopback anchor (Unified Protect Slice 3):
 * render shape (drill-parity), the MANDATORY fail-closed liveness check
 * (including the loaded-but-unhooked blind spot: rules in a named anchor
 * enforce nothing until the MAIN ruleset calls the anchor), arm semantics
 * (main-ruleset hook install, settle-probe, rollback on settle failure),
 * and disarm symmetry. All pfctl interaction is through a scripted mock
 * runner; no test touches a real pf.
 */

import { describe, it, expect } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  PF_ANCHOR_NAME,
  renderPfAnchorRules,
  renderPfMainRulesetHook,
  checkPfAnchorLiveness,
  findPreemptingQuickPassRules,
  findLoopbackSkipLines,
  armPfAnchor,
  disarmPfAnchor,
  type PfCommandResult,
  type PfCommandRunner,
} from "../../src/egress-gate/pf-anchor.js";

const POLICY = { agent_uid: 502, gate_port: 19998 };

const PASS_RULE =
  "pass quick on lo0 inet proto tcp from any to 127.0.0.1 port = 19998 user = 502 flags S/SA keep state";

/** pfctl's canonical print of the loaded anchor (collapsed `all` spelling). */
const CANONICAL_ANCHOR_PRINT = [
  PASS_RULE,
  "block drop quick on lo0 inet proto tcp all user = 502",
  "block drop quick on lo0 inet proto udp all user = 502",
  "block drop quick on lo0 inet6 proto tcp all user = 502",
  "block drop quick on lo0 inet6 proto udp all user = 502",
].join("\n");

const PF_INFO_ENABLED = "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n";
const PF_INFO_DISABLED = "Status: Disabled                              Debug: Urgent\n";

/** Main ruleset WITH the Sanctuary anchor call rule hooked in (pfctl print). */
const MAIN_RULESET_HOOKED = [
  'anchor "com.apple/*" all',
  `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
  "",
].join("\n");

/** Stock main ruleset: com.apple anchors only, Sanctuary anchor NOT called. */
const MAIN_RULESET_UNHOOKED = 'anchor "com.apple/*" all\n';

/** `pfctl -v -s Interfaces` with NO skip flag on loopback (healthy). */
const PF_IFACES_CLEAN = ["all", "en0", "lo0", "utun0", ""].join("\n");
/** Loopback interface flagged skip (`set skip on lo0`): pf never filters lo0. */
const PF_IFACES_LO0_SKIP = ["all", "en0", "lo0 (skip)", "utun0", ""].join("\n");
/** The `lo` interface GROUP flagged skip (`set skip on lo`): same void. */
const PF_IFACES_LO_GROUP_SKIP = ["all", "en0", "lo (skip)", "lo0", "utun0", ""].join("\n");

interface ScriptedCall {
  match: (command: string, args: readonly string[]) => boolean;
  result: PfCommandResult;
}

function scriptedRunner(script: ScriptedCall[]): PfCommandRunner & { calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    async run(command: string, args: readonly string[]): Promise<PfCommandResult> {
      calls.push([command, ...args]);
      for (const entry of script) {
        if (entry.match(command, args)) return entry.result;
      }
      return { code: 1, stdout: "", stderr: `unscripted: ${command} ${args.join(" ")}` };
    },
  };
}

const ok = (stdout: string): PfCommandResult => ({ code: 0, stdout, stderr: "" });

const infoCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a[0] === "-s" && a[1] === "info",
  result,
});
const rulesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a[0] === "-a" && a[2] === "-sr",
  result,
});
/** Bare `pfctl -sr`: the MAIN ruleset (anchor-call-rule probe). */
const mainRulesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a.length === 1 && a[0] === "-sr",
  result,
});
/** `pfctl -v -s Interfaces`: the loopback skip-flag probe. */
const ifacesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a[0] === "-v" && a[1] === "-s" && a[2] === "Interfaces",
  result,
});

describe("egress-gate/pf-anchor", () => {
  describe("renderPfAnchorRules (single source)", () => {
    it("renders the drill-proven pass rule plus block-drop coverage for tcp+udp v4+v6", () => {
      const text = renderPfAnchorRules(POLICY);
      expect(text).toContain(PASS_RULE);
      expect(text).toContain("block drop quick on lo0 inet proto tcp from any to any user = 502");
      expect(text).toContain("block drop quick on lo0 inet proto udp from any to any user = 502");
      expect(text).toContain("block drop quick on lo0 inet6 proto tcp from any to any user = 502");
      expect(text).toContain("block drop quick on lo0 inet6 proto udp from any to any user = 502");
      // The pass rule must come FIRST: quick rules are first-match-wins.
      expect(text.indexOf("pass quick")).toBeLessThan(text.indexOf("block drop"));
    });

    it("throws on a malformed policy (never a permissive-by-accident anchor)", () => {
      expect(() => renderPfAnchorRules({ agent_uid: 0, gate_port: 19998 })).toThrow(
        /malformed exclusive-egress gate policy/,
      );
    });
  });

  describe("renderPfMainRulesetHook (the anchor call that makes rules enforced)", () => {
    it("renders the drill-proven call + load lines", () => {
      const hook = renderPfMainRulesetHook(PF_ANCHOR_NAME, "/tmp/x/egress-gate.rules");
      expect(hook).toContain(`anchor "${PF_ANCHOR_NAME}" on lo0`);
      expect(hook).toContain(`load anchor "${PF_ANCHOR_NAME}" from "/tmp/x/egress-gate.rules"`);
    });

    it("refuses a rules-file path that would escape the quoted conf token", () => {
      expect(() => renderPfMainRulesetHook(PF_ANCHOR_NAME, '/tmp/evil" pass all #')).toThrow(
        /quote or newline/,
      );
    });

    it("refuses an anchor name outside the conservative charset", () => {
      expect(() => renderPfMainRulesetHook('bad"name', "/tmp/x.rules")).toThrow(/anchor name/);
    });
  });

  describe("checkPfAnchorLiveness (fail-closed, positive evidence only)", () => {
    it("is live when pf is enabled, the anchor prints all expected rules, the main ruleset calls the anchor, AND loopback is not skipped", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result).toEqual({ live: true, reasons: [] });
    });

    it("accepts the uncollapsed 'from any to any' block spelling too", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(renderPfAnchorRules(POLICY))),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(true);
    });

    it("accepts the anchor call rule without pfctl's trailing 'all'", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(`anchor "${PF_ANCHOR_NAME}" on lo0\n`)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(true);
    });

    it("is NOT live when the anchor is loaded and pf is enabled but the MAIN ruleset never calls the anchor (loaded-but-unhooked = enforcing nothing)", async () => {
      // The green-when-dead blind spot: `pfctl -a <name> -sr` prints a
      // loaded anchor's rules whether or not any call rule transfers
      // evaluation into it, and `pfctl -s info` is Enabled regardless.
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_UNHOOKED)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/main ruleset is missing the anchor call rule/);
    });

    it("is NOT live when pf skips filtering on lo0 ('set skip on lo0': hooked but SKIPPED = enforcing nothing)", async () => {
      // The hooked-but-skipped blind spot: all three earlier probes pass
      // (pf Enabled, anchor rules print, call rule prints) while pf never
      // evaluates a single lo0 packet.
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_LO0_SKIP)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/hooked but SKIPPED/);
    });

    it("is NOT live when the 'lo' interface GROUP is skipped ('set skip on lo')", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_LO_GROUP_SKIP)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/hooked but SKIPPED/);
    });

    it("is NOT live when the interfaces probe itself fails (fail-closed)", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall({ code: 1, stdout: "", stderr: "pfctl: /dev/pf: Permission denied" }),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toContain("pfctl -v -s Interfaces exited 1");
    });

    it("is NOT live when an earlier 'pass quick on lo0' rule preempts the anchor call (hooked but PREEMPTED)", async () => {
      // pf quick semantics: a matching earlier quick pass terminates
      // evaluation before the (last-position, non-quick) anchor call rule.
      const preempted = [
        'anchor "com.apple/*" all',
        "pass in quick on lo0 all flags any keep state",
        `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
        "",
      ].join("\n");
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(preempted)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/hooked but PREEMPTED/);
    });

    it("is NOT live when an earlier interface-less 'pass quick' rule preempts (matches every interface incl lo0)", async () => {
      const preempted = [
        "pass quick all flags S/SA keep state",
        `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
        "",
      ].join("\n");
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(preempted)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/hooked but PREEMPTED/);
    });

    it("stays live when earlier quick pass rules are positively bound off-loopback or explicitly exclude it", async () => {
      const benign = [
        "pass in quick on en0 all flags S/SA keep state",
        "pass out quick on ! lo0 inet all",
        `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
        "",
      ].join("\n");
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(benign)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result).toEqual({ live: true, reasons: [] });
    });

    it("stays live when a quick pass rule appears AFTER the anchor call (cannot preempt: the anchor's quick rules match first)", async () => {
      const afterCall = [
        `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
        "pass in quick on lo0 all",
        "",
      ].join("\n");
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(afterCall)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result).toEqual({ live: true, reasons: [] });
    });

    it("is NOT live when the main-ruleset probe itself fails (fail-closed)", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall({ code: 1, stdout: "", stderr: "pfctl: /dev/pf: Permission denied" }),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toContain("pfctl -sr exited 1");
    });

    it("is NOT live when pf is disabled", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_DISABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/not enabled/);
    });

    it("is NOT live when the anchor is empty (silently-unloaded anchor)", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok("")),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.some((r) => r.includes("pass rule"))).toBe(true);
    });

    it("is NOT live when the pass rule targets a different port", async () => {
      const wrongPort = CANONICAL_ANCHOR_PRINT.replace("port = 19998", "port = 19999");
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(wrongPort)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
    });

    it("is NOT live when a block rule is missing (partial anchor)", async () => {
      const partial = [PASS_RULE, "block drop quick on lo0 inet proto tcp all user = 502"].join("\n");
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(partial)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.some((r) => r.includes("udp"))).toBe(true);
    });

    it("is NOT live when pfctl exits non-zero (fail-closed on error)", async () => {
      const runner = scriptedRunner([
        infoCall({ code: 1, stdout: "", stderr: "pfctl: /dev/pf: Permission denied" }),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
    });

    it("is NOT live when the runner throws (fail-closed on spawn failure)", async () => {
      const runner: PfCommandRunner = {
        run: () => Promise.reject(new Error("spawn pfctl ENOENT")),
      };
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toContain("ENOENT");
    });

    it("is NOT live for a malformed policy", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
      ]);
      const result = await checkPfAnchorLiveness(runner, { agent_uid: -1, gate_port: 19998 });
      expect(result.live).toBe(false);
    });
  });

  describe("findLoopbackSkipLines (arm-time base-config guard)", () => {
    it("detects the bare, braced-list, and group spellings", () => {
      expect(findLoopbackSkipLines("set skip on lo0\n")).toEqual(["set skip on lo0"]);
      expect(findLoopbackSkipLines("set skip on { lo0 en0 }\n")).toHaveLength(1);
      expect(findLoopbackSkipLines("set skip on { lo0, en0 }\n")).toHaveLength(1);
      expect(findLoopbackSkipLines("  set skip on lo\n")).toHaveLength(1);
    });

    it("ignores non-loopback skips, comments, and lookalike interface names", () => {
      expect(findLoopbackSkipLines("set skip on en0\n")).toEqual([]);
      expect(findLoopbackSkipLines("# set skip on lo0\n")).toEqual([]);
      expect(findLoopbackSkipLines("set skip on lo1\n")).toEqual([]);
      expect(findLoopbackSkipLines('anchor "com.apple/*"\npass in all\n')).toEqual([]);
    });
  });

  describe("findPreemptingQuickPassRules (main-ruleset preemption scan)", () => {
    it("flags only quick PASS rules before the anchor call that can match lo0", () => {
      const text = [
        "block drop quick on lo0 all",
        "pass in on lo0 all",
        "pass in quick on en1 all",
        "pass out quick inet proto tcp all",
        `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
        "pass in quick on lo0 all",
        "",
      ].join("\n");
      // block quick: not a pass; non-quick pass: last-match loses to the
      // anchor's quick rules; en1-bound quick pass: cannot match lo0;
      // post-call quick pass: never reached first. Only the interface-less
      // quick pass preempts.
      expect(findPreemptingQuickPassRules(text)).toEqual([
        "pass out quick inet proto tcp all",
      ]);
    });
  });

  describe("armPfAnchor (settle-probe before 'armed')", () => {
    const loadCall: ScriptedCall = {
      match: (_c, a) => a[0] === "-a" && a[2] === "-f",
      result: ok(""),
    };
    const enableCall: ScriptedCall = {
      match: (_c, a) => a[0] === "-E",
      result: { code: 0, stdout: "", stderr: "pf enabled\nToken : 4204204242\n" },
    };

    it("loads, enables, captures the token, and settles on consecutive liveness (hook already present: main ruleset NOT reloaded)", async () => {
      const runner = scriptedRunner([
        loadCall,
        enableCall,
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const result = await armPfAnchor(runner, POLICY, {
        settleDelayMs: 1,
        sleep: () => Promise.resolve(),
      });
      expect(result.enableToken).toBe("4204204242");
      expect(result.settleProbes).toBeGreaterThanOrEqual(2);
      const loaded = runner.calls.find((c) => c[1] === "-a" && c[3] === "-f");
      expect(loaded?.[2]).toBe(PF_ANCHOR_NAME);
      // Idempotence: the call rule was already in the main ruleset, so no
      // bare `pfctl -f <mainfile>` reload happened.
      expect(runner.calls.some((c) => c[1] === "-f")).toBe(false);
    });

    it("installs the main-ruleset hook when the call rule is absent (preserving the base config)", async () => {
      const fixtureDir = await mkdtemp(join(tmpdir(), "sanctuary-pf-test-"));
      const baseConfPath = join(fixtureDir, "pf.conf");
      const baseConf = 'anchor "com.apple/*"\nload anchor "com.apple" from "/etc/pf.anchors/com.apple"\n';
      await writeFile(baseConfPath, baseConf, "utf8");
      try {
        let hooked = false;
        let composed = "";
        const calls: string[][] = [];
        const runner: PfCommandRunner = {
          async run(command, args): Promise<PfCommandResult> {
            calls.push([command, ...args]);
            if (args[0] === "-a" && args[2] === "-f") return ok("");
            if (args.length === 1 && args[0] === "-sr") {
              return ok(hooked ? MAIN_RULESET_HOOKED : MAIN_RULESET_UNHOOKED);
            }
            if (args[0] === "-f") {
              // The composed main ruleset: capture it at load time (the
              // temp file is removed after arm returns).
              composed = readFileSync(args[1]!, "utf8");
              hooked = true;
              return ok("");
            }
            if (args[0] === "-E") {
              return { code: 0, stdout: "", stderr: "pf enabled\nToken : 4204204242\n" };
            }
            if (args[0] === "-s" && args[1] === "info") return ok(PF_INFO_ENABLED);
            if (args[0] === "-a" && args[2] === "-sr") return ok(CANONICAL_ANCHOR_PRINT);
            if (args[0] === "-v" && args[1] === "-s" && args[2] === "Interfaces") {
              return ok(PF_IFACES_CLEAN);
            }
            return { code: 1, stdout: "", stderr: `unscripted: ${command} ${args.join(" ")}` };
          },
        };
        const result = await armPfAnchor(runner, POLICY, {
          mainConfPath: baseConfPath,
          settleDelayMs: 1,
          sleep: () => Promise.resolve(),
        });
        expect(result.enableToken).toBe("4204204242");
        // The composed main ruleset preserves the operator's base config...
        expect(composed).toContain('anchor "com.apple/*"');
        expect(composed).toContain('load anchor "com.apple" from "/etc/pf.anchors/com.apple"');
        // ...and appends the drill-proven hook (call rule + load anchor).
        expect(composed).toContain(`anchor "${PF_ANCHOR_NAME}" on lo0`);
        expect(composed).toMatch(new RegExp(`load anchor "${PF_ANCHOR_NAME}" from ".+"`));
      } finally {
        await rm(fixtureDir, { recursive: true, force: true });
      }
    });

    it("refuses to hook through a base pf config that skips loopback ('set skip on lo0' would void the anchor)", async () => {
      const fixtureDir = await mkdtemp(join(tmpdir(), "sanctuary-pf-test-"));
      const baseConfPath = join(fixtureDir, "pf.conf");
      await writeFile(
        baseConfPath,
        'set skip on lo0\nanchor "com.apple/*"\n',
        "utf8",
      );
      try {
        const runner = scriptedRunner([
          loadCall,
          mainRulesCall(ok(MAIN_RULESET_UNHOOKED)),
          { match: (_c, a) => a[0] === "-a" && a[2] === "-F", result: ok("") },
        ]);
        await expect(
          armPfAnchor(runner, POLICY, {
            mainConfPath: baseConfPath,
            settleDelayMs: 1,
            sleep: () => Promise.resolve(),
          }),
        ).rejects.toThrow(/skip filtering on\s+loopback/);
        // pf was never enabled; the half-armed anchor was flushed (rollback).
        expect(runner.calls.some((c) => c[1] === "-E")).toBe(false);
        expect(runner.calls.some((c) => c[1] === "-f" && c[0] === "pfctl" && c.length === 3)).toBe(false);
        expect(runner.calls.some((c) => c[1] === "-a" && c[3] === "-F")).toBe(true);
      } finally {
        await rm(fixtureDir, { recursive: true, force: true });
      }
    });

    it("aborts (with rollback) when the hook is needed but the base pf config is unreadable (never hook blind)", async () => {
      const runner = scriptedRunner([
        loadCall,
        mainRulesCall(ok(MAIN_RULESET_UNHOOKED)),
        { match: (_c, a) => a[0] === "-a" && a[2] === "-F", result: ok("") },
      ]);
      await expect(
        armPfAnchor(runner, POLICY, {
          mainConfPath: "/nonexistent/sanctuary-test/pf.conf",
          settleDelayMs: 1,
          sleep: () => Promise.resolve(),
        }),
      ).rejects.toThrow(/cannot read base pf config/);
      // pf was never enabled; the half-armed anchor was flushed.
      expect(runner.calls.some((c) => c[1] === "-E")).toBe(false);
      expect(runner.calls.some((c) => c[1] === "-a" && c[3] === "-F")).toBe(true);
    });

    it("disarms and throws when the settle-probe never confirms liveness", async () => {
      const runner = scriptedRunner([
        loadCall,
        enableCall,
        infoCall(ok(PF_INFO_ENABLED)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-a" && a[2] === "-F", result: ok("") },
        { match: (_c, a) => a[0] === "-X", result: ok("") },
        rulesCall(ok("")), // anchor never prints rules: warmup race persists
      ]);
      await expect(
        armPfAnchor(runner, POLICY, {
          settleDelayMs: 1,
          settleTimeoutMs: 20,
          sleep: () => Promise.resolve(),
        }),
      ).rejects.toThrow(/settle-probe timed out/);
      // Symmetric rollback: the anchor was flushed and the token released.
      expect(runner.calls.some((c) => c[1] === "-a" && c[3] === "-F")).toBe(true);
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "4204204242")).toBe(true);
    });

    it("throws when the anchor load fails and never enables pf", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: { code: 1, stdout: "", stderr: "syntax error" } },
      ]);
      await expect(
        armPfAnchor(runner, POLICY, { settleDelayMs: 1, sleep: () => Promise.resolve() }),
      ).rejects.toThrow(/-f exited 1/);
      expect(runner.calls.some((c) => c[1] === "-E")).toBe(false);
    });

    it("throws on a malformed policy before touching pfctl", async () => {
      const runner = scriptedRunner([]);
      await expect(armPfAnchor(runner, { agent_uid: 502, gate_port: 0 })).rejects.toThrow(
        /malformed exclusive-egress gate policy/,
      );
      expect(runner.calls).toHaveLength(0);
    });
  });

  describe("disarmPfAnchor (symmetry)", () => {
    it("flushes the anchor and releases the enable token", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-F", result: ok("rules cleared") },
        { match: (_c, a) => a[0] === "-X", result: ok("") },
      ]);
      await disarmPfAnchor(runner, { enableToken: "4204204242" });
      expect(runner.calls[0]).toEqual(["pfctl", "-a", PF_ANCHOR_NAME, "-F", "all"]);
      expect(runner.calls[1]).toEqual(["pfctl", "-X", "4204204242"]);
    });

    it("throws when the flush fails (a silent no-op disarm is worse)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-F", result: { code: 1, stdout: "", stderr: "denied" } },
      ]);
      await expect(disarmPfAnchor(runner)).rejects.toThrow(/-F all exited 1/);
    });

    it("rejects a non-numeric enable token (no argv smuggling into pfctl)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-F", result: ok("") },
      ]);
      await expect(disarmPfAnchor(runner, { enableToken: "-e; rm -rf /" })).rejects.toThrow(
        /numeric pfctl reference token/,
      );
    });
  });
});
