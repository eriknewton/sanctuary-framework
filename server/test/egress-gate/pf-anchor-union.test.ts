/**
 * Tests for the multi-uid pf-anchor UNION primitives (Unified Protect Slice 5
 * S5-1): `renderPfAnchorRulesForUids` (deterministic union render),
 * `checkPfAnchorUnionLiveness` (EXACT-union liveness -- folds Codex H4), and
 * `armPfAnchorUnion` (arm-equivalent load: hook + enable + settle, reference-
 * counted enable, non-destructive on failure -- folds Codex H3/B2). All pfctl
 * interaction is a scripted mock; no test touches a real pf.
 */

import { describe, it, expect } from "vitest";

import {
  PF_ANCHOR_NAME,
  renderPfAnchorRules,
  renderPfAnchorRulesForUids,
  checkPfAnchorUnionLiveness,
  armPfAnchorUnion,
  type PfCommandResult,
  type PfCommandRunner,
} from "../../src/egress-gate/pf-anchor.js";

const A = { agent_uid: 502, gate_port: 19998 };
const B = { agent_uid: 504, gate_port: 20001 };

function passRule(uid: number, port: number): string {
  return `pass quick on lo0 inet proto tcp from any to 127.0.0.1 port = ${port} user = ${uid} flags S/SA keep state`;
}

/** pfctl's canonical print (collapsed `all` spelling) of one uid's block rules. */
function canonicalUidPrint(uid: number, port: number): string[] {
  return [
    passRule(uid, port),
    `block drop quick on lo0 inet proto tcp all user = ${uid}`,
    `block drop quick on lo0 inet proto udp all user = ${uid}`,
    `block drop quick on lo0 inet6 proto tcp all user = ${uid}`,
    `block drop quick on lo0 inet6 proto udp all user = ${uid}`,
  ];
}

/** Canonical anchor print for a union of uids, sorted ascending (pfctl order). */
function canonicalUnionPrint(entries: Array<{ agent_uid: number; gate_port: number }>): string {
  const sorted = [...entries].sort((a, b) => a.agent_uid - b.agent_uid);
  const lines: string[] = [];
  for (const e of sorted) lines.push(...canonicalUidPrint(e.agent_uid, e.gate_port));
  return lines.join("\n") + "\n";
}

const PF_INFO_ENABLED = "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n";
const MAIN_RULESET_HOOKED = [
  'anchor "com.apple/*" all',
  `anchor "${PF_ANCHOR_NAME}" on lo0 all`,
  "",
].join("\n");
const MAIN_RULESET_UNHOOKED = 'anchor "com.apple/*" all\n';
const PF_IFACES_CLEAN = ["all", "en0", "lo0", "utun0", ""].join("\n");
const PF_IFACES_LO0_SKIP = ["all", "en0", "lo0 (skip)", "utun0", ""].join("\n");

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
const anchorRulesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a[0] === "-a" && a[2] === "-sr",
  result,
});
const mainRulesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a.length === 1 && a[0] === "-sr",
  result,
});
const ifacesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a[0] === "-v" && a[1] === "-s" && a[2] === "Interfaces",
  result,
});

/** A liveness script that is fully LIVE for the given union. */
function liveScript(entries: Array<{ agent_uid: number; gate_port: number }>): ScriptedCall[] {
  return [
    infoCall(ok(PF_INFO_ENABLED)),
    anchorRulesCall(ok(canonicalUnionPrint(entries))),
    mainRulesCall(ok(MAIN_RULESET_HOOKED)),
    ifacesCall(ok(PF_IFACES_CLEAN)),
  ];
}

describe("egress-gate/pf-anchor union primitives", () => {
  describe("renderPfAnchorRulesForUids", () => {
    it("renders both uids' rules, sorted ascending by uid, deterministic on rerender", () => {
      const text1 = renderPfAnchorRulesForUids([B, A]);
      const text2 = renderPfAnchorRulesForUids([A, B]);
      expect(text1).toBe(text2); // set-equal inputs -> byte-identical output
      expect(text1).toContain(passRule(502, 19998));
      expect(text1).toContain(passRule(504, 20001));
      // uid 502's block appears before uid 504's (ascending sort).
      expect(text1.indexOf("user = 502")).toBeLessThan(text1.indexOf("user = 504"));
    });

    it("single-uid render equals the one-entry union (no drift)", () => {
      expect(renderPfAnchorRules(A)).toBe(renderPfAnchorRulesForUids([A]));
    });

    it("throws on an EMPTY union (callers flush, never load empty)", () => {
      expect(() => renderPfAnchorRulesForUids([])).toThrow(/EMPTY union/);
    });

    it("throws on a DUPLICATE uid in the union", () => {
      expect(() => renderPfAnchorRulesForUids([A, { agent_uid: 502, gate_port: 3000 }])).toThrow(
        /duplicate agent_uid 502/,
      );
    });

    it("throws on a malformed entry (never a permissive-by-accident anchor)", () => {
      expect(() => renderPfAnchorRulesForUids([A, { agent_uid: 0, gate_port: 3000 }])).toThrow(
        /malformed/,
      );
    });
  });

  describe("checkPfAnchorUnionLiveness (exact-union)", () => {
    it("is LIVE when the anchor holds exactly the union and is enabled+hooked+unskipped", async () => {
      const runner = scriptedRunner(liveScript([A, B]));
      const res = await checkPfAnchorUnionLiveness(runner, [A, B]);
      expect(res.live).toBe(true);
      expect(res.reasons).toEqual([]);
    });

    it("is NOT live when a uid's rule is missing from the snapshot", async () => {
      // Anchor holds only A's rules, but the union claims A+B.
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([A]))),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const res = await checkPfAnchorUnionLiveness(runner, [A, B]);
      expect(res.live).toBe(false);
      expect(res.reasons.join(" ")).toMatch(/uid 504/);
    });

    it("is NOT live when the anchor holds an UNEXPECTED permissive rule (Codex H4)", async () => {
      const stray = canonicalUnionPrint([A]) + "\npass quick on lo0 inet proto tcp all user = 502";
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(stray)),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const res = await checkPfAnchorUnionLiveness(runner, [A]);
      expect(res.live).toBe(false);
      expect(res.reasons.join(" ")).toMatch(/unexpected rule/);
    });

    it("is NOT live when the anchor is loaded but UNHOOKED", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([A]))),
        mainRulesCall(ok(MAIN_RULESET_UNHOOKED)),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const res = await checkPfAnchorUnionLiveness(runner, [A]);
      expect(res.live).toBe(false);
      expect(res.reasons.join(" ")).toMatch(/not hooked/i);
    });

    it("is NOT live when pf skips filtering on loopback", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([A]))),
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        ifacesCall(ok(PF_IFACES_LO0_SKIP)),
      ]);
      const res = await checkPfAnchorUnionLiveness(runner, [A]);
      expect(res.live).toBe(false);
      expect(res.reasons.join(" ")).toMatch(/skip/i);
    });

    it("is NOT live for an empty or duplicate union", async () => {
      const runner = scriptedRunner(liveScript([A]));
      expect((await checkPfAnchorUnionLiveness(runner, [])).live).toBe(false);
      expect(
        (await checkPfAnchorUnionLiveness(runner, [A, { agent_uid: 502, gate_port: 3 }])).live,
      ).toBe(false);
    });
  });

  describe("armPfAnchorUnion (arm-equivalent)", () => {
    const settleFast = { settleConsecutive: 1, settleDelayMs: 0, sleep: async () => {} };

    it("loads the union, installs the hook when absent, enables pf, and returns a token", async () => {
      // The main ruleset (`pfctl -sr`) reads UNHOOKED on the first probe (so the
      // hook install fires) then HOOKED afterward (so the settle-probe passes).
      let mainProbes = 0;
      const statefulMain: ScriptedCall = {
        match: (_c, a) => a.length === 1 && a[0] === "-sr",
        result: ok(""), // unused; overridden below
      };
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") }, // load anchor
        {
          match: (c, a) => statefulMain.match(c, a),
          get result(): PfCommandResult {
            mainProbes += 1;
            return ok(mainProbes === 1 ? MAIN_RULESET_UNHOOKED : MAIN_RULESET_HOOKED);
          },
        } as ScriptedCall,
        { match: (_c, a) => a.length === 2 && a[0] === "-f", result: ok("") }, // hook install
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 12345\n") }, // enable
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([A, B]))),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const res = await armPfAnchorUnion(runner, [A, B], {
        mainConfPath: "/dev/null",
        ...settleFast,
      });
      expect(res.enableToken).toBe("12345");
      // pf -E was called exactly once.
      expect(runner.calls.filter((c) => c[1] === "-E").length).toBe(1);
      // The hook install (pfctl -f <mainfile>) fired because the first probe was unhooked.
      // calls entries are [command, ...args] -> ["pfctl", "-f", <mainfile>].
      expect(runner.calls.some((c) => c[1] === "-f" && c.length === 3)).toBe(true);
    });

    it("does NOT re-enable pf when an existingEnableToken is supplied (reference counting)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)), // already hooked -> no hook install
        ...liveScript([A]),
      ]);
      const res = await armPfAnchorUnion(runner, [A], {
        mainConfPath: "/dev/null",
        existingEnableToken: "999",
        ...settleFast,
      });
      expect(res.enableToken).toBe("999");
      expect(runner.calls.filter((c) => c[1] === "-E").length).toBe(0);
    });

    it("throws WITHOUT flushing the anchor on a load failure (Codex B2)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: { code: 1, stdout: "", stderr: "denied" } },
      ]);
      await expect(armPfAnchorUnion(runner, [A, B], { mainConfPath: "/dev/null", ...settleFast })).rejects.toThrow(
        /pfctl -a .* -f exited 1/,
      );
      // No `-F all` flush was issued (would drop other uids' confinement).
      expect(runner.calls.some((c) => c.includes("-F"))).toBe(false);
    });

    it("throws on an empty union (never loads empty)", async () => {
      const runner = scriptedRunner([]);
      await expect(armPfAnchorUnion(runner, [], { mainConfPath: "/dev/null", ...settleFast })).rejects.toThrow(
        /EMPTY union/,
      );
    });

    it("releases its OWN acquired -E reference on a post-enable failure, and does NOT flush (gate finding)", async () => {
      // Load + hook + enable succeed, but the anchor never becomes live (pf
      // reports Disabled), so settle times out AFTER -E acquired a reference.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 777\n") },
        // liveness: pf reports DISABLED -> never live -> settle times out
        infoCall(ok("Status: Disabled\n")),
        anchorRulesCall(ok(canonicalUnionPrint([A]))),
        ifacesCall(ok(PF_IFACES_CLEAN)),
        // the release on failure:
        { match: (_c, a) => a[0] === "-X" && a[1] === "777", result: ok("") },
      ]);
      await expect(
        armPfAnchorUnion(runner, [A], {
          mainConfPath: "/dev/null",
          settleConsecutive: 1,
          settleDelayMs: 0,
          settleTimeoutMs: 30,
          sleep: async () => {},
        }),
      ).rejects.toThrow(/settle-probe timed out/);
      // The acquired -E reference (token 777) was released via -X.
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "777")).toBe(true);
      // The shared anchor was NOT flushed (would drop other uids).
      expect(runner.calls.some((c) => c.includes("-F"))).toBe(false);
    });

    it("does NOT release a token it did not acquire (existing token belongs to a prior arm)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        infoCall(ok("Status: Disabled\n")), // never live
        anchorRulesCall(ok(canonicalUnionPrint([A]))),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      await expect(
        armPfAnchorUnion(runner, [A], {
          mainConfPath: "/dev/null",
          existingEnableToken: "555",
          settleConsecutive: 1,
          settleDelayMs: 0,
          settleTimeoutMs: 30,
          sleep: async () => {},
        }),
      ).rejects.toThrow(/settle-probe timed out/);
      // Never -X the existing token (a prior arm / other uid still depends on it),
      // and never -E (already enabled).
      expect(runner.calls.some((c) => c[1] === "-X")).toBe(false);
      expect(runner.calls.some((c) => c[1] === "-E")).toBe(false);
    });

    it("fails closed when pfctl -E exits 0 but prints no numeric token (gate finding)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled (no token line)\n") },
      ]);
      await expect(
        armPfAnchorUnion(runner, [A], { mainConfPath: "/dev/null", ...settleFast }),
      ).rejects.toThrow(/no numeric token/);
    });
  });
});
