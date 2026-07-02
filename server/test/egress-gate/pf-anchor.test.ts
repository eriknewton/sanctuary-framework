/**
 * Tests for the per-uid pf loopback anchor (Unified Protect Slice 3):
 * render shape (drill-parity), the MANDATORY fail-closed liveness check,
 * arm settle-probe semantics (including rollback on settle failure), and
 * disarm symmetry. All pfctl interaction is through a scripted mock runner;
 * no test touches a real pf.
 */

import { describe, it, expect } from "vitest";

import {
  PF_ANCHOR_NAME,
  renderPfAnchorRules,
  checkPfAnchorLiveness,
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

  describe("checkPfAnchorLiveness (fail-closed, positive evidence only)", () => {
    it("is live when pf is enabled and the anchor prints all expected rules", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result).toEqual({ live: true, reasons: [] });
    });

    it("accepts the uncollapsed 'from any to any' block spelling too", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(renderPfAnchorRules(POLICY))),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(true);
    });

    it("is NOT live when pf is disabled", async () => {
      const runner = scriptedRunner([
        infoCall(ok(PF_INFO_DISABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
      ]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.join(" ")).toMatch(/not enabled/);
    });

    it("is NOT live when the anchor is empty (silently-unloaded anchor)", async () => {
      const runner = scriptedRunner([infoCall(ok(PF_INFO_ENABLED)), rulesCall(ok(""))]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.some((r) => r.includes("pass rule"))).toBe(true);
    });

    it("is NOT live when the pass rule targets a different port", async () => {
      const wrongPort = CANONICAL_ANCHOR_PRINT.replace("port = 19998", "port = 19999");
      const runner = scriptedRunner([infoCall(ok(PF_INFO_ENABLED)), rulesCall(ok(wrongPort))]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
    });

    it("is NOT live when a block rule is missing (partial anchor)", async () => {
      const partial = [PASS_RULE, "block drop quick on lo0 inet proto tcp all user = 502"].join("\n");
      const runner = scriptedRunner([infoCall(ok(PF_INFO_ENABLED)), rulesCall(ok(partial))]);
      const result = await checkPfAnchorLiveness(runner, POLICY);
      expect(result.live).toBe(false);
      expect(result.reasons.some((r) => r.includes("udp"))).toBe(true);
    });

    it("is NOT live when pfctl exits non-zero (fail-closed on error)", async () => {
      const runner = scriptedRunner([
        infoCall({ code: 1, stdout: "", stderr: "pfctl: /dev/pf: Permission denied" }),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
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

  describe("armPfAnchor (settle-probe before 'armed')", () => {
    const loadCall: ScriptedCall = {
      match: (_c, a) => a[0] === "-a" && a[2] === "-f",
      result: ok(""),
    };
    const enableCall: ScriptedCall = {
      match: (_c, a) => a[0] === "-E",
      result: { code: 0, stdout: "", stderr: "pf enabled\nToken : 4204204242\n" },
    };

    it("loads, enables, captures the token, and settles on consecutive liveness", async () => {
      const runner = scriptedRunner([
        loadCall,
        enableCall,
        infoCall(ok(PF_INFO_ENABLED)),
        rulesCall(ok(CANONICAL_ANCHOR_PRINT)),
      ]);
      const result = await armPfAnchor(runner, POLICY, {
        settleDelayMs: 1,
        sleep: () => Promise.resolve(),
      });
      expect(result.enableToken).toBe("4204204242");
      expect(result.settleProbes).toBeGreaterThanOrEqual(2);
      const loaded = runner.calls.find((c) => c[1] === "-a" && c[3] === "-f");
      expect(loaded?.[2]).toBe(PF_ANCHOR_NAME);
    });

    it("disarms and throws when the settle-probe never confirms liveness", async () => {
      const runner = scriptedRunner([
        loadCall,
        enableCall,
        infoCall(ok(PF_INFO_ENABLED)),
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
