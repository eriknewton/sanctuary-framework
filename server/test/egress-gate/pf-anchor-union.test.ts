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

const referencesCall = (result: PfCommandResult): ScriptedCall => ({
  match: (_c, a) => a[0] === "-s" && a[1] === "References",
  result,
});

/**
 * `pfctl -s References` output in the shape captured on hardware
 * (`fixtures/pf-hardware-capture.ts`): a `TOKENS:` line, a column header, then
 * one row per held reference. Tokens are rendered into the real column layout
 * rather than a shape of the test author's invention.
 */
function referenceTable(tokens: readonly string[]): string {
  if (tokens.length === 0) return "No pf starter references held\n";
  const rows = tokens.map(
    (t, i) => `${4063 + i}     pfctl                        ${t}     0 days 00:00:00`,
  );
  return ["TOKENS:", "PID      Process Name                 TOKEN                    TIMESTAMP", ...rows, ""].join(
    "\n",
  );
}

/** A fixed boot session so no test shells out to sysctl. */
const BOOT_SESSION_UUID = "4E4A2428-2FBD-4164-B6B6-B1FDA7DA43BD";
const BOOT_SESSION = async (): Promise<string> => BOOT_SESSION_UUID;

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
        referencesCall(ok(referenceTable(["12345"]))),
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([A, B]))),
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      const res = await armPfAnchorUnion(runner, [A, B], {
        mainConfPath: "/dev/null",
        bootSession: BOOT_SESSION,
        ...settleFast,
      });
      expect(res.enableReference).toEqual({ token: "12345", boot_session_uuid: BOOT_SESSION_UUID });
      // pf -E was called exactly once.
      expect(runner.calls.filter((c) => c[1] === "-E").length).toBe(1);
      // The hook install (pfctl -f <mainfile>) fired because the first probe was unhooked.
      // calls entries are [command, ...args] -> ["pfctl", "-f", <mainfile>].
      expect(runner.calls.some((c) => c[1] === "-f" && c.length === 3)).toBe(true);
    });

    it("does NOT re-enable pf when the supplied reference is CONFIRMED ours and live (reference counting)", async () => {
      // Reference counting is preserved for the case the token exists for: an
      // in-boot re-arm. What changed is that the record alone no longer earns
      // the reuse -- pf must be enabled AND the reference table must attribute
      // token 999 to us.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)), // already hooked -> no hook install
        referencesCall(ok(referenceTable(["999"]))),
        ...liveScript([A]),
      ]);
      const res = await armPfAnchorUnion(runner, [A], {
        mainConfPath: "/dev/null",
        existingEnableReference: { token: "999", boot_session_uuid: BOOT_SESSION_UUID },
        bootSession: BOOT_SESSION,
        ...settleFast,
      });
      expect(res.enableReference).toEqual({ token: "999", boot_session_uuid: BOOT_SESSION_UUID });
      expect(res.acquiredEnableReference).toBe(false);
      expect(runner.calls.filter((c) => c[1] === "-E").length).toBe(0);
    });

    it("F-PFBOOT: RE-ENABLES pf when the supplied reference is from a PREVIOUS boot", async () => {
      // The measured post-reboot state: the persisted token is byte-identical
      // to its pre-reboot value while pf is Status: Disabled and the anchor is
      // enforcing nothing. The old predicate (`token supplied -> skip -E`) left
      // pf disabled here, which is the wrong-allow.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 24680\n") },
        referencesCall(ok(referenceTable(["24680"]))),
        { match: (_c, a) => a[0] === "-X", result: { code: 1, stdout: "", stderr: "pfctl: pf not enabled" } },
        ...liveScript([A]),
      ]);
      const res = await armPfAnchorUnion(runner, [A], {
        mainConfPath: "/dev/null",
        existingEnableReference: { token: "999", boot_session_uuid: "AAAAAAAA-0000-4000-8000-000000000001" },
        bootSession: BOOT_SESSION,
        ...settleFast,
      });
      expect(res.acquiredEnableReference).toBe(true);
      expect(res.enableReference).toEqual({ token: "24680", boot_session_uuid: BOOT_SESSION_UUID });
      expect(runner.calls.filter((c) => c[1] === "-E").length).toBe(1);
    });

    it("F-PFTHIRDPARTY: RE-ENABLES pf when it is held up by a reference that is not ours", async () => {
      // pf reads Status: Enabled and our record looks plausible, but the
      // reference table attributes the only reference to somebody else. On
      // hardware, reusing here meant the gate was declared LIVE on a reference
      // whose release destroyed confinement in the same boot and generation.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 13579\n") },
        // Before -E only the third party's token is held; after, both are.
        (() => {
          let seen = 0;
          return {
            match: (_c: string, a: readonly string[]) => a[0] === "-s" && a[1] === "References",
            get result(): PfCommandResult {
              seen += 1;
              return ok(referenceTable(seen === 1 ? ["3557565746035151565"] : ["13579", "3557565746035151565"]));
            },
          } as ScriptedCall;
        })(),
        { match: (_c, a) => a[0] === "-X", result: { code: 1, stdout: "", stderr: "pfctl: pf: token invalid" } },
        ...liveScript([A]),
      ]);
      const res = await armPfAnchorUnion(runner, [A], {
        mainConfPath: "/dev/null",
        existingEnableReference: { token: "999", boot_session_uuid: BOOT_SESSION_UUID },
        bootSession: BOOT_SESSION,
        ...settleFast,
      });
      expect(res.acquiredEnableReference).toBe(true);
      expect(res.enableReference?.token).toBe("13579");
      // The third party's reference is never released: it is not ours.
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "3557565746035151565")).toBe(false);
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
      // Load + hook + enable succeed and pf really does come up, but the anchor
      // never becomes live (its rules do not match the union), so settle times
      // out AFTER -E acquired a reference.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 777\n") },
        referencesCall(ok(referenceTable(["777"]))),
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([B]))), // wrong uid -> never live
        ifacesCall(ok(PF_IFACES_CLEAN)),
        // the release on failure:
        { match: (_c, a) => a[0] === "-X" && a[1] === "777", result: ok("") },
      ]);
      await expect(
        armPfAnchorUnion(runner, [A], {
          mainConfPath: "/dev/null",
          bootSession: BOOT_SESSION,
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

    it("REFUSES rather than reporting a reference when -E leaves pf disabled, and gives the token back", async () => {
      // A 0-exit `pfctl -E` is not evidence that pf is enabled. Previously
      // this shape surfaced only as a generic settle timeout; now the
      // invariant is asserted at the point it was supposed to be established,
      // and the reference this call took is released rather than leaked.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 888\n") },
        infoCall(ok("Status: Disabled\n")),
        { match: (_c, a) => a[0] === "-X" && a[1] === "888", result: ok("") },
      ]);
      await expect(
        armPfAnchorUnion(runner, [A], {
          mainConfPath: "/dev/null",
          bootSession: BOOT_SESSION,
          ...settleFast,
        }),
      ).rejects.toThrow(/but pf is still not enabled/);
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "888")).toBe(true);
      expect(runner.calls.some((c) => c.includes("-F"))).toBe(false);
    });

    it("does NOT release a reference it did not acquire (it belongs to a prior arm)", async () => {
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        referencesCall(ok(referenceTable(["555"]))), // confirmed ours and live
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([B]))), // wrong uid -> never live
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      await expect(
        armPfAnchorUnion(runner, [A], {
          mainConfPath: "/dev/null",
          existingEnableReference: { token: "555", boot_session_uuid: BOOT_SESSION_UUID },
          bootSession: BOOT_SESSION,
          settleConsecutive: 1,
          settleDelayMs: 0,
          settleTimeoutMs: 30,
          sleep: async () => {},
        }),
      ).rejects.toThrow(/settle-probe timed out/);
      // Never -X the existing reference (a prior arm / other uid still depends
      // on it), and never -E (we already hold a confirmed live reference).
      expect(runner.calls.some((c) => c[1] === "-X")).toBe(false);
      expect(runner.calls.some((c) => c[1] === "-E")).toBe(false);
    });

    it("carries the superseded release OUT, reason included, when it could not be accounted for", async () => {
      // FIX-ROUND F3. An unaccountable `pfctl -X` on the superseded token means
      // the registry drops that token from its record while the kernel may
      // still hold the reference: an ORPHAN with no row naming it. It
      // over-enforces (pf stays enabled) and can never be a wrong-allow, but it
      // is what leaves an operator staring at a pf that is still enabled after
      // an unprotect with nothing to read. The reason string used to be
      // discarded at this boundary; now it reaches the caller.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 222\n") },
        referencesCall(ok(referenceTable(["111", "222"]))),
        // Neither captured absence message, and pf is observed ENABLED, so the
        // release is unexplained and `releasePfEnableReference` throws.
        {
          match: (_c, a) => a[0] === "-X" && a[1] === "111",
          result: { code: 1, stdout: "", stderr: "pfctl: DIOCSTOPREF: Device busy" },
        },
        ...liveScript([A]),
      ]);
      const res = await armPfAnchorUnion(runner, [A], {
        mainConfPath: "/dev/null",
        // A previous boot, so the resolver reaches `not-ours` with no pfctl call.
        existingEnableReference: { token: "111", boot_session_uuid: "AAAAAAAA-0000-4000-8000-000000000001" },
        bootSession: BOOT_SESSION,
        ...settleFast,
      });
      expect(res.supersededEnableRelease?.disposition).toBe("already-gone");
      expect(res.supersededEnableRelease?.reason).toMatch(/could not be released/);
      expect(res.supersededEnableRelease?.reason).toMatch(/Device busy/);
    });

    it("does NOT release its acquired reference when the acquire SUPERSEDED a live one (bystander uid)", async () => {
      // FIX-ROUND F1. The failure path must never take pf's reference count to
      // zero under a loaded anchor. The six-step shape, all of it reachable:
      //
      //   1. The host is already confining uid A under live token 111.
      //   2. The operator adds uid B, so the registry re-arms the union.
      //   3. The resolver's `pfctl -s info` hits a TRANSIENT failure (a slow
      //      fork, EAGAIN under memory pressure, an execFile timeout), so the
      //      verdict is `unknown` -- which re-acquires by design.
      //   4. `-E` mints 222 and the superseded 111 is RELEASED (exit 0). 222 is
      //      now the ONLY reference holding pf up.
      //   5. The settle probe fails (uid B's rules never appear).
      //   6. Releasing 222 here would DISABLE pf -- and uid A, which was
      //      correctly confined and is not even the subject of this mutation,
      //      would regain full loopback reach until the registry rollback's own
      //      `-E`. That is a wrong-allow on a bystander.
      //
      // The reference is deliberately left ORPHANED instead: an extra pf enable
      // reference over-enforces, is releasable, and is visible in
      // `pfctl -s References`. That is this module's stated fail direction.
      let infoCalls = 0;
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        {
          match: (_c: string, a: readonly string[]) => a[0] === "-s" && a[1] === "info",
          // Call 1 is the resolver's probe and fails transiently -> `unknown`.
          // Every later call (post-acquire assertion, settle probe) succeeds.
          get result(): PfCommandResult {
            infoCalls += 1;
            return infoCalls === 1
              ? { code: 1, stdout: "", stderr: "pfctl: fork: Resource temporarily unavailable" }
              : ok(PF_INFO_ENABLED);
          },
        } as ScriptedCall,
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 222\n") },
        referencesCall(ok(referenceTable(["111", "222"]))),
        // The superseded release SUCCEEDS: 111 is really gone after this.
        { match: (_c, a) => a[0] === "-X" && a[1] === "111", result: ok("") },
        anchorRulesCall(ok(canonicalUnionPrint([A]))), // uid B missing -> never live
        ifacesCall(ok(PF_IFACES_CLEAN)),
      ]);
      await expect(
        armPfAnchorUnion(runner, [A, B], {
          mainConfPath: "/dev/null",
          existingEnableReference: { token: "111", boot_session_uuid: BOOT_SESSION_UUID },
          bootSession: BOOT_SESSION,
          settleConsecutive: 1,
          settleDelayMs: 0,
          settleTimeoutMs: 30,
          sleep: async () => {},
        }),
      ).rejects.toThrow(/settle-probe timed out/);
      // The superseded reference really was released, so 222 is load-bearing.
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "111")).toBe(true);
      // THE ASSERTION: 222 is NOT given back. Releasing it would disable pf for
      // every OTHER confined uid on this host.
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "222")).toBe(false);
      expect(runner.calls.some((c) => c.includes("-F"))).toBe(false);
    });

    it("STILL releases its acquired reference when nothing live was superseded", async () => {
      // The complement of the test above, so the F1 fix cannot be widened into
      // "never release on failure". Here the recorded token is from a PREVIOUS
      // boot, so the superseded release reports `already-gone` -- nothing that
      // was holding pf up was destroyed, and the reference this call took is
      // the one it added, so it must be given back.
      const runner = scriptedRunner([
        { match: (_c, a) => a[0] === "-a" && a[2] === "-f", result: ok("") },
        mainRulesCall(ok(MAIN_RULESET_HOOKED)),
        { match: (_c, a) => a[0] === "-E", result: ok("pf enabled\nToken : 333\n") },
        referencesCall(ok(referenceTable(["333"]))),
        { match: (_c, a) => a[0] === "-X" && a[1] === "111", result: { code: 1, stdout: "", stderr: "pfctl: pf: token invalid" } },
        infoCall(ok(PF_INFO_ENABLED)),
        anchorRulesCall(ok(canonicalUnionPrint([A]))), // uid B missing -> never live
        ifacesCall(ok(PF_IFACES_CLEAN)),
        { match: (_c, a) => a[0] === "-X" && a[1] === "333", result: ok("") },
      ]);
      await expect(
        armPfAnchorUnion(runner, [A, B], {
          mainConfPath: "/dev/null",
          existingEnableReference: { token: "111", boot_session_uuid: "AAAAAAAA-0000-4000-8000-000000000001" },
          bootSession: BOOT_SESSION,
          settleConsecutive: 1,
          settleDelayMs: 0,
          settleTimeoutMs: 30,
          sleep: async () => {},
        }),
      ).rejects.toThrow(/settle-probe timed out/);
      expect(runner.calls.some((c) => c[1] === "-X" && c[2] === "333")).toBe(true);
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
