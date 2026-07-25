/**
 * Tests for the block-only TOMBSTONE union member (Unified Protect Slice 5
 * S5-2, folds Codex M4). A tombstoned uid renders ONLY its four block-drops
 * (no gate pass), and exact-union liveness both requires those blocks and
 * REJECTS any stray pass for it -- the confined-but-gateless state the
 * generation state machine's crash recovery leaves. All host-state-free.
 */

import { describe, it, expect } from "vitest";

import {
  renderPfAnchorRulesForUids,
  checkPfAnchorUnionLiveness,
  armPfAnchorUnion,
  PF_ANCHOR_NAME,
  type PfAnchorUnionEntry,
  type PfCommandResult,
  type PfCommandRunner,
} from "../../src/egress-gate/pf-anchor.js";

const LIVE_A: PfAnchorUnionEntry = { agent_uid: 502, gate_port: 19998 };
const TOMB_A: PfAnchorUnionEntry = { agent_uid: 502, gate_port: 19998, tombstone: true };

function blockLines(uid: number): string[] {
  return [
    `block drop quick on lo0 inet proto tcp from any to any user = ${uid}`,
    `block drop quick on lo0 inet proto udp from any to any user = ${uid}`,
    `block drop quick on lo0 inet6 proto tcp from any to any user = ${uid}`,
    `block drop quick on lo0 inet6 proto udp from any to any user = ${uid}`,
  ];
}
function passLine(uid: number, port: number): string {
  return `pass quick on lo0 inet proto tcp from any to 127.0.0.1 port = ${port} user = ${uid} flags S/SA keep state`;
}

/** A pfctl mock that returns a fixed anchor rule listing + healthy hook/skip/info. */
function runnerFor(anchorRules: string): PfCommandRunner {
  return {
    async run(_cmd: string, args: readonly string[]): Promise<PfCommandResult> {
      const a = args.join(" ");
      if (a === "-s info") return { code: 0, stdout: "Status: Enabled\n", stderr: "" };
      if (a === `-a ${PF_ANCHOR_NAME} -sr`) return { code: 0, stdout: anchorRules, stderr: "" };
      if (a === "-sr") return { code: 0, stdout: `anchor "${PF_ANCHOR_NAME}" on lo0\n`, stderr: "" };
      if (a === "-v -s Interfaces") return { code: 0, stdout: "lo0\n", stderr: "" };
      return { code: 0, stdout: "", stderr: "" };
    },
  };
}

describe("egress-gate/pf-anchor tombstone (S5-2 M4)", () => {
  it("renders a tombstoned uid as block-drops ONLY (no gate pass)", () => {
    const text = renderPfAnchorRulesForUids([TOMB_A]);
    expect(text).not.toContain("pass quick");
    for (const b of blockLines(502)) expect(text).toContain(b);
  });

  it("a live uid still renders pass + 4 blocks (backward-compatible)", () => {
    const text = renderPfAnchorRulesForUids([LIVE_A]);
    expect(text).toContain(passLine(502, 19998));
    for (const b of blockLines(502)) expect(text).toContain(b);
  });

  it("mixes a live uid and a tombstoned uid in one deterministic union", () => {
    const B_LIVE: PfAnchorUnionEntry = { agent_uid: 504, gate_port: 20001 };
    const text = renderPfAnchorRulesForUids([B_LIVE, TOMB_A]);
    // uid 502 (tombstone) sorts first: its 4 blocks, no pass; then uid 504 live.
    expect(text).not.toContain(passLine(502, 19998));
    expect(text).toContain(passLine(504, 20001));
    for (const b of blockLines(502)) expect(text).toContain(b);
  });

  it("liveness LIVE when the anchor holds exactly a tombstoned uid's 4 blocks", async () => {
    const runner = runnerFor(blockLines(502).join("\n") + "\n");
    const res = await checkPfAnchorUnionLiveness(runner, [TOMB_A], PF_ANCHOR_NAME);
    expect(res.live).toBe(true);
  });

  it("liveness NOT live when a tombstoned uid still carries a stray gate pass (exactness)", async () => {
    // A stale/uncommitted pass rule for the tombstoned uid must make it NOT live.
    const stray = [passLine(502, 19998), ...blockLines(502)].join("\n") + "\n";
    const runner = runnerFor(stray);
    const res = await checkPfAnchorUnionLiveness(runner, [TOMB_A], PF_ANCHOR_NAME);
    expect(res.live).toBe(false);
    expect(res.reasons.join(" ")).toContain("unexpected rule");
  });

  it("liveness NOT live when a tombstoned uid is missing a block-drop", async () => {
    const missing = blockLines(502).slice(0, 3).join("\n") + "\n";
    const runner = runnerFor(missing);
    const res = await checkPfAnchorUnionLiveness(runner, [TOMB_A], PF_ANCHOR_NAME);
    expect(res.live).toBe(false);
  });

  it("armPfAnchorUnion arms a tombstoned uid (hook+enable+settle) block-only", async () => {
    const calls: string[] = [];
    const runner: PfCommandRunner = {
      async run(_cmd, args): Promise<PfCommandResult> {
        const a = args.join(" ");
        calls.push(a);
        if (a === "-s info") return { code: 0, stdout: "Status: Enabled\n", stderr: "" };
        if (a === `-a ${PF_ANCHOR_NAME} -sr`) return { code: 0, stdout: blockLines(502).join("\n") + "\n", stderr: "" };
        if (a === "-sr") return { code: 0, stdout: `anchor "${PF_ANCHOR_NAME}" on lo0\n`, stderr: "" };
        if (a === "-v -s Interfaces") return { code: 0, stdout: "lo0\n", stderr: "" };
        if (a === "-E") return { code: 0, stdout: "Token : 42\n", stderr: "" };
        // The enable-reference chokepoint attributes the reference by token.
        if (a === "-s References") {
          return {
            code: 0,
            stdout:
              "TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n" +
              "4063     pfctl                        42                       0 days 00:00:00\n",
            stderr: "",
          };
        }
        return { code: 0, stdout: "", stderr: "" };
      },
    };
    const res = await armPfAnchorUnion(runner, [TOMB_A], {
      anchorName: PF_ANCHOR_NAME,
      settleConsecutive: 1,
      settleDelayMs: 0,
      sleep: async () => {},
      bootSession: async () => "4E4A2428-2FBD-4164-B6B6-B1FDA7DA43BD",
    });
    expect(res.enableReference?.token).toBe("42");
    // The anchor load happened (a `-f` into the anchor).
    expect(calls.some((c) => c.startsWith(`-a ${PF_ANCHOR_NAME} -f`))).toBe(true);
  });
});
