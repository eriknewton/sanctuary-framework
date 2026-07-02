/**
 * Tests for advisory loopback peer-identity recovery (Unified Protect
 * Slice 2). All lsof interaction is a scripted mock; the advisory stance
 * (errors resolve to null, never a throw) is pinned here.
 */

import { describe, it, expect } from "vitest";

import {
  parseLsofPeer,
  resolveLoopbackPeer,
  type PeerCommandRunner,
} from "../../src/egress-gate/peer-identity.js";

/**
 * Realistic `lsof -nP -Fpun -iTCP@127.0.0.1:52344` output: the gate process
 * (pid 900, our side of the connection) plus the client process (pid 777,
 * uid 502, local endpoint 52344).
 */
const LSOF_OUTPUT = [
  "p900",
  "u501",
  "f21",
  "n127.0.0.1:19998->127.0.0.1:52344",
  "p777",
  "u502",
  "f14",
  "n127.0.0.1:52344->127.0.0.1:19998",
  "",
].join("\n");

function runnerWith(code: number, stdout: string): PeerCommandRunner & { argv: string[][] } {
  const argv: string[][] = [];
  return {
    argv,
    run(command: string, args: readonly string[]) {
      argv.push([command, ...args]);
      return Promise.resolve({ code, stdout });
    },
  };
}

describe("egress-gate/peer-identity", () => {
  describe("parseLsofPeer", () => {
    it("finds the process whose LOCAL endpoint is the client port", () => {
      expect(parseLsofPeer(LSOF_OUTPUT, 52344, 900)).toEqual({ pid: 777, uid: 502 });
    });

    it("skips our own pid even when its name field orientation would match", () => {
      const selfOnly = ["p900", "u501", "n127.0.0.1:52344->127.0.0.1:19998", ""].join("\n");
      expect(parseLsofPeer(selfOnly, 52344, 900)).toBeNull();
    });

    it("does not match the gate-side record (remote endpoint on the client port)", () => {
      const gateSideOnly = ["p900", "u501", "n127.0.0.1:19998->127.0.0.1:52344", ""].join("\n");
      expect(parseLsofPeer(gateSideOnly, 52344, 123)).toBeNull();
    });

    it("returns null on empty or garbage output", () => {
      expect(parseLsofPeer("", 52344, 900)).toBeNull();
      expect(parseLsofPeer("not lsof output at all", 52344, 900)).toBeNull();
    });

    it("returns null when the uid field is missing for the matching process", () => {
      const missingUid = ["p777", "n127.0.0.1:52344->127.0.0.1:19998", ""].join("\n");
      expect(parseLsofPeer(missingUid, 52344, 900)).toBeNull();
    });
  });

  describe("resolveLoopbackPeer (advisory: never throws)", () => {
    it("resolves via the injected runner with argv-only lsof invocation", async () => {
      const runner = runnerWith(0, LSOF_OUTPUT);
      const peer = await resolveLoopbackPeer({ clientPort: 52344, selfPid: 900, runner });
      expect(peer).toEqual({ pid: 777, uid: 502 });
      expect(runner.argv[0]).toEqual(["lsof", "-nP", "-Fpun", "-iTCP@127.0.0.1:52344"]);
    });

    it("resolves null when lsof exits non-zero", async () => {
      const peer = await resolveLoopbackPeer({
        clientPort: 52344,
        selfPid: 900,
        runner: runnerWith(1, ""),
      });
      expect(peer).toBeNull();
    });

    it("resolves null when the runner rejects (lsof missing)", async () => {
      const runner: PeerCommandRunner = { run: () => Promise.reject(new Error("ENOENT")) };
      const peer = await resolveLoopbackPeer({ clientPort: 52344, selfPid: 900, runner });
      expect(peer).toBeNull();
    });

    it("resolves null for an out-of-range client port without running lsof", async () => {
      const runner = runnerWith(0, LSOF_OUTPUT);
      expect(await resolveLoopbackPeer({ clientPort: 0, selfPid: 900, runner })).toBeNull();
      expect(await resolveLoopbackPeer({ clientPort: 70000, selfPid: 900, runner })).toBeNull();
      expect(runner.argv).toHaveLength(0);
    });
  });
});
