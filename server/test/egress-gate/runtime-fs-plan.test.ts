/**
 * Fix-round BLOCKER-1 + BLOCKER-2: the runtime filesystem layout plan. These
 * tests pin the COMPUTED ownership/mode/order plan (injected recorder ops,
 * never a same-uid tmp-dir roundtrip): the per-uid gate-owned runtime subdir
 * (the gate daemon must be able to write its runtime state as the non-root
 * gate uid), the 0711 traversal modes on gate-cred/gate-liveness (the gate
 * uid must reach its .accept/.token, the agent uid its .token), the 0755
 * traversal invariant on /var/db/sanctuary, and the explicit chmod after
 * every mkdir (umask-independent, drift-healing).
 */

import { describe, expect, it } from "vitest";
import { lstatSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  SANCTUARY_VAR_DB_DIR,
  applyGateRuntimeFsPlan,
  createRealGateRuntimeFsOps,
  planExclusiveEgressRuntimeFs,
  type GateRuntimeFsOps,
  type GateRuntimeFsStep,
} from "../../src/egress-gate/runtime-fs-plan.js";
import { EGRESS_GATE_RUNTIME_DIR, egressGateRuntimeUidDirPath, egressGateRuntimeStatePath } from "../../src/egress-gate/gate-daemon.js";
import { GATE_CRED_DIR } from "../../src/egress-gate/gate-credential.js";
import { GATE_LIVENESS_DIR } from "../../src/egress-gate/liveness-oracle.js";
import { PEER_RESOLVER_DIR } from "../../src/egress-gate/peer-resolver-daemon.js";
import { AGENT_HARNESS_HOLD_DIR } from "../../src/egress-gate/release-barrier.js";

const AGENT_UID = 502;
const GATE_UID = 511;

describe("planExclusiveEgressRuntimeFs", () => {
  it("computes the EXACT ordered ownership/mode plan (the BLOCKER-1/2 permission model)", () => {
    const plan = planExclusiveEgressRuntimeFs({ agentUid: AGENT_UID, gateUid: GATE_UID });
    expect(plan).toEqual([
      // Traversal invariant: every reader below can search /var/db/sanctuary.
      { op: "mkdir", path: "/var/db/sanctuary" },
      { op: "chown", path: "/var/db/sanctuary", uid: 0, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary", mode: 0o755 },
      // Root-written configs live in the parent; the gate writes ONLY its subdir.
      { op: "mkdir", path: "/var/db/sanctuary/gate-runtime" },
      { op: "chown", path: "/var/db/sanctuary/gate-runtime", uid: 0, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary/gate-runtime", mode: 0o755 },
      // BLOCKER-1: the per-uid runtime dir is GATE-UID-owned so the non-root
      // gate daemon can create its state tmp file + rename.
      { op: "mkdir", path: "/var/db/sanctuary/gate-runtime/502" },
      { op: "chown", path: "/var/db/sanctuary/gate-runtime/502", uid: GATE_UID, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary/gate-runtime/502", mode: 0o755 },
      // BLOCKER-2: traversal WITHOUT listing; per-file 0600 + ownership bind
      // .accept to the gate uid and .token to the agent uid.
      { op: "mkdir", path: "/var/db/sanctuary/gate-cred" },
      { op: "chown", path: "/var/db/sanctuary/gate-cred", uid: 0, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary/gate-cred", mode: 0o711 },
      // Same traversal model for the liveness token + pinned public key.
      { op: "mkdir", path: "/var/db/sanctuary/gate-liveness" },
      { op: "chown", path: "/var/db/sanctuary/gate-liveness", uid: 0, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary/gate-liveness", mode: 0o711 },
      // 2026-07-24 S5-3 fix: same traversal model for the privileged
      // peer-resolver's per-agent socket (the socket FILE itself is bound +
      // chowned to the gate uid by peer-resolver-daemon.ts, not this plan).
      { op: "mkdir", path: "/var/db/sanctuary/gate-peer-resolver" },
      { op: "chown", path: "/var/db/sanctuary/gate-peer-resolver", uid: 0, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary/gate-peer-resolver", mode: 0o711 },
      // Hold dir: agent uid reads the hold file + wrapper.
      { op: "mkdir", path: "/var/db/sanctuary/agent-harness" },
      { op: "chown", path: "/var/db/sanctuary/agent-harness", uid: 0, gid: 0 },
      { op: "chmod", path: "/var/db/sanctuary/agent-harness", mode: 0o755 },
    ] satisfies GateRuntimeFsStep[]);
  });

  it("stays consistent with the real path constants the modules use", () => {
    const plan = planExclusiveEgressRuntimeFs({ agentUid: AGENT_UID, gateUid: GATE_UID });
    const mkdirs = plan.filter((s) => s.op === "mkdir").map((s) => s.path);
    expect(mkdirs).toContain(EGRESS_GATE_RUNTIME_DIR);
    expect(mkdirs).toContain(GATE_CRED_DIR);
    expect(mkdirs).toContain(GATE_LIVENESS_DIR);
    expect(mkdirs).toContain(PEER_RESOLVER_DIR);
    expect(mkdirs).toContain(AGENT_HARNESS_HOLD_DIR);
    expect(mkdirs).toContain(egressGateRuntimeUidDirPath(AGENT_UID));
    expect(mkdirs[0]).toBe(SANCTUARY_VAR_DB_DIR);
    // The gate daemon's state file lives INSIDE the gate-owned subdir.
    expect(egressGateRuntimeStatePath(AGENT_UID)).toBe(
      `${egressGateRuntimeUidDirPath(AGENT_UID)}/state.json`,
    );
  });

  it("every mkdir is followed by an explicit chown then chmod on the same path (never umask luck)", () => {
    const plan = planExclusiveEgressRuntimeFs({ agentUid: AGENT_UID, gateUid: GATE_UID });
    for (let i = 0; i < plan.length; i += 3) {
      const [mk, own, mode] = [plan[i]!, plan[i + 1]!, plan[i + 2]!];
      expect(mk.op).toBe("mkdir");
      expect(own.op).toBe("chown");
      expect(mode.op).toBe("chmod");
      expect(own.path).toBe(mk.path);
      expect(mode.path).toBe(mk.path);
    }
  });

  it("refuses invalid principals (non-positive uids; agent==gate)", () => {
    expect(() => planExclusiveEgressRuntimeFs({ agentUid: 0, gateUid: GATE_UID })).toThrow(/agent uid/);
    expect(() => planExclusiveEgressRuntimeFs({ agentUid: AGENT_UID, gateUid: -1 })).toThrow(/gate uid/);
    expect(() => planExclusiveEgressRuntimeFs({ agentUid: 502, gateUid: 502 })).toThrow(/distinct principals/);
  });
});

describe("applyGateRuntimeFsPlan", () => {
  function recorder(): { ops: GateRuntimeFsOps; calls: string[] } {
    const calls: string[] = [];
    return {
      calls,
      ops: {
        mkdir: async (path) => void calls.push(`mkdir ${path}`),
        chown: async (path, uid, gid) => void calls.push(`chown ${path} ${uid}:${gid}`),
        chmod: async (path, mode) => void calls.push(`chmod ${path} 0o${mode.toString(8)}`),
      },
    };
  }

  it("applies the steps strictly in order through the injected ops", async () => {
    const { ops, calls } = recorder();
    await applyGateRuntimeFsPlan(
      planExclusiveEgressRuntimeFs({ agentUid: AGENT_UID, gateUid: GATE_UID }),
      ops,
    );
    expect(calls.slice(0, 3)).toEqual([
      "mkdir /var/db/sanctuary",
      "chown /var/db/sanctuary 0:0",
      "chmod /var/db/sanctuary 0o755",
    ]);
    expect(calls).toContain(`chown /var/db/sanctuary/gate-runtime/502 ${GATE_UID}:0`);
    expect(calls).toContain("chmod /var/db/sanctuary/gate-cred 0o711");
    expect(calls).toContain("chmod /var/db/sanctuary/gate-liveness 0o711");
    expect(calls).toContain("chmod /var/db/sanctuary/gate-peer-resolver 0o711");
    expect(calls).toHaveLength(21);
  });

  it("fail-closed: the first failing step throws (named) and nothing continues", async () => {
    const { ops, calls } = recorder();
    const failing: GateRuntimeFsOps = {
      ...ops,
      chown: async (path, uid, gid) => {
        if (path === "/var/db/sanctuary/gate-runtime/502") throw new Error("EPERM");
        calls.push(`chown ${path} ${uid}:${gid}`);
      },
    };
    await expect(
      applyGateRuntimeFsPlan(
        planExclusiveEgressRuntimeFs({ agentUid: AGENT_UID, gateUid: GATE_UID }),
        failing,
      ),
    ).rejects.toThrow(/chown \/var\/db\/sanctuary\/gate-runtime\/502 failed: EPERM/);
    // Nothing after the failing step ran (gate-cred was never touched).
    expect(calls.some((c) => c.includes("gate-cred"))).toBe(false);
  });
});

/**
 * F7 (Codex lens, 2026-07-18): the PRODUCTION ops, against a real filesystem.
 *
 * The plan tests above use recorder ops, which by construction cannot show
 * what `mkdir`/`chmod` do to a symlink. The lens demonstrated empirically that
 * `mkdir` reports EEXIST on a symlink-to-directory and the following `chmod`
 * then changes the TARGET's mode. This code runs as root and establishes the
 * traversal invariant the gate and agent uids depend on, so it must refuse
 * that shape rather than rely on `/var/db` being root-owned. Runs entirely in
 * a private tmpdir and needs no privileges.
 */
describe("createRealGateRuntimeFsOps mkdir (F7: refuses symlink-shaped runtime dirs)", () => {
  it("accepts a real directory and is idempotent over an existing one", async () => {
    const root = mkdtempSync(join(tmpdir(), "s5-fsplan-ok-"));
    try {
      const target = join(root, "gate-runtime");
      const ops = createRealGateRuntimeFsOps();
      await ops.mkdir(target);
      await ops.mkdir(target); // second call must not throw
      expect(lstatSync(target).isDirectory()).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("REFUSES a path that is a symlink to a directory, so no chown/chmod ever reaches the target", async () => {
    const root = mkdtempSync(join(tmpdir(), "s5-fsplan-link-"));
    try {
      const realTarget = join(root, "elsewhere");
      const linkPath = join(root, "gate-cred");
      mkdirSync(realTarget, { mode: 0o700 });
      symlinkSync(realTarget, linkPath);
      const modeBefore = lstatSync(realTarget).mode & 0o777;

      const ops = createRealGateRuntimeFsOps();
      await expect(ops.mkdir(linkPath)).rejects.toThrow(/symlink/);

      // The property that matters: the link target was not re-shaped.
      expect(lstatSync(realTarget).mode & 0o777).toBe(modeBefore);
      expect(lstatSync(linkPath).isSymbolicLink()).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("REFUSES a plain file sitting where a runtime directory should be", async () => {
    const root = mkdtempSync(join(tmpdir(), "s5-fsplan-file-"));
    try {
      const filePath = join(root, "gate-liveness");
      writeFileSync(filePath, "not a directory");
      const ops = createRealGateRuntimeFsOps();
      await expect(ops.mkdir(filePath)).rejects.toThrow(/non-directory/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
