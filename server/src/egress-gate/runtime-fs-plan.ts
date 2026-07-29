/**
 * Root-supervisor filesystem LAYOUT PLAN for the exclusive-egress runtime
 * surfaces (Unified Protect Slice 5 S5-6 fix-round, review BLOCKER-1 +
 * BLOCKER-2): the ONE place that states, computes, and enforces which
 * directory is owned by whom, with what mode, in what order.
 *
 * THE DEFECTS THIS RETIRES (both adversarial review families):
 *   - `/var/db/sanctuary/gate-runtime` was root-owned 0755 while the NON-ROOT
 *     gate daemon had to create its runtime-state tmp file inside it -> every
 *     real install EACCES'd, timed out at `waitForGateRuntime`, and degraded
 *     to coarse. The plan now pre-creates a PER-UID subdir owned by the gate
 *     uid; the gate daemon writes only inside its own subdir.
 *   - `/var/db/sanctuary/gate-cred` (and `gate-liveness`) were created 0700
 *     root-owned, so the gate uid could not traverse to its 0600 `.accept`
 *     (or `.token`) file and the agent uid could not traverse to its 0600
 *     `.token` file -> every CONNECT denied. The plan sets 0711 (execute/
 *     search WITHOUT read): any uid can traverse to a file it can name, but
 *     only root can list or write the directory, and the per-file 0600 +
 *     ownership still bind each file to exactly its one intended reader.
 *   - `mkdir(..., { mode })` is UMASK-MASKED and the previous creation sites
 *     swallowed failures, so the modes above were order-of-creation luck. The
 *     plan applies an EXPLICIT chmod after every mkdir (idempotent; also
 *     heals drifted modes from older builds) and every step failure THROWS
 *     (fail-closed: arming aborts rather than arming over a broken layout).
 *
 * STATED INVARIANT (enforced here, not assumed): the gate uid and the agent
 * uid can TRAVERSE `/var/db/sanctuary` (0755 root) and the specific subdirs
 * below; nothing under it is writable by either uid except the gate's own
 * per-uid runtime subdir.
 *
 *   /var/db/sanctuary                     root 0755  (traversal for all)
 *   +- gate-runtime                       root 0755  (root-written configs, world-readable)
 *   ¦  +- <agent_uid>/                    GATE UID 0755 (the gate daemon's
 *   ¦                                     runtime-state dir; root+posture read)
 *   +- gate-cred                          root 0711  (traversal w/o listing;
 *   ¦                                     .accept -> gate uid 0600, .token -> agent uid 0600)
 *   +- gate-liveness                      root 0711  (gate reads its 0600 token +
 *   ¦                                     the 0644 pinned oracle public key)
 *   +- gate-peer-resolver                 root 0711  (traversal w/o listing;
 *   ¦                                     <agent_uid>.sock -> root-bound, then chowned to
 *   ¦                                     the GATE uid 0600 by peer-resolver-daemon.ts itself
 *   ¦                                     at listen time -- 2026-07-24 S5-3 fix, see that
 *   ¦                                     module; this dir only needs to pre-exist traversable)
 *   +- agent-harness                      root 0755  (agent uid reads hold file + wrapper)
 *
 * Applied by ROOT at arming time (install + repair, `productionBringUp`) and
 * re-asserted by the boot supervisor before each boot release. Host-free:
 * the plan is a pure computation and `applyGateRuntimeFsPlan` runs over
 * injected ops, so tests pin the EXACT ownership/mode/order sequence.
 */

import { basename, join } from "node:path";

import { AGENT_HARNESS_HOLD_DIR, AGENT_HARNESS_HOLD_DIR_MODE } from "./release-barrier.js";

/** The root of every exclusive-egress runtime surface. */
export const SANCTUARY_VAR_DB_DIR = "/var/db/sanctuary";

/** One step of the layout plan. Order inside the plan array is normative. */
export type GateRuntimeFsStep =
  | { op: "mkdir"; path: string }
  | { op: "chown"; path: string; uid: number; gid: number }
  | { op: "chmod"; path: string; mode: number };

/** Injected side effects for {@link applyGateRuntimeFsPlan} (root in production). */
export interface GateRuntimeFsOps {
  /** Create the directory; an ALREADY-EXISTING directory is success. Throws otherwise. */
  mkdir(path: string): Promise<void>;
  /** chown(2). Throws on failure. */
  chown(path: string, uid: number, gid: number): Promise<void>;
  /** chmod(2) with the EXPLICIT mode (never umask-masked). Throws on failure. */
  chmod(path: string, mode: number): Promise<void>;
}

/** Input for {@link planExclusiveEgressRuntimeFs}. */
export interface GateRuntimeFsPlanInput {
  /** The confined agent uid (names the per-uid runtime subdir). */
  agentUid: number;
  /** The dedicated gate service uid (owns the per-uid runtime subdir). */
  gateUid: number;
  /** Base dir override (tests only). Default {@link SANCTUARY_VAR_DB_DIR}. */
  baseDir?: string;
}

function assertPositiveUid(value: number, what: string): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`gate runtime fs plan: ${what} must be a positive integer (got ${String(value)})`);
  }
}

/**
 * Compute the ordered layout plan (pure). Parents strictly before children;
 * each directory is mkdir -> chown -> chmod so the FINAL mode is explicit
 * (never umask luck) and applies to pre-existing (drifted) directories too.
 */
export function planExclusiveEgressRuntimeFs(input: GateRuntimeFsPlanInput): GateRuntimeFsStep[] {
  assertPositiveUid(input.agentUid, "agent uid");
  assertPositiveUid(input.gateUid, "gate uid");
  if (input.agentUid === input.gateUid) {
    throw new Error(
      `gate runtime fs plan: agent uid and gate uid must be distinct principals (both ${input.agentUid})`,
    );
  }
  const base = input.baseDir ?? SANCTUARY_VAR_DB_DIR;
  const dir = (name?: string): string => (name === undefined ? base : join(base, name));
  const rootDir = (path: string, mode: number): GateRuntimeFsStep[] => [
    { op: "mkdir", path },
    { op: "chown", path, uid: 0, gid: 0 },
    { op: "chmod", path, mode },
  ];
  const gateRuntimeUidDir = join(dir("gate-runtime"), String(input.agentUid));
  return [
    // Traversal invariant for every reader below (gate uid + agent uid).
    ...rootDir(dir(), 0o755),
    // Root-written gate configs (0644 files) + the per-uid gate-owned subdir.
    ...rootDir(dir("gate-runtime"), 0o755),
    { op: "mkdir", path: gateRuntimeUidDir },
    { op: "chown", path: gateRuntimeUidDir, uid: input.gateUid, gid: 0 },
    { op: "chmod", path: gateRuntimeUidDir, mode: 0o755 },
    // Credential dir: traversal WITHOUT listing; per-file 0600 + ownership
    // bind .accept to the gate uid and .token to the agent uid.
    ...rootDir(dir("gate-cred"), 0o711),
    // Liveness dir: same traversal model (gate reads its 0600 token + the
    // 0644 pinned supervisor public key; the 0600 private key stays root's).
    ...rootDir(dir("gate-liveness"), 0o711),
    // Peer-resolver dir (2026-07-24 S5-3 fix): same traversal model. The
    // per-agent `<agent_uid>.sock` FILE inside it is bound + chowned to the
    // gate uid by `peer-resolver-daemon.ts` itself at listen time (parity
    // with how the liveness oracle owns its own token-file chown); this plan
    // only owns the parent directory, so a resolver daemon that has not
    // started yet still has somewhere traversable to bind into.
    ...rootDir(dir("gate-peer-resolver"), 0o711),
    // Hold dir: agent uid reads the hold file + exec wrapper (integrity by
    // root ownership; no secret content). Name AND mode come from the
    // release-barrier constants, so this plan and the parked install's
    // hold-dir chokepoint (`writeIntoHoldDir`) can never state two different
    // layouts for the same directory (drill D1, 2026-07-18).
    ...rootDir(dir(basename(AGENT_HARNESS_HOLD_DIR)), AGENT_HARNESS_HOLD_DIR_MODE),
  ];
}

/**
 * Apply a plan over injected ops, IN ORDER, fail-closed: the first failing
 * step throws (with the step named) and nothing continues. Idempotent by
 * construction (mkdir tolerates existing dirs; chown/chmod re-assert).
 */
export async function applyGateRuntimeFsPlan(
  plan: readonly GateRuntimeFsStep[],
  ops: GateRuntimeFsOps,
): Promise<void> {
  for (const step of plan) {
    try {
      if (step.op === "mkdir") await ops.mkdir(step.path);
      else if (step.op === "chown") await ops.chown(step.path, step.uid, step.gid);
      else await ops.chmod(step.path, step.mode);
    } catch (err) {
      throw new Error(
        `gate runtime fs plan: step ${step.op} ${step.path} failed: ${(err as Error).message} ` +
          "(refusing to arm over a broken runtime layout)",
        { cause: err },
      );
    }
  }
}

/**
 * Production ops (root): real mkdir (EEXIST-tolerant), chown, chmod.
 *
 * SYMLINK REFUSAL (Codex lens, 2026-07-18, demonstrated empirically in a temp
 * dir): when `path` is a symlink to a directory, `mkdir` reports EEXIST and
 * the following `chown(0,0)`/`chmod` then apply to the LINK TARGET, while
 * `lstat` still reports a symlink. These ops run as root and this plan is what
 * establishes the traversal invariant the gate + agent uids depend on, so a
 * link-shaped runtime directory is refused before any ownership or mode is
 * applied to whatever it points at, rather than trusting that `/var/db` being
 * root-owned makes the shape impossible.
 */
export function createRealGateRuntimeFsOps(): GateRuntimeFsOps {
  return {
    async mkdir(path: string): Promise<void> {
      const { lstat, mkdir } = await import("node:fs/promises");
      try {
        await mkdir(path);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      }
      const st = await lstat(path);
      if (!st.isDirectory()) {
        throw new Error(
          `${path} is a ${st.isSymbolicLink() ? "symlink" : "non-directory"}, not a real directory; ` +
            "refusing to apply root ownership or mode through it. Remove it and re-run.",
        );
      }
    },
    async chown(path: string, uid: number, gid: number): Promise<void> {
      const { chown } = await import("node:fs/promises");
      await chown(path, uid, gid);
    },
    async chmod(path: string, mode: number): Promise<void> {
      const { chmod } = await import("node:fs/promises");
      await chmod(path, mode);
    },
  };
}

/**
 * Convenience: compute + apply the production plan for one agent. Called by
 * the install/repair bring-up and the boot supervisor, as root, BEFORE the
 * gate daemon is bootstrapped and BEFORE any credential/token is minted.
 */
export async function ensureExclusiveEgressRuntimeFs(input: {
  agentUid: number;
  gateUid: number;
}): Promise<void> {
  await applyGateRuntimeFsPlan(
    planExclusiveEgressRuntimeFs({ agentUid: input.agentUid, gateUid: input.gateUid }),
    createRealGateRuntimeFsOps(),
  );
}
