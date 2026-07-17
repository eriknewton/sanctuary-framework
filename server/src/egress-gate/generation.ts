/**
 * Gate-port generation state machine + bind-first helper (Unified Protect
 * Slice 5 S5-2, folds Codex M6 + M4).
 *
 * THE PROBLEM (review MED-6). The exclusive-egress gate binds a loopback TCP
 * port that the pf anchor's pass rule and the signed manifest's gate rule both
 * reference. Rev1's "re-pin the port on each arm" left restart/crash semantics
 * undefined, and a fixed/predictable port invites a pre-bind SQUAT (a hostile
 * process binds the port before the gate does, then the pass rule points at
 * the squatter). The current gate + policy validator also reject port 0, so
 * there is no shipped way to bind an ephemeral port and learn it.
 *
 * THE FIX (this module). Each exclusive-egress bring-up is a GENERATION with a
 * monotonic-per-agent `generation_id`, staged through five transitions with a
 * crash-recovery rule for EACH, so a bind/owner/pf/manifest step that dies
 * mid-flight never leaves a green-looking-but-dead channel and never reopens
 * non-gate loopback:
 *
 *   G1  staged bind    the gate binds 127.0.0.1:0 and learns the real port
 *                      (bind-first: the gate OWNS the port before any pass or
 *                      manifest rule references it, so there is no pre-bind
 *                      squat window). Crash -> no staging record exists yet ->
 *                      the next bring-up simply starts fresh.
 *   G2  owner check    root verifies the listener on that port is the gate.
 *                      Crash after the staging record is written -> the record
 *                      is a dead (uncommitted) generation; recovery deletes it,
 *                      pf was never armed to the staged port, no packet change.
 *   G3  pf load        the registry arms the union with this uid at the staged
 *                      port + generation. Crash -> recovery BLOCK-ONLY
 *                      TOMBSTONES the uid (folds Codex M4): the four block-drops
 *                      survive (non-gate loopback stays CLOSED) while the
 *                      stale, uncommitted pass rule is dropped. Never remove the
 *                      whole entry (that would drop the block-drops too and
 *                      reopen non-gate loopback mid-repair).
 *   G4  manifest       the generation-bearing gate policy file is published
 *                      (port + generation). Crash -> the manifest generation
 *                      will not match the committed generation; posture reads
 *                      amber and repair coordinates a new generation. Recovery
 *                      tombstones the uncommitted pass exactly as G3.
 *   G5  commit         the staging record is REMOVED. The registry entry's
 *                      `generation_id` (written at G3) is now the ACTIVE
 *                      committed generation by virtue of there being no staging
 *                      record. This is the barrier line: only after G5 may a
 *                      consumer unpark the agent harness (S5-5/S5-6, owed).
 *
 * GENERATION MATCH (never green from stale rules). {@link evaluateGenerationMatch}
 * refuses traffic unless the pf pass-rule port, the manifest port, and the
 * committed registry port all AGREE and the manifest generation equals the
 * committed generation. A restarted gate ({@link resolveGateRestart}) may
 * RESUME only if it rebinds the committed port AND the owner check passes;
 * otherwise it refuses traffic and a full new generation is coordinated.
 *
 * HONESTY BOUNDS. This is the generation state-machine + bind-first LIBRARY
 * only, over INJECTED ops (bind, owner-check, registry, manifest-publish,
 * staging store), so the whole machine -- every crash-recovery branch -- is
 * unit-testable with no host, root, gate, or pf. It does NOT wire arming into
 * install (S5-6, owed), does NOT provision the gate service uid or its
 * client-auth / liveness oracle (S5-3, owed), does NOT compose the exclusive
 * routing manifest (S5-4 owns the endpoint re-scope; G4 here only publishes the
 * generation-bearing gate policy file), and does NOT park/unpark the harness
 * (S5-5, owed). No caller routes through it yet; it advances no capability
 * claim and arms nothing.
 */

import net from "node:net";

import {
  withProvisionLock,
  type ProvisionLockOps,
} from "../castle-wall/provision/lockfile.js";

/** Default per-uid generation lock path prefix (an internal on-disk artifact). */
export const GENERATION_LOCK_PATH_PREFIX = "/var/db/sanctuary/generation";

/** How far a bring-up progressed, recorded in the staging record for recovery. */
export type GenerationPhase = "owner_checked" | "pf_loaded" | "manifest_reloaded";

/** A bound gate port (G1 output). `release` frees it on an aborted bring-up. */
export interface GateBinding {
  /** The real loopback port the gate bound (never 0). */
  port: number;
  /** The listener process pid (for the owner check). */
  pid: number;
  /**
   * A process-identity token the owner check re-verifies. Production `bind`
   * impls (S5-6) supply the real listener's start-time so it defeats pid reuse;
   * the default {@link bindEphemeralGatePort} sets a NON-AUTHORITATIVE
   * placeholder (the pid, no start-time), so pid-reuse defense there comes only
   * from the injected {@link GenerationOps.verifyOwner} (S5-3), never this field.
   */
  pidStart: string;
  /** Free the port. Called only when a bring-up aborts (never after G5 commit). */
  release(): Promise<void>;
}

/** What the caller wants confined behind a fresh generation. */
export interface GenerationBringUpRequest {
  /** The dedicated agent service-account uid to confine (must be a non-root uid). */
  agent_uid: number;
  /** The fortress this confinement belongs to (persisted for boot re-arm + posture). */
  fortress_path: string;
}

/** A committed exclusive-egress generation (G5 output). */
export interface CommittedGeneration {
  generation_id: number;
  agent_uid: number;
  gate_port: number;
  gate_pid: number;
  gate_pid_start: string;
  fortress_path: string;
}

/**
 * The on-disk staging record (`generation-staging-<uid>.json`). Its PRESENCE is
 * the "a generation is in flight / was never committed" marker; G5 deletes it.
 */
export interface GenerationStagingRecord extends CommittedGeneration {
  /** How far the bring-up got, so recovery applies the right per-transition rule. */
  phase: GenerationPhase;
}

/** Injected persistence for the per-uid staging record. */
export interface GenerationStagingStore {
  load(agentUid: number): Promise<GenerationStagingRecord | null>;
  save(record: GenerationStagingRecord): Promise<void>;
  delete(agentUid: number): Promise<void>;
}

/** The registry surface the generation machine drives (the real PfAnchorRegistry satisfies it via a thin adapter). */
export interface GenerationRegistryOps {
  /** G3: arm/update the uid's confinement at the staged port + generation. */
  armEntry(entry: {
    agent_uid: number;
    gate_port: number;
    fortress_path: string;
    generation_id: number;
  }): Promise<void>;
  /** Recovery: block-only tombstone the uid (drop stale pass, keep block-drops).
   *  The fallback carries the dead generation's id so a tombstone that ADDS a
   *  block-only entry (uid absent) preserves generation-id monotonicity. */
  tombstone(
    agentUid: number,
    fallback?: { gate_port: number; fortress_path: string; generation_id?: number },
  ): Promise<void>;
  /** Read the committed entry for a uid (port + committed generation), or null. */
  readEntry(agentUid: number): Promise<{
    agent_uid: number;
    gate_port: number;
    generation_id?: number;
    tombstone?: boolean;
  } | null>;
}

/** Everything the coordinator needs, all injectable so it is host-free in tests. */
export interface GenerationOps {
  /** G1: bind an ephemeral loopback gate port and learn it (default {@link bindEphemeralGatePort}). */
  bind(request: GenerationBringUpRequest): Promise<GateBinding>;
  /** G2 (and restart/recovery): verify the listener on `port` is the expected gate process. */
  verifyOwner(input: { port: number; pid: number; pidStart: string }): Promise<boolean>;
  /** G3 / recovery: the pf-anchor registry surface. */
  registry: GenerationRegistryOps;
  /** G4: publish the generation-bearing gate policy file (port + generation). */
  publishManifest(gen: {
    agent_uid: number;
    gate_port: number;
    generation_id: number;
  }): Promise<void>;
  /** The staging-record store. */
  staging: GenerationStagingStore;
  /**
   * Per-uid exclusive lock (the shipped O_EXCL {@link ProvisionLockOps}
   * discipline). {@link GenerationCoordinator.bringUp} and {@link GenerationCoordinator.recover}
   * both run UNDER this lock, keyed per uid, so two concurrent bring-ups for one
   * uid cannot both observe "no staging record", bind different ports, and
   * interleave G3-G5 (the TOCTOU the gate flagged). Fail-loud on contention.
   */
  lock: ProvisionLockOps;
  /** Lock-path prefix (default {@link GENERATION_LOCK_PATH_PREFIX}); the uid is appended. */
  lockPathPrefix?: string;
}

/** A generation-machine invariant was violated or a transition failed. Fail-closed. */
export class GenerationStateError extends Error {
  constructor(message: string) {
    super(`gate generation state machine: ${message}`);
    this.name = "GenerationStateError";
  }
}

/** What recovery did with an in-flight (uncommitted) staging record. */
export interface GenerationRecoveryOutcome {
  agent_uid: number;
  /**
   * - `none`: no staging record; any committed generation stands.
   * - `discarded`: a pre-pf (G2) dead record; deleted, no packet change.
   * - `tombstoned`: a G3/G4 uncommitted generation; the uid's pass was dropped
   *   and its four block-drops re-armed (non-gate loopback stays closed). A new
   *   generation must be coordinated before the uid has a gate again.
   */
  action: "none" | "discarded" | "tombstoned";
  /** The dead generation's id (when a record was present). */
  generation_id?: number;
  /** Whether the staged gate still owned the port at recovery (observability). */
  owner_holds?: boolean;
}

/** Inputs to the three-surface generation-match check. */
export interface GenerationMatchInput {
  /** The registry entry's committed generation (undefined = no committed generation). */
  committedGenerationId: number | undefined;
  /** The registry entry's committed gate port. */
  committedPort: number | undefined;
  /** The port the LIVE pf pass rule actually points at. */
  pfPassPort: number | undefined;
  /** The port in the published gate policy file. */
  manifestPort: number | undefined;
  /** The generation in the published gate policy file. */
  manifestGenerationId: number | undefined;
}

/** The result of a gate restart resolution. */
export interface GateRestartOutcome {
  action: "resume" | "new_generation_required" | "no_committed_generation";
  generation_id?: number;
  reasons: string[];
}

/**
 * Monotonic-per-agent next generation id: strictly greater than any generation
 * this agent has committed OR staged, so a restart/crash can never reuse an id
 * (a reused id would let a stale manifest/pf rule masquerade as current).
 */
export function computeNextGenerationId(
  committedGenerationId: number | undefined,
  stagingGenerationId: number | undefined,
): number {
  const highest = Math.max(committedGenerationId ?? 0, stagingGenerationId ?? 0);
  return highest + 1;
}

/**
 * Resolve the COMMITTED generation of a registry entry for the generation-match
 * check. THE LOAD-BEARING GATE (folds the reviewers' shared finding): a
 * registry entry's `generation_id` is written at G3 (pf load), BEFORE the G5
 * commit, so the raw entry alone cannot be trusted as "committed" -- between
 * G3/G4 and G5 the pf pass port, manifest port, and entry `generation_id` all
 * agree while the generation is still UNCOMMITTED. A uid is committed ONLY when
 * NO staging record exists for it AND it is not tombstoned AND the registry is
 * not dirty. Callers of {@link evaluateGenerationMatch} MUST derive the
 * `committed*` inputs through THIS resolver (never the raw entry), so a naive
 * consumer cannot read an armed-but-uncommitted generation as green.
 */
export function resolveCommittedGeneration(input: {
  entry: { gate_port: number; generation_id?: number; tombstone?: boolean } | null;
  stagingRecordPresent: boolean;
  registryDirty?: boolean;
}): { committedGenerationId: number | undefined; committedPort: number | undefined } {
  const { entry } = input;
  // Uncommitted / not-green if: no entry, a staging record is in flight, the uid
  // is tombstoned (gate dropped), the registry is dirty (needs repair), or the
  // entry carries no committed generation id (a legacy/never-committed entry).
  if (
    entry === null ||
    input.stagingRecordPresent ||
    entry.tombstone === true ||
    input.registryDirty === true ||
    entry.generation_id === undefined
  ) {
    return { committedGenerationId: undefined, committedPort: undefined };
  }
  return { committedGenerationId: entry.generation_id, committedPort: entry.gate_port };
}

/**
 * The three-surface generation-match check: refuse traffic ("never green from
 * stale rules") unless the pf pass-rule port, the manifest port, and the
 * committed registry port ALL agree and the manifest generation equals the
 * committed generation. Any missing or mismatched surface -> `serve: false`
 * with the specific reasons (posture reads amber). Pure; no I/O.
 *
 * The `committed*` inputs MUST come from {@link resolveCommittedGeneration}
 * (which returns `undefined` for an armed-but-uncommitted generation), NEVER
 * from a raw registry entry -- otherwise a G4-before-G5 generation would serve
 * green. A `committedGenerationId`/`committedPort` of `undefined` always yields
 * `serve: false`.
 */
export function evaluateGenerationMatch(input: GenerationMatchInput): {
  serve: boolean;
  reasons: string[];
} {
  const reasons: string[] = [];
  if (input.committedGenerationId === undefined) {
    reasons.push("no committed generation");
  }
  if (input.committedPort === undefined) {
    reasons.push("no committed gate port");
  }
  if (input.committedPort !== undefined && input.pfPassPort !== input.committedPort) {
    reasons.push(
      `pf pass port ${String(input.pfPassPort)} != committed port ${String(input.committedPort)}`,
    );
  }
  if (input.committedPort !== undefined && input.manifestPort !== input.committedPort) {
    reasons.push(
      `manifest port ${String(input.manifestPort)} != committed port ${String(input.committedPort)}`,
    );
  }
  if (
    input.committedGenerationId !== undefined &&
    input.manifestGenerationId !== input.committedGenerationId
  ) {
    reasons.push(
      `manifest generation ${String(input.manifestGenerationId)} != committed generation ${String(input.committedGenerationId)}`,
    );
  }
  return { serve: reasons.length === 0, reasons };
}

/**
 * Gate restart semantics: a restarted gate reads the committed generation and
 * tries to rebind the committed port. RESUME only if the rebind succeeded AND
 * the owner check passed on the rebound port; otherwise the gate must refuse
 * traffic (posture amber) and a full new generation (G1-G5) is coordinated
 * before any CONNECT is served. Pure; the rebind/owner attempts are the
 * caller's, their booleans passed in.
 */
export function resolveGateRestart(input: {
  committed: { generation_id: number; gate_port: number } | null;
  rebindOk: boolean;
  ownerVerified: boolean;
}): GateRestartOutcome {
  if (input.committed === null) {
    return { action: "no_committed_generation", reasons: ["no committed generation to rebind"] };
  }
  if (input.rebindOk && input.ownerVerified) {
    return { action: "resume", generation_id: input.committed.generation_id, reasons: [] };
  }
  const reasons: string[] = [];
  if (!input.rebindOk) {
    reasons.push(`could not rebind the committed gate port ${input.committed.gate_port} (port taken)`);
  }
  if (!input.ownerVerified) {
    reasons.push("owner check failed on the rebound port (start-time mismatch: a different process held it)");
  }
  return { action: "new_generation_required", generation_id: input.committed.generation_id, reasons };
}

/**
 * BIND-FIRST helper (folds MED-6's "validator rejects port 0 -- extend"). Binds
 * a loopback TCP listener on `127.0.0.1:0`, learns the real ephemeral port, and
 * KEEPS it bound (returned `release` frees it). Binding first is what closes the
 * pre-bind squat window: the gate owns the port before any pass or manifest rule
 * references it. The concrete learned port then passes the ordinary gate-policy
 * validator (which rejects 0), so no validator is weakened.
 *
 * HONESTY: this default impl binds a bare listener in THIS process, so `pid` is
 * `process.pid` and `pidStart` is a best-effort token; the AUTHORITATIVE owner
 * check (root reading the real listener's pid/uid/start-time) is the injected
 * {@link GenerationOps.verifyOwner}, whose production form lands with the gate
 * TCB (S5-3). Production (S5-6) supplies a `bind` that starts the real gate.
 */
export async function bindEphemeralGatePort(host = "127.0.0.1"): Promise<GateBinding> {
  // IPv4-loopback ONLY by construction: the WHOLE exclusive-egress stack is
  // 127.0.0.1-only -- the pf pass rule (`renderUidAnchorLines`), the manifest
  // gate CIDR (`GATE_LOOPBACK_CIDR`), and the gate bind (`GATE_BIND_HOST`) are
  // all IPv4 127.0.0.1. Binding-first on `::1` would NOT reserve the IPv4
  // `127.0.0.1:<port>` the rest of the stack references (a same-port IPv4 bind
  // still succeeds), so it would defeat the anti-squat guarantee. Reject
  // anything but 127.0.0.1 until IPv6 policy/pf/gate support exists (gate
  // finding: allowing `::1` was an anti-squat hole).
  if (host !== "127.0.0.1") {
    throw new GenerationStateError(
      `bind-first helper refuses host ${JSON.stringify(host)} (IPv4 loopback 127.0.0.1 only; the pf/manifest/gate stack is IPv4-only)`,
    );
  }
  const server = net.createServer();
  // Keep an error handler attached for the LIFETIME of the held listener: a
  // late 'error' after listen (e.g. while the port is held) would otherwise be
  // an unhandled event and crash the process (gate finding).
  server.on("error", () => undefined);
  await new Promise<void>((resolve, reject) => {
    const onListenError = (err: unknown): void => reject(err);
    server.once("error", onListenError);
    server.listen(0, host, () => {
      server.removeListener("error", onListenError);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new GenerationStateError("bind-first helper could not determine the bound ephemeral port");
  }
  const port = address.port;
  return {
    port,
    pid: process.pid,
    // NON-AUTHORITATIVE placeholder (the pid, not a start-time) -- see the
    // GateBinding.pidStart doc; production `bind` (S5-6) supplies the real token.
    pidStart: `pid-${process.pid}`,
    async release(): Promise<void> {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

const GENERATION_PHASES: readonly GenerationPhase[] = [
  "owner_checked",
  "pf_loaded",
  "manifest_reloaded",
];

/**
 * Post-parse shape validation for an on-disk staging record. `JSON.parse`
 * output is untrusted-shape even on a root-only path (a truncated write, a
 * hand-edited file, or an older/newer binary's layout): recovery decisions key
 * off these fields, so a malformed record must FAIL CLOSED (loud error naming
 * the file) rather than flow through as `undefined`/wrong-typed values.
 */
export function parseGenerationStagingRecord(
  text: string,
  path: string,
): GenerationStagingRecord {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new GenerationStateError(
      `staging record at ${path} is not valid JSON (${(err as Error).message}); refusing to interpret it`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new GenerationStateError(
      `staging record at ${path} is not a JSON object; refusing to interpret it`,
    );
  }
  const record = parsed as Record<string, unknown>;
  const bad = (field: string, want: string): GenerationStateError =>
    new GenerationStateError(
      `staging record at ${path} has a missing/invalid ${JSON.stringify(field)} (expected ${want}); refusing to interpret it`,
    );
  const requireInt = (field: string): number => {
    const value = record[field];
    if (typeof value !== "number" || !Number.isSafeInteger(value)) throw bad(field, "an integer");
    return value;
  };
  const requireString = (field: string): string => {
    const value = record[field];
    if (typeof value !== "string" || value.length === 0) throw bad(field, "a non-empty string");
    return value;
  };
  const phase = record.phase;
  if (typeof phase !== "string" || !(GENERATION_PHASES as readonly string[]).includes(phase)) {
    throw bad("phase", `one of ${GENERATION_PHASES.join(", ")}`);
  }
  return {
    generation_id: requireInt("generation_id"),
    agent_uid: requireInt("agent_uid"),
    gate_port: requireInt("gate_port"),
    gate_pid: requireInt("gate_pid"),
    gate_pid_start: requireString("gate_pid_start"),
    fortress_path: requireString("fortress_path"),
    phase: phase as GenerationPhase,
  };
}

/** A default FS staging store: one `generation-staging-<uid>.json` per uid (0600). */
export function createFsGenerationStagingStore(
  dir = "/var/db/sanctuary",
): GenerationStagingStore {
  const fileFor = async (agentUid: number): Promise<string> => {
    const { join } = await import("node:path");
    return join(dir, `generation-staging-${agentUid}.json`);
  };
  return {
    async load(agentUid: number): Promise<GenerationStagingRecord | null> {
      const { readFile } = await import("node:fs/promises");
      const path = await fileFor(agentUid);
      let text: string;
      try {
        text = await readFile(path, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
      return parseGenerationStagingRecord(text, path);
    },
    async save(record: GenerationStagingRecord): Promise<void> {
      const { writeFile, rename, mkdir } = await import("node:fs/promises");
      await mkdir(dir, { recursive: true, mode: 0o700 }).catch(() => undefined);
      const path = await fileFor(record.agent_uid);
      const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
      await writeFile(tmp, JSON.stringify(record), { mode: 0o600 });
      await rename(tmp, path);
    },
    async delete(agentUid: number): Promise<void> {
      const { rm } = await import("node:fs/promises");
      const path = await fileFor(agentUid);
      await rm(path, { force: true });
    },
  };
}

function validateRequest(request: GenerationBringUpRequest): GenerationBringUpRequest {
  const uid = request.agent_uid;
  if (typeof uid !== "number" || !Number.isInteger(uid) || uid <= 0) {
    throw new GenerationStateError(`refusing a bring-up for a non-positive/root agent_uid ${String(uid)}`);
  }
  if (typeof request.fortress_path !== "string" || request.fortress_path.length === 0) {
    throw new GenerationStateError("refusing a bring-up with an empty fortress_path");
  }
  return { agent_uid: uid, fortress_path: request.fortress_path };
}

/**
 * The gate-port generation state machine. Construct once with injected ops;
 * {@link bringUp} runs G1-G5 to a committed generation, {@link recover} applies
 * the crash-recovery rule for whatever transition an in-flight generation died
 * on. Both are host-free: every side effect is an injected op.
 */
export class GenerationCoordinator {
  constructor(private readonly ops: GenerationOps) {}

  private lockPathFor(agentUid: number): string {
    const prefix = this.ops.lockPathPrefix ?? GENERATION_LOCK_PATH_PREFIX;
    return `${prefix}-${agentUid}.lock`;
  }

  /**
   * Run G1-G5 to a committed generation, UNDER the per-uid lock (so two
   * concurrent bring-ups for one uid cannot race past the staging-record
   * check). Write-ahead journaling: each phase's intent is persisted to the
   * staging record BEFORE its side effect, so a crash mid-step is recoverable
   * fail-closed (recovery tombstones an uncommitted pass rather than trusting
   * it). On an in-process failure the uncommitted pass is DROPPED (recovery)
   * BEFORE the staged port is released, so a stale pass never points at a
   * now-free squattable port; if that recovery fails the port is KEPT held and
   * the failure surfaces. Refuses to start when a staging record already exists
   * (recover first).
   */
  async bringUp(request: GenerationBringUpRequest): Promise<CommittedGeneration> {
    const { agent_uid, fortress_path } = validateRequest(request);
    return withProvisionLock(this.lockPathFor(agent_uid), this.ops.lock, () =>
      this.bringUpLocked(agent_uid, fortress_path),
    );
  }

  private async bringUpLocked(
    agent_uid: number,
    fortress_path: string,
  ): Promise<CommittedGeneration> {
    const existing = await this.ops.staging.load(agent_uid);
    if (existing !== null) {
      throw new GenerationStateError(
        `a staging record for uid ${agent_uid} already exists (generation ${existing.generation_id}, ` +
          `phase ${existing.phase}); recover() before starting a new bring-up`,
      );
    }

    // G1: staged bind -- the gate owns an ephemeral port before any rule names it.
    const binding = await this.ops.bind({ agent_uid, fortress_path });
    try {
      const committed = await this.ops.registry.readEntry(agent_uid);
      const generation_id = computeNextGenerationId(committed?.generation_id, undefined);
      const base: CommittedGeneration = {
        generation_id,
        agent_uid,
        gate_port: binding.port,
        gate_pid: binding.pid,
        gate_pid_start: binding.pidStart,
        fortress_path,
      };

      // G2: owner check -- the listener on the staged port must be the gate.
      const owned = await this.ops.verifyOwner({
        port: binding.port,
        pid: binding.pid,
        pidStart: binding.pidStart,
      });
      if (!owned) {
        throw new GenerationStateError(
          `G2 owner check failed: the listener on staged port ${binding.port} is not the gate`,
        );
      }
      // Journal G2 completion (the staging record now exists -> recover() can act).
      await this.ops.staging.save({ ...base, phase: "owner_checked" });

      // Write-ahead the pf-load intent BEFORE arming, so a crash mid-arm is
      // recovered fail-closed (tombstone the maybe-armed pass, never trust it).
      await this.ops.staging.save({ ...base, phase: "pf_loaded" });
      // G3: pf load -- the registry arms the union with this uid at the staged port.
      await this.ops.registry.armEntry({
        agent_uid,
        gate_port: binding.port,
        fortress_path,
        generation_id,
      });

      // Write-ahead the manifest-publish intent BEFORE publishing.
      await this.ops.staging.save({ ...base, phase: "manifest_reloaded" });
      // G4: publish the generation-bearing gate policy file (port + generation).
      await this.ops.publishManifest({ agent_uid, gate_port: binding.port, generation_id });

      // G5: commit -- removing the staging record makes the G3-written
      // generation_id the ACTIVE committed generation. The gate keeps holding
      // the port (NOT released). Only now may a consumer unpark the harness
      // (S5-5/S5-6, owed -- not this library).
      await this.ops.staging.delete(agent_uid);
      return base;
    } catch (err) {
      // Uncommitted. ORDER MATTERS (gate finding): DROP any uncommitted pass
      // (recovery/tombstone) BEFORE freeing the port -- releasing first would
      // leave the stale pass pointing at a now-free, squattable port. Only after
      // recovery succeeds is the port released. If recovery FAILS, KEEP the port
      // held (so the stale pass still points at a port WE own, never a squatter)
      // and leave the staging record for a later recover(); the original error
      // still propagates.
      try {
        await this.recoverLocked(agent_uid);
        await binding.release().catch(() => undefined);
      } catch {
        // Recovery failed: do NOT release the port. Surface the original error.
      }
      throw err;
    }
  }

  /**
   * Apply the crash-recovery rule for an in-flight (uncommitted) staging record,
   * UNDER the per-uid lock. No record -> `none` (a committed generation, if any,
   * stands). A pre-pf (G2) record -> `discarded` (pf was never armed; delete it,
   * no packet change). A G3/G4 record -> `tombstoned`: the uid's four block-drops
   * are re-armed and its stale/uncommitted pass dropped, so non-gate loopback
   * stays CLOSED while a fresh generation is owed. An uncommitted generation is
   * NEVER trusted to serve, so the tombstone is unconditional for
   * pf-loaded/manifest phases (stricter than the design table's "if the gate no
   * longer holds the port": it also covers the gate-still-holds-but-uncommitted
   * case, which must likewise never present as a committed green channel).
   */
  async recover(agentUid: number): Promise<GenerationRecoveryOutcome> {
    return withProvisionLock(this.lockPathFor(agentUid), this.ops.lock, () =>
      this.recoverLocked(agentUid),
    );
  }

  private async recoverLocked(agentUid: number): Promise<GenerationRecoveryOutcome> {
    const record = await this.ops.staging.load(agentUid);
    if (record === null) {
      return { agent_uid: agentUid, action: "none" };
    }
    const ownerHolds = await this.ops
      .verifyOwner({
        port: record.gate_port,
        pid: record.gate_pid,
        pidStart: record.gate_pid_start,
      })
      .catch(() => false);

    if (record.phase === "owner_checked") {
      // G2 crash: the pf arm (which runs only after the pf_loaded write-ahead)
      // never happened, so the staged port has no pass rule. Delete the dead
      // record; no packet-layer change.
      await this.ops.staging.delete(agentUid);
      return {
        agent_uid: agentUid,
        action: "discarded",
        generation_id: record.generation_id,
        owner_holds: ownerHolds,
      };
    }

    // pf_loaded | manifest_reloaded: the uid's pass rule MAY have been armed.
    // Tombstone fail-closed (drop the uncommitted pass, keep the block-drops);
    // the fallback supplies a valid port + the dead generation id (so the next
    // bring-up's monotonic id can never reuse it) if the arm did not land.
    await this.ops.registry.tombstone(agentUid, {
      gate_port: record.gate_port,
      fortress_path: record.fortress_path,
      generation_id: record.generation_id,
    });
    await this.ops.staging.delete(agentUid);
    return {
      agent_uid: agentUid,
      action: "tombstoned",
      generation_id: record.generation_id,
      owner_holds: ownerHolds,
    };
  }
}
