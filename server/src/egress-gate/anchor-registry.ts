/**
 * Locked multi-uid pf-anchor registry (Unified Protect Slice 5, S5-1).
 *
 * THE PROBLEM (review HIGH-4). The shared `sanctuary.egress-gate` pf anchor
 * holds one confinement block per confined uid, but the shipped primitives
 * treat it as single-uid: `armPfAnchor` loads ONE uid's rules with
 * `pfctl -a <anchor> -f` (a full REPLACE of the anchor contents) and
 * `disarmPfAnchor` runs `-F all` (flush EVERY uid's rules). So arming a second
 * confined uid would overwrite the first's confinement, and unprotecting agent
 * A would strip agent B's confinement until some drift-repair happened to
 * notice. There is no safe multi-agent story, and even single-agent re-arm is
 * a full replace with no concurrency guard.
 *
 * THE FIX (this module). A root-owned persistent registry is the single source
 * of truth for the anchor's contents: one entry per confined uid. Every
 * mutation takes an exclusive interprocess lock (the shipped O_EXCL
 * {@link ProvisionLockOps} discipline, fail-loud on contention), then applies
 * the change to the committed set, re-renders the FULL remaining union, loads
 * it into the anchor through the arm-equivalent {@link armPfAnchorUnion}
 * (hook + enable + settle -- never a bare `-f` that leaves rules unhooked),
 * verifies EXACT-union liveness for the whole set, and persists. Flush
 * (`disarmPfAnchor`'s `-F all`) is permitted ONLY when the set becomes empty.
 *
 * TRANSACTION SAFETY (Codex B1/M7 -- journaled two-phase). A liveness or save
 * failure must never leave the anchor and the registry divergent-and-silent.
 * Each mutation: (1) journals the `pending` desired set BEFORE touching the
 * anchor; (2) on success flips `committed = pending` and clears `pending`;
 * (3) on ANY apply failure, ROLLS BACK by re-asserting the previous committed
 * union and re-verifying it; (4) if rollback ALSO fails, sets a `dirty`
 * (needs-repair) marker and throws {@link PfAnchorRegistryDirtyError}. `list()`
 * exposes `dirty` so posture is forced red until an operator repair.
 *
 * DRIFT BEFORE LOCK (Codex H5 -- reconcile-on-entry). `withProvisionLock` only
 * serializes cooperating registry callers; it cannot stop the live anchor
 * drifting (a flush by macOS update, a crashed prior run). After acquiring the
 * lock, the registry re-verifies the committed union is still exact-live and
 * re-asserts it if not, before applying the new mutation. A repair that itself
 * fails marks the registry dirty.
 *
 * HONESTY BOUNDS. This is the multi-uid mutation-SAFETY primitive only. It does
 * NOT arm anything at install (that is S5-6's `arming-wiring.ts`), does NOT own the generation
 * state machine (S5-2, owed -- the state schema is versioned so `generation_id`
 * is added additively there), does NOT start the gate (S5-3, owed), and makes
 * NO external enforcement claim. HIGH-4 is REMEDIATED-once-callers-route-through
 * -this; the defect is not closed until the arming wiring lands. The anchor
 * confines TCP/UDP loopback sockets on lo0 per uid -- the exact drill-proven
 * scope, nothing wider.
 *
 * Every side effect (store I/O, lock, pfctl arm/disarm/liveness) is injected,
 * so the whole state machine -- including every rollback and dirty branch -- is
 * unit-testable against mocks without a real host, root, or pf.
 *
 * KNOWN BOUNDED RESIDUAL (gate re-review, LOW, accept-and-documented). On a
 * FIRST arm, the `pfctl -E` reference is acquired INSIDE `armPfAnchorUnion` and
 * only persisted when the mutation's commit save lands. If the process is KILLED
 * in the microsecond window between that `-E` and the commit save, the fresh
 * token is lost from both memory and disk: the next reconcile forces posture red
 * (the journaled `pending` reads dirty) and flushes the anchor to a known-empty
 * state, but it cannot `-X` a token it never learned, so pf is left with one
 * dangling enable reference (over-restrictive, never a confinement escape). This
 * is inherent to `-E` living inside the arm primitive; closing it fully would
 * require splitting enable from arm and journaling the token before the settle
 * probe. Bounded to one leaked reference per hard-crash-in-window; not fixed
 * here by deliberate minimalism (the primitive is not yet wired into install).
 */

import { validateExclusiveEgressGatePolicy } from "../castle-wall/allowlist/gate-derivation.js";
import {
  withProvisionLock,
  type ProvisionLockOps,
} from "../castle-wall/provision/lockfile.js";
import {
  PF_ANCHOR_NAME,
  armPfAnchorUnion,
  checkPfAnchorUnionLiveness,
  disarmPfAnchor,
  type ArmPfAnchorResult,
  type ArmPfAnchorUnionOptions,
  type PfAnchorUnionEntry,
  type PfCommandRunner,
  type PfLivenessResult,
} from "./pf-anchor.js";

export { ProvisionLockHeldError } from "../castle-wall/provision/lockfile.js";

/** Default root-owned registry file (0600). An internal on-disk artifact, not a frozen surface. */
export const PF_ANCHOR_REGISTRY_PATH = "/var/db/sanctuary/egress-anchor-registry.json";
/** Default O_EXCL lock beside the registry file. */
export const PF_ANCHOR_REGISTRY_LOCK_PATH = "/var/db/sanctuary/egress-anchor-registry.lock";
/** Persisted state schema version (S5-2 adds `generation_id` additively). */
export const PF_ANCHOR_REGISTRY_STATE_VERSION = 1 as const;

/** One confined uid in the registry. */
export interface PfAnchorRegistryEntry {
  /** The dedicated agent service-account uid the anchor confines. */
  agent_uid: number;
  /** The loopback TCP gate port this uid is confined to. */
  gate_port: number;
  /** The fortress this confinement belongs to (for boot re-arm + posture). */
  fortress_path: string;
  /**
   * The committed exclusive-egress GENERATION for this uid (Unified Protect
   * Slice 5 S5-2). Written by the generation state machine's G3 (pf load) with
   * the staged generation id; a uid is "actively committed" at that generation
   * only once the generation state machine's staging record is removed (G5).
   * ADDITIVE + OPTIONAL: v1 on-disk state that predates the generation machine
   * carries no `generation_id`; such an entry loads unchanged (a legacy
   * pre-generation confinement) and the state version stays `1`.
   */
  generation_id?: number;
  /**
   * Block-only tombstone (Unified Protect Slice 5 S5-2, folds Codex M4). When
   * `true`, the shared-anchor union renders ONLY this uid's four block-drops,
   * NOT its gate pass rule: the uid stays confined (non-gate loopback blocked)
   * but has no gate channel. The generation state machine's crash recovery sets
   * this when a uid's gate generation was staged into the anchor but never
   * committed, so the stale pass is removed without reopening loopback relay or
   * dropping the whole uid. `gate_port` is retained for schema validity but is
   * not rendered while tombstoned. ADDITIVE + OPTIONAL: absent === live.
   */
  tombstone?: boolean;
}

/** Persisted registry state. */
export interface PfAnchorRegistryState {
  version: typeof PF_ANCHOR_REGISTRY_STATE_VERSION;
  /** The last known-good armed union (one entry per confined uid). */
  committed: PfAnchorRegistryEntry[];
  /** The `pfctl -E` reference token held while the union is non-empty. */
  enable_token?: string;
  /** Journaled desired set mid-mutation (Codex B1); absent when quiescent. */
  pending?: PfAnchorRegistryEntry[];
  /** Needs-repair: the anchor and registry may diverge; posture MUST be red. */
  dirty?: boolean;
  /**
   * Generation floor (fix-round-5 P1): a STRICTLY-EXCEEDED lower bound for any
   * future generation allocation. Written by {@link PfAnchorRegistry.repairQuarantined}
   * when it REMOVES a quarantined entry whose raw parse carried a valid
   * `generation_id` that no surviving entry preserves (a removed duplicate, or
   * a malformed entry that could not be salvaged as a tombstone) -- without the
   * floor, the next bring-up would recompute from the surviving entry alone and
   * could REUSE the discarded generation, letting a stale manifest/pf rule
   * masquerade as current. Monotone: only ever raised. ADDITIVE + OPTIONAL
   * (absent === no floor); the state version stays `1`.
   */
  generation_floor?: number;
  /**
   * PRESERVED raw value of a malformed `generation_floor` (fix-round-6 F1).
   * A present-but-malformed floor must never be silently dropped: dropped
   * dirty-only, a later successful mutation cleared dirty and saved a state
   * WITHOUT the floor, making the discarded generation reallocatable
   * (monotonicity fail-open). Instead the raw value is carried here through
   * every mutation, the dirty marker stays STICKY while it is present (see
   * `clearDirtyUnlessFloorRepairOwed`), and only
   * {@link PfAnchorRegistry.repairQuarantined} resolves it (best-effort
   * numeric parse folded into the repaired floor; loud reset when
   * unrecoverable). A PARSEABLE raw is additionally folded into the effective
   * `generation_floor` on load, so the generation allocator respects it even
   * before repair. ADDITIVE + OPTIONAL; the state version stays `1`.
   */
  generation_floor_raw?: unknown;
}

/** Injected persistence for the registry state (root-owned file in production). */
export interface PfAnchorRegistryStore {
  /** Load the state, or `null` when no registry exists yet (first run). */
  load(): Promise<PfAnchorRegistryState | null>;
  /** Persist the state atomically (production: temp-write + rename, 0600). */
  save(state: PfAnchorRegistryState): Promise<void>;
  /**
   * Read the persisted state's RAW BYTES verbatim (`null` when no registry
   * exists). OPTIONAL, but the production FS store provides it: the quarantine
   * repair's forensic sidecar must preserve the byte-exact pre-repair file
   * (duplicate JSON keys, formatting -- everything `JSON.parse` flattens,
   * fix-round-5 P3). A store without raw access degrades the sidecar to a
   * canonical re-serialization of the parsed state.
   */
  loadRaw?(): Promise<string | null>;
}

/** Everything the registry needs, all injectable so it is host-free in tests. */
export interface PfAnchorRegistryOps {
  store: PfAnchorRegistryStore;
  lock: ProvisionLockOps;
  runner: PfCommandRunner;
  /** Defaults to {@link PF_ANCHOR_REGISTRY_LOCK_PATH}. */
  lockPath?: string;
  /** Defaults to {@link PF_ANCHOR_NAME}. */
  anchorName?: string;
  /** Arm-union options threaded to {@link armPfAnchorUnion} (settle tuning, mainConfPath). */
  armOptions?: Omit<ArmPfAnchorUnionOptions, "anchorName" | "existingEnableToken">;
  /** Injected for tests; default to the real pf-anchor functions. */
  armUnion?: (
    entries: readonly PfAnchorUnionEntry[],
    options: ArmPfAnchorUnionOptions,
  ) => Promise<ArmPfAnchorResult>;
  disarm?: (options: { anchorName: string; enableToken?: string }) => Promise<void>;
  unionLiveness?: (
    entries: readonly PfAnchorUnionEntry[],
    anchorName: string,
  ) => Promise<PfLivenessResult>;
  /**
   * Forensic sink for {@link PfAnchorRegistry.repairQuarantined}: persist the
   * BYTE-EXACT pre-repair registry file (fix-round-5 P3; the store's raw bytes
   * when it exposes {@link PfAnchorRegistryStore.loadRaw}, else a canonical
   * snapshot of the parsed state) BEFORE anything is removed and return the
   * absolute path written. MUST throw on failure (the repair then refuses to
   * remove anything -- an entry is never dropped without its bytes preserved).
   * Injected for tests; defaults to {@link createFsQuarantineForensicsWriter}.
   */
  quarantineForensics?: (payload: string) => Promise<string>;
}

/** The result of a mutation: the new committed set and whether repair is owed. */
export interface PfAnchorRegistryMutationResult {
  committed: PfAnchorRegistryEntry[];
  dirty: boolean;
}

/** One quarantined committed entry the repair verb acted on (fix-round-4 P2). */
export interface PfAnchorQuarantineRepairFinding {
  /** Position of the raw entry in the on-disk `committed` array. */
  index: number;
  /** The quarantine listing's classification reason. */
  reason: string;
  /** Best-effort uid recovered from the raw entry (`null` when unrecoverable). */
  agent_uid: number | null;
  /**
   * `tombstoned`: the raw entry's uid/port/fortress still validate, so the uid
   * is KEPT in the union as a block-only tombstone (packet-confined, no gate
   * channel) -- fail-closed for the affected agent. `removed`: nothing
   * renderable could be salvaged (or the uid duplicates a valid entry), so the
   * entry is dropped from the committed set outright.
   */
  disposition: "tombstoned" | "removed";
  /**
   * Present ONLY when a structurally VALID duplicate of a kept uid was REMOVED
   * (fix-round-5 P1): discarding a valid committed entry must be LOUD, naming
   * the kept sibling's generation and the removed one's (`null` when the
   * respective entry carries no generation). A removed generation is folded
   * into the persisted {@link PfAnchorRegistryState.generation_floor} so it
   * can never be reallocated.
   */
  duplicate?: {
    kept_generation_id: number | null;
    removed_generation_id: number | null;
  };
}

/** Result of {@link PfAnchorRegistry.repairQuarantined} (fix-round-4 P2). */
export interface PfAnchorQuarantineRepairResult {
  /** True when at least one quarantined entry was removed/tombstoned. */
  repaired: boolean;
  /** What was acted on, per entry (empty when `repaired` is false). */
  findings: PfAnchorQuarantineRepairFinding[];
  /** Absolute path of the forensic sidecar (`null` when nothing was repaired). */
  forensicPath: string | null;
  /** The committed set after the repair (valid entries + salvaged tombstones). */
  remaining: PfAnchorRegistryEntry[];
  /**
   * Present when the persisted generation floor itself was malformed and this
   * repair resolved it (fix-round-6 F1). `parsed` is the best-effort numeric
   * recovery of the preserved raw value (`null` = unrecoverable). When
   * unrecoverable, the floor is RESET to the maximum generation observed
   * across surviving entries + tombstones (+ any generation removed by this
   * repair) with NO invented safety margin; the caller MUST report that reset
   * loudly (the original floor was unrecoverable; re-provision is advised).
   * `resolved_floor` is the floor actually persisted (`null` when no
   * generation survived anywhere to derive a floor from, in which case no
   * floor is persisted at all).
   */
  floorRepair?: {
    raw: unknown;
    parsed: number | null;
    resolved_floor: number | null;
    unrecoverable: boolean;
  };
}

/**
 * Production forensic writer for {@link PfAnchorRegistry.repairQuarantined}:
 * a root-only (0600) timestamped sidecar beside the registry file, opened
 * `wx` so an existing capture is never overwritten. Returns the path written.
 */
export function createFsQuarantineForensicsWriter(
  registryPath: string = PF_ANCHOR_REGISTRY_PATH,
): (payload: string) => Promise<string> {
  return async (payload: string): Promise<string> => {
    const { writeFile, mkdir } = await import("node:fs/promises");
    const { dirname } = await import("node:path");
    await mkdir(dirname(registryPath), { recursive: true, mode: 0o700 }).catch(() => undefined);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const path = `${registryPath}.quarantine-${stamp}-${process.pid}.json`;
    await writeFile(path, payload, { mode: 0o600, flag: "wx" });
    return path;
  };
}

/** The persisted state was corrupt/unusable. Fail-closed: never mutate from an unknown baseline. */
export class PfAnchorRegistryStateError extends Error {
  constructor(message: string) {
    super(`pf-anchor registry state is unusable: ${message}`);
    this.name = "PfAnchorRegistryStateError";
  }
}

/**
 * A mutation failed AND the rollback to the previous committed union also
 * failed -- the anchor and the registry may diverge. The registry is marked
 * dirty; posture MUST read red and an operator repair is owed. Carries both
 * the original cause and the rollback failure.
 */
export class PfAnchorRegistryDirtyError extends Error {
  readonly cause: unknown;
  readonly rollbackError: unknown;
  constructor(cause: unknown, rollbackError: unknown) {
    super(
      "pf-anchor registry is DIRTY: a mutation failed and the rollback to the previous " +
        "confined-uid union also failed, so the anchor and the registry may diverge. Posture " +
        "must be treated as NOT protected until 'sanctuary ... repair-egress-gate' re-asserts " +
        `the union. Original failure: ${errText(cause)}. Rollback failure: ${errText(rollbackError)}.`,
    );
    this.name = "PfAnchorRegistryDirtyError";
    this.cause = cause;
    this.rollbackError = rollbackError;
  }
}

function errText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function isNonNegativeInt(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 0;
}

/** Validate one entry (untrusted JSON from the store). Fail-closed on anything off. */
function validateEntry(candidate: unknown): PfAnchorRegistryEntry | null {
  if (candidate === null || typeof candidate !== "object") return null;
  const c = candidate as Record<string, unknown>;
  // Reuse the gate-policy floor (uid >= 1, not root, valid port).
  if (validateExclusiveEgressGatePolicy({ agent_uid: c.agent_uid, gate_port: c.gate_port }) === null) {
    return null;
  }
  if (typeof c.fortress_path !== "string" || c.fortress_path.length === 0) return null;
  // ADDITIVE optional fields (S5-2). Reject a present-but-malformed value
  // (fail-closed: a garbled generation/tombstone marker is a repair signal,
  // never silently coerced); a MISSING field is the v1-compatible legacy shape.
  // `generation_id` must be a POSITIVE integer WITH allocation headroom
  // (fix-round-8, `hasGenerationHeadroom`): generated ids start at 1
  // (`computeNextGenerationId`), so a persisted 0 is a corruption/reuse
  // signal, and an unsafe-magnitude id would wedge every future allocation
  // (n+1 === n at 2^53) -- both are repair signals, never silently coerced.
  if (
    c.generation_id !== undefined &&
    (typeof c.generation_id !== "number" || !hasGenerationHeadroom(c.generation_id))
  ) {
    return null;
  }
  if (c.tombstone !== undefined && typeof c.tombstone !== "boolean") return null;
  const entry: PfAnchorRegistryEntry = {
    agent_uid: c.agent_uid as number,
    gate_port: c.gate_port as number,
    fortress_path: c.fortress_path,
  };
  if (c.generation_id !== undefined) entry.generation_id = c.generation_id as number;
  if (c.tombstone === true) entry.tombstone = true;
  return entry;
}

/**
 * A generation value is usable ONLY with allocation headroom (fix-round-8):
 * the value and value+1 must both be safe integers, because
 * `computeNextGenerationId` allocates value+1 and the gate runtime rejects
 * unsafe generation ids -- at 2^53-1, n+1 === n, so an at-or-above value
 * would make every future allocation collide. This is the SINGLE boundary
 * shared by entry validation, floor classification/parsing, and repair
 * salvage, so no unsafe number can reach the allocator.
 */
function hasGenerationHeadroom(n: number): boolean {
  return Number.isSafeInteger(n) && n >= 1 && Number.isSafeInteger(n + 1);
}

/**
 * Best-effort numeric recovery of a malformed generation-floor value
 * (fix-round-6 F1): a number, or a numeric string (e.g. `"8"`), that resolves
 * to a finite value >= 1 WITH allocation headroom (`hasGenerationHeadroom`).
 * Fractional values round UP (a floor must never be lowered by coercion).
 * Anything else is unrecoverable (`null`).
 */
function parseGenerationFloorRaw(raw: unknown): number | null {
  const n =
    typeof raw === "number"
      ? raw
      : typeof raw === "string" && raw.trim() !== ""
        ? Number(raw)
        : Number.NaN;
  if (!Number.isFinite(n) || n < 1) return null;
  const ceiled = Math.ceil(n);
  if (!hasGenerationHeadroom(ceiled)) return null;
  return ceiled;
}

/**
 * Classify the persisted generation floor of a loaded state (fix-round-6 F1):
 * the SHARED boundary between `normalizeState`, `listQuarantined`, and
 * `repairQuarantined`, so all three agree on what counts as a malformed floor.
 * `validFloor` is a well-formed persisted `generation_floor`; `raw` is the
 * preserved evidence of a malformed one (either a malformed `generation_floor`
 * observed now, or a `generation_floor_raw` carried from an earlier load);
 * `rawParsed` is the best-effort numeric recovery across that evidence.
 */
function classifyGenerationFloor(loaded: PfAnchorRegistryState): {
  validFloor?: number;
  raw?: unknown;
  rawParsed: number | null;
} {
  const out: { validFloor?: number; raw?: unknown; rawParsed: number | null } = {
    rawParsed: null,
  };
  const rawCandidates: unknown[] = [];
  if (loaded.generation_floor !== undefined) {
    // Same allocation-headroom bound as parseGenerationFloorRaw: a
    // well-formed-looking floor at or above 2^53-1 cannot allocate a distinct
    // next id, so it is malformed evidence, not a valid floor.
    if (
      typeof loaded.generation_floor === "number" &&
      hasGenerationHeadroom(loaded.generation_floor)
    ) {
      out.validFloor = loaded.generation_floor;
    } else {
      rawCandidates.push(loaded.generation_floor);
    }
  }
  if (loaded.generation_floor_raw !== undefined) {
    rawCandidates.push(loaded.generation_floor_raw);
  }
  if (rawCandidates.length > 0) {
    // The newest malformed evidence wins as the preserved raw (a malformed
    // `generation_floor` can only appear via external mutation and is newer
    // than a carried raw); the parse folds across ALL candidates, monotone.
    out.raw = rawCandidates[0];
    for (const candidate of rawCandidates) {
      const parsed = parseGenerationFloorRaw(candidate);
      if (parsed !== null) out.rawParsed = Math.max(out.rawParsed ?? 0, parsed);
    }
  }
  return out;
}

/**
 * Clear the needs-repair marker after a successful mutation, reconcile, or
 * rollback -- UNLESS a preserved malformed generation-floor raw is still
 * pending repair (fix-round-6 F1). A successful apply proves the ANCHOR
 * matches the registry, but it cannot resolve the floor: clearing dirty here
 * would let posture read green (and the next save look clean) while the
 * floor's true value is still unknown. Only
 * {@link PfAnchorRegistry.repairQuarantined} resolves the raw and clears this.
 */
function clearDirtyUnlessFloorRepairOwed(state: PfAnchorRegistryState): void {
  if (state.generation_floor_raw === undefined) {
    delete state.dirty;
  } else {
    state.dirty = true;
  }
}

/** Normalize a loaded state (or `null`) into a usable state. Throws on corruption. */
function normalizeState(loaded: PfAnchorRegistryState | null): PfAnchorRegistryState {
  if (loaded === null) {
    return { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed: [] };
  }
  if (typeof loaded !== "object") {
    throw new PfAnchorRegistryStateError("not an object");
  }
  if (loaded.version !== PF_ANCHOR_REGISTRY_STATE_VERSION) {
    throw new PfAnchorRegistryStateError(`unknown state version ${String(loaded.version)}`);
  }
  if (!Array.isArray(loaded.committed)) {
    throw new PfAnchorRegistryStateError("committed is not an array");
  }
  const committed: PfAnchorRegistryEntry[] = [];
  const seen = new Set<number>();
  for (const raw of loaded.committed) {
    const entry = validateEntry(raw);
    if (entry === null) {
      throw new PfAnchorRegistryStateError("a committed entry is malformed");
    }
    if (seen.has(entry.agent_uid)) {
      throw new PfAnchorRegistryStateError(`duplicate committed agent_uid ${entry.agent_uid}`);
    }
    seen.add(entry.agent_uid);
    committed.push(entry);
  }
  const state: PfAnchorRegistryState = { version: PF_ANCHOR_REGISTRY_STATE_VERSION, committed };
  if (typeof loaded.enable_token === "string" && /^\d+$/.test(loaded.enable_token)) {
    state.enable_token = loaded.enable_token;
  }
  // Preserve the journaled `pending` set (gate finding: it was dropped on
  // reload, making the two-phase journal dead across a crash). Validate it the
  // same way as `committed`; a malformed journal is a REPAIR signal (dirty),
  // never silently discarded.
  if (loaded.pending !== undefined) {
    const pending: PfAnchorRegistryEntry[] = [];
    const pseen = new Set<number>();
    let pendingOk = Array.isArray(loaded.pending);
    if (pendingOk) {
      for (const raw of loaded.pending) {
        const e = validateEntry(raw);
        if (e === null || pseen.has(e.agent_uid)) {
          pendingOk = false;
          break;
        }
        pseen.add(e.agent_uid);
        pending.push(e);
      }
    }
    if (pendingOk) {
      state.pending = pending;
    } else {
      state.dirty = true;
    }
  }
  if (loaded.dirty === true) state.dirty = true;
  // Fix-round-5 P1 + fix-round-6 F1: preserve the persisted generation floor
  // (a strictly-exceeded lower bound for future generation allocation, written
  // by the quarantine repair verb when it removes an entry carrying a
  // generation_id no surviving entry preserves). A present-but-malformed floor
  // is a repair signal (dirty) and its RAW value is PRESERVED in
  // `generation_floor_raw`, never silently dropped: a floor that vanished on
  // the next save would make the discarded generation reallocatable once a
  // later mutation cleared dirty (the round-6 fail-open). A parseable raw is
  // ALSO folded into the effective floor (defense in depth: the allocator
  // respects it even before repair), and dirty stays STICKY until
  // repairQuarantined resolves the raw (see clearDirtyUnlessFloorRepairOwed).
  const floorInfo = classifyGenerationFloor(loaded);
  if (floorInfo.validFloor !== undefined || floorInfo.rawParsed !== null) {
    state.generation_floor = Math.max(floorInfo.validFloor ?? 0, floorInfo.rawParsed ?? 0);
  }
  if (floorInfo.raw !== undefined) {
    state.generation_floor_raw = floorInfo.raw;
    state.dirty = true;
  }
  // A non-empty committed set with no valid enable token is inconsistent (pf
  // should be enabled and its reference releasable): treat as needs-repair
  // (gate finding). reconcile-on-entry re-asserts the committed union, which
  // re-acquires a fresh `-E` token.
  if (committed.length > 0 && state.enable_token === undefined) {
    state.dirty = true;
  }
  return state;
}

/**
 * Structural checks + per-entry quarantine classification of a loaded state
 * (the SHARED boundary between `listQuarantined` and `repairQuarantined`,
 * fix-round-4 P2: what the listing classifies as malformed is exactly what
 * the repair verb may act on -- nothing more). STRUCTURAL corruption throws;
 * a malformed or duplicate ENTRY becomes a quarantined finding carrying its
 * raw value (for forensics), while the valid entries stay usable.
 */
function classifyCommitted(loaded: PfAnchorRegistryState): {
  entries: PfAnchorRegistryEntry[];
  quarantined: { index: number; reason: string; raw: unknown }[];
} {
  if (typeof loaded !== "object") {
    throw new PfAnchorRegistryStateError("not an object");
  }
  if (loaded.version !== PF_ANCHOR_REGISTRY_STATE_VERSION) {
    throw new PfAnchorRegistryStateError(`unknown state version ${String(loaded.version)}`);
  }
  if (!Array.isArray(loaded.committed)) {
    throw new PfAnchorRegistryStateError("committed is not an array");
  }
  const entries: PfAnchorRegistryEntry[] = [];
  const quarantined: { index: number; reason: string; raw: unknown }[] = [];
  const seen = new Set<number>();
  loaded.committed.forEach((raw, index) => {
    const entry = validateEntry(raw);
    if (entry === null) {
      quarantined.push({
        index,
        reason: "malformed committed entry (failed the fail-closed entry validation)",
        raw,
      });
      return;
    }
    if (seen.has(entry.agent_uid)) {
      quarantined.push({ index, reason: `duplicate committed agent_uid ${entry.agent_uid}`, raw });
      return;
    }
    seen.add(entry.agent_uid);
    entries.push(entry);
  });
  return { entries, quarantined };
}

/**
 * The pf-union view of a registry entry (what the pf primitives consume). A
 * tombstoned entry (S5-2) is threaded through as a block-only union member, so
 * arm + liveness render/verify its four block-drops and REJECT any gate pass
 * for it; a live entry renders pass + block-drops as before.
 */
function toUnionEntry(entry: PfAnchorRegistryEntry): PfAnchorUnionEntry {
  return {
    agent_uid: entry.agent_uid,
    gate_port: entry.gate_port,
    ...(entry.tombstone === true ? { tombstone: true } : {}),
  };
}

/**
 * An FS-backed store (temp-write + rename for atomicity, 0600).
 *
 * HONEST BOUND (fix-round-6 F3, accepted documented residual). The registry
 * file -- including `generation_floor` -- is protected by root-only fs modes
 * (0700 directory / 0600 file) and by COOPERATIVE-MUTATION monotonicity only
 * (this module never lowers the floor and never drops a preserved raw). An
 * EXTERNAL restore of an older registry file (a root actor, a backup/rollback
 * tool, disk-image restore) can lower the floor or resurrect a removed entry;
 * nothing here anchors the file against that. This is the same residual class
 * as the other root-owned state files in this codebase; anti-rollback
 * anchoring is a separate ratified mechanism class and is deliberately NOT
 * built into this store.
 */
export function createFsRegistryStore(path: string = PF_ANCHOR_REGISTRY_PATH): PfAnchorRegistryStore {
  return {
    async load(): Promise<PfAnchorRegistryState | null> {
      const { readFile } = await import("node:fs/promises");
      let text: string;
      try {
        text = await readFile(path, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
      try {
        return JSON.parse(text) as PfAnchorRegistryState;
      } catch (err) {
        throw new PfAnchorRegistryStateError(
          `registry file ${path} is not valid JSON: ${errText(err)}`,
        );
      }
    },
    async loadRaw(): Promise<string | null> {
      const { readFile } = await import("node:fs/promises");
      try {
        return await readFile(path, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
    },
    async save(state: PfAnchorRegistryState): Promise<void> {
      const { writeFile, rename, mkdir } = await import("node:fs/promises");
      const { dirname } = await import("node:path");
      await mkdir(dirname(path), { recursive: true, mode: 0o700 }).catch(() => undefined);
      const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
      await writeFile(tmp, JSON.stringify(state), { mode: 0o600 });
      await rename(tmp, path);
    },
  };
}

/**
 * The locked multi-uid pf-anchor registry. Construct once with injected ops;
 * call {@link addOrUpdate} / {@link remove} to change the confined-uid set and
 * {@link list} to read it. Every mutation is serialized by the exclusive lock
 * and is transaction-safe (journaled pending -> commit, rollback-on-failure,
 * dirty-on-rollback-failure) and drift-repairing (reconcile-on-entry).
 */
export class PfAnchorRegistry {
  private readonly store: PfAnchorRegistryStore;
  private readonly lock: ProvisionLockOps;
  private readonly lockPath: string;
  private readonly anchorName: string;
  private readonly armOptions: Omit<ArmPfAnchorUnionOptions, "anchorName" | "existingEnableToken">;
  private readonly armUnion: NonNullable<PfAnchorRegistryOps["armUnion"]>;
  private readonly disarm: NonNullable<PfAnchorRegistryOps["disarm"]>;
  private readonly unionLiveness: NonNullable<PfAnchorRegistryOps["unionLiveness"]>;
  private readonly quarantineForensics: NonNullable<PfAnchorRegistryOps["quarantineForensics"]>;

  constructor(ops: PfAnchorRegistryOps) {
    this.store = ops.store;
    this.lock = ops.lock;
    this.lockPath = ops.lockPath ?? PF_ANCHOR_REGISTRY_LOCK_PATH;
    this.anchorName = ops.anchorName ?? PF_ANCHOR_NAME;
    this.armOptions = ops.armOptions ?? {};
    const runner = ops.runner;
    const anchorName = this.anchorName;
    this.armUnion =
      ops.armUnion ?? ((entries, options) => armPfAnchorUnion(runner, entries, options));
    this.disarm = ops.disarm ?? ((options) => disarmPfAnchor(runner, options));
    this.unionLiveness =
      ops.unionLiveness ??
      ((entries) => checkPfAnchorUnionLiveness(runner, entries, anchorName));
    this.quarantineForensics = ops.quarantineForensics ?? createFsQuarantineForensicsWriter();
  }

  /**
   * Read the current confined-uid set and whether repair is owed. Lockless
   * snapshot. A journaled `pending` set (a mutation that was in flight when the
   * process died) counts as dirty: the anchor may not match `committed` until
   * the next mutation's reconcile-on-entry re-asserts it, so posture must not
   * read green (gate finding: `pending` was ignored here).
   */
  async list(): Promise<{ entries: PfAnchorRegistryEntry[]; dirty: boolean; generationFloor?: number }> {
    const state = normalizeState(await this.store.load());
    return {
      entries: state.committed,
      dirty: state.dirty === true || state.pending !== undefined,
      // Fix-round-5 P1: surface the persisted generation floor so allocation
      // adapters (generation bring-up) can never reuse a repair-discarded id.
      // Fix-round-6 F1: this includes a PARSEABLE malformed-raw floor folded
      // on load, so allocation respects it even while repair is still owed.
      ...(state.generation_floor !== undefined ? { generationFloor: state.generation_floor } : {}),
    };
  }

  /**
   * Read the committed set with PER-ENTRY QUARANTINE (fix-round-2 MED-6): one
   * malformed committed entry must not starve the boot daemon's oracle
   * refresh loop for every OTHER agent -- with the wholesale-throwing
   * {@link list}, a single bad entry made the refresh return before
   * refreshing anyone and every gate denied within one token TTL.
   *
   * SEMANTICS (fail-closed direction preserved):
   *  - STRUCTURAL corruption (unparseable JSON, wrong version, `committed`
   *    not an array) still THROWS wholesale: there is no trustworthy entry to
   *    salvage from a file whose shape is unknown.
   *  - A malformed or duplicate ENTRY is returned as a `quarantined` finding
   *    (individually identified by index + reason) while the remaining valid
   *    entries stay usable. The quarantined entry's own agent gets NO
   *    refresh, so ITS gate keeps denying (fail-closed for the bad entry,
   *    live for the good ones).
   *  - Any quarantined entry forces `dirty` (repair owed): posture must
   *    never read green over a quarantine.
   *
   * READ-ONLY consumers only (the refresh loop / boot supervisor). Every
   * MUTATION still normalizes wholesale fail-closed via `normalizeState`:
   * never mutate from a partially-valid baseline.
   */
  async listQuarantined(): Promise<{
    entries: PfAnchorRegistryEntry[];
    dirty: boolean;
    quarantined: { index: number; reason: string }[];
  }> {
    const loaded = await this.store.load();
    if (loaded === null) {
      return { entries: [], dirty: false, quarantined: [] };
    }
    const { entries, quarantined } = classifyCommitted(loaded);
    const enableTokenValid =
      typeof loaded.enable_token === "string" && /^\d+$/.test(loaded.enable_token);
    // Fix-round-6 F2: a malformed persisted generation_floor must be VISIBLE
    // on this read path too -- the boot supervisor and oracle refresh loop
    // read through here, and a floor problem only normalizeState noticed
    // would let the boot refresh run green over a monotonicity hole. It is
    // reported as a registry-LEVEL finding (index -1: it is not a committed
    // entry) and FORCES dirty, so every token is withheld until repair.
    const floorInfo = classifyGenerationFloor(loaded);
    const quarantinedOut = quarantined.map((q) => ({ index: q.index, reason: q.reason }));
    if (floorInfo.raw !== undefined) {
      quarantinedOut.push({
        index: -1,
        reason:
          "registry-level generation_floor is malformed (not a committed entry; the raw value " +
          "is preserved for repair); generation-floor monotonicity cannot be trusted until " +
          "'sanctuary protect --repair-egress-gate' resolves it",
      });
    }
    const dirty =
      loaded.dirty === true ||
      loaded.pending !== undefined ||
      quarantined.length > 0 ||
      floorInfo.raw !== undefined ||
      (entries.length > 0 && !enableTokenValid);
    return {
      entries,
      dirty,
      quarantined: quarantinedOut,
    };
  }

  /**
   * The coded recovery path for a QUARANTINED committed entry (fix-round-4
   * P2). A malformed committed entry correctly marks the registry dirty
   * (fail-closed: every token is withheld host-wide), but every registry
   * MUTATION normalizes wholesale via `normalizeState`, which THROWS on that
   * same entry -- so without this verb the documented repair
   * (`--repair-egress-gate`) failed before it could rewrite anything and the
   * only way out was manual registry surgery.
   *
   * SEMANTICS (root-only caller, loud, audited by the repair sequence):
   *  - Acts ONLY on entries the quarantine listing itself classifies as
   *    malformed/duplicate ({@link classifyCommitted} -- the exact same
   *    boundary `listQuarantined` reports). Transiently-invalid state (a
   *    missing/garbled enable token, a journaled `pending` set, an explicit
   *    dirty marker) is NEVER grounds to drop an entry: with no quarantined
   *    entry this is a read-only no-op and the normal mutation reconcile
   *    handles that dirt without discarding confinement state.
   *  - STRUCTURAL corruption (unparseable file, wrong version, `committed`
   *    not an array) still throws wholesale: nothing salvageable.
   *  - Forensics FIRST and BYTE-EXACT (fix-round-5 P3): the pre-repair
   *    registry file's raw bytes are persisted verbatim through the injected
   *    {@link PfAnchorRegistryOps.quarantineForensics} sink BEFORE any
   *    removal; a forensic write failure aborts the repair with the registry
   *    untouched.
   *  - Fail-closed disposition per entry: when the raw entry's
   *    uid/port/fortress still validate, the uid is KEPT as a block-only
   *    TOMBSTONE (packet-confined, gate channel gone) rather than dropped --
   *    removing it would drop its live block rules from the anchor
   *    (fail-open). Only an entry with nothing renderable (or a duplicate of
   *    a valid sibling) is removed outright. Either way the affected uid
   *    needs re-provisioning before its gate serves again.
   *  - Generation monotonicity (fix-round-5 P1): a REMOVED entry whose raw
   *    parse carried a valid `generation_id` folds that id into the persisted
   *    {@link PfAnchorRegistryState.generation_floor}, and removing a
   *    structurally VALID duplicate is reported loudly with both generations
   *    (see {@link PfAnchorQuarantineRepairFinding.duplicate}) -- a discarded
   *    generation must never be silently reusable.
   *  - Malformed floor resolution (fix-round-6 F1): a preserved malformed
   *    `generation_floor` raw (see
   *    {@link PfAnchorRegistryState.generation_floor_raw}) is RESOLVED here:
   *    a parseable raw folds into the repaired floor; an unrecoverable raw
   *    resets the floor to the maximum generation still observable across
   *    surviving entries + tombstones (no invented margin), reported via
   *    {@link PfAnchorQuarantineRepairResult.floorRepair} so the caller says
   *    LOUDLY that the original floor was unrecoverable and re-provision is
   *    advised. A floor problem alone makes this verb act (it is not a no-op).
   *  - The remaining union is re-rendered + re-armed and the state persisted
   *    CLEAN (the explicit re-assert supersedes any journaled `pending`,
   *    exactly like reconcile-on-entry). An arm/save failure leaves the
   *    on-disk registry untouched (still quarantined + dirty, posture red)
   *    and throws.
   */
  async repairQuarantined(): Promise<PfAnchorQuarantineRepairResult> {
    return withProvisionLock(this.lockPath, this.lock, async () => {
      const loaded = await this.store.load();
      if (loaded === null) {
        return { repaired: false, findings: [], forensicPath: null, remaining: [] };
      }
      const { entries: valid, quarantined } = classifyCommitted(loaded);
      // Fix-round-6 F1: a malformed persisted generation_floor is ALSO a
      // repairable finding -- without this, the preserved raw kept the
      // registry dirty forever (sticky by design) while the documented repair
      // verb reported "nothing to repair".
      const floorInfo = classifyGenerationFloor(loaded);
      if (quarantined.length === 0 && floorInfo.raw === undefined) {
        return { repaired: false, findings: [], forensicPath: null, remaining: valid };
      }
      // Forensics FIRST, and BYTE-EXACT (fix-round-5 P3): the sidecar is the
      // ORIGINAL on-disk registry file copied verbatim BEFORE any mutation --
      // duplicate JSON keys, formatting, everything `JSON.parse` flattens. A
      // store without raw access (an injected non-FS store) degrades to a
      // canonical snapshot of the parsed state; the production FS store is raw.
      // Nothing is removed unless this write lands.
      const rawBytes = this.store.loadRaw !== undefined ? await this.store.loadRaw() : null;
      const forensicPath = await this.quarantineForensics(
        rawBytes ??
          JSON.stringify(
            {
              captured_at: new Date().toISOString(),
              registry_version: loaded.version,
              note:
                "canonical (non-byte-exact) pre-repair snapshot -- the store exposed no raw bytes; " +
                "raw committed entries removed/tombstoned by the quarantine repair verb " +
                "(sanctuary protect --repair-egress-gate); the affected uid(s) must be re-provisioned",
              quarantined,
            },
            null,
            2,
          ),
      );
      const findings: PfAnchorQuarantineRepairFinding[] = [];
      const next = [...valid];
      let removedGenerationMax: number | undefined;
      for (const q of quarantined) {
        const raw = (q.raw !== null && typeof q.raw === "object" ? q.raw : {}) as Record<string, unknown>;
        const uid =
          typeof raw.agent_uid === "number" && Number.isInteger(raw.agent_uid) ? raw.agent_uid : null;
        const rawGenerationId =
          typeof raw.generation_id === "number" && hasGenerationHeadroom(raw.generation_id)
            ? raw.generation_id
            : null;
        let disposition: PfAnchorQuarantineRepairFinding["disposition"] = "removed";
        let duplicate: PfAnchorQuarantineRepairFinding["duplicate"];
        if (uid !== null && !next.some((e) => e.agent_uid === uid)) {
          // Carry the raw generation_id when it is independently valid (the
          // entry may be malformed for an unrelated field): dropping a live
          // id here would let the next bring-up reuse an already-committed
          // generation (the same monotonicity rule the S5-2 tombstone
          // fallback preserves).
          const salvage = validateEntry({
            agent_uid: raw.agent_uid,
            gate_port: raw.gate_port,
            fortress_path: raw.fortress_path,
            tombstone: true,
            ...(rawGenerationId !== null ? { generation_id: rawGenerationId } : {}),
          });
          if (salvage !== null) {
            next.push(salvage);
            disposition = "tombstoned";
          }
        } else if (uid !== null && validateEntry(q.raw) !== null) {
          // Fix-round-5 P1 (loudness): a structurally VALID committed entry is
          // being REMOVED because it duplicates a kept uid. Name both
          // generations in the report so the discard is loud, never silent.
          const kept = next.find((e) => e.agent_uid === uid);
          duplicate = {
            kept_generation_id: kept?.generation_id ?? null,
            removed_generation_id: rawGenerationId,
          };
        }
        if (disposition === "removed" && rawGenerationId !== null) {
          // Fix-round-5 P1 (monotonicity): a REMOVED entry's parseable
          // generation_id survives in no entry, so fold it into the persisted
          // floor below -- otherwise the next bring-up recomputes from the
          // kept sibling (e.g. gen 7) and REUSES the discarded id (gen 8).
          removedGenerationMax = Math.max(removedGenerationMax ?? 0, rawGenerationId);
        }
        findings.push({
          index: q.index,
          reason: q.reason,
          agent_uid: uid,
          disposition,
          ...(duplicate !== undefined ? { duplicate } : {}),
        });
      }
      // Re-render + re-arm the union from what remains, then persist CLEAN. A
      // failure here propagates with the on-disk registry untouched: still
      // quarantined + dirty, posture red, repair still owed -- never a
      // half-repaired silent state.
      const state: PfAnchorRegistryState = {
        version: PF_ANCHOR_REGISTRY_STATE_VERSION,
        committed: next,
      };
      if (typeof loaded.enable_token === "string" && /^\d+$/.test(loaded.enable_token)) {
        state.enable_token = loaded.enable_token;
      }
      // Fold the generation floor: carry any valid persisted floor forward and
      // raise it to cover every generation removed above. Monotone by
      // construction (Math.max); never lowered, never dropped by a repair.
      const priorFloor = floorInfo.validFloor;
      let nextFloor =
        priorFloor !== undefined || removedGenerationMax !== undefined
          ? Math.max(priorFloor ?? 0, removedGenerationMax ?? 0)
          : undefined;
      // Fix-round-6 F1: RESOLVE a preserved malformed floor. Parseable raw:
      // fold the recovered value in (monotone). Unrecoverable raw: reset the
      // floor to the maximum generation still observable across surviving
      // entries + tombstones (+ anything removed above) -- no invented safety
      // margin; the honest bound is "at least every generation we can still
      // see". The caller must report the reset loudly (the original floor was
      // unrecoverable; re-provision is advised). Either way the raw is
      // consumed here: the repaired state carries no `generation_floor_raw`,
      // which un-sticks the dirty marker.
      let floorRepair: PfAnchorQuarantineRepairResult["floorRepair"];
      if (floorInfo.raw !== undefined) {
        if (floorInfo.rawParsed !== null) {
          nextFloor = Math.max(nextFloor ?? 0, floorInfo.rawParsed);
          floorRepair = {
            raw: floorInfo.raw,
            parsed: floorInfo.rawParsed,
            resolved_floor: nextFloor,
            unrecoverable: false,
          };
        } else {
          const maxObservedGeneration = next.reduce(
            (max, entry) => Math.max(max, entry.generation_id ?? 0),
            0,
          );
          const reset = Math.max(nextFloor ?? 0, maxObservedGeneration);
          nextFloor = reset >= 1 ? reset : undefined;
          floorRepair = {
            raw: floorInfo.raw,
            parsed: null,
            resolved_floor: nextFloor ?? null,
            unrecoverable: true,
          };
        }
      }
      if (nextFloor !== undefined) {
        state.generation_floor = nextFloor;
      }
      await this.applyUnion(state, next);
      await this.store.save(state);
      return {
        repaired: true,
        findings,
        forensicPath,
        remaining: next,
        ...(floorRepair !== undefined ? { floorRepair } : {}),
      };
    });
  }

  /**
   * Add a confined uid, or update the gate_port/fortress of an existing one.
   * Re-renders + re-arms the full union and verifies exact-union liveness for
   * every remaining uid; a second uid never drops the first's rules.
   */
  async addOrUpdate(entry: PfAnchorRegistryEntry): Promise<PfAnchorRegistryMutationResult> {
    const validated = validateEntry(entry);
    if (validated === null) {
      throw new PfAnchorRegistryStateError(
        `refusing to add a malformed registry entry (uid ${String(entry?.agent_uid)}, ` +
          `port ${String(entry?.gate_port)})`,
      );
    }
    return this.mutate((committed) => {
      const next = committed.filter((e) => e.agent_uid !== validated.agent_uid);
      next.push(validated);
      return next;
    });
  }

  /**
   * Remove a confined uid. The remaining union is re-armed and re-verified;
   * the anchor is flushed (`disarmPfAnchor`'s `-F all`, the ONLY permitted
   * flush) only when the LAST uid leaves. Removing an absent uid is a no-op
   * that still reconciles the current union.
   */
  async remove(agentUid: number): Promise<PfAnchorRegistryMutationResult> {
    if (!isNonNegativeInt(agentUid)) {
      throw new PfAnchorRegistryStateError(`refusing to remove a non-integer uid ${String(agentUid)}`);
    }
    return this.mutate((committed) => committed.filter((e) => e.agent_uid !== agentUid));
  }

  /**
   * Block-only TOMBSTONE a confined uid (Unified Protect Slice 5 S5-2, folds
   * Codex M4). The uid stays in the union but its gate pass rule is dropped and
   * ONLY its four block-drops are re-armed, so non-gate loopback stays CLOSED
   * for the uid while its stale/uncommitted gate channel is removed. This is
   * the generation state machine's crash-recovery action when a uid's gate
   * generation was staged into the anchor (its pass loaded at G3) but never
   * committed (G5): dropping the whole entry would drop the block-drops too and
   * reopen non-gate loopback mid-repair, so the tombstone keeps the packet
   * layer closed until a fresh generation commits or unprotect removes the uid.
   *
   * FAIL-CLOSED for the not-yet-armed uid: if the uid is absent from the
   * registry (a crash BEFORE G3's arm actually landed the entry, where the
   * write-ahead journal recorded intent), a block-only entry is ADDED from the
   * `fallback` (the staged port + fortress from the generation staging record),
   * so recovery reaches a confined-but-gateless state rather than leaving the
   * uid un-confined. A `fallback` is REQUIRED when the uid is absent (no port to
   * validate an entry otherwise). Idempotent: tombstoning an already-tombstoned
   * uid re-arms the same block-only union.
   */
  async tombstone(
    agentUid: number,
    fallback?: { gate_port: number; fortress_path: string; generation_id?: number },
  ): Promise<PfAnchorRegistryMutationResult> {
    if (!isNonNegativeInt(agentUid)) {
      throw new PfAnchorRegistryStateError(`refusing to tombstone a non-integer uid ${String(agentUid)}`);
    }
    return this.mutate((committed) => {
      const existing = committed.find((e) => e.agent_uid === agentUid);
      if (existing !== undefined) {
        return committed.map((e) =>
          e.agent_uid === agentUid ? { ...e, tombstone: true } : e,
        );
      }
      // Absent: add a block-only entry from the fallback (validated below). The
      // dead generation's id is CARRIED so generation-id monotonicity holds
      // across this recovery (gate finding: dropping it let the next bring-up
      // reuse an already-staged id).
      if (fallback === undefined) {
        throw new PfAnchorRegistryStateError(
          `refusing to tombstone absent uid ${agentUid} without a fallback {gate_port, fortress_path} ` +
            "(no port to construct a valid block-only entry)",
        );
      }
      const added = validateEntry({
        agent_uid: agentUid,
        gate_port: fallback.gate_port,
        fortress_path: fallback.fortress_path,
        tombstone: true,
        ...(fallback.generation_id !== undefined ? { generation_id: fallback.generation_id } : {}),
      });
      if (added === null) {
        throw new PfAnchorRegistryStateError(
          `refusing to tombstone uid ${agentUid}: malformed fallback (port ${String(fallback.gate_port)})`,
        );
      }
      return [...committed, added];
    });
  }

  /**
   * The shared mutation core: lock -> load -> reconcile-on-entry -> journal
   * pending -> apply (arm union or flush) -> commit -> (on failure) rollback
   * -> (on rollback failure) dirty. See the module doc for the full contract.
   */
  private async mutate(
    apply: (committed: PfAnchorRegistryEntry[]) => PfAnchorRegistryEntry[],
  ): Promise<PfAnchorRegistryMutationResult> {
    return withProvisionLock(this.lockPath, this.lock, async () => {
      const state = normalizeState(await this.store.load());

      // Reconcile-on-entry (Codex H5): make sure the committed union is still
      // exact-live before layering a new mutation on top. Re-asserts on drift;
      // marks dirty if the re-assert itself fails.
      await this.reconcile(state);

      const previousCommitted = [...state.committed];
      const previousToken = state.enable_token;
      const desired = apply(state.committed);
      assertNoDuplicateUids(desired);

      // Journal the pending desired set BEFORE touching the anchor (Codex B1).
      state.pending = desired;
      await this.store.save(state);

      let forwardReleased = false;
      try {
        // `forwardReleased` is true iff this apply released the pf enable
        // reference (the remove-last flush path). rollback needs it to decide
        // whether to re-acquire a fresh `-E` vs reuse the prior token.
        forwardReleased = await this.applyUnion(state, desired);
        state.committed = desired;
        delete state.pending;
        clearDirtyUnlessFloorRepairOwed(state);
        await this.store.save(state);
        // Fix-round-6 F1: report the REAL post-mutation dirtiness -- a sticky
        // malformed-floor raw keeps the registry dirty through a successful
        // mutation, and the caller must not read that as clean.
        return { committed: state.committed, dirty: state.dirty === true };
      } catch (applyErr) {
        // Roll back to the previous committed union. Throws
        // PfAnchorRegistryDirtyError if the rollback itself fails.
        await this.rollback(state, previousCommitted, previousToken, forwardReleased, applyErr);
        throw applyErr;
      }
    });
  }

  /**
   * Apply a desired set to the anchor: flush when empty (releasing the enable
   * token), otherwise arm the union (reusing hook + enable + settle). Updates
   * `state.enable_token` and returns whether it RELEASED the enable reference
   * (the empty/flush path), so a caller's rollback knows to re-acquire a fresh
   * `-E` rather than reuse a spent token (gate finding).
   */
  private async applyUnion(
    state: PfAnchorRegistryState,
    desired: PfAnchorRegistryEntry[],
  ): Promise<boolean> {
    if (desired.length === 0) {
      // Empty set: flush the anchor and release the pf enable reference. This
      // is the ONLY sanctioned `-F all`.
      const hadToken = state.enable_token !== undefined;
      await this.disarm({
        anchorName: this.anchorName,
        ...(hadToken ? { enableToken: state.enable_token } : {}),
      });
      delete state.enable_token;
      return hadToken;
    }
    const res = await this.armUnion(desired.map(toUnionEntry), {
      ...this.armOptions,
      anchorName: this.anchorName,
      ...(state.enable_token !== undefined ? { existingEnableToken: state.enable_token } : {}),
    });
    if (res.enableToken !== undefined) {
      state.enable_token = res.enableToken;
    }
    return false;
  }

  /**
   * Reconcile the live anchor with the committed union on entry. A drifted
   * (not exact-live) committed union is re-asserted; a re-assert that fails
   * marks the registry dirty and throws {@link PfAnchorRegistryDirtyError}.
   * An empty committed set has nothing to re-assert (the next add loads the
   * anchor fresh, which replaces any stale contents).
   */
  private async reconcile(state: PfAnchorRegistryState): Promise<void> {
    if (state.committed.length === 0) {
      // Nothing confined. If a repair marker is set (dirty, or a journaled
      // pending from a crashed run), do a REAL repair -- actively flush the
      // anchor + release any enable reference to reach a KNOWN-empty state --
      // rather than just deleting the marker (gate finding: clearing dirty
      // without proving the anchor empty could leave stale rules + a stuck pf
      // enable while posture reads clean). Only clear the marker on success.
      if (state.dirty || state.pending !== undefined) {
        try {
          await this.applyUnion(state, []); // disarm: `-F all` + release token
          clearDirtyUnlessFloorRepairOwed(state);
          delete state.pending;
          await this.store.save(state);
        } catch (repairErr) {
          state.dirty = true;
          await this.store.save(state).catch(() => undefined);
          throw new PfAnchorRegistryDirtyError(
            new Error("reconcile-on-entry could not flush the anchor to a known-empty state"),
            repairErr,
          );
        }
      }
      return;
    }
    const live = await this.unionLiveness(state.committed.map(toUnionEntry), this.anchorName);
    if (live.live && state.dirty !== true && state.pending === undefined) {
      return; // already exact-live and clean
    }
    // Drift (or a leftover dirty/pending marker): re-assert the committed set.
    try {
      await this.applyUnion(state, state.committed);
      clearDirtyUnlessFloorRepairOwed(state);
      delete state.pending;
      await this.store.save(state);
    } catch (repairErr) {
      state.dirty = true;
      await this.store.save(state).catch(() => undefined);
      throw new PfAnchorRegistryDirtyError(
        new Error("reconcile-on-entry could not re-assert the committed union"),
        repairErr,
      );
    }
  }

  /**
   * Roll back a failed mutation by re-asserting the previous committed union.
   * On success, restores committed/token and returns (the caller rethrows the
   * original apply error). On rollback failure, marks the registry dirty and
   * throws {@link PfAnchorRegistryDirtyError}.
   *
   * `forwardReleased` (gate finding) tells rollback whether the FAILED apply
   * already released the pf enable reference (the remove-last flush path). If
   * so, `previousToken` is spent and pf is disabled, so rollback must re-arm
   * the previous union with a FRESH `-E`, not reuse the dead token.
   */
  private async rollback(
    state: PfAnchorRegistryState,
    previousCommitted: PfAnchorRegistryEntry[],
    previousToken: string | undefined,
    forwardReleased: boolean,
    cause: unknown,
  ): Promise<void> {
    try {
      if (previousCommitted.length === 0) {
        // The previous state was empty, so rolling back means returning the
        // anchor to empty. CRITICAL (gate re-review finding): flush using the
        // token CURRENTLY in state, NOT previousToken. A forward add-to-empty
        // that SUCCEEDED (acquiring a fresh `-E` into state.enable_token) and
        // then failed at commit-save must have that fresh token RELEASED by the
        // flush; resetting to previousToken (undefined) here would drop it and
        // leak the pf enable reference silently. applyUnion([]) releases
        // whatever token state currently holds (the fresh one, or none if the
        // forward arm threw and cleaned up its own reference).
        await this.applyUnion(state, []);
        state.committed = [];
      } else if (forwardReleased) {
        // The forward apply RELEASED the enable reference (remove-last flushed +
        // `-X`, then the commit save failed). pf is disabled and `previousToken`
        // is spent -- clear it so the re-arm acquires a FRESH `-E`.
        delete state.enable_token;
        await this.applyUnion(state, previousCommitted);
        state.committed = previousCommitted;
      } else {
        // The forward apply threw WITHOUT releasing (a mid-arm failure). The
        // previous token, if any, is still live; re-assert with it.
        if (previousToken !== undefined) {
          state.enable_token = previousToken;
        } else {
          delete state.enable_token;
        }
        await this.applyUnion(state, previousCommitted);
        state.committed = previousCommitted;
      }
      delete state.pending;
      clearDirtyUnlessFloorRepairOwed(state);
      await this.store.save(state);
    } catch (rollbackErr) {
      state.dirty = true;
      // Keep `pending` so a later repair knows what was attempted.
      await this.store.save(state).catch(() => undefined);
      throw new PfAnchorRegistryDirtyError(cause, rollbackErr);
    }
  }
}

/** Fail-closed guard: the desired set must never carry two entries for one uid. */
function assertNoDuplicateUids(entries: PfAnchorRegistryEntry[]): void {
  const seen = new Set<number>();
  for (const e of entries) {
    if (seen.has(e.agent_uid)) {
      throw new PfAnchorRegistryStateError(
        `duplicate agent_uid ${e.agent_uid} in the desired confined-uid set`,
      );
    }
    seen.add(e.agent_uid);
  }
}
