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
 * NOT arm anything at install (that is S5-6, owed), does NOT own the generation
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
}

/** Injected persistence for the registry state (root-owned file in production). */
export interface PfAnchorRegistryStore {
  /** Load the state, or `null` when no registry exists yet (first run). */
  load(): Promise<PfAnchorRegistryState | null>;
  /** Persist the state atomically (production: temp-write + rename, 0600). */
  save(state: PfAnchorRegistryState): Promise<void>;
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
}

/** The result of a mutation: the new committed set and whether repair is owed. */
export interface PfAnchorRegistryMutationResult {
  committed: PfAnchorRegistryEntry[];
  dirty: boolean;
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
  // `generation_id` must be a POSITIVE integer: generated ids start at 1
  // (`computeNextGenerationId`), so a persisted 0 is a corruption/reuse signal,
  // never a legitimate committed generation (gate finding).
  if (c.generation_id !== undefined && (!Number.isInteger(c.generation_id) || (c.generation_id as number) < 1)) {
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

/** An FS-backed store (temp-write + rename for atomicity, 0600). */
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
  }

  /**
   * Read the current confined-uid set and whether repair is owed. Lockless
   * snapshot. A journaled `pending` set (a mutation that was in flight when the
   * process died) counts as dirty: the anchor may not match `committed` until
   * the next mutation's reconcile-on-entry re-asserts it, so posture must not
   * read green (gate finding: `pending` was ignored here).
   */
  async list(): Promise<{ entries: PfAnchorRegistryEntry[]; dirty: boolean }> {
    const state = normalizeState(await this.store.load());
    return {
      entries: state.committed,
      dirty: state.dirty === true || state.pending !== undefined,
    };
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
        delete state.dirty;
        await this.store.save(state);
        return { committed: state.committed, dirty: false };
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
          delete state.dirty;
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
      delete state.dirty;
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
      delete state.dirty;
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
