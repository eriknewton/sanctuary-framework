/**
 * Sanctuary exit machinery — Slice 1: ownership provenance (memory class).
 *
 * This module adds the *ownership* axis to the exit path. It is orthogonal to
 * the SDW *secrecy* taint lattice (`sdw/provenance.ts`): secrecy controls
 * whether a byte may be persisted; ownership controls whether a byte may
 * travel *with whom* on exit. The two axes ride together but answer different
 * questions.
 *
 * ── WHAT THIS SLICE SHIPS (and, just as load-bearing, what it does NOT) ─────
 * It ships the honest infrastructure: a write-time ownership stamp, the three
 * memory classes, a conservative partition at the exit boundary, a first-class
 * audited consent transition, and an exit tombstone that is labelled as an
 * auditable receipt of intent-to-remove (NOT cryptographic erasure). It ships
 * NO external "provable clean exit" claim. The reasons are written into the
 * code so a future reader cannot accidentally promote the claim:
 *
 *   1. `memory_class` rides a forgeable carrier on any write path that bypasses
 *      or re-mints the sealed minter (the documented `taintClean` /
 *      caller-asserted `mintPersistable` hole — `sdw/README.md:17-29`). SDW has
 *      no live crown-jewel consumers yet, so the sealed minter is bypassable.
 *      Routing real sources through the sealed minter and retiring the
 *      caller-asserted path is **Slice 2 — the SECURITY PRECONDITION** for any
 *      external clean-exit claim. Until then `memory_class` is forgeable on
 *      un-instrumented paths.
 *   2. Tombstone is not erasure: a full-disk snapshot restore resurrects
 *      "scrubbed" data and is locally undetectable, exactly as
 *      `core/anti-rollback.ts` documents for the credential case. This module
 *      labels its tombstone accordingly and never claims erasure.
 *
 * ── THE LOAD-BEARING SAFETY PROPERTY (the conservative default) ─────────────
 * Anything that did NOT arrive through the sealed minter as verifiably
 * `agent_owned` defaults to `operator_owned` / `shared_entangled` at the
 * partition boundary, NEVER `agent_owned`. Forgeable-class data therefore fails
 * toward "stays with the operator." Because the default fails toward staying,
 * this slice cannot create a new leak: the worst case is that legitimately
 * agent-owned work is conservatively retained (recoverable through the audited
 * consent path), never that operator data walks out cryptographically blessed.
 *
 * Because the partition is mandatory at the export boundary (the export throws
 * unless the caller either supplies a partition or explicitly opts into a loud,
 * named full-export), and because a sealed stamp is bound to the one record it
 * was minted for (no stamp-confusion across records), the ownership-classed exit
 * path does not weaken the existing export: an entry only travels when a live,
 * record-bound, sealed `agent_owned` stamp says so. The residual is the
 * disclosed M-1/A1 hole — on un-instrumented or re-authoring paths `memory_class`
 * is forgeable, which is why those paths conservatively stay with the operator
 * and why NO external clean-exit claim ships until Slice 2 binds stamps to
 * provenance at the source.
 *
 * Asymmetry of harm (review judgment, kept verbatim in spirit): a false
 * retention is recoverable by an audited agreement; a false release is
 * irreversible exfiltration. We default to the recoverable error.
 */

const SEALED_STAMP_BRAND: unique symbol = Symbol("sanctuary.exit.sealed-memory-class-stamp");

/**
 * Registry of stamps minted by THIS module's sealed minter in THIS process.
 * Mirrors the `Tainted<V>` carrier's anti-forgery pattern in
 * `sdw/provenance.ts`: a plain object that merely *looks* like a stamp is not
 * in the set, so it cannot pass `assertSealedStamp`. This is the in-process
 * guarantee. The cross-process / on-disk guarantee is the consumer-integration
 * follow-on (Slice 2): until real sources route through this minter, an
 * on-disk stamp deserialized from an un-instrumented write is NOT in the set
 * and is treated as unsealed (conservative default).
 */
const sealedStamps = new WeakSet<object>();

/** The three exit dispositions, one-to-one with the three memory classes. */
export type MemoryClass = "operator_owned" | "agent_owned" | "shared_entangled";

/** Who authored the write. Reuses the SDW actor vocabulary. */
export type OriginActor = "operator" | "agent" | "system";

/**
 * The append-only ownership stamp, written at the same moment as the secrecy
 * taint. `derived_from` is the lineage-graph edge set: a non-empty edge into an
 * `operator_owned` lineage is what promotes an otherwise-`agent_owned` write to
 * `shared_entangled` (purely graph-mechanical, no inference).
 */
export interface ProvenanceStamp {
  readonly memory_class: MemoryClass;
  readonly origin_actor: OriginActor;
  readonly origin_ref: string;
  readonly lineage_id: string;
  readonly written_at: string;
  readonly derived_from: readonly string[];
  /**
   * The exit-partition identity of the record this stamp was minted FOR (the
   * `"<namespace>/<key>"` of the state entry, or any stable per-record id). The
   * partition requires `entry_binding === candidate.id` so a sealed stamp minted
   * for record A cannot be presented to release record B (the stamp-confusion
   * attack). A stamp minted with no binding (`undefined`) is never includable
   * via the bundle partition — it can only be used for classification/telemetry.
   */
  readonly entry_binding?: string;
}

/**
 * A stamp produced by the sealed minter. The brand is non-enumerable and the
 * carrier is frozen and registered in `sealedStamps`, so the *only* way to
 * obtain a `SealedProvenanceStamp` that passes `assertSealedStamp` is through
 * `mintProvenanceStamp` in this process. A hand-built object literal with the
 * same shape is NOT sealed.
 */
export interface SealedProvenanceStamp extends ProvenanceStamp {
  readonly [SEALED_STAMP_BRAND]: true;
}

/** Inputs the caller declares. The agent's ONLY influence is `derived_from`. */
export interface MintStampInput {
  readonly origin_actor: OriginActor;
  readonly origin_ref: string;
  readonly lineage_id: string;
  /**
   * Lineage ids this datum is derived from, paired with the class each derived
   * lineage carried. The caller supplies the edges; the class is then computed
   * deterministically, never declared. An omitted edge is the residual A1 hole
   * (semantic re-authoring) — disclosed, not solved, by this slice.
   */
  readonly derived_from?: readonly DerivedFromEdge[];
  readonly written_at?: string;
  /**
   * The `"<namespace>/<key>"` (or stable record id) this stamp is minted FOR.
   * Required for any stamp that will be presented to the exit-bundle partition;
   * the partition rejects a stamp whose binding does not equal the candidate id.
   * Omit only for classification-only / telemetry uses that never travel.
   */
  readonly entry_binding?: string;
}

export interface DerivedFromEdge {
  readonly lineage_id: string;
  readonly memory_class: MemoryClass;
}

export class MemoryClassError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "MemoryClassError";
    this.code = code;
  }
}

/**
 * The single source of truth for the `memory_class` assignment. The class is
 * *defaulted by deterministic rule*, never trusted from a caller-declared
 * field. Rules (no ML, no heuristics that could mis-class toward `agent_owned`):
 *
 *   - origin_actor === "operator"  → operator_owned
 *   - origin_actor === "system"    → operator_owned (system bookkeeping stays
 *                                     with the fortress; never travels)
 *   - origin_actor === "agent" with NO operator-derived edge → agent_owned
 *   - origin_actor === "agent" WITH an operator_owned/shared_entangled edge
 *                                  → shared_entangled
 *
 * The "derived from operator data ⇒ shared" rule is the only non-trivial one,
 * and it is purely graph-mechanical: it reads recorded edges, it does not infer.
 *
 * Note the conservative tilt: an agent write only earns `agent_owned` when it
 * has no recorded operator/shared lineage. Any recorded entanglement demotes it
 * to `shared_entangled` (which does not travel absent consent).
 */
export function classifyMemoryClass(input: MintStampInput): MemoryClass {
  // Assert the actor at runtime: TypeScript types vanish at runtime, and a
  // fall-through default to `agent_owned` for an unrecognized actor would be a
  // class-assignment hole if this function were ever reused directly. Invalid
  // actor fails closed (throws), never defaults toward `agent_owned`.
  assertOriginActor(input.origin_actor);
  if (input.origin_actor === "operator") return "operator_owned";
  if (input.origin_actor === "system") return "operator_owned";
  // origin_actor === "agent"
  const edges = input.derived_from ?? [];
  for (const edge of edges) {
    assertEdge(edge);
    if (edge.memory_class === "operator_owned" || edge.memory_class === "shared_entangled") {
      return "shared_entangled";
    }
  }
  return "agent_owned";
}

/**
 * Mint a SEALED ownership stamp. This is the ONLY path that can produce a stamp
 * that passes `assertSealedStamp` (and therefore the only path that can produce
 * a *trusted* `agent_owned` class at partition time). The class is computed by
 * `classifyMemoryClass`; the caller cannot inject a class.
 */
export function mintProvenanceStamp(input: MintStampInput): SealedProvenanceStamp {
  assertOriginActor(input.origin_actor);
  assertNonEmpty(input.origin_ref, "origin_ref");
  assertNonEmpty(input.lineage_id, "lineage_id");
  const memory_class = classifyMemoryClass(input);
  const derived_from = Object.freeze(
    (input.derived_from ?? []).map((edge) => {
      assertEdge(edge);
      return edge.lineage_id;
    }),
  );
  if (input.entry_binding !== undefined) {
    assertNonEmpty(input.entry_binding, "entry_binding");
  }
  const stamp = Object.create(null) as SealedProvenanceStamp;
  Object.defineProperties(stamp, {
    [SEALED_STAMP_BRAND]: { value: true },
    memory_class: { value: memory_class, enumerable: true },
    origin_actor: { value: input.origin_actor, enumerable: true },
    origin_ref: { value: input.origin_ref, enumerable: true },
    lineage_id: { value: input.lineage_id, enumerable: true },
    written_at: { value: input.written_at ?? new Date().toISOString(), enumerable: true },
    derived_from: { value: derived_from, enumerable: true },
    ...(input.entry_binding !== undefined
      ? { entry_binding: { value: input.entry_binding, enumerable: true } }
      : {}),
  });
  Object.freeze(stamp);
  sealedStamps.add(stamp);
  return stamp;
}

/**
 * True iff `value` is a stamp minted by this module's sealed minter in this
 * process. A plain object that merely matches the shape returns false.
 */
export function isSealedStamp(value: unknown): value is SealedProvenanceStamp {
  return (
    value !== null &&
    typeof value === "object" &&
    sealedStamps.has(value as object)
  );
}

export function assertSealedStamp(value: unknown): asserts value is SealedProvenanceStamp {
  if (!isSealedStamp(value)) {
    throw new MemoryClassError(
      "unsealed_stamp",
      "Ownership stamp did not arrive through the sealed memory-class minter",
    );
  }
}

/**
 * Serialize a stamp to a plain JSON object for persistence (riding alongside a
 * record). The serialized form is INTENTIONALLY NOT sealed: once it has touched
 * disk and been re-read by an un-instrumented path, it must be re-evaluated
 * conservatively, not trusted by virtue of carrying a class field. This is the
 * on-disk expression of M-1: the seal is an in-process property, not a
 * persisted credential. Slice 2 closes this by routing real consumers through
 * the minter so the persisted form is bound to provenance.
 */
export function serializeStamp(stamp: SealedProvenanceStamp): ProvenanceStamp {
  assertSealedStamp(stamp);
  return {
    memory_class: stamp.memory_class,
    origin_actor: stamp.origin_actor,
    origin_ref: stamp.origin_ref,
    lineage_id: stamp.lineage_id,
    written_at: stamp.written_at,
    derived_from: [...stamp.derived_from],
    ...(stamp.entry_binding !== undefined ? { entry_binding: stamp.entry_binding } : {}),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Conservative partition — the load-bearing exit-boundary filter.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A candidate record at the partition boundary. `sealedStamp` is the in-process
 * sealed stamp when (and only when) this record was minted via the sealed
 * minter in this process and the stamp object was carried through unchanged. On
 * every other path it is undefined — a deserialized-from-disk stamp, an
 * un-instrumented write, a re-minted stamp — and the partition treats the
 * record as unsealed.
 */
export interface PartitionCandidate {
  readonly id: string;
  /**
   * The in-process sealed stamp, if present. Carrying the live object (not a
   * deserialized copy) is what proves the record went through the sealed minter
   * this process. Absent ⇒ unsealed ⇒ conservative default.
   */
  readonly sealedStamp?: SealedProvenanceStamp;
  /**
   * The on-disk / declared stamp, if any. Used ONLY to compute the conservative
   * fallback class for telemetry; it is NEVER trusted to mark a record
   * includable. A declared `agent_owned` on an unsealed record is downgraded.
   */
  readonly declaredStamp?: ProvenanceStamp;
}

export type PartitionExclusionReason =
  | "unsealed_stamp_defaulted_operator_owned"
  | "stamp_binding_mismatch_defaulted_operator_owned"
  | "class_operator_owned"
  | "class_shared_entangled_no_consent"
  | "released_by_consent";

/**
 * A consent release as consumed by the partition. This is the SHAPE of
 * `ConsentReleaseReceipt` (defined in `consent.ts`), restated here to avoid a
 * cyclic import. The partition only releases a `shared_entangled` record when a
 * receipt for its exact lineage exists with `disposition: "released_to_agent"`
 * and `memory_class: "shared_entangled"` — a raw lineage-id string is no longer
 * sufficient (codex MED: an unauthenticated string list let a caller release
 * shared data without an audited receipt).
 */
export interface PartitionConsentRelease {
  readonly lineage_id: string;
  readonly memory_class: MemoryClass;
  readonly disposition: string;
}

export interface PartitionDecision {
  readonly id: string;
  /** The class used for the exit decision (post conservative-default). */
  readonly effective_class: MemoryClass;
  /** True iff this record is includable in the outbound (agent) bundle. */
  readonly includable: boolean;
  /** Why a record was excluded (undefined when includable). */
  readonly reason?: PartitionExclusionReason;
  /** True iff the record's stamp arrived through the sealed minter. */
  readonly sealed: boolean;
}

export interface PartitionResult {
  readonly includable: readonly PartitionDecision[];
  readonly excluded: readonly PartitionDecision[];
  readonly decisions: readonly PartitionDecision[];
}

/**
 * Partition records by ownership for the exit bundle, applying the conservative
 * default. A record is includable in the agent's outbound bundle IFF:
 *
 *   (a) its stamp arrived through the sealed minter in this process
 *       (`isSealedStamp` on the carried object), AND
 *   (b) that sealed stamp's class is `agent_owned`, OR the record's lineage_id
 *       is in `consentReleasedLineageIds` (an audited consent release, below).
 *
 * EVERYTHING ELSE is excluded:
 *   - any unsealed record → effective `operator_owned` (conservative default;
 *     the most restrictive failure, NEVER `agent_owned`),
 *   - sealed `operator_owned` → stays,
 *   - sealed `shared_entangled` without consent → stays (escrow disposition is
 *     the deferred Slice-2 holding pen; here it simply does not travel).
 *
 * This is the function the review named the load-bearing one: a bypassed /
 * re-minted / absent stamp defaults to operator_owned and is EXCLUDED.
 */
export function partitionByMemoryClass(
  candidates: readonly PartitionCandidate[],
  options?: {
    /**
     * Audited consent-release receipts (the persisted records returned by
     * `recordConsentRelease`). A `shared_entangled` record becomes includable
     * ONLY when a receipt for its exact `lineage_id` is present with
     * `disposition: "released_to_agent"` and `memory_class: "shared_entangled"`.
     * A bare lineage-id string is intentionally NOT accepted (codex MED): the
     * release must trace to an audited two-party receipt, not an unauthenticated
     * caller-supplied list.
     */
    readonly consentReleases?: readonly PartitionConsentRelease[];
  },
): PartitionResult {
  const released = new Map<string, PartitionConsentRelease>();
  for (const receipt of options?.consentReleases ?? []) {
    if (
      receipt !== null &&
      typeof receipt === "object" &&
      typeof receipt.lineage_id === "string" &&
      receipt.lineage_id.length > 0 &&
      receipt.disposition === "released_to_agent" &&
      receipt.memory_class === "shared_entangled"
    ) {
      released.set(receipt.lineage_id, receipt);
    }
  }
  const includable: PartitionDecision[] = [];
  const excluded: PartitionDecision[] = [];
  const decisions: PartitionDecision[] = [];

  for (const candidate of candidates) {
    const decision = decideOne(candidate, released);
    decisions.push(decision);
    if (decision.includable) includable.push(decision);
    else excluded.push(decision);
  }

  return {
    includable,
    excluded,
    decisions,
  };
}

function decideOne(
  candidate: PartitionCandidate,
  released: ReadonlyMap<string, PartitionConsentRelease>,
): PartitionDecision {
  const sealed = isSealedStamp(candidate.sealedStamp);

  if (!sealed) {
    // Conservative default: any record whose stamp did not arrive through the
    // sealed minter is treated as operator_owned and excluded. We NEVER honor a
    // declared `agent_owned` on an unsealed record — that is precisely the
    // forgery the default exists to defeat.
    return {
      id: candidate.id,
      effective_class: "operator_owned",
      includable: false,
      reason: "unsealed_stamp_defaulted_operator_owned",
      sealed: false,
    };
  }

  const stamp = candidate.sealedStamp as SealedProvenanceStamp;

  // Stamp-confusion defense (codex HIGH): a sealed stamp is only valid for the
  // record it was minted FOR. A stamp with no binding, or one whose binding
  // does not equal this candidate's id, is treated as unsealed-equivalent and
  // defaults to operator_owned. This stops presenting a legit agent_owned stamp
  // (minted for record A) under record B's entry key to smuggle B out.
  if (stamp.entry_binding === undefined || stamp.entry_binding !== candidate.id) {
    return {
      id: candidate.id,
      effective_class: "operator_owned",
      includable: false,
      reason: "stamp_binding_mismatch_defaulted_operator_owned",
      sealed: false,
    };
  }

  const cls = stamp.memory_class;

  if (cls === "agent_owned") {
    return { id: candidate.id, effective_class: cls, includable: true, sealed: true };
  }

  if (cls === "shared_entangled") {
    if (released.has(stamp.lineage_id)) {
      // Released by an audited two-party agreement (consent path). It travels,
      // and the exclusion reason records that it was a consent release, not a
      // default inclusion.
      return {
        id: candidate.id,
        effective_class: cls,
        includable: true,
        reason: "released_by_consent",
        sealed: true,
      };
    }
    return {
      id: candidate.id,
      effective_class: cls,
      includable: false,
      reason: "class_shared_entangled_no_consent",
      sealed: true,
    };
  }

  // operator_owned
  return {
    id: candidate.id,
    effective_class: cls,
    includable: false,
    reason: "class_operator_owned",
    sealed: true,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function assertOriginActor(actor: unknown): asserts actor is OriginActor {
  if (actor !== "operator" && actor !== "agent" && actor !== "system") {
    throw new MemoryClassError("invalid_origin_actor", "origin_actor must be operator|agent|system");
  }
}

function assertNonEmpty(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new MemoryClassError("invalid_field", `${label} must be a non-empty string`);
  }
}

function assertEdge(edge: unknown): asserts edge is DerivedFromEdge {
  if (
    edge === null ||
    typeof edge !== "object" ||
    typeof (edge as { lineage_id?: unknown }).lineage_id !== "string" ||
    (edge as { lineage_id: string }).lineage_id.length === 0
  ) {
    throw new MemoryClassError("invalid_edge", "derived_from edge must carry a non-empty lineage_id");
  }
  const cls = (edge as { memory_class?: unknown }).memory_class;
  if (cls !== "operator_owned" && cls !== "agent_owned" && cls !== "shared_entangled") {
    throw new MemoryClassError("invalid_edge", "derived_from edge must carry a valid memory_class");
  }
}
