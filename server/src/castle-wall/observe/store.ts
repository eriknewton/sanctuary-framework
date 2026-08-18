/**
 * Castle Wall Observe / Learn Allow-List v1 -- StateStore persistence.
 *
 * A candidate row (and the observe-mode toggle) is a first-class encrypted
 * state object in the reserved `_castle_wall_observe` namespace, exactly
 * like `_file_grants` (see `file-grant/store.ts`). This is the ONLY place
 * that knows how a candidate is serialized into a StateStore entry; the CLI
 * goes through it. Because it calls the StateStore's own
 * `write`/`read`/`list`/`delete` methods directly, a candidate round-trips
 * through the same encrypted, signed, monotonic-versioned, Merkle-verified
 * machinery every other piece of Sanctuary state does (AGENTS.md Invariant
 * #2), and the reserved `_`-prefix namespace firewall in
 * `cognitive/tools.ts` keeps the agent-facing `state_read`/`state_list`/
 * `state_delete` MCP tools from reaching it directly -- a candidate
 * describes exactly which destinations the operator has NOT yet allowed, so
 * it must never be a policy-inference oracle for the agent it describes
 * (Invariant #7, property #11; adversarial review finding M1).
 *
 * WHY THE LISTING LOOPS BELOW DO NOT USE THE TOLERANT NAMESPACE SCAN. The
 * shared `cognitive/namespace-scan.ts` fan-out isolates a per-entry read
 * failure so a caller can act on a partial set. That is right where a partial
 * set is still useful, and wrong here. Each of these three loops feeds a
 * consumer that treats a MISSING row as a positive verdict: an absent
 * `source-state:` row means "this source never contributed", which is what
 * carries definitive-empty authority downstream; an absent `candidate:` row
 * means "no denial was observed for this destination"; an absent
 * `candidate-review:` row means "not yet reviewed". Skipping an unreadable row
 * would be indistinguishable from those, so an unreadable row would be READ AS
 * A PASS. A propagating read failure is the fail-closed answer here, and the
 * malformed-row cases that CAN be told apart are already routed to the
 * `quarantined` lists rather than dropped. Do not "fix" these into tolerance.
 *
 * THE RED-LINE INVARIANT: nothing in this file, or anywhere reachable from
 * it, ever writes to the live signed allowlist manifest. This store is
 * read/written ONLY by the observe CLI surface and `promote.ts`'s
 * orchestration (which itself never mutates the manifest without an
 * explicit approved promote). The enforcing evaluator
 * (`../egress-proxy.ts`) has no dependency on this module at all.
 */

import type { EncryptedPayload } from "../../core/encryption.js";
import type { StateStore } from "../../cognitive/state-store.js";
import { mergeCandidateObservations } from "./fold.js";
import {
  OBSERVE_AUDIT_SOURCE_IDS,
  OBSERVE_NAMESPACE,
  OBSERVE_SCHEMA_VERSION,
  candidateKey,
  candidateKeyDigest,
  isObserveAuditSourceId,
  type CandidateObservation,
  type FoldWatermark,
  type ObserveAuditSourceId,
  type ObserveCandidateReviewAction,
  type ObserveCandidateReviewRecord,
  type ObserveModeState,
} from "./types.js";

/** The signing identity a `ObserveStore` writes under. */
export interface ObserveWriteIdentity {
  identityId: string;
  encryptedPrivateKey: EncryptedPayload;
  identityEncryptionKey: Uint8Array;
}

const STATE_KEY = "state";
const FOLD_WATERMARK_KEY = "fold-watermark";
const LAST_REFRESH_KEY = "last-refresh";
const CANDIDATE_KEY_PREFIX = "candidate:";
const CANDIDATE_REVIEW_KEY_PREFIX = "candidate-review:";
const SOURCE_STATE_KEY_PREFIX = "source-state:";
const PAGE_SIZE = 100;

export type ObserveSourceReadStatus = "read_ok" | "read_failed" | "absent";

/**
 * Fixed-key metadata for an audit source. This is deliberately NOT a per-row
 * contribution map: Option A keeps candidate rows aggregate-only, and uses
 * this marker solely to distinguish "source never contributed here" from
 * "source used to contribute and is now missing/unreadable" for empty-claim
 * honesty.
 */
export interface ObserveSourceState {
  source_id: ObserveAuditSourceId;
  ever_contributed: boolean;
  last_read_status: ObserveSourceReadStatus;
  last_read_at: string;
  last_instance_id?: string;
  last_contributed_at?: string;
}

export interface QuarantinedObserveSourceState {
  key: string;
  reason: string;
  source_id?: string;
}

export interface ObserveSourceStateSnapshot {
  known: Map<ObserveAuditSourceId, ObserveSourceState>;
  quarantined: QuarantinedObserveSourceState[];
}

export interface QuarantinedObserveCandidateReviewRecord {
  key: string;
  reason: string;
  candidate_key?: string;
}

export interface ObserveCandidateReviewSnapshot {
  known: Map<string, ObserveCandidateReviewRecord>;
  quarantined: QuarantinedObserveCandidateReviewRecord[];
}

export type ObserveLastRefreshStatus =
  | "refreshed"
  | "source_read_incomplete"
  | "allowlist_unverified";

export type ObserveLastRefreshFailure =
  | "source_unreadable"
  | "missing_after_contribution"
  | "instance_changed_after_contribution";

export interface ObserveLastRefreshSourceRead {
  source_id: ObserveAuditSourceId;
  status: ObserveSourceReadStatus;
  entries_read?: number;
  flow_events?: number;
  candidate_rows?: number;
  head_sequence?: number | null;
  head_hash?: string | null;
  reason?: string;
  failure?: ObserveLastRefreshFailure;
  instance_id?: string;
}

export interface ObserveLastRefreshOutcome {
  schema_version: typeof OBSERVE_SCHEMA_VERSION;
  refreshed_at: string;
  status: ObserveLastRefreshStatus;
  source_reads: ObserveLastRefreshSourceRead[];
  quarantined_sources: QuarantinedObserveSourceState[];
  definitive_empty?: boolean;
  reason?: string;
}

function sourceStateKey(sourceId: ObserveAuditSourceId): string {
  return `${SOURCE_STATE_KEY_PREFIX}${sourceId}`;
}

function candidateReviewKeyFor(key: string): string {
  return `${CANDIDATE_REVIEW_KEY_PREFIX}${candidateKeyDigest(key)}`;
}

function parseSourceState(
  key: string,
  value: string,
): { state: ObserveSourceState } | { quarantine: QuarantinedObserveSourceState } {
  const sourceId = key.slice(SOURCE_STATE_KEY_PREFIX.length);
  if (!isObserveAuditSourceId(sourceId)) {
    return {
      quarantine: { key, source_id: sourceId, reason: "unknown source id" },
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return { quarantine: { key, source_id: sourceId, reason: "malformed JSON" } };
  }

  const candidate = parsed as Partial<ObserveSourceState>;
  const validStatus =
    candidate.last_read_status === "read_ok" ||
    candidate.last_read_status === "read_failed" ||
    candidate.last_read_status === "absent";
  if (
    candidate.source_id !== sourceId ||
    typeof candidate.ever_contributed !== "boolean" ||
    !validStatus ||
    typeof candidate.last_read_at !== "string" ||
    (candidate.last_instance_id !== undefined && typeof candidate.last_instance_id !== "string") ||
    (candidate.last_contributed_at !== undefined && typeof candidate.last_contributed_at !== "string")
  ) {
    return {
      quarantine: { key, source_id: sourceId, reason: "malformed source state" },
    };
  }

  return { state: candidate as ObserveSourceState };
}

function parseCandidateReview(
  key: string,
  value: string,
): { review: ObserveCandidateReviewRecord } | { quarantine: QuarantinedObserveCandidateReviewRecord } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return { quarantine: { key, reason: "malformed JSON" } };
  }

  const candidate = parsed as Partial<ObserveCandidateReviewRecord>;
  const validAction = candidate.action === "promote" || candidate.action === "discard";
  const validTimestamp =
    typeof candidate.reviewed_at === "string" && !Number.isNaN(Date.parse(candidate.reviewed_at));
  if (
    candidate.schema_version !== OBSERVE_SCHEMA_VERSION ||
    typeof candidate.candidate_key !== "string" ||
    candidate.candidate_key.length === 0 ||
    !validAction ||
    !validTimestamp
  ) {
    return {
      quarantine: {
        key,
        reason: "malformed candidate review record",
        ...(typeof candidate.candidate_key === "string"
          ? { candidate_key: candidate.candidate_key }
          : {}),
      },
    };
  }
  if (candidateReviewKeyFor(candidate.candidate_key) !== key) {
    return {
      quarantine: {
        key,
        candidate_key: candidate.candidate_key,
        reason: "candidate key digest mismatch",
      },
    };
  }

  return { review: candidate as ObserveCandidateReviewRecord };
}

/**
 * Strict per-row validation for a persisted source read. A persisted
 * `"absent"` row carries definitive-empty authority downstream (the shared
 * R2 predicate), so a shallow top-level parse is not enough: a stale or
 * malformed record must never gain that authority by omission. Any
 * unrecognized shape rejects the WHOLE outcome (fail-closed -- consumers then
 * render UNDETERMINED, never verified-empty).
 */
function isValidPersistedSourceRead(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  const row = value as Record<string, unknown>;
  if (!isObserveAuditSourceId(row.source_id)) return false;
  if (row.instance_id !== undefined && typeof row.instance_id !== "string") return false;
  const finiteCount = (n: unknown): boolean =>
    typeof n === "number" && Number.isFinite(n) && n >= 0;
  switch (row.status) {
    case "read_ok":
      // The persisted shape keeps the count fields optional; validate them
      // only when present. The definitive-empty authority hinges on "absent"
      // below, which stays strict.
      return (
        (row.entries_read === undefined || finiteCount(row.entries_read)) &&
        (row.flow_events === undefined || finiteCount(row.flow_events)) &&
        (row.candidate_rows === undefined || finiteCount(row.candidate_rows)) &&
        (row.head_sequence === undefined ||
          row.head_sequence === null ||
          finiteCount(row.head_sequence)) &&
        (row.head_hash === undefined ||
          row.head_hash === null ||
          typeof row.head_hash === "string")
      );
    case "absent":
      // A downgraded previously-contributing source is status "read_failed"
      // with an explicit failure enum; a valid persisted "absent" row must
      // not smuggle one in.
      return typeof row.reason === "string" && row.failure === undefined;
    case "read_failed":
      return (
        typeof row.reason === "string" &&
        (row.failure === "source_unreadable" ||
          row.failure === "missing_after_contribution" ||
          row.failure === "instance_changed_after_contribution")
      );
    default:
      return false;
  }
}

function parseLastRefreshOutcome(value: string): ObserveLastRefreshOutcome | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return null;
  }
  const candidate = parsed as Partial<ObserveLastRefreshOutcome>;
  const validStatus =
    candidate.status === "refreshed" ||
    candidate.status === "source_read_incomplete" ||
    candidate.status === "allowlist_unverified";
  const validTimestamp =
    typeof candidate.refreshed_at === "string" && !Number.isNaN(Date.parse(candidate.refreshed_at));
  if (
    candidate.schema_version !== OBSERVE_SCHEMA_VERSION ||
    !validStatus ||
    !validTimestamp ||
    !Array.isArray(candidate.source_reads) ||
    !Array.isArray(candidate.quarantined_sources) ||
    (candidate.definitive_empty !== undefined && typeof candidate.definitive_empty !== "boolean") ||
    (candidate.reason !== undefined && typeof candidate.reason !== "string")
  ) {
    return null;
  }
  // Every enumerated registry source must appear EXACTLY once with a strictly
  // valid row. A record that lists only one source (e.g. persisted before the
  // second source existed) or duplicates a source must never carry
  // definitive-empty authority for the full registry.
  if (!candidate.source_reads.every(isValidPersistedSourceRead)) {
    return null;
  }
  const seen = candidate.source_reads.map((row) => (row as { source_id: string }).source_id);
  if (
    seen.length !== OBSERVE_AUDIT_SOURCE_IDS.length ||
    new Set(seen).size !== seen.length ||
    !OBSERVE_AUDIT_SOURCE_IDS.every((id) => seen.includes(id))
  ) {
    return null;
  }
  return candidate as ObserveLastRefreshOutcome;
}

export class ObserveStore {
  constructor(
    private readonly stateStore: StateStore,
    private readonly identity: ObserveWriteIdentity,
  ) {}

  private async put(key: string, value: unknown): Promise<void> {
    await this.stateStore.write(
      OBSERVE_NAMESPACE,
      key,
      JSON.stringify(value),
      this.identity.identityId,
      this.identity.encryptedPrivateKey,
      this.identity.identityEncryptionKey,
      { content_type: "application/json", tags: ["castle-wall-observe"] },
    );
  }

  /** Read the observe-mode toggle. Absent state reads as "never started" -- disabled, no started_at. */
  async getState(): Promise<ObserveModeState> {
    const result = await this.stateStore.read(OBSERVE_NAMESPACE, STATE_KEY);
    if (!result) {
      return { enabled: false, started_at: null, updated_at: new Date(0).toISOString() };
    }
    return JSON.parse(result.value) as ObserveModeState;
  }

  async setState(state: ObserveModeState): Promise<void> {
    await this.put(STATE_KEY, state);
  }

  /**
   * Read the legacy fold watermark record. Option A refreshes no longer depend
   * on this record (they full-recompute every retained source), but the getter
   * stays for backward-compatible diagnostics and evidence-pack inventory.
   */
  async getFoldWatermark(): Promise<FoldWatermark | null> {
    const result = await this.stateStore.read(OBSERVE_NAMESPACE, FOLD_WATERMARK_KEY);
    if (!result) return null;
    const parsed = JSON.parse(result.value) as FoldWatermark;
    if (
      typeof parsed?.folded_through_sequence !== "number" ||
      !Number.isSafeInteger(parsed.folded_through_sequence) ||
      parsed.folded_through_sequence < 0 ||
      typeof parsed.entry_hash !== "string" ||
      parsed.entry_hash.length === 0
    ) {
      // A malformed watermark is treated as absent: the refresh chokepoint
      // then RECOMPUTES with replace semantics, which converges to the true
      // retained-history counts rather than double-adding (fail toward
      // correct-and-conservative, never toward inflation).
      return null;
    }
    return parsed;
  }

  /** Persist the legacy fold watermark record. Kept for compatibility with older tests/fixtures and evidence-pack metadata. */
  async setFoldWatermark(watermark: FoldWatermark): Promise<void> {
    await this.put(FOLD_WATERMARK_KEY, watermark);
  }

  /** Storage key for a given candidate dedup key. Hashed so an operator-supplied host string can never itself become an unsafe StateStore key. */
  private storageKeyFor(key: string): string {
    return `${CANDIDATE_KEY_PREFIX}${candidateKeyDigest(key)}`;
  }

  async putCandidate(candidate: CandidateObservation): Promise<void> {
    await this.put(this.storageKeyFor(candidateKey(candidate)), candidate);
  }

  async removeCandidate(key: string): Promise<void> {
    await this.stateStore.delete(OBSERVE_NAMESPACE, this.storageKeyFor(key));
  }

  async putCandidateReview(review: ObserveCandidateReviewRecord): Promise<void> {
    await this.put(candidateReviewKeyFor(review.candidate_key), review);
  }

  /**
   * Resolve a candidate row by first writing its durable per-candidate review
   * tombstone, then removing the row. If the process crashes after the
   * tombstone write, a later refresh still treats pre-review retained denials
   * as resolved and converges by removing the stale row.
   */
  async removeCandidateAfterReview(
    candidate: CandidateObservation,
    action: ObserveCandidateReviewAction,
    reviewedAt: string,
  ): Promise<void> {
    const key = candidateKey(candidate);
    await this.putCandidateReview({
      schema_version: OBSERVE_SCHEMA_VERSION,
      candidate_key: key,
      action,
      reviewed_at: reviewedAt,
    });
    await this.removeCandidate(key);
  }

  async listCandidateReviews(): Promise<ObserveCandidateReviewSnapshot> {
    const known = new Map<string, ObserveCandidateReviewRecord>();
    const quarantined: QuarantinedObserveCandidateReviewRecord[] = [];
    let offset = 0;
    for (;;) {
      const { keys, total } = await this.stateStore.list(
        OBSERVE_NAMESPACE,
        CANDIDATE_REVIEW_KEY_PREFIX,
        undefined,
        PAGE_SIZE,
        offset,
      );
      for (const { key } of keys) {
        const result = await this.stateStore.read(OBSERVE_NAMESPACE, key);
        if (!result) continue;
        const parsed = parseCandidateReview(key, result.value);
        if ("review" in parsed) known.set(parsed.review.candidate_key, parsed.review);
        else quarantined.push(parsed.quarantine);
      }
      offset += keys.length;
      if (keys.length === 0 || offset >= total) break;
    }
    return { known, quarantined };
  }

  async getLastRefreshOutcome(): Promise<ObserveLastRefreshOutcome | null> {
    const result = await this.stateStore.read(OBSERVE_NAMESPACE, LAST_REFRESH_KEY);
    if (!result) return null;
    return parseLastRefreshOutcome(result.value);
  }

  async putLastRefreshOutcome(outcome: ObserveLastRefreshOutcome): Promise<void> {
    await this.put(LAST_REFRESH_KEY, outcome);
  }

  async listSourceStates(): Promise<ObserveSourceStateSnapshot> {
    const known = new Map<ObserveAuditSourceId, ObserveSourceState>();
    const quarantined: QuarantinedObserveSourceState[] = [];
    let offset = 0;
    for (;;) {
      const { keys, total } = await this.stateStore.list(
        OBSERVE_NAMESPACE,
        SOURCE_STATE_KEY_PREFIX,
        undefined,
        PAGE_SIZE,
        offset,
      );
      for (const { key } of keys) {
        const result = await this.stateStore.read(OBSERVE_NAMESPACE, key);
        if (!result) continue;
        const parsed = parseSourceState(key, result.value);
        if ("state" in parsed) known.set(parsed.state.source_id, parsed.state);
        else quarantined.push(parsed.quarantine);
      }
      offset += keys.length;
      if (keys.length === 0 || offset >= total) break;
    }
    return { known, quarantined };
  }

  async putSourceState(state: ObserveSourceState): Promise<void> {
    if (!OBSERVE_AUDIT_SOURCE_IDS.includes(state.source_id)) {
      throw new Error(`unknown observe source id: ${String(state.source_id)}`);
    }
    await this.put(sourceStateKey(state.source_id), state);
  }

  /** List every persisted candidate, keyed by its dedup `candidateKey`. Pages through every StateStore key so a large candidate set is never silently truncated (mirrors `FileGrantStore.list`). */
  async listCandidates(): Promise<Map<string, CandidateObservation>> {
    const out = new Map<string, CandidateObservation>();
    let offset = 0;
    for (;;) {
      const { keys, total } = await this.stateStore.list(
        OBSERVE_NAMESPACE,
        CANDIDATE_KEY_PREFIX,
        undefined,
        PAGE_SIZE,
        offset,
      );
      for (const { key } of keys) {
        const result = await this.stateStore.read(OBSERVE_NAMESPACE, key);
        if (!result) continue;
        const candidate = JSON.parse(result.value) as CandidateObservation;
        out.set(candidateKey(candidate), candidate);
      }
      offset += keys.length;
      if (keys.length === 0 || offset >= total) break;
    }
    return out;
  }

  /**
   * Merge freshly folded observations into the persisted candidate set:
   * bump `times_seen` / extend first-last-seen for an existing key, insert a
   * new row otherwise. Never touches the live ruleset -- this only ever
   * writes to this reserved, agent-invisible namespace (THE RED-LINE
   * INVARIANT above).
   */
  async mergeObservations(observations: readonly CandidateObservation[]): Promise<void> {
    if (observations.length === 0) return;
    const existing = await this.listCandidates();
    const merged = mergeCandidateObservations(existing, observations);
    for (const [key, candidate] of merged) {
      const prior = existing.get(key);
      if (prior && JSON.stringify(prior) === JSON.stringify(candidate)) continue;
      await this.putCandidate(candidate);
    }
  }

  /**
   * REPLACE-write selected observations without deleting missing keys. Kept
   * for older repair/test paths that want per-key overwrite semantics. The
   * Option A refresh path uses `replaceCandidateSnapshot()` instead so a full
   * recompute can also prune rows absent from retained source history.
   */
  async replaceObservations(observations: readonly CandidateObservation[]): Promise<void> {
    if (observations.length === 0) return;
    const existing = await this.listCandidates();
    for (const incoming of observations) {
      const prior = existing.get(candidateKey(incoming));
      if (prior && JSON.stringify(prior) === JSON.stringify(incoming)) continue;
      await this.putCandidate(incoming);
    }
  }

  /**
   * Replace the whole candidate set with one recomputed snapshot. This is the
   * Option A crash contract: refreshes no longer add deltas to existing rows,
   * so retrying after a partial write converges to the same aggregate counts
   * instead of double-counting retained audit entries.
   */
  async replaceCandidateSnapshot(observations: readonly CandidateObservation[]): Promise<void> {
    const existing = await this.listCandidates();
    const incoming = new Map(observations.map((row) => [candidateKey(row), row]));

    for (const [key, row] of incoming) {
      const prior = existing.get(key);
      if (prior && JSON.stringify(prior) === JSON.stringify(row)) continue;
      await this.putCandidate(row);
    }

    for (const key of existing.keys()) {
      if (!incoming.has(key)) await this.removeCandidate(key);
    }
  }
}
