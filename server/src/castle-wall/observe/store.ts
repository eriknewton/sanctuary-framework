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
  OBSERVE_NAMESPACE,
  candidateKey,
  candidateKeyDigest,
  type CandidateObservation,
  type FoldWatermark,
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
const CANDIDATE_KEY_PREFIX = "candidate:";
const PAGE_SIZE = 100;

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
   * Read the fold watermark: the highest authenticated audit-chain sequence
   * the refresh chokepoint has already folded (see `refresh.ts`). Absent on a
   * store that has never completed a watermarked refresh (fresh install, or a
   * store written by the pre-watermark engine) -- reads as `null`, which the
   * refresh chokepoint treats as "recompute from scratch with replace
   * semantics" (the one-time heal for stores the pre-watermark additive
   * re-fold inflated).
   */
  async getFoldWatermark(): Promise<FoldWatermark | null> {
    const result = await this.stateStore.read(OBSERVE_NAMESPACE, FOLD_WATERMARK_KEY);
    if (!result) return null;
    const parsed = JSON.parse(result.value) as FoldWatermark;
    if (
      typeof parsed?.folded_through_sequence !== "number" ||
      !Number.isSafeInteger(parsed.folded_through_sequence) ||
      parsed.folded_through_sequence < 0
    ) {
      // A malformed watermark is treated as absent: the refresh chokepoint
      // then RECOMPUTES with replace semantics, which converges to the true
      // retained-history counts rather than double-adding (fail toward
      // correct-and-conservative, never toward inflation).
      return null;
    }
    return parsed;
  }

  /** Persist the fold watermark. Written by the refresh chokepoint ONLY after a fold pass committed cleanly. */
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
   * REPLACE-write freshly folded observations: each folded row overwrites the
   * persisted row for its key outright (no count addition). Keys present in
   * the store but absent from `observations` are left untouched (their audit
   * history may simply have aged out of FIFO retention -- an unreviewed
   * candidate is never silently dropped by a recompute).
   *
   * Used by the refresh chokepoint's RECOMPUTE mode (no valid watermark):
   * replaying the full retained history yields the true per-key counts, so
   * replacing converges -- this is the one-time heal for stores the
   * pre-watermark additive re-fold inflated (sweep finding R3-1). Same
   * RED-LINE scope as `mergeObservations`: only ever writes this reserved,
   * agent-invisible namespace, never the live ruleset.
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
}
