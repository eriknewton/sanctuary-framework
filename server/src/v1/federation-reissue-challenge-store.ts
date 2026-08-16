/**
 * Durable single-use challenge store for federation node-cert reissue.
 *
 * The reissue endpoint is pre-session and credential-issuing, so a proof is
 * bound to a server-issued challenge and a consumed challenge id is persisted
 * before the certificate is issued. Pending challenges are intentionally
 * in-memory only: after a daemon restart the caller asks for a fresh challenge.
 * Consumed ids are durable so an accepted proof cannot be replayed after restart.
 */

import { randomBytes, randomUUID } from "node:crypto";
import type { StorageBackend } from "../storage/interface.js";
import { toBase64url } from "../core/encoding.js";
import { DurableSpentSetStore } from "../mesh/lifecycle/durable-spent-set-store.js";

export const FEDERATION_REISSUE_CHALLENGE_TTL_MS = 60_000;
export const FEDERATION_REISSUE_CHALLENGE_STORE_NAMESPACE = "_federation";
export const FEDERATION_REISSUE_CHALLENGE_STORE_KEY =
  "reissue-node-cert-challenges-v1";
export const FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO =
  "federation-reissue-node-cert-challenge-set";

const MAX_PENDING_REISSUE_CHALLENGES = 1024;

/**
 * Per-origin ceiling (LD3 FED-REISSUE-DOS-01 corroboration). The GLOBAL cap
 * above stops the map from growing without bound, but by itself does nothing
 * against a DISTRIBUTED flood of distinct node_ids: `node_id` is an
 * attacker-chosen string the challenge handler accepts before it knows
 * whether the id is real (see `isNodeRevoked` in v1/federation.ts), so it
 * costs an attacker nothing to mint a fresh one per request. An attacker
 * spread across N origins, each individually under the federation_peer rate
 * limit (60 requests per 60s window; must match RATE_LIMIT_FEDERATION_PEER in
 * principal-policy/dashboard.ts), could still fill the global 1024-entry cap
 * with ~N*60 pending entries and starve every legitimate joiner's real
 * challenge behind a "challenge_store_unavailable" decoy. Bounding each
 * origin's own contribution well under the global cap means exhausting it
 * needs many distinct ORIGINS, not just many distinct node_ids — the same
 * distributed-source cost the rate limiter already imposes elsewhere. 64 =
 * the federation_peer window budget (60) plus slack for clock skew between
 * the rate limiter's window and this store's TTL, still well under the 1024
 * global cap so no single origin can starve the others by itself.
 */
const MAX_PENDING_REISSUE_CHALLENGES_PER_ORIGIN = 64;

/** Shared bucket for callers that cannot supply a per-request origin (see `issue`). */
const UNKNOWN_ORIGIN_KEY = "unknown-origin";

export interface FederationReissueChallenge {
  challenge_id: string;
  challenge: string;
  expires_at: string;
}

interface PendingReissueChallenge {
  fortressId: string;
  nodeId: string;
  challenge: string;
  expiresAtMs: number;
  originKey: string;
}

export class FederationReissueChallengeStore {
  private readonly pending = new Map<string, PendingReissueChallenge>();
  private readonly pendingByOrigin = new Map<string, number>();
  private readonly spent = new Map<string, number>();
  private loadOnce: Promise<void> | null = null;

  constructor(private readonly durable?: DurableSpentSetStore) {}

  static durableFromBoot(
    storage: StorageBackend,
    masterKey: Uint8Array,
  ): FederationReissueChallengeStore {
    return new FederationReissueChallengeStore(
      new DurableSpentSetStore({
        storage,
        masterKey,
        namespace: FEDERATION_REISSUE_CHALLENGE_STORE_NAMESPACE,
        recordKey: FEDERATION_REISSUE_CHALLENGE_STORE_KEY,
        hkdfLabel: FEDERATION_REISSUE_CHALLENGE_STORE_HKDF_INFO,
      }),
    );
  }

  async init(nowMs = Date.now()): Promise<void> {
    if (!this.durable) return;
    if (this.loadOnce === null) {
      this.loadOnce = this.durable.load(nowMs).then((loaded) => {
        for (const [key, expiresAtMs] of loaded) this.spent.set(key, expiresAtMs);
      });
    }
    await this.loadOnce;
  }

  /**
   * `originKey` is optional ONLY so a caller with no live request (there are
   * none in production today; the direct unit test is the one exception)
   * still gets a bounded bucket rather than a thrown type error — every
   * request-driven caller (principal-policy/dashboard.ts) supplies a real
   * rate-limit key. Omitted keys share one bucket, so they are bounded
   * exactly like any other single origin, never exempt from the cap.
   */
  issue(params: {
    fortressId: string;
    nodeId: string;
    originKey?: string;
    nowMs?: number;
  }): FederationReissueChallenge {
    const nowMs = params.nowMs ?? Date.now();
    this.prune(nowMs);
    const originKey = params.originKey ?? UNKNOWN_ORIGIN_KEY;
    if (this.pending.size >= MAX_PENDING_REISSUE_CHALLENGES) {
      throw new Error("too many pending federation reissue challenges");
    }
    if (
      (this.pendingByOrigin.get(originKey) ?? 0) >=
      MAX_PENDING_REISSUE_CHALLENGES_PER_ORIGIN
    ) {
      throw new Error("too many pending federation reissue challenges for this origin");
    }
    const challengeId = randomUUID();
    const challenge = toBase64url(randomBytes(32));
    const expiresAtMs = nowMs + FEDERATION_REISSUE_CHALLENGE_TTL_MS;
    this.pending.set(challengeId, {
      fortressId: params.fortressId,
      nodeId: params.nodeId,
      challenge,
      expiresAtMs,
      originKey,
    });
    this.pendingByOrigin.set(originKey, (this.pendingByOrigin.get(originKey) ?? 0) + 1);
    return {
      challenge_id: challengeId,
      challenge,
      expires_at: new Date(expiresAtMs).toISOString(),
    };
  }

  async consume(params: {
    fortressId: string;
    nodeId: string;
    challengeId: string;
    challenge: string;
    nowMs?: number;
  }): Promise<boolean> {
    const nowMs = params.nowMs ?? Date.now();
    await this.init(nowMs);
    this.prune(nowMs);

    const pending = this.pending.get(params.challengeId);
    this.removePending(params.challengeId);
    if (
      pending === undefined ||
      pending.fortressId !== params.fortressId ||
      pending.nodeId !== params.nodeId ||
      pending.challenge !== params.challenge ||
      pending.expiresAtMs < nowMs
    ) {
      return false;
    }

    const key = this.key(params.fortressId, params.nodeId, params.challengeId);
    if (this.spent.has(key)) return false;
    this.spent.set(key, pending.expiresAtMs);
    if (this.durable) {
      try {
        await this.durable.persist(this.spent);
      } catch {
        this.spent.delete(key);
        return false;
      }
    }
    return true;
  }

  isSpent(
    fortressId: string,
    nodeId: string,
    challengeId: string,
    nowMs = Date.now(),
  ): boolean {
    const expiresAtMs = this.spent.get(this.key(fortressId, nodeId, challengeId));
    if (expiresAtMs === undefined) return false;
    return expiresAtMs >= nowMs;
  }

  private key(fortressId: string, nodeId: string, challengeId: string): string {
    return `${fortressId} ${nodeId} reissue-node-cert ${challengeId}`;
  }

  /**
   * The ONE place that deletes a `pending` entry, so `pendingByOrigin` can
   * never drift from `pending` itself (a second removal site that forgot the
   * decrement would silently leak the per-origin count upward until every
   * future request from that origin was wrongly refused).
   */
  private removePending(id: string): void {
    const entry = this.pending.get(id);
    if (entry === undefined) return;
    this.pending.delete(id);
    const remaining = (this.pendingByOrigin.get(entry.originKey) ?? 1) - 1;
    if (remaining <= 0) {
      this.pendingByOrigin.delete(entry.originKey);
    } else {
      this.pendingByOrigin.set(entry.originKey, remaining);
    }
  }

  private prune(nowMs: number): void {
    for (const [id, pending] of this.pending) {
      if (pending.expiresAtMs < nowMs) this.removePending(id);
    }
    for (const [key, expiresAtMs] of this.spent) {
      if (expiresAtMs < nowMs) this.spent.delete(key);
    }
  }
}
