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
}

export class FederationReissueChallengeStore {
  private readonly pending = new Map<string, PendingReissueChallenge>();
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

  issue(params: {
    fortressId: string;
    nodeId: string;
    nowMs?: number;
  }): FederationReissueChallenge {
    const nowMs = params.nowMs ?? Date.now();
    this.prune(nowMs);
    if (this.pending.size >= MAX_PENDING_REISSUE_CHALLENGES) {
      throw new Error("too many pending federation reissue challenges");
    }
    const challengeId = randomUUID();
    const challenge = toBase64url(randomBytes(32));
    const expiresAtMs = nowMs + FEDERATION_REISSUE_CHALLENGE_TTL_MS;
    this.pending.set(challengeId, {
      fortressId: params.fortressId,
      nodeId: params.nodeId,
      challenge,
      expiresAtMs,
    });
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
    this.pending.delete(params.challengeId);
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

  private prune(nowMs: number): void {
    for (const [id, pending] of this.pending) {
      if (pending.expiresAtMs < nowMs) this.pending.delete(id);
    }
    for (const [key, expiresAtMs] of this.spent) {
      if (expiresAtMs < nowMs) this.spent.delete(key);
    }
  }
}
