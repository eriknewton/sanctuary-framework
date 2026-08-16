/**
 * Durable spent-set for OPERATOR_SIGNED v1 authorizations.
 *
 * This store is intentionally independent from federation sync state. The
 * /v1/agents write routes exist on the default single-node dashboard, so their
 * replay defense must be present even when no federation materials are
 * provisioned. A write failure still denies the authorized effect.
 */

import type { StorageBackend } from "../storage/interface.js";
import type { OperatorAuthorizationConsumeParams } from "./operator-signed.js";
import { DurableSpentSetStore } from "../mesh/lifecycle/durable-spent-set-store.js";

export const OPERATOR_AUTHORIZATION_SPENT_STORE_NAMESPACE =
  "_operator_authorizations";
export const OPERATOR_AUTHORIZATION_SPENT_STORE_KEY = "spent-v1";
export const OPERATOR_AUTHORIZATION_SPENT_STORE_HKDF_INFO =
  "v1-operator-authorization-spent-set";

export class OperatorAuthorizationSpentStore {
  private readonly durable?: DurableSpentSetStore;
  private readonly spent = new Map<string, number>();
  private loadOnce: Promise<void> | null = null;

  constructor(durable?: DurableSpentSetStore) {
    this.durable = durable;
  }

  static durableFromBoot(
    storage: StorageBackend,
    masterKey: Uint8Array,
  ): OperatorAuthorizationSpentStore {
    return new OperatorAuthorizationSpentStore(
      new DurableSpentSetStore({
        storage,
        masterKey,
        namespace: OPERATOR_AUTHORIZATION_SPENT_STORE_NAMESPACE,
        recordKey: OPERATOR_AUTHORIZATION_SPENT_STORE_KEY,
        hkdfLabel: OPERATOR_AUTHORIZATION_SPENT_STORE_HKDF_INFO,
      }),
    );
  }

  async init(nowMs = Date.now()): Promise<void> {
    if (!this.durable) return;
    if (this.loadOnce === null) {
      this.loadOnce = this.durable.load(nowMs).then((loaded) => {
        this.spent.clear();
        for (const [key, expiresAtMs] of loaded) this.spent.set(key, expiresAtMs);
      });
    }
    await this.loadOnce;
  }

  async consume({
    replayKey,
    expiresAt,
  }: OperatorAuthorizationConsumeParams): Promise<"consumed" | "replayed"> {
    const nowMs = Date.now();
    await this.init(nowMs);
    this.prune(nowMs);
    if (this.spent.has(replayKey)) return "replayed";
    const expiresAtMs = Date.parse(expiresAt);
    if (!Number.isFinite(expiresAtMs)) {
      throw new Error("operator authorization expiry is invalid");
    }
    this.spent.set(replayKey, expiresAtMs);
    if (this.durable) {
      try {
        await this.durable.persist(this.spent);
      } catch (err) {
        if (this.spent.get(replayKey) === expiresAtMs) {
          this.spent.delete(replayKey);
        }
        throw err;
      }
    }
    return "consumed";
  }

  private prune(nowMs: number): void {
    for (const [key, expiresAtMs] of this.spent) {
      if (expiresAtMs < nowMs) this.spent.delete(key);
    }
  }
}
