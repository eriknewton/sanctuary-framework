/**
 * Hardening wave 6 finding #86, token expiry pruning hooked into the
 * cocoon-unlock initialization path.
 *
 * Two regressions:
 *   1. tick-fires-prune      , Broker.pruneExpiredTokens() actually drops
 *                               expired tokens from the issuer map.
 *   2. unlock-cycle-fires-prune, openBroker() fires Broker.pruneExpiredTokens
 *                                 once during the cocoon-unlock path so
 *                                 each unlock cycle clears stale state
 *                                 before any operator interaction.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TokenIssuer,
  type SkillSecretGrant,
} from "../../../src/l3-disclosure/broker/token-issuer.js";
import { Broker } from "../../../src/l3-disclosure/broker/broker.js";
import {
  openBroker,
  saveBrokerPolicy,
} from "../../../src/l3-disclosure/broker/open.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";
import type {
  Backend,
} from "../../../src/l3-disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../../src/l3-disclosure/broker/backend-interface.js";

function makeFakeBackend(secrets: Record<string, string>): Backend {
  const store = new Map(Object.entries(secrets));
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(name, value) {
      if (store.has(name)) throw new Error("exists");
      store.set(name, value);
    },
    async readSecret(name) {
      const v = store.get(name);
      if (v === undefined) throw new SecretNotFoundError(name);
      return v;
    },
    async rotateSecret(name, value) {
      if (!store.has(name)) throw new SecretNotFoundError(name);
      store.set(name, value);
    },
    async deleteSecret(name) {
      if (!store.delete(name)) throw new SecretNotFoundError(name);
    },
    async listSecretNames() {
      return Array.from(store.keys());
    },
  };
}

describe("token expiry pruning fires on cocoon-unlock (finding #86)", () => {
  it("tick-fires-prune: Broker.pruneExpiredTokens() removes expired bindings", async () => {
    let now = 1_700_000_000_000;
    const grant: SkillSecretGrant = {
      skill: "test",
      secret: "api-key",
      scope: "read",
      ttlSeconds: 60,
    };
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    const backend = makeFakeBackend({ "api-key": "value" });
    // We construct the issuer directly so we can advance the clock.
    const issuer = new TokenIssuer({
      backend,
      auditLog,
      grants: [grant],
      now: () => now,
    });
    // Wrap Broker around the same issuer indirectly by giving it the same
    // backend and grants, Broker's TokenIssuer is internal, but
    // pruneExpiredTokens() is the public verb.
    const broker = new Broker({
      backend,
      auditLog,
      grants: [grant],
      principalIdentityId: "test-principal",
    });

    // Issue a token through the broker so the broker's internal issuer
    // owns it, pruneExpiredTokens() must drop this one when expired.
    const binding = await broker.issueToken({
      skill: "test",
      secret: "api-key",
      requestedScope: "read",
      ttlSeconds: 60,
      agent: "test-agent",
      identity_id: "test-principal",
    });
    expect(binding.token).toBeTruthy();
    expect(broker.liveTokenCount()).toBe(1);

    // Advance time past expiry.
    const issuedAt = Date.parse(binding.expires_at);
    vi.useFakeTimers();
    vi.setSystemTime(new Date(issuedAt + 1));
    try {
      const removed = broker.pruneExpiredTokens();
      expect(removed).toBe(1);
      expect(broker.liveTokenCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }

    // Issuer constructed earlier is unaffected, sanity that prune is
    // local to a single TokenIssuer and the broker owns its own.
    expect(issuer.liveTokenCount()).toBe(0);
  });

  it("unlock-cycle-fires-prune: openBroker fires pruneExpiredTokens during cocoon-unlock", async () => {
    const tmp = mkdtempSync(join(tmpdir(), "sanctuary-broker-prune-"));
    try {
      // Pre-stage the broker policy so loadBrokerGrants returns deterministic state.
      await saveBrokerPolicy(tmp, [
        {
          name: "skill-x",
          secrets: [{ name: "api-x", scope: "read", ttl: 60 }],
        },
      ]);
      // Spy on Broker.prototype.pruneExpiredTokens so we can verify openBroker fires it
      // exactly once during the cocoon-unlock initialization path.
      const spy = vi.spyOn(Broker.prototype, "pruneExpiredTokens");
      try {
        const fakeBackend = makeFakeBackend({ "api-x": "abc" });
        const handle = await openBroker({
          passphrase: "test-passphrase-1234",
          storagePath: tmp,
          principalIdentityId: "unlock-cycle-test",
          backend: fakeBackend,
        });
        try {
          expect(spy).toHaveBeenCalledTimes(1);
          // The hook fires synchronously before openBroker resolves.
          expect(spy.mock.invocationCallOrder.length).toBe(1);
          // And the broker is fully usable.
          expect(handle.broker.liveTokenCount()).toBe(0);
        } finally {
          await handle.close();
        }
      } finally {
        spy.mockRestore();
      }
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
