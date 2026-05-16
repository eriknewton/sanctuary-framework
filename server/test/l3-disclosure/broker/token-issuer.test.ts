/**
 * Token Issuer Tests
 *
 * Verifies:
 * - Token issuance requires a matching grant.
 * - Scope enforcement (requested <= granted).
 * - TTL default, override, and clamp at max.
 * - Expired tokens are rejected on readViaToken.
 * - Revoking a grant invalidates outstanding tokens.
 * - Every issuance / denial / read writes an L3 audit entry with the
 *   right operation and does NOT leak the secret value.
 * - Backend failures propagate but still audit.
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import type { Backend } from "../../../src/l3-disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../../src/l3-disclosure/broker/backend-interface.js";
import {
  TokenIssuer,
  BrokerDeniedError,
  BrokerTokenExpiredError,
  BrokerTokenUnknownError,
  DEFAULT_TOKEN_TTL_SECONDS,
  MAX_TOKEN_TTL_SECONDS,
  type VerifiedBrokerCallerClaims,
} from "../../../src/l3-disclosure/broker/token-issuer.js";
import { AuditLog, BROKER_OPS } from "../../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

class FailingAuditStorage extends MemoryStorage {
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit") {
      const err = new Error("audit storage full") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    }
    return super.write(namespace, key, data);
  }
}

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

async function makeIssuer(overrides: {
  backend?: Backend;
  now?: () => number;
  grants?: Parameters<TokenIssuer["setGrant"]>[0][];
} = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const backend = overrides.backend ?? makeFakeBackend({ gmail_oauth: "secret-value-xyz" });
  const issuer = new TokenIssuer({
    backend,
    auditLog,
    grants: overrides.grants,
    now: overrides.now,
  });
  return { issuer, auditLog, backend };
}

function caller(
  skill: string,
  overrides: Partial<VerifiedBrokerCallerClaims> = {}
): VerifiedBrokerCallerClaims {
  return {
    skill,
    agent: "nsa",
    identity_id: "did:sanctuary:1",
    tenant_id: "tenant-alpha",
    fortress_id: "fortress-alpha",
    audience: "sanctuary-broker",
    ...overrides,
  };
}

describe("TokenIssuer", () => {
  describe("issueToken", () => {
    it("issues a token when a matching grant exists", async () => {
      const { issuer, auditLog } = await makeIssuer({
        grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
      });

      const binding = await issuer.issueToken({
        skill: "gmail-triage",
        secret: "gmail_oauth",
        caller: caller("gmail-triage"),
      });

      expect(binding.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(binding.scope).toBe("read");
      expect(binding.skill).toBe("gmail-triage");
      expect(binding.agent).toBe("nsa");
      expect(binding.tenant_id).toBe("tenant-alpha");
      expect(binding.fortress_id).toBe("fortress-alpha");
      expect(binding.audience).toBe("sanctuary-broker");

      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_ISSUED, layer: "l3" });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.result).toBe("success");
      expect(audit.entries[0]!.details?.skill).toBe("gmail-triage");
      expect(audit.entries[0]!.details?.secret).toBe("gmail_oauth");
    });

    it("does not issue a live token when critical audit persistence fails", async () => {
      const auditLog = new AuditLog(new FailingAuditStorage(), generateRandomKey());
      const issuer = new TokenIssuer({
        backend: makeFakeBackend({ gmail_oauth: "secret-value-xyz" }),
        auditLog,
        grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
      });

      await expect(
        issuer.issueToken({
          skill: "gmail-triage",
          secret: "gmail_oauth",
          caller: caller("gmail-triage"),
        })
      ).rejects.toMatchObject({
        name: "AuditPersistenceError",
        classification: "storage_full",
      });
      expect(issuer.liveTokenCount()).toBe(0);
    });

    it("denies when no grant exists and audits the denial", async () => {
      const { issuer, auditLog } = await makeIssuer();

      await expect(
        issuer.issueToken({
          skill: "unknown",
          secret: "gmail_oauth",
          caller: caller("unknown"),
        })
      ).rejects.toBeInstanceOf(BrokerDeniedError);

      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_DENIED, layer: "l3" });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.result).toBe("failure");
      expect(audit.entries[0]!.details?.reason).toBe("no_grant");
    });

    it("denies an ungranted caller that claims a granted skill", async () => {
      const { issuer, auditLog } = await makeIssuer({
        grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
      });

      await expect(
        issuer.issueToken({
          skill: "gmail-triage",
          secret: "gmail_oauth",
          caller: caller("ungranted-skill"),
        })
      ).rejects.toBeInstanceOf(BrokerDeniedError);

      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_DENIED, layer: "l3" });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.details?.reason).toBe("caller_skill_mismatch");
      expect(audit.entries[0]!.details?.skill).toBe("gmail-triage");
      expect(audit.entries[0]!.details?.verified_skill).toBe("ungranted-skill");
    });

    it("denies when verified caller claims do not match constrained grant", async () => {
      const { issuer, auditLog } = await makeIssuer({
        grants: [
          {
            skill: "gmail-triage",
            secret: "gmail_oauth",
            scope: "read",
            agent: "agent-alpha",
            tenant_id: "tenant-alpha",
            fortress_id: "fortress-alpha",
            audience: "sanctuary-broker",
          },
        ],
      });

      await expect(
        issuer.issueToken({
          skill: "gmail-triage",
          secret: "gmail_oauth",
          caller: caller("gmail-triage", { agent: "agent-beta" }),
        })
      ).rejects.toBeInstanceOf(BrokerDeniedError);

      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_DENIED, layer: "l3" });
      expect(audit.entries[0]!.details?.reason).toBe("caller_claim_mismatch");
      expect(audit.entries[0]!.details?.claim).toBe("agent");
    });

    it("denies when requested scope exceeds grant scope", async () => {
      const { issuer, auditLog } = await makeIssuer({
        grants: [{ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" }],
      });

      await expect(
        issuer.issueToken({
          skill: "gmail-triage",
          secret: "gmail_oauth",
          caller: caller("gmail-triage"),
          requestedScope: "rotate",
        })
      ).rejects.toBeInstanceOf(BrokerDeniedError);

      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_DENIED, layer: "l3" });
      expect(audit.entries[0]!.details?.reason).toBe("scope_exceeds_grant");
    });

    it("allows read when granted rotate (higher scope covers lower)", async () => {
      const { issuer } = await makeIssuer({
        grants: [{ skill: "gmail-admin", secret: "gmail_oauth", scope: "rotate" }],
      });

      const binding = await issuer.issueToken({
        skill: "gmail-admin",
        secret: "gmail_oauth",
        caller: caller("gmail-admin"),
        requestedScope: "read",
      });
      expect(binding.scope).toBe("read");
    });

    it("uses default TTL when none specified", async () => {
      const t0 = 1_700_000_000_000;
      const { issuer } = await makeIssuer({
        now: () => t0,
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });

      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });

      const issued = Date.parse(binding.issued_at);
      const expires = Date.parse(binding.expires_at);
      expect(expires - issued).toBe(DEFAULT_TOKEN_TTL_SECONDS * 1000);
    });

    it("clamps requested TTL at MAX_TOKEN_TTL_SECONDS", async () => {
      const t0 = 1_700_000_000_000;
      const { issuer } = await makeIssuer({
        now: () => t0,
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });

      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
        ttlSeconds: MAX_TOKEN_TTL_SECONDS * 1000, // absurdly large
      });

      const expires = Date.parse(binding.expires_at);
      const issued = Date.parse(binding.issued_at);
      expect(expires - issued).toBe(MAX_TOKEN_TTL_SECONDS * 1000);
    });

    it("ignores non-positive TTL and falls back to default", async () => {
      const t0 = 1_700_000_000_000;
      const { issuer } = await makeIssuer({
        now: () => t0,
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });

      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
        ttlSeconds: -5,
      });

      const expires = Date.parse(binding.expires_at);
      const issued = Date.parse(binding.issued_at);
      expect(expires - issued).toBe(DEFAULT_TOKEN_TTL_SECONDS * 1000);
    });

    it("audit entry does NOT include the secret value", async () => {
      const { issuer, auditLog } = await makeIssuer({
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });
      await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      const audit = await auditLog.query({ operation_type: BROKER_OPS.TOKEN_ISSUED });
      const serialized = JSON.stringify(audit.entries);
      expect(serialized).not.toContain("secret-value-xyz");
    });
  });

  describe("readViaToken", () => {
    it("returns secret value for a valid live token", async () => {
      const { issuer } = await makeIssuer({
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });
      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      const value = await issuer.readViaToken(binding.token);
      expect(value).toBe("secret-value-xyz");
    });

    it("rejects unknown tokens and audits", async () => {
      const { issuer, auditLog } = await makeIssuer();
      await expect(issuer.readViaToken("no-such-token")).rejects.toBeInstanceOf(
        BrokerTokenUnknownError
      );
      const audit = await auditLog.query({ operation_type: BROKER_OPS.SECRET_READ });
      expect(audit.entries).toHaveLength(1);
      expect(audit.entries[0]!.result).toBe("failure");
      expect(audit.entries[0]!.details?.reason).toBe("token_unknown");
    });

    it("rejects expired tokens", async () => {
      let now = 1_700_000_000_000;
      const { issuer } = await makeIssuer({
        now: () => now,
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read", ttlSeconds: 60 }],
      });
      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      now += 61_000; // 61 seconds later, TTL was 60
      await expect(issuer.readViaToken(binding.token)).rejects.toBeInstanceOf(
        BrokerTokenExpiredError
      );
    });

    it("revoking a grant immediately denies subsequent reads", async () => {
      const { issuer, auditLog } = await makeIssuer({
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });
      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      // First read OK.
      expect(await issuer.readViaToken(binding.token)).toBe("secret-value-xyz");
      // Revoke.
      issuer.revokeGrant("s", "gmail_oauth");
      // Now denied.
      await expect(issuer.readViaToken(binding.token)).rejects.toBeInstanceOf(
        BrokerDeniedError
      );
      const audit = await auditLog.query({ operation_type: BROKER_OPS.SECRET_READ });
      const last = audit.entries[audit.entries.length - 1]!;
      expect(last.result).toBe("failure");
      expect(last.details?.reason).toBe("grant_revoked");
    });

    it("propagates backend errors and audits without leaking the value", async () => {
      const backend = makeFakeBackend({});
      const readSpy = vi.spyOn(backend, "readSecret").mockRejectedValue(
        new Error("backend exploded")
      );
      const { issuer, auditLog } = await makeIssuer({
        backend,
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });
      const binding = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      await expect(issuer.readViaToken(binding.token)).rejects.toThrow("backend exploded");
      expect(readSpy).toHaveBeenCalled();
      const audit = await auditLog.query({ operation_type: BROKER_OPS.SECRET_READ });
      const last = audit.entries[audit.entries.length - 1]!;
      expect(last.result).toBe("failure");
      expect(last.details?.reason).toBe("backend_error");
    });
  });

  describe("administrative", () => {
    it("revokeToken invalidates a single token without touching the grant", async () => {
      const { issuer } = await makeIssuer({
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });
      const b1 = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      const b2 = await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      expect(issuer.revokeToken(b1.token)).toBe(true);
      await expect(issuer.readViaToken(b1.token)).rejects.toBeInstanceOf(BrokerTokenUnknownError);
      expect(await issuer.readViaToken(b2.token)).toBe("secret-value-xyz");
    });

    it("pruneExpired drops only expired tokens", async () => {
      let now = 1_700_000_000_000;
      const { issuer } = await makeIssuer({
        now: () => now,
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read", ttlSeconds: 10 }],
      });
      await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      now += 15_000;
      await issuer.issueToken({
        skill: "s",
        secret: "gmail_oauth",
        caller: caller("s", { agent: "a", identity_id: "i" }),
      });
      expect(issuer.liveTokenCount()).toBe(2);
      const removed = issuer.pruneExpired();
      expect(removed).toBe(1);
      expect(issuer.liveTokenCount()).toBe(1);
    });

    it("setGrant replaces existing grant for (skill, secret)", async () => {
      const { issuer } = await makeIssuer({
        grants: [{ skill: "s", secret: "gmail_oauth", scope: "read" }],
      });
      issuer.setGrant({ skill: "s", secret: "gmail_oauth", scope: "rotate" });
      const grants = issuer.getGrants();
      expect(grants).toHaveLength(1);
      expect(grants[0]!.scope).toBe("rotate");
    });
  });
});
