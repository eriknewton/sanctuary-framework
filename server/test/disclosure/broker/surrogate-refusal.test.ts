/**
 * Capability: a secret bound as a surrogate cannot be reached through any broker
 * path. The issuer refuses to mint a token for it, refuses to serve a token that
 * predates the binding, and the broker refuses to record a grant for it. Covers
 * the required-set contract (a construction with no set does not compile, proven
 * by the tests typecheck baseline rather than at runtime).
 *
 * Defect id: SURROGATE-BROKER-REACHABLE.
 */

import { describe, it, expect } from "vitest";
import type { Backend } from "../../../src/disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../../src/disclosure/broker/backend-interface.js";
import { Broker } from "../../../src/disclosure/broker/broker.js";
import {
  BrokerDeniedError,
  TokenIssuer,
} from "../../../src/disclosure/broker/token-issuer.js";
import { AuditLog, BROKER_OPS } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

/** Generated in the test; never a literal that could be mistaken for a real value. */
const BOUND_VALUE = Buffer.from(generateRandomKey()).toString("base64url");

function makeFakeBackend(seed: Record<string, string> = {}): Backend {
  const store = new Map(Object.entries(seed));
  return {
    async ensureInitialized() {},
    async unlock() {},
    async isUnlocked() {
      return true;
    },
    async addSecret(name, value) {
      if (store.has(name)) throw new Error(`exists: ${name}`);
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

const CALLER = {
  identity_id: "did:sanctuary:agent",
  skill: "mailer",
  agent: "hermes",
  tenant_id: "t1",
  fortress_id: "f1",
  audience: "broker",
};

function harness(opts: { bound: string[]; seed?: Record<string, string> }) {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const backend = makeFakeBackend(opts.seed);
  return { storage, auditLog, backend, bound: new Set(opts.bound) };
}

describe("broker refuses every path to a surrogate-bound secret", () => {
  it("issueToken refuses a bound secret even when a matching grant exists", async () => {
    const h = harness({ bound: ["openai-api-key"] });
    const issuer = new TokenIssuer({
      backend: h.backend,
      auditLog: h.auditLog,
      surrogateBoundSecrets: h.bound,
      grants: [{ skill: "mailer", secret: "openai-api-key", scope: "read" }],
    });

    await expect(
      issuer.issueToken({ skill: "mailer", secret: "openai-api-key", caller: CALLER }),
    ).rejects.toBeInstanceOf(BrokerDeniedError);

    const audit = await h.auditLog.query({
      operation_type: BROKER_OPS.SURROGATE_TOKEN_REFUSED,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details?.surface).toBe("issue_token");
    expect(audit.entries[0]!.details?.reason).toBe("surrogate_bound");
    expect(audit.entries[0]!.result).toBe("failure");
  });

  it("the denial a bound secret produces is the same generic denial a missing grant produces", async () => {
    const h = harness({ bound: ["openai-api-key"] });
    const issuer = new TokenIssuer({
      backend: h.backend,
      auditLog: h.auditLog,
      surrogateBoundSecrets: h.bound,
      grants: [{ skill: "mailer", secret: "openai-api-key", scope: "read" }],
    });
    // Enumeration guard: the agent must not be able to tell "bound" from
    // "ungranted" by the error it gets back.
    const denial = async (secret: string): Promise<Error> => {
      try {
        await issuer.issueToken({ skill: "mailer", secret, caller: CALLER });
      } catch (err) {
        return err as Error;
      }
      throw new Error(`expected a denial for ${secret}`);
    };
    const boundErr = await denial("openai-api-key");
    const ungrantedErr = await denial("never-granted");
    expect(boundErr.name).toBe(ungrantedErr.name);
    expect(boundErr.message).toBe(ungrantedErr.message);
  });

  it("readViaToken refuses a live token whose secret became bound after issuance", async () => {
    // The scenario `issueToken`'s own check cannot cover: the token was minted
    // while the name was free. The bound set is the live one the issuer holds,
    // so binding the name is what a policy reload does, not a test back door.
    const h = harness({ bound: [], seed: { "openai-api-key": BOUND_VALUE } });
    const bound = new Set<string>();
    const issuer = new TokenIssuer({
      backend: h.backend,
      auditLog: h.auditLog,
      surrogateBoundSecrets: bound,
      grants: [{ skill: "mailer", secret: "openai-api-key", scope: "read" }],
    });
    const token = (
      await issuer.issueToken({ skill: "mailer", secret: "openai-api-key", caller: CALLER })
    ).token;
    expect(await issuer.readViaToken(token)).toBe(BOUND_VALUE);

    bound.add("openai-api-key");

    await expect(issuer.readViaToken(token)).rejects.toBeInstanceOf(BrokerDeniedError);
    const audit = await h.auditLog.query({
      operation_type: BROKER_OPS.SURROGATE_TOKEN_REFUSED,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details?.surface).toBe("read_via_token");

    // The token is dropped, so a second attempt cannot even be classified as a
    // surrogate refusal, and no audit detail anywhere carries the value.
    await expect(issuer.readViaToken(token)).rejects.toThrow();
    for (const e of (await h.auditLog.query({})).entries) {
      expect(JSON.stringify(e.details ?? {})).not.toContain(BOUND_VALUE);
    }
  });

  it("the refusal fires ahead of expiry, so a bound name never reads as merely expired", async () => {
    const h = harness({ bound: [], seed: { "openai-api-key": BOUND_VALUE } });
    const bound = new Set<string>();
    let clock = Date.parse("2026-09-30T00:00:00.000Z");
    const issuer = new TokenIssuer({
      backend: h.backend,
      auditLog: h.auditLog,
      surrogateBoundSecrets: bound,
      now: () => clock,
      grants: [{ skill: "mailer", secret: "openai-api-key", scope: "read" }],
    });
    const token = (
      await issuer.issueToken({ skill: "mailer", secret: "openai-api-key", caller: CALLER })
    ).token;
    bound.add("openai-api-key");
    clock += 2 * 60 * 60 * 1000; // well past any TTL the issuer will grant

    await expect(issuer.readViaToken(token)).rejects.toBeInstanceOf(BrokerDeniedError);
    const refusals = await h.auditLog.query({
      operation_type: BROKER_OPS.SURROGATE_TOKEN_REFUSED,
    });
    expect(refusals.entries).toHaveLength(1);
  });

  it("Broker.grant refuses a bound secret and records the refusal", async () => {
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    const broker = new Broker({
      backend: makeFakeBackend(),
      auditLog,
      surrogateBoundSecrets: new Set(["openai-api-key"]),
      principalIdentityId: "did:sanctuary:principal",
    });

    expect(() =>
      broker.grant({ skill: "mailer", secret: "openai-api-key", scope: "read" }),
    ).toThrow(BrokerDeniedError);

    // Refused at the point of writing: the name must not appear in the operator
    // inventory as though the grant took.
    expect(broker.getGrants()).toHaveLength(0);
    await auditLog.flush();
    const audit = await auditLog.query({
      operation_type: BROKER_OPS.SURROGATE_TOKEN_REFUSED,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details?.surface).toBe("grant");
  });

  it("an ordinary unbound secret still grants, issues and reads", async () => {
    // No-regression: the refusal is narrow, not a broker-wide denial.
    const storage = new MemoryStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    const broker = new Broker({
      backend: makeFakeBackend({ "sendgrid-key": BOUND_VALUE }),
      auditLog,
      surrogateBoundSecrets: new Set(["openai-api-key"]),
      principalIdentityId: "did:sanctuary:principal",
    });
    broker.grant({ skill: "mailer", secret: "sendgrid-key", scope: "read" });
    const binding = await broker.issueToken({
      skill: "mailer",
      secret: "sendgrid-key",
      caller: CALLER,
    });
    expect(await broker.readViaToken(binding.token)).toBe(BOUND_VALUE);
  });
});
