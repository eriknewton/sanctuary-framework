/**
 * Broker Orchestrator Tests
 *
 * Verifies the Broker class correctly composes Backend + TokenIssuer +
 * AuditLog, and that every administrative operation (add/rotate/delete,
 * grant/revoke) produces the right audit entry with the configured
 * principal identity.
 */

import { describe, it, expect } from "vitest";
import type { Backend } from "../../../src/l3-disclosure/broker/backend-interface.js";
import { SecretNotFoundError } from "../../../src/l3-disclosure/broker/backend-interface.js";
import { Broker } from "../../../src/l3-disclosure/broker/broker.js";
import { AuditLog, BROKER_OPS } from "../../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { generateRandomKey } from "../../../src/core/random.js";

function makeFakeBackend(seed: Record<string, string> = {}): Backend {
  const store = new Map(Object.entries(seed));
  let unlocked = true;
  return {
    async ensureInitialized() {
      unlocked = true;
    },
    async unlock() {
      unlocked = true;
    },
    async isUnlocked() {
      return unlocked;
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

async function makeBroker(seed: Record<string, string> = {}) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const backend = makeFakeBackend(seed);
  const broker = new Broker({
    backend,
    auditLog,
    principalIdentityId: "did:sanctuary:principal",
  });
  return { broker, auditLog, backend };
}

describe("Broker", () => {
  it("addSecret writes to backend and audits", async () => {
    const { broker, auditLog } = await makeBroker();
    await broker.addSecret("gmail_oauth", "xyz");
    expect(await broker.listSecretNames()).toEqual(["gmail_oauth"]);

    const audit = await auditLog.query({ operation_type: BROKER_OPS.SECRET_ADDED });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details?.secret).toBe("gmail_oauth");
    expect(audit.entries[0]!.identity_id).toBe("did:sanctuary:principal");
  });

  it("audit entries never contain secret values", async () => {
    const { broker, auditLog } = await makeBroker();
    await broker.addSecret("gmail_oauth", "super-secret-value-abc");
    await broker.rotateSecret("gmail_oauth", "rotated-value-def");
    const audit = await auditLog.query({ layer: "l3", limit: 100 });
    const serialized = JSON.stringify(audit.entries);
    expect(serialized).not.toContain("super-secret-value-abc");
    expect(serialized).not.toContain("rotated-value-def");
  });

  it("rotateSecret updates value and audits", async () => {
    const { broker, backend, auditLog } = await makeBroker({ gmail_oauth: "v1" });
    await broker.rotateSecret("gmail_oauth", "v2");
    expect(await backend.readSecret("gmail_oauth")).toBe("v2");
    const audit = await auditLog.query({ operation_type: BROKER_OPS.SECRET_ROTATED });
    expect(audit.entries).toHaveLength(1);
  });

  it("rotateSecret throws SecretNotFoundError for unknown name", async () => {
    const { broker } = await makeBroker();
    await expect(broker.rotateSecret("unknown", "v")).rejects.toBeInstanceOf(SecretNotFoundError);
  });

  it("deleteSecret removes and audits", async () => {
    const { broker, auditLog } = await makeBroker({ gmail_oauth: "v" });
    await broker.deleteSecret("gmail_oauth");
    expect(await broker.listSecretNames()).toEqual([]);
    const audit = await auditLog.query({ operation_type: BROKER_OPS.SECRET_DELETED });
    expect(audit.entries).toHaveLength(1);
  });

  it("grant + revoke are audited", async () => {
    const { broker, auditLog } = await makeBroker();
    broker.grant({ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" });
    broker.revoke("gmail-triage", "gmail_oauth");

    const granted = await auditLog.query({ operation_type: BROKER_OPS.SECRET_GRANTED });
    const revoked = await auditLog.query({ operation_type: BROKER_OPS.SECRET_REVOKED });
    expect(granted.entries).toHaveLength(1);
    expect(revoked.entries).toHaveLength(1);
    expect(granted.entries[0]!.details?.skill).toBe("gmail-triage");
  });

  it("end-to-end: add -> grant -> issueToken -> readViaToken -> revoke", async () => {
    const { broker, auditLog } = await makeBroker();
    await broker.addSecret("gmail_oauth", "value-abc");
    broker.grant({ skill: "gmail-triage", secret: "gmail_oauth", scope: "read" });

    const binding = await broker.issueToken({
      skill: "gmail-triage",
      secret: "gmail_oauth",
      agent: "nsa",
      identity_id: "did:sanctuary:principal",
    });
    expect(await broker.readViaToken(binding.token)).toBe("value-abc");

    broker.revoke("gmail-triage", "gmail_oauth");
    await expect(broker.readViaToken(binding.token)).rejects.toThrow();

    const audit = await broker.queryAudit();
    const ops = audit.entries.map((e) => e.operation);
    expect(ops).toContain(BROKER_OPS.SECRET_ADDED);
    expect(ops).toContain(BROKER_OPS.SECRET_GRANTED);
    expect(ops).toContain(BROKER_OPS.TOKEN_ISSUED);
    expect(ops).toContain(BROKER_OPS.SECRET_READ);
    expect(ops).toContain(BROKER_OPS.SECRET_REVOKED);
  });

  it("queryAudit surfaces only broker-scoped entries", async () => {
    const { broker, auditLog } = await makeBroker();
    // Inject an unrelated L2 entry.
    auditLog.append("l2", "unrelated_op", "did:sanctuary:principal", {}, "success");
    await broker.addSecret("gmail_oauth", "v");
    const summary = await broker.queryAudit();
    for (const e of summary.entries) {
      expect(Object.values(BROKER_OPS)).toContain(e.operation);
    }
  });

  it("ensureUnlocked delegates to backend and audits unlock", async () => {
    const { broker, auditLog } = await makeBroker();
    await broker.ensureUnlocked("pp");
    const audit = await auditLog.query({ operation_type: BROKER_OPS.BACKEND_UNLOCKED });
    expect(audit.entries).toHaveLength(1);
  });
});
