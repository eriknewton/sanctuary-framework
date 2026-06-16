import { describe, expect, it } from "vitest";
import { sign as identitySign, verify as identityVerify } from "../src/core/identity.js";
import { fromBase64url, stringToBytes, toBase64url } from "../src/core/encoding.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { generateRandomKey } from "../src/core/random.js";
import { StateStore } from "../src/cognitive/state-store.js";
import {
  AUDIT_EVENT_SIGNING_DOMAIN,
  INTERNAL_RECEIPT_SIGNING_DOMAIN,
  createL1Tools,
  domainSeparatedSigningBytes,
  type AuditEventSigningPayload,
  type InternalReceiptSigningPayload,
} from "../src/cognitive/tools.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { MemoryStorage } from "../src/storage/memory.js";

async function callTool(
  tools: Array<{
    name: string;
    handler: (
      args: Record<string, unknown>
    ) => Promise<{ content: Array<{ type: string; text: string }> }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

function makeRig() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const l1 = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { ...l1, masterKey };
}

const auditPayload: AuditEventSigningPayload = {
  event_id: "audit-evt-1",
  layer: "l2",
  operation: "gate_allow:state_read",
  actor: "system",
  timestamp: "2026-05-15T12:00:00.000Z",
  event_hash: `sha256:${"a".repeat(64)}`,
  previous_event_hash: `sha256:${"b".repeat(64)}`,
};

const receiptPayload: InternalReceiptSigningPayload = {
  receipt_id: "receipt-1",
  receipt_type: "approval",
  subject: "identity_sign",
  issued_at: "2026-05-15T12:00:00.000Z",
  status: "approved",
  body_hash: `sha256:${"c".repeat(64)}`,
};

describe("internal identity signing helpers", () => {
  it("keeps typed signing helpers off the MCP tool surface", () => {
    const { tools } = makeRig();
    const names = tools.map((tool) => tool.name);

    expect(names).toContain("identity_sign");
    expect(names).toContain("identity_verify");
    expect(names).not.toContain("audit_event_sign");
    expect(names).not.toContain("internal_receipt_sign");
  });

  it("signs audit events and internal receipts without using operator approval", async () => {
    const { tools, identityManager, internalSigning } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "internal-signer",
    });

    const auditSigned = await internalSigning.audit_event_sign(auditPayload, {
      identity_id: identity.identity_id as string,
    });
    const receiptSigned = await internalSigning.internal_receipt_sign(receiptPayload, {
      identity_id: identity.identity_id as string,
    });

    expect(auditSigned.domain).toBe(AUDIT_EVENT_SIGNING_DOMAIN);
    expect(receiptSigned.domain).toBe(INTERNAL_RECEIPT_SIGNING_DOMAIN);
    expect(auditSigned.signature).toEqual(expect.any(String));
    expect(receiptSigned.signature).toEqual(expect.any(String));
  });

  it("rejects arbitrary bytes smuggled through the receipt schema", async () => {
    const { tools, identityManager, internalSigning } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "receipt-schema",
    });

    expect(() =>
      internalSigning.internal_receipt_sign(
        {
          ...receiptPayload,
          payload: "raw arbitrary commitment",
        } as unknown as InternalReceiptSigningPayload,
        { identity_id: identity.identity_id as string }
      )
    ).toThrow(/unsupported field: payload/);
  });

  it("domain-separated signatures cannot be replayed across audit and receipt domains", async () => {
    const { tools, identityManager, internalSigning } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "domain-separation",
    });

    const signed = await internalSigning.audit_event_sign(auditPayload, {
      identity_id: identity.identity_id as string,
    });
    const signature = fromBase64url(signed.signature);
    const publicKey = fromBase64url(identity.public_key as string);

    const auditBytes = domainSeparatedSigningBytes(
      AUDIT_EVENT_SIGNING_DOMAIN,
      auditPayload as unknown as Record<string, unknown>
    );
    const receiptBytes = domainSeparatedSigningBytes(
      INTERNAL_RECEIPT_SIGNING_DOMAIN,
      auditPayload as unknown as Record<string, unknown>
    );

    expect(identityVerify(auditBytes, signature, publicKey)).toBe(true);
    expect(identityVerify(receiptBytes, signature, publicKey)).toBe(false);
  });

  it("keeps identity_verify available for arbitrary payload verification", async () => {
    const { tools, identityManager, masterKey } = makeRig();
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", {
      label: "verify-only",
    });
    const storedIdentity = identityManager.get(identity.identity_id as string);
    if (!storedIdentity) throw new Error("identity was not saved");

    const payloadBytes = stringToBytes("verify this arbitrary external payload");
    const payload = toBase64url(payloadBytes);
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const signature = identitySign(
      payloadBytes,
      storedIdentity.encrypted_private_key,
      identityEncKey
    );

    const verified = await callTool(tools, "identity_verify", {
      public_key: identity.public_key,
      payload,
      signature: toBase64url(signature),
    });

    expect(verified.valid).toBe(true);
  });
});
