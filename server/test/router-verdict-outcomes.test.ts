/**
 * A verdict a tool reports inside an otherwise well-formed body, about whether
 * this call was permitted, reaches the agent through tools/call as the one
 * refusal, and the operator ledger records the post-allow cause. Each tool's
 * ordinary success passes through unchanged.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer, type ToolDefinition } from "../src/router.js";
import { AuditLog } from "../src/operational/audit-log.js";
import { MemoryStorage } from "../src/storage/memory.js";
import { generateRandomKey } from "../src/core/random.js";
import { StateStore } from "../src/cognitive/state-store.js";
import { createL1Tools, type InternalIdentitySigningHelpers } from "../src/cognitive/tools.js";
import { createIdentity, type StoredIdentity } from "../src/core/identity.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import { defaultConfig } from "../src/config.js";
import { createHandshakeTools } from "../src/handshake/tools.js";
import { generateSHR } from "../src/shr/generator.js";
import type { SignedSHR } from "../src/shr/types.js";
import { createDistressTools, DISTRESS_REASONS, DISTRESS_SEVERITIES } from "../src/distress/tools.js";
import { defaultDistressConfig } from "../src/distress/config.js";
import { expectedRefusal } from "./helpers/expected-refusal.js";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  const errors: unknown[] = [];
  for (const cleanup of cleanups.splice(0).reverse()) {
    try { await cleanup(); } catch (error) { errors.push(error); }
  }
  if (errors.length > 0) throw errors[0];
});

type WireResult = Awaited<ReturnType<Client["callTool"]>>;

// The composition root's read set includes handshake_status; every other tool
// used here is a write tool there.
const READ_TOOLS_HERE: ReadonlySet<string> = new Set(["handshake_status"]);

/** One call through a real router whose ledger writes to routerAudit. */
async function callThroughRouter(
  tools: ToolDefinition[],
  name: string,
  args: Record<string, unknown>,
  routerAudit: AuditLog,
): Promise<WireResult> {
  const classified = tools.map((definition): ToolDefinition => ({
    ...definition,
    tool_class: READ_TOOLS_HERE.has(definition.name) ? "read" : "write",
  }));
  const server = createServer(classified, { auditLog: routerAudit });
  const client = new Client({ name: "verdict-outcome-witness", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    return await client.callTool({ name, arguments: args });
  } finally {
    await client.close();
    await server.close();
  }
}

async function denialRows(routerAudit: AuditLog) {
  await routerAudit.flush();
  return (await routerAudit.query({ operation_type: "denial_cause" })).entries;
}

function parse(result: unknown): Record<string, any> {
  return JSON.parse((result as { content: Array<{ text: string }> }).content[0]!.text);
}

function makeFortress() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();
  const { identityManager } = createL1Tools(
    new StateStore(storage, masterKey),
    storage,
    masterKey,
    "recovery-key",
    auditLog,
  );
  const handshake = createHandshakeTools(config, identityManager, masterKey, auditLog);
  return { masterKey, config, identityManager, auditLog, handshake };
}

async function addIdentity(fortress: ReturnType<typeof makeFortress>, label: string): Promise<StoredIdentity> {
  const encKey = derivePurposeKey(fortress.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity(label, encKey, "recovery-key");
  await fortress.identityManager.save(storedIdentity);
  return storedIdentity;
}

function shrFor(fortress: ReturnType<typeof makeFortress>, identityId: string): SignedSHR {
  const shr = generateSHR(identityId, {
    config: fortress.config,
    identityManager: fortress.identityManager,
    masterKey: fortress.masterKey,
  });
  if (typeof shr === "string") throw new Error(shr);
  return shr;
}

function tool(tools: ToolDefinition[], name: string): ToolDefinition {
  const found = tools.find((candidate) => candidate.name === name);
  if (!found) throw new Error(`missing tool: ${name}`);
  return found;
}

describe("handshake_exchange", () => {
  it("a preview whose trust record this fortress refuses reaches the agent as the one refusal", async () => {
    const fortress = makeFortress();
    const a = await addIdentity(fortress, "identity-a");
    const b = await addIdentity(fortress, "identity-b");
    const routerAudit = new AuditLog(new MemoryStorage(), generateRandomKey());

    // The counterparty's signing key is held by this same fortress, so the
    // preview may not be recorded as a trust-ingest entry.
    const result = await callThroughRouter(fortress.handshake.tools, "handshake_exchange", {
      identity_id: a.identity_id,
      counterparty_shr: shrFor(fortress, b.identity_id),
    }, routerAudit);

    expect(result).toEqual(expectedRefusal());
    expect(fortress.handshake.handshakeResults.size).toBe(0);
    expect(await denialRows(routerAudit)).toEqual([expect.objectContaining({
      identity_id: "system",
      details: expect.objectContaining({ tool: "handshake_exchange", cause: "post_allow_refusal" }),
    })]);
  });

  it("a preview of another fortress's identity passes through unchanged", async () => {
    const local = makeFortress();
    const a = await addIdentity(local, "identity-a");
    const remote = makeFortress();
    const c = await addIdentity(remote, "identity-c");
    const routerAudit = new AuditLog(new MemoryStorage(), generateRandomKey());

    const result = await callThroughRouter(local.handshake.tools, "handshake_exchange", {
      identity_id: a.identity_id,
      counterparty_shr: shrFor(remote, c.identity_id),
    }, routerAudit);

    expect(result.isError).toBeUndefined();
    const body = parse(result);
    expect(body.verification.recorded).toBe(true);
    expect(body.verification).not.toHaveProperty("record_error");
    expect(body.attestation).toBeDefined();
    expect(await denialRows(routerAudit)).toEqual([]);
  });
});

describe("handshake_status", () => {
  async function respondedPair() {
    const initiator = makeFortress();
    const a = await addIdentity(initiator, "identity-a");
    const responder = makeFortress();
    const b = await addIdentity(responder, "identity-b");
    const initiated = parse(await tool(initiator.handshake.tools, "handshake_initiate").handler({ identity_id: a.identity_id }));
    const responded = parse(await tool(responder.handshake.tools, "handshake_respond").handler({
      challenge: initiated.challenge,
      identity_id: b.identity_id,
    }));
    const completed = parse(await tool(initiator.handshake.tools, "handshake_complete").handler({
      session_id: initiated.session_id,
      response: responded.response,
    }));
    expect(completed.result.verified).toBe(true);
    return { a, responder, sessionId: responded.session_id as string, completion: completed.completion };
  }

  it("a verified completion this fortress may not record reaches the agent as the one refusal", async () => {
    const { a, responder, sessionId, completion } = await respondedPair();
    // The responder's fortress gains custody of the initiator's identity before
    // it verifies the completion, so recording the result is refused.
    await responder.identityManager.save(a);
    const routerAudit = new AuditLog(new MemoryStorage(), generateRandomKey());

    const result = await callThroughRouter(responder.handshake.tools, "handshake_status", {
      session_id: sessionId,
      completion,
    }, routerAudit);

    expect(result).toEqual(expectedRefusal());
    expect(responder.handshake.handshakeResults.size).toBe(0);
    expect(await denialRows(routerAudit)).toEqual([expect.objectContaining({
      identity_id: "system",
      details: expect.objectContaining({
        tool: "handshake_status",
        cause: "post_allow_refusal",
        error_name: "error",
        error_message: expect.stringContaining("same fortress"),
      }),
    })]);
  });

  it("a verified completion that is recorded passes through unchanged", async () => {
    const { responder, sessionId, completion } = await respondedPair();
    const routerAudit = new AuditLog(new MemoryStorage(), generateRandomKey());

    const result = await callThroughRouter(responder.handshake.tools, "handshake_status", {
      session_id: sessionId,
      completion,
    }, routerAudit);

    expect(result.isError).toBeUndefined();
    expect(parse(result).result.verified).toBe(true);
    expect(responder.handshake.handshakeResults.size).toBe(1);
    expect(await denialRows(routerAudit)).toEqual([]);
  });
});

describe("sanctuary_distress", () => {
  function signingHelpers(): InternalIdentitySigningHelpers {
    const signed = (domain: string) => ({
      identity_id: "id-test",
      public_key: "pk-test",
      signature: "sig-test",
      algorithm: "Ed25519" as const,
      domain: domain as never,
      signed_payload: "payload",
      payload_encoding: "domain-separated-canonical-json-v1" as const,
      signed_at: new Date(0).toISOString(),
    });
    return {
      audit_event_sign: async () => signed("sanctuary.audit.v1"),
      internal_receipt_sign: async () => signed("sanctuary.receipt.v1"),
    } as InternalIdentitySigningHelpers;
  }

  it("a signal past the hourly admission limit reaches the agent as the one refusal", async () => {
    const fortressPath = await mkdtemp(join(tmpdir(), "sanctuary-distress-verdict-"));
    cleanups.push(() => rm(fortressPath, { recursive: true, force: true }));
    const fixedNow = Date.parse("2026-01-01T00:00:00.000Z");
    const { tools } = createDistressTools({
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      signingHelpers: signingHelpers(),
      config: { ...defaultDistressConfig(), max_signals_per_hour: 1 },
      fortressPath,
      currentActorId: () => "agent-1",
      now: () => fixedNow,
      notify: () => undefined,
    });
    const args = { reason: DISTRESS_REASONS[0], severity: DISTRESS_SEVERITIES[0] };

    const admitted = await callThroughRouter(tools, "sanctuary_distress", args, new AuditLog(new MemoryStorage(), generateRandomKey()));
    expect(admitted.isError).toBeUndefined();
    expect(parse(admitted).ok).toBe(true);

    const routerAudit = new AuditLog(new MemoryStorage(), generateRandomKey());
    const limited = await callThroughRouter(tools, "sanctuary_distress", args, routerAudit);

    expect(limited).toEqual(expectedRefusal());
    expect(await denialRows(routerAudit)).toEqual([expect.objectContaining({
      identity_id: "system",
      details: expect.objectContaining({ tool: "sanctuary_distress", cause: "post_allow_refusal" }),
    })]);
  });
});
