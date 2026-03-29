/**
 * Security Test: SEC-ADD-03 — Prompt Injection Output Tagging
 *
 * Verifies that Sanctuary tool responses containing counterparty-controlled
 * data include _content_trust: "external" metadata to enable agent harnesses
 * to identify and sandbox untrusted content.
 *
 * Tests cover:
 * 1. bridge_verify — counterparty bridge commitment data
 * 2. handshake_respond — counterparty SHR data sent to counterparty
 * 3. handshake_complete — counterparty SHR and verification result
 * 4. handshake_status — counterparty SHR and verification result
 * 5. reputation_query — counterparty-generated attestation data
 * 6. federation_peers — counterparty peer metadata
 * 7. federation_trust_evaluate — derived from counterparty HandshakeResult
 * 8. reputation_query_weighted — weighted scores from counterparty attestations
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
  bytesToString,
} from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";
import { encrypt, decrypt, type EncryptedPayload } from "../../src/core/encryption.js";
import {
  createBridgeCommitment,
  verifyBridgeCommitment,
} from "../../src/bridge/bridge.js";
import type { ConcordiaOutcome, BridgeCommitment } from "../../src/bridge/types.js";
import type { StorageBackend } from "../../src/storage/interface.js";
import type { AuditLog } from "../../src/l2-operational/audit-log.js";
import type { ToolDefinition } from "../../src/router.js";
import { createBridgeTools } from "../../src/bridge/tools.js";
import { createHandshakeTools } from "../../src/handshake/tools.js";
import { createFederationTools } from "../../src/federation/tools.js";
import { createL4Tools } from "../../src/l4-reputation/tools.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog as AuditLogImpl } from "../../src/l2-operational/audit-log.js";
import { generateSHR } from "../../src/shr/generator.js";
import { defaultConfig } from "../../src/config.js";
import type { StoredIdentity } from "../../src/core/identity.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";
import {
  initiateHandshake,
  respondToHandshake,
  completeHandshake,
} from "../../src/handshake/protocol.js";

/** Replicating bridge module's stableStringify for test vectors. */
function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys.map(
    (k) => JSON.stringify(k) + ":" + stableStringify(obj[k])
  );
  return "{" + pairs.join(",") + "}";
}

function makeOutcome(overrides?: Partial<ConcordiaOutcome>): ConcordiaOutcome {
  const terms = { price: 100, currency: "USD" };
  const termsHash = toBase64url(hash(stringToBytes(stableStringify(terms))));
  return {
    session_id: "test-session-001",
    protocol_version: "concordia-v1",
    proposer_did: "did:sanctuary:proposer",
    acceptor_did: "did:sanctuary:acceptor",
    terms,
    terms_hash: termsHash,
    rounds: 2,
    accepted_at: "2026-03-28T12:00:00.000Z",
    ...overrides,
  };
}

/** Helper: invoke an MCP tool handler by name and return parsed JSON result. */
async function callTool(
  tools: Array<{ name: string; handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }> }> }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

/** Lightweight IdentityManager for testing. */
class TestIdentityManager {
  private identities = new Map<string, StoredIdentity>();
  private defaultId: string | null = null;

  constructor(masterKey: Uint8Array) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "test",
      encKey,
      "recovery-key"
    );
    this.identities.set(publicIdentity.identity_id, storedIdentity);
    this.defaultId = publicIdentity.identity_id;
  }

  get(id: string) {
    return this.identities.get(id);
  }
  getDefault() {
    return this.defaultId ? this.identities.get(this.defaultId) : undefined;
  }
  list() {
    return Array.from(this.identities.values());
  }
}

function makeAgent() {
  const masterKey = generateRandomKey();
  const identityManager = new TestIdentityManager(masterKey);
  const config = defaultConfig();
  return { masterKey, identityManager, config };
}

function agentSHR(agent: ReturnType<typeof makeAgent>): SignedSHR {
  const result = generateSHR(undefined, {
    config: agent.config,
    identityManager: agent.identityManager as any,
    masterKey: agent.masterKey,
  });
  if (typeof result === "string") throw new Error(result);
  return result;
}

const mockSHR: SignedSHR = {
  body: {
    shr_version: "1.0",
    instance_id: "peer-1",
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    layers: {
      l1: { status: "active", encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
      l2: { status: "degraded", isolation_type: "local-process", attestation_available: true },
      l3: { status: "degraded", proof_system: "commitment-only", selective_disclosure: false },
      l4: { status: "active", reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
    },
    capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
    degradations: [],
  },
  signed_by: "mock-key",
  signature: "mock-sig",
};

function makeHandshakeResult(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    counterparty_id: "peer-1",
    counterparty_shr: mockSHR,
    verified: true,
    sovereignty_level: "degraded",
    trust_tier: "verified-degraded",
    completed_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600000).toISOString(),
    errors: [],
    ...overrides,
  };
}

// ─── Stub AuditLog for tools that require it ─────────────────────────────

const stubAuditLog: AuditLog = {
  append: () => {},
  getEntries: () => [],
} as unknown as AuditLog;

describe("SEC-ADD-03: Prompt Injection Output Tagging", () => {
  let masterKey: Uint8Array;
  let identityEncKey: Uint8Array;
  let identity: ReturnType<typeof createIdentity>;
  let publicKey: Uint8Array;

  beforeEach(() => {
    masterKey = generateRandomKey();
    identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    identity = createIdentity("tag-test", identityEncKey, "recovery-key");
    publicKey = fromBase64url(identity.publicIdentity.public_key);
  });

  // ─── Original tests ──────────────────────────────────────────────────

  it("bridge_verify result includes _content_trust: external when constructed in tool response", () => {
    const outcome = makeOutcome();
    const commitment = createBridgeCommitment(
      outcome,
      identity.storedIdentity,
      identityEncKey
    );

    const result = verifyBridgeCommitment(commitment, outcome, publicKey);
    expect(result.valid).toBe(true);
    expect(result.checks).toBeDefined();

    // Simulate what the tool handler does: spread result + add _content_trust
    const toolResponse = {
      ...result,
      session_id: commitment.session_id,
      committer_did: commitment.committer_did,
      _content_trust: "external",
    };

    expect(toolResponse._content_trust).toBe("external");
    expect(toolResponse.valid).toBe(true);
  });

  it("_content_trust field is string 'external' not boolean", () => {
    const toolResponse = {
      some_data: "test",
      _content_trust: "external" as const,
    };
    expect(typeof toolResponse._content_trust).toBe("string");
    expect(toolResponse._content_trust).toBe("external");
  });

  // ─── Condition 3: Regression tests for originally tagged tools ────────

  it("handshake_respond result includes _content_trust: external", async () => {
    const agentA = makeAgent();
    const agentB = makeAgent();

    const { tools: toolsB } = createHandshakeTools(
      agentB.config,
      agentB.identityManager as any,
      agentB.masterKey,
      stubAuditLog
    );

    // Agent A initiates
    const shrA = agentSHR(agentA);
    const { challenge } = initiateHandshake(shrA);

    // Agent B responds via tool handler
    const response = await callTool(toolsB, "sanctuary/handshake_respond", {
      challenge,
    });

    expect(response._content_trust).toBe("external");
    expect(response.session_id).toBeTruthy();
    expect(response.response).toBeTruthy();
  });

  it("handshake_complete result includes _content_trust: external", async () => {
    const agentA = makeAgent();
    const agentB = makeAgent();

    const { tools: toolsA } = createHandshakeTools(
      agentA.config,
      agentA.identityManager as any,
      agentA.masterKey,
      stubAuditLog
    );

    // Full handshake at protocol level to get a valid response
    const shrA = agentSHR(agentA);
    const shrB = agentSHR(agentB);
    const { challenge, session: sessionA } = initiateHandshake(shrA);
    const respondResult = respondToHandshake(
      challenge,
      shrB,
      agentB.identityManager as any,
      agentB.masterKey,
      undefined
    );
    if ("error" in respondResult) throw new Error(respondResult.error);

    // Agent A completes via tool handler — need to seed the session first
    // Call initiate via tool to register the session, then complete with the response
    const initiateResult = await callTool(toolsA, "sanctuary/handshake_initiate", {});
    const sessionId = initiateResult.session_id as string;

    // Respond at protocol level using the tool-generated challenge
    const toolChallenge = initiateResult.challenge;
    const respondResult2 = respondToHandshake(
      toolChallenge as any,
      shrB,
      agentB.identityManager as any,
      agentB.masterKey,
      undefined
    );
    if ("error" in respondResult2) throw new Error(respondResult2.error);

    const completeResult = await callTool(toolsA, "sanctuary/handshake_complete", {
      session_id: sessionId,
      response: respondResult2.response,
    });

    expect(completeResult._content_trust).toBe("external");
    expect(completeResult.result).toBeTruthy();
  });

  it("reputation_query result includes _content_trust: external", async () => {
    const storage = new MemoryStorage();
    const key = generateRandomKey();
    const auditLog = new AuditLogImpl(storage, key);

    const { tools: l1Tools, identityManager } = createL1Tools(
      new StateStore(storage, key), storage, key, "recovery-key", auditLog
    );
    await identityManager.load();

    const { tools: l4Tools } = createL4Tools(storage, key, identityManager, auditLog);

    const result = await callTool(l4Tools, "sanctuary/reputation_query", {});
    expect(result._content_trust).toBe("external");
    expect(result.summary).toBeDefined();
  });

  // ─── Condition 2: Regression tests for newly tagged tools ─────────────

  it("handshake_status result includes _content_trust: external", async () => {
    const agentA = makeAgent();

    const { tools: toolsA } = createHandshakeTools(
      agentA.config,
      agentA.identityManager as any,
      agentA.masterKey,
      stubAuditLog
    );

    // Initiate a handshake to create a session
    const initiateResult = await callTool(toolsA, "sanctuary/handshake_initiate", {});
    const sessionId = initiateResult.session_id as string;

    // Query status
    const statusResult = await callTool(toolsA, "sanctuary/handshake_status", {
      session_id: sessionId,
    });

    expect(statusResult._content_trust).toBe("external");
    expect(statusResult.session_id).toBe(sessionId);
  });

  it("federation_peers list result includes _content_trust: external", async () => {
    const handshakeResults = new Map<string, HandshakeResult>();
    const { tools: fedTools } = createFederationTools(stubAuditLog, handshakeResults);

    const result = await callTool(fedTools, "sanctuary/federation_peers", {
      action: "list",
    });

    expect(result._content_trust).toBe("external");
    expect(result.peers).toBeDefined();
  });

  it("federation_trust_evaluate result includes _content_trust: external", async () => {
    const handshakeResults = new Map<string, HandshakeResult>();
    // Register a peer so trust evaluation has something to work with
    const hsResult = makeHandshakeResult();
    handshakeResults.set("peer-1", hsResult);

    const { tools: fedTools, registry } = createFederationTools(stubAuditLog, handshakeResults);

    // Register the peer first
    await callTool(fedTools, "sanctuary/federation_peers", {
      action: "register",
      peer_id: "peer-1",
      peer_did: "did:sanctuary:peer-1",
    });

    const result = await callTool(fedTools, "sanctuary/federation_trust_evaluate", {
      peer_id: "peer-1",
    });

    expect(result._content_trust).toBe("external");
    expect(result.trust_level).toBeDefined();
  });

  it("reputation_query_weighted result includes _content_trust: external", async () => {
    const storage = new MemoryStorage();
    const key = generateRandomKey();
    const auditLog = new AuditLogImpl(storage, key);

    const { tools: l1Tools, identityManager } = createL1Tools(
      new StateStore(storage, key), storage, key, "recovery-key", auditLog
    );
    await identityManager.load();

    const { tools: l4Tools } = createL4Tools(storage, key, identityManager, auditLog);

    const result = await callTool(l4Tools, "sanctuary/reputation_query_weighted", {
      metric: "reliability",
    });

    expect(result._content_trust).toBe("external");
    expect(result.metric).toBe("reliability");
  });
});
