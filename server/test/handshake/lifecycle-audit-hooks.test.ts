/**
 * Hardening wave 6 finding #90, handshake session-lifecycle audit hooks.
 *
 * Verifies that every session transition emits a session-lifecycle audit
 * event in addition to the existing tool-action audit:
 *   handshake_initiated  on initiator-side initiate and responder-side respond
 *   handshake_completed  on successful complete (initiator) and verify_completion (responder)
 *   handshake_failed     on verification rejection (signature, SHR, version)
 *   handshake_aborted    on operator cancel (handshake_abort tool)
 *
 * Each test exercises the production tool surface end-to-end so the hooks
 * fire on the same code path operators run in production.
 */

import { describe, it, expect } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createHandshakeTools } from "../../src/handshake/tools.js";
import { defaultConfig } from "../../src/config.js";
import { HANDSHAKE_LIFECYCLE_OPS } from "../../src/handshake/audit.js";
import type {
  HandshakeChallenge,
  HandshakeResponse,
  HandshakeCompletion,
} from "../../src/handshake/types.js";

async function makeAgent() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const config = defaultConfig();
  const { identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  // Create a primary identity so handshake tools can find one to sign with.
  const encKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("test", encKey, "recovery-key");
  await identityManager.save(storedIdentity);
  return { storage, masterKey, config, identityManager, auditLog };
}

async function lifecycleEntries(auditLog: AuditLog) {
  await auditLog.flush();
  const r = await auditLog.query({ layer: "l4", limit: 1000 });
  return r.entries.filter((e) =>
    Object.values(HANDSHAKE_LIFECYCLE_OPS).includes(
      e.operation as (typeof HANDSHAKE_LIFECYCLE_OPS)[keyof typeof HANDSHAKE_LIFECYCLE_OPS]
    )
  );
}

describe("handshake session-lifecycle audit hooks (finding #90)", () => {
  it("handshake_initiated fires when a new session is created", async () => {
    const agent = await makeAgent();
    const { tools } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );
    const initiate = tools.find((t) => t.name === "handshake_initiate")!;

    await initiate.handler({});

    const lifecycle = await lifecycleEntries(agent.auditLog);
    const initiated = lifecycle.filter(
      (e) => e.operation === HANDSHAKE_LIFECYCLE_OPS.INITIATED
    );
    expect(initiated.length).toBe(1);
    expect(initiated[0]!.result).toBe("success");
    expect((initiated[0]!.details as { role: string }).role).toBe("initiator");
    expect((initiated[0]!.details as { session_id: string }).session_id).toBeTruthy();
  });

  it("handshake_completed fires when the initiator completes the round-trip", async () => {
    const agentA = await makeAgent();
    const agentB = await makeAgent();
    const { tools: toolsA } = createHandshakeTools(
      agentA.config,
      agentA.identityManager,
      agentA.masterKey,
      agentA.auditLog
    );
    const { tools: toolsB } = createHandshakeTools(
      agentB.config,
      agentB.identityManager,
      agentB.masterKey,
      agentB.auditLog
    );

    const initiateRes = await toolsA
      .find((t) => t.name === "handshake_initiate")!
      .handler({});
    const initiated = JSON.parse(initiateRes.content[0]!.text) as {
      session_id: string;
      challenge: HandshakeChallenge;
    };

    const respondRes = await toolsB
      .find((t) => t.name === "handshake_respond")!
      .handler({ challenge: initiated.challenge });
    const responded = JSON.parse(respondRes.content[0]!.text) as {
      response: HandshakeResponse;
    };

    await toolsA
      .find((t) => t.name === "handshake_complete")!
      .handler({ session_id: initiated.session_id, response: responded.response });

    const lifecycleA = await lifecycleEntries(agentA.auditLog);
    const completedA = lifecycleA.filter(
      (e) => e.operation === HANDSHAKE_LIFECYCLE_OPS.COMPLETED
    );
    expect(completedA.length).toBe(1);
    expect(completedA[0]!.result).toBe("success");
    expect((completedA[0]!.details as { role: string }).role).toBe("initiator");
    expect((completedA[0]!.details as { trust_tier: string }).trust_tier).toBeTruthy();
    expect(
      (completedA[0]!.details as { counterparty_id: string }).counterparty_id
    ).toBeTruthy();
  });

  it("handshake_failed fires when verification rejects a tampered completion", async () => {
    const agentA = await makeAgent();
    const agentB = await makeAgent();
    const { tools: toolsA } = createHandshakeTools(
      agentA.config,
      agentA.identityManager,
      agentA.masterKey,
      agentA.auditLog
    );
    const { tools: toolsB } = createHandshakeTools(
      agentB.config,
      agentB.identityManager,
      agentB.masterKey,
      agentB.auditLog
    );

    const initiateRes = await toolsA
      .find((t) => t.name === "handshake_initiate")!
      .handler({});
    const initiated = JSON.parse(initiateRes.content[0]!.text) as {
      session_id: string;
      challenge: HandshakeChallenge;
    };

    const respondRes = await toolsB
      .find((t) => t.name === "handshake_respond")!
      .handler({ challenge: initiated.challenge });
    const responded = JSON.parse(respondRes.content[0]!.text) as {
      response: HandshakeResponse;
    };

    // Tamper the responder nonce signature so completeHandshake rejects.
    const tamperedResponse: HandshakeResponse = {
      ...responded.response,
      initiator_nonce_signature: "AAAA" + responded.response.initiator_nonce_signature.slice(4),
    };

    await toolsA
      .find((t) => t.name === "handshake_complete")!
      .handler({ session_id: initiated.session_id, response: tamperedResponse });

    const lifecycleA = await lifecycleEntries(agentA.auditLog);
    const failed = lifecycleA.filter(
      (e) => e.operation === HANDSHAKE_LIFECYCLE_OPS.FAILED
    );
    expect(failed.length).toBe(1);
    expect(failed[0]!.result).toBe("failure");
    expect((failed[0]!.details as { reason: string }).reason).toBe(
      "nonce_signature_invalid"
    );
  });

  it("handshake_aborted fires when handshake_abort is invoked on an in-flight session", async () => {
    const agent = await makeAgent();
    const { tools } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );

    const initiateRes = await tools
      .find((t) => t.name === "handshake_initiate")!
      .handler({});
    const initiated = JSON.parse(initiateRes.content[0]!.text) as {
      session_id: string;
    };

    const abortRes = await tools
      .find((t) => t.name === "handshake_abort")!
      .handler({ session_id: initiated.session_id, reason: "operator_cancelled" });
    const aborted = JSON.parse(abortRes.content[0]!.text) as { aborted: boolean };
    expect(aborted.aborted).toBe(true);

    const lifecycle = await lifecycleEntries(agent.auditLog);
    const abortedEntries = lifecycle.filter(
      (e) => e.operation === HANDSHAKE_LIFECYCLE_OPS.ABORTED
    );
    expect(abortedEntries.length).toBe(1);
    expect(abortedEntries[0]!.result).toBe("failure");
    expect((abortedEntries[0]!.details as { reason: string }).reason).toBe(
      "operator_cancelled"
    );
  });
});
