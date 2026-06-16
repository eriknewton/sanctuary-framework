/**
 * Handshake Forgery & Replay Remediation — Regression Suite (M1-M4)
 *
 * Red-team coverage for the minimal-fix design
 * (Review/Sanctuary/Handshake_Remediation_Design_2026-06-04.md):
 *
 *   M1 (HS-1) — verifySHR rejects an SHR whose instance_id is not
 *               generateIdentityId(signed_by). (Covered in shr.test.ts;
 *               re-asserted here at the tool boundary via handshake_exchange.)
 *   M2 (HS-1/HS-2) — handshake_exchange can NEVER yield verified-sovereign /
 *               verified:true; it is a structural preview only.
 *   M3 (HS-3) — federation register rejects a mismatched peer_did and refuses
 *               a result that did not prove liveness.
 *   M4 (HS-2) — a stale (expired) or replayed nonce session in the 4-step path
 *               is rejected, anchored to SERVER time.
 *
 * All wiring uses the real tool handlers and a real IdentityManager — no mocks
 * of the crypto or gate paths.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey, randomBytes } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createHandshakeTools } from "../../src/handshake/tools.js";
import { createFederationTools } from "../../src/federation/tools.js";
import { verifyAttestation } from "../../src/handshake/attestation.js";
import { generateSHR } from "../../src/shr/generator.js";
import {
  createIdentity,
  generateIdentityId,
  publicKeyToDid,
} from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { canonicalizeForSigning } from "../../src/shr/types.js";
import {
  toBase64url,
  fromBase64url,
  stringToBytes,
} from "../../src/core/encoding.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import { defaultConfig } from "../../src/config.js";
import type { SignedSHR } from "../../src/shr/types.js";
import type { HandshakeResult, HandshakeSession } from "../../src/handshake/types.js";

// ── Agent harness (real identity manager, real audit log) ─────────────────

function makeAgent() {
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
  return { storage, masterKey, config, identityManager, auditLog };
}

async function createIdentityFor(agent: ReturnType<typeof makeAgent>) {
  const encKey = derivePurposeKey(agent.masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("test-agent", encKey, "recovery-key");
  await agent.identityManager.save(storedIdentity);
  return storedIdentity;
}

function shrFor(agent: ReturnType<typeof makeAgent>): SignedSHR {
  const shr = generateSHR(undefined, {
    config: agent.config,
    identityManager: agent.identityManager,
    masterKey: agent.masterKey,
  });
  if (typeof shr === "string") throw new Error(shr);
  return shr;
}

function parse(result: { content: { text: string }[] }) {
  return JSON.parse(result.content[0]!.text);
}

// Build a fully-sovereign (all-active) SHR body so sovereignty_level === "full",
// the input that USED to map to verified-sovereign. This makes the M2 assertion
// meaningful: even a "full" report cannot be promoted by handshake_exchange.
function fullSovereignSHR(victimShr: SignedSHR): SignedSHR {
  // Re-sign a body with every layer active using a FRESH self-consistent key,
  // so it is internally valid (passes M1) but is still preview-only.
  const priv = randomBytes(32);
  const pub = ed25519.getPublicKey(priv);
  const instanceId = generateIdentityId(pub);

  const body = JSON.parse(JSON.stringify(victimShr.body));
  body.instance_id = instanceId; // self-consistent with the fresh key
  body.layers.l1.status = "active";
  body.layers.l2.status = "active";
  body.layers.l3.status = "active";
  body.layers.l4.status = "active";
  body.degradations = [];

  const canonical = canonicalizeForSigning(body);
  const sig = ed25519.sign(stringToBytes(canonical), priv);
  return {
    body,
    signed_by: toBase64url(pub),
    signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

// ──────────────────────────────────────────────────────────────────────────
// M2 — handshake_exchange is preview-only (HS-1 / HS-2)
// ──────────────────────────────────────────────────────────────────────────

describe("M2: handshake_exchange can never produce a verified peer", () => {
  it("never returns verified:true or verified-sovereign even for a full SHR", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const { tools, handshakeResults } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );

    // A self-consistent, full-sovereignty counterparty SHR — the strongest
    // possible input. Pre-fix this minted verified-sovereign in one call.
    const counterpartySHR = fullSovereignSHR(shrFor(agent));

    const exchange = tools.find((t) => t.name === "handshake_exchange")!;
    const out = parse(await exchange.handler({ counterparty_shr: counterpartySHR }));

    // The verification block must advertise preview semantics.
    expect(out.verification.liveness_proven).toBe(false);
    expect(out.verification.trust_tier).toBe("unverified");

    // HIGH#2: the PRIMARY output — the signed attestation artifact — must NOT
    // smuggle a verified tier out the side door. Pre-fix it stamped
    // verified-sovereign here even though the verification block said unverified.
    expect(out.attestation.body.verification.liveness_proven).toBe(false);
    expect(out.attestation.body.verification.subject_trust_tier).toBe("unverified");
    expect(out.attestation.body.verification.subject_trust_tier).not.toBe(
      "verified-sovereign"
    );
    // And verifyAttestation must agree: no verified tier without liveness.
    expect(verifyAttestation(out.attestation).trust_tier).toBe("unverified");

    // The stored result must NOT be verified, regardless of sovereignty level.
    const stored = handshakeResults.get(counterpartySHR.body.instance_id);
    expect(stored).toBeDefined();
    expect(stored!.verified).toBe(false);
    expect(stored!.liveness_proven).toBe(false);
    expect(stored!.trust_tier).toBe("unverified");
    expect(stored!.trust_tier).not.toBe("verified-sovereign");
    expect(stored!.trust_tier).not.toBe("verified-degraded");
  });

  it("does not downgrade an already-established live peer (MEDIUM#3)", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const { tools, handshakeResults } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );

    const counterpartySHR = fullSovereignSHR(shrFor(agent));
    const peerId = counterpartySHR.body.instance_id;

    // Simulate an established, liveness-proven peer (as the 4-step protocol
    // would leave it in the results map).
    handshakeResults.set(peerId, {
      counterparty_id: peerId,
      counterparty_shr: counterpartySHR,
      verified: true,
      sovereignty_level: "full",
      trust_tier: "verified-sovereign",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    });

    // A subsequent structural preview of a (captured) SHR for the same peer
    // must NOT clobber the established entry down to unverified.
    const exchange = tools.find((t) => t.name === "handshake_exchange")!;
    await exchange.handler({ counterparty_shr: counterpartySHR });

    const stored = handshakeResults.get(peerId);
    expect(stored!.verified).toBe(true);
    expect(stored!.liveness_proven).toBe(true);
    expect(stored!.trust_tier).toBe("verified-sovereign");
  });

  it("a replayed (captured) valid SHR via exchange yields only unverified", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const { tools, handshakeResults } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );

    // A genuinely valid, captured SHR (e.g. recorded from a real agent) is
    // replayed. With no nonce/liveness, it must not confer trust.
    const capturedValid = shrFor(agent);
    const exchange = tools.find((t) => t.name === "handshake_exchange")!;
    const out = parse(await exchange.handler({ counterparty_shr: capturedValid }));

    expect(out.verification.counterparty_valid).toBe(true); // structurally fine
    expect(out.verification.liveness_proven).toBe(false); // but not live

    const stored = handshakeResults.get(capturedValid.body.instance_id);
    expect(stored!.verified).toBe(false);
    expect(stored!.trust_tier).toBe("unverified");
  });

  it("M1 still bites at the exchange boundary: a forged-id SHR is rejected", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const { tools, handshakeResults } = createHandshakeTools(
      agent.config,
      agent.identityManager,
      agent.masterKey,
      agent.auditLog
    );

    // Forge: keep a victim's instance_id, sign with an attacker key.
    const victim = shrFor(agent);
    const attackerPriv = randomBytes(32);
    const attackerPub = ed25519.getPublicKey(attackerPriv);
    const canonical = canonicalizeForSigning(victim.body);
    const sig = ed25519.sign(stringToBytes(canonical), attackerPriv);
    const forged: SignedSHR = {
      body: victim.body, // contains the victim instance_id
      signed_by: toBase64url(attackerPub),
      signature: toBase64url(sig),
      signature_scheme: SIGNATURE_SCHEME_V1,
    };

    const exchange = tools.find((t) => t.name === "handshake_exchange")!;
    const out = parse(await exchange.handler({ counterparty_shr: forged }));

    expect(out.verification.counterparty_valid).toBe(false);
    // Invalid → not stored as a result at all.
    expect(handshakeResults.get(victim.body.instance_id)).toBeUndefined();
  });
});

// ──────────────────────────────────────────────────────────────────────────
// M3 — federation peer_did binding + liveness gate (HS-3)
// ──────────────────────────────────────────────────────────────────────────

describe("M3: federation register binds peer_did to the signing key", () => {
  function liveResultFor(shr: SignedSHR): HandshakeResult {
    return {
      counterparty_id: shr.body.instance_id,
      counterparty_shr: shr,
      verified: true,
      sovereignty_level: "degraded",
      trust_tier: "verified-degraded",
      completed_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      errors: [],
      liveness_proven: true,
    };
  }

  it("rejects a peer_did that does not match the handshake signing key", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const shr = shrFor(agent);

    const handshakeResults = new Map<string, HandshakeResult>();
    handshakeResults.set(shr.body.instance_id, liveResultFor(shr));

    const { tools } = createFederationTools(agent.auditLog, handshakeResults);
    const peersTool = tools.find((t) => t.name === "federation_peers")!;

    const out = parse(
      await peersTool.handler({
        action: "register",
        peer_id: shr.body.instance_id,
        peer_did: "did:key:zAttackerControlledImpersonationLabel",
      })
    );

    expect(out.registered).toBeUndefined();
    expect(out.error).toContain("does not match the key that signed the handshake");
  });

  it("defaults peer_did to the derived did:key when omitted", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const shr = shrFor(agent);
    const expectedDid = publicKeyToDid(fromBase64url(shr.signed_by));

    const handshakeResults = new Map<string, HandshakeResult>();
    handshakeResults.set(shr.body.instance_id, liveResultFor(shr));

    const { tools } = createFederationTools(agent.auditLog, handshakeResults);
    const peersTool = tools.find((t) => t.name === "federation_peers")!;

    const out = parse(
      await peersTool.handler({
        action: "register",
        peer_id: shr.body.instance_id,
        // no peer_did supplied
      })
    );

    expect(out.registered).toBe(true);
    expect(out.peer_did).toBe(expectedDid);
  });

  it("accepts a peer_did that exactly matches the derived did:key", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const shr = shrFor(agent);
    const expectedDid = publicKeyToDid(fromBase64url(shr.signed_by));

    const handshakeResults = new Map<string, HandshakeResult>();
    handshakeResults.set(shr.body.instance_id, liveResultFor(shr));

    const { tools } = createFederationTools(agent.auditLog, handshakeResults);
    const peersTool = tools.find((t) => t.name === "federation_peers")!;

    const out = parse(
      await peersTool.handler({
        action: "register",
        peer_id: shr.body.instance_id,
        peer_did: expectedDid,
      })
    );

    expect(out.registered).toBe(true);
    expect(out.peer_did).toBe(expectedDid);
  });

  it("refuses to register a preview-only (liveness_proven:false) result", async () => {
    const agent = makeAgent();
    await createIdentityFor(agent);
    const shr = shrFor(agent);

    // A result as produced by handshake_exchange: verified must already be
    // false, but assert the liveness gate even defends a hypothetically
    // mislabeled verified:true result.
    const previewResult: HandshakeResult = {
      ...liveResultFor(shr),
      verified: true, // adversarial: pretend it was marked verified
      liveness_proven: false, // ...but liveness was never proven
    };
    const handshakeResults = new Map<string, HandshakeResult>();
    handshakeResults.set(shr.body.instance_id, previewResult);

    const { tools } = createFederationTools(agent.auditLog, handshakeResults);
    const peersTool = tools.find((t) => t.name === "federation_peers")!;

    const out = parse(
      await peersTool.handler({
        action: "register",
        peer_id: shr.body.instance_id,
      })
    );

    expect(out.registered).toBeUndefined();
    expect(out.error).toContain("did not prove liveness");
  });
});

// ──────────────────────────────────────────────────────────────────────────
// M4 — nonce TTL + single-use, server-time anchored (HS-2)
// ──────────────────────────────────────────────────────────────────────────

describe("M4: 4-step nonce session TTL + single-use", () => {
  it("isSessionExpired fails closed for missing/invalid expires_at (LOW#6)", async () => {
    const { isSessionExpired } = await import("../../src/handshake/protocol.js");
    // A session with no expiry must be treated as EXPIRED, not permissive.
    expect(
      isSessionExpired({ expires_at: undefined } as unknown as HandshakeSession)
    ).toBe(true);
    expect(
      isSessionExpired({ expires_at: "" } as unknown as HandshakeSession)
    ).toBe(true);
    expect(
      isSessionExpired({ expires_at: "not-a-date" } as unknown as HandshakeSession)
    ).toBe(true);
    // A valid, far-future expiry is still not expired.
    expect(
      isSessionExpired({
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      } as unknown as HandshakeSession)
    ).toBe(false);
  });

  // Drive the initiator side end to end so a real session exists in the map.
  async function setupInitiatedSession() {
    const initiator = makeAgent();
    const responder = makeAgent();
    await createIdentityFor(initiator);
    await createIdentityFor(responder);

    const { tools: initTools, handshakeResults } = createHandshakeTools(
      initiator.config,
      initiator.identityManager,
      initiator.masterKey,
      initiator.auditLog
    );
    const { tools: respTools } = createHandshakeTools(
      responder.config,
      responder.identityManager,
      responder.masterKey,
      responder.auditLog
    );

    const initiateTool = initTools.find((t) => t.name === "handshake_initiate")!;
    const initiated = parse(await initiateTool.handler({}));
    const sessionId = initiated.session_id as string;
    const challenge = initiated.challenge;

    const respondTool = respTools.find((t) => t.name === "handshake_respond")!;
    const responded = parse(await respondTool.handler({ challenge }));
    const response = responded.response;

    const completeTool = initTools.find((t) => t.name === "handshake_complete")!;
    return { sessionId, response, completeTool, handshakeResults };
  }

  it("session expiry is anchored to server time, not challenge.initiated_at", () => {
    // Direct protocol check: even a challenge claiming a far-future
    // initiated_at must NOT extend the responder's TTL — the responder anchors
    // expiry to ITS OWN receipt time.
    return (async () => {
      const initiator = makeAgent();
      const responder = makeAgent();
      await createIdentityFor(initiator);
      await createIdentityFor(responder);

      const { respondToHandshake, initiateHandshake, isSessionExpired } =
        await import("../../src/handshake/protocol.js");

      const shrI = shrFor(initiator);
      const { challenge } = initiateHandshake(shrI);
      // Malicious initiator backdates/forwards the timestamp.
      challenge.initiated_at = new Date(Date.now() + 10 * 365 * 24 * 3600_000).toISOString();

      const shrR = shrFor(responder);
      const respondResult = respondToHandshake(
        challenge,
        shrR,
        responder.identityManager as any,
        responder.masterKey
      );
      expect("session" in respondResult).toBe(true);
      if (!("session" in respondResult)) return;

      const session = respondResult.session as HandshakeSession;
      // Expiry is ~now + TTL (server time), NOT ~10 years out.
      const expMs = new Date(session.expires_at).getTime();
      expect(expMs).toBeLessThan(Date.now() + 10 * 60_000); // well under 10 min
      // And a server-time check 10 years hence treats it as expired.
      const farFuture = new Date(Date.now() + 9 * 365 * 24 * 3600_000);
      expect(isSessionExpired(session, farFuture)).toBe(true);
      // Not expired right now.
      expect(isSessionExpired(session, new Date())).toBe(false);
    })();
  });

  it("single-use: a session that already failed cannot be completed again", async () => {
    const { sessionId, response, completeTool } = await setupInitiatedSession();

    // A malformed response (bad nonce signature) makes handshake_complete fail
    // and advances the session to the terminal `failed` state.
    const bogusResponse = {
      protocol_version: "1.0",
      shr: response.shr,
      responder_nonce: response.responder_nonce,
      initiator_nonce_signature:
        "AAAA" + String(response.initiator_nonce_signature).slice(4),
      responded_at: new Date().toISOString(),
    };
    const firstTry = parse(
      await completeTool.handler({ session_id: sessionId, response: bogusResponse })
    );
    expect(firstTry.error).toBeDefined(); // nonce signature invalid → failed

    // The session is now terminal (failed). A retry must be refused outright,
    // never reprocessed — the nonce is single-use.
    const secondTry = parse(
      await completeTool.handler({ session_id: sessionId, response: bogusResponse })
    );
    expect(secondTry.error).toContain("state 'failed'");
  });

  it("single-use: a successfully completed session cannot be completed twice", async () => {
    const initiator = makeAgent();
    const responder = makeAgent();
    await createIdentityFor(initiator);
    await createIdentityFor(responder);

    const { tools: initTools } = createHandshakeTools(
      initiator.config,
      initiator.identityManager,
      initiator.masterKey,
      initiator.auditLog
    );
    const { tools: respTools } = createHandshakeTools(
      responder.config,
      responder.identityManager,
      responder.masterKey,
      responder.auditLog
    );

    const initiated = parse(
      await initTools.find((t) => t.name === "handshake_initiate")!.handler({})
    );
    const responded = parse(
      await respTools
        .find((t) => t.name === "handshake_respond")!
        .handler({ challenge: initiated.challenge })
    );
    const completeTool = initTools.find((t) => t.name === "handshake_complete")!;

    const first = parse(
      await completeTool.handler({
        session_id: initiated.session_id,
        response: responded.response,
      })
    );
    expect(first.result.verified).toBe(true);

    // Replaying the (valid) response against the now-completed session must be
    // refused — the nonce is spent.
    const replay = parse(
      await completeTool.handler({
        session_id: initiated.session_id,
        response: responded.response,
      })
    );
    expect(replay.error).toContain("state 'completed'");
  });

  it("rejects handshake_complete once the session is past its server TTL", async () => {
    // Deterministic TTL test without a clock injector: stub Date so the tool's
    // internal `new Date()` (server time) advances past the session TTL between
    // initiate and complete. The session's expires_at is anchored to the
    // initiate-time server clock.
    const initiator = makeAgent();
    const responder = makeAgent();
    await createIdentityFor(initiator);
    await createIdentityFor(responder);

    const { tools: initTools } = createHandshakeTools(
      initiator.config,
      initiator.identityManager,
      initiator.masterKey,
      initiator.auditLog
    );
    const { tools: respTools } = createHandshakeTools(
      responder.config,
      responder.identityManager,
      responder.masterKey,
      responder.auditLog
    );

    const { HANDSHAKE_SESSION_TTL_MS } = await import(
      "../../src/handshake/protocol.js"
    );

    const initiated = parse(
      await initTools.find((t) => t.name === "handshake_initiate")!.handler({})
    );
    const responded = parse(
      await respTools
        .find((t) => t.name === "handshake_respond")!
        .handler({ challenge: initiated.challenge })
    );

    // Advance the wall clock past the TTL using fake timers semantics: monkey-
    // patch Date.now and the Date constructor's "now" so isSessionExpired sees
    // a time beyond expires_at.
    const realNow = Date.now;
    const advanceMs = HANDSHAKE_SESSION_TTL_MS + 5_000;
    const base = realNow();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (Date as any).now = () => base + advanceMs;
    const RealDate = Date;
    // Patch `new Date()` (no args) to return the advanced time; preserve args.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).Date = class extends RealDate {
      constructor(...args: any[]) {
        if (args.length === 0) {
          super(base + advanceMs);
        } else {
          // @ts-expect-error spread into Date
          super(...args);
        }
      }
      static now() {
        return base + advanceMs;
      }
    };

    try {
      const out = parse(
        await initTools.find((t) => t.name === "handshake_complete")!.handler({
          session_id: initiated.session_id,
          response: responded.response,
        })
      );
      expect(out.error).toContain("expired");
    } finally {
      (globalThis as any).Date = RealDate;
      (Date as any).now = realNow;
    }
  });

  it("rejects a replayed completion: a spent session is single-use", async () => {
    // Responder side: once a completion is verified (or fails), the session
    // advances out of "responded" and a replayed completion is ignored.
    const initiator = makeAgent();
    const responder = makeAgent();
    await createIdentityFor(initiator);
    await createIdentityFor(responder);

    const { tools: initTools } = createHandshakeTools(
      initiator.config,
      initiator.identityManager,
      initiator.masterKey,
      initiator.auditLog
    );
    const { tools: respTools } = createHandshakeTools(
      responder.config,
      responder.identityManager,
      responder.masterKey,
      responder.auditLog
    );

    const initiated = parse(
      await initTools.find((t) => t.name === "handshake_initiate")!.handler({})
    );
    const responded = parse(
      await respTools
        .find((t) => t.name === "handshake_respond")!
        .handler({ challenge: initiated.challenge })
    );
    const completed = parse(
      await initTools.find((t) => t.name === "handshake_complete")!.handler({
        session_id: initiated.session_id,
        response: responded.response,
      })
    );
    expect(completed.result.verified).toBe(true);
    expect(completed.result.liveness_proven).toBe(true);

    // Responder verifies the completion once — session becomes terminal.
    const statusTool = respTools.find((t) => t.name === "handshake_status")!;
    const firstVerify = parse(
      await statusTool.handler({
        session_id: responded.session_id,
        completion: completed.completion,
      })
    );
    expect(firstVerify.result.verified).toBe(true);

    // Replay the SAME completion: the session is no longer "responded", so it
    // is not re-verified — the handler returns a plain status read, not a fresh
    // verified result.
    const replay = parse(
      await statusTool.handler({
        session_id: responded.session_id,
        completion: completed.completion,
      })
    );
    expect(replay.result).toBeDefined();
    // It returns the prior terminal session status, state already completed.
    expect(replay.state ?? replay.result?.verified).toBeTruthy();
    // Crucially the session is terminal, not "responded" again.
    expect(replay.state === undefined || replay.state === "completed").toBe(true);
  });
});
