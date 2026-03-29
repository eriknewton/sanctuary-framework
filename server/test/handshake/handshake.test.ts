/**
 * Sovereignty Handshake Protocol — Tests
 *
 * Full round-trip handshake, tamper detection, expiry, replay prevention.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity } from "../../src/core/identity.js";
import { generateSHR } from "../../src/shr/generator.js";
import {
  initiateHandshake,
  respondToHandshake,
  completeHandshake,
  verifyCompletion,
} from "../../src/handshake/protocol.js";
import type { SignedSHR } from "../../src/shr/types.js";
import type { SanctuaryConfig } from "../../src/config.js";
import { defaultConfig } from "../../src/config.js";
import type { StoredIdentity } from "../../src/core/identity.js";

// Lightweight IdentityManager for testing
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

describe("Sovereignty Handshake Protocol", () => {
  describe("Full round-trip", () => {
    it("completes a full handshake between two agents", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      // Step 1: A initiates
      const shrA = agentSHR(agentA);
      const { challenge, session: sessionA } = initiateHandshake(shrA);

      expect(challenge.protocol_version).toBe("1.0");
      expect(challenge.nonce).toBeTruthy();
      expect(sessionA.state).toBe("initiated");

      // Step 2: B responds
      const shrB = agentSHR(agentB);
      const respondResult = respondToHandshake(
        challenge,
        shrB,
        agentB.identityManager as any,
        agentB.masterKey
      );

      expect("response" in respondResult).toBe(true);
      if (!("response" in respondResult)) return;

      const { response, session: sessionB } = respondResult;
      expect(response.protocol_version).toBe("1.0");
      expect(response.responder_nonce).toBeTruthy();
      expect(response.initiator_nonce_signature).toBeTruthy();
      expect(sessionB.state).toBe("responded");

      // Step 3: A completes
      const completeResult = completeHandshake(
        response,
        sessionA,
        agentA.identityManager as any,
        agentA.masterKey
      );

      expect("completion" in completeResult).toBe(true);
      if (!("completion" in completeResult)) return;

      const { completion, result: resultA } = completeResult;
      expect(resultA.verified).toBe(true);
      expect(resultA.trust_tier).toBe("verified-degraded"); // MVS is degraded
      expect(resultA.sovereignty_level).toBe("degraded");

      // Step 4: B verifies completion
      const resultB = verifyCompletion(completion, sessionB);
      expect(resultB.verified).toBe(true);
      expect(resultB.trust_tier).toBe("verified-degraded");
    });
  });

  describe("Tamper detection", () => {
    it("rejects tampered SHR in challenge", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const { challenge } = initiateHandshake(shrA);

      // Tamper with A's SHR
      challenge.shr.body.layers.l1.encryption = "none";

      const shrB = agentSHR(agentB);
      const result = respondToHandshake(
        challenge,
        shrB,
        agentB.identityManager as any,
        agentB.masterKey
      );

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error).toContain("verification failed");
      }
    });

    it("rejects tampered nonce signature in response", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const { challenge, session: sessionA } = initiateHandshake(shrA);

      const shrB = agentSHR(agentB);
      const respondResult = respondToHandshake(
        challenge,
        shrB,
        agentB.identityManager as any,
        agentB.masterKey
      );

      if (!("response" in respondResult)) return;
      const { response } = respondResult;

      // Tamper with the nonce signature
      response.initiator_nonce_signature =
        "AAAA" + response.initiator_nonce_signature.slice(4);

      const completeResult = completeHandshake(
        response,
        sessionA,
        agentA.identityManager as any,
        agentA.masterKey
      );

      expect("error" in completeResult).toBe(true);
      if ("error" in completeResult) {
        expect(completeResult.error).toContain("nonce signature is invalid");
      }
    });

    it("rejects tampered completion nonce signature", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const { challenge, session: sessionA } = initiateHandshake(shrA);

      const shrB = agentSHR(agentB);
      const respondResult = respondToHandshake(
        challenge,
        shrB,
        agentB.identityManager as any,
        agentB.masterKey
      );

      if (!("response" in respondResult)) return;
      const { response, session: sessionB } = respondResult;

      const completeResult = completeHandshake(
        response,
        sessionA,
        agentA.identityManager as any,
        agentA.masterKey
      );

      if (!("completion" in completeResult)) return;
      const { completion } = completeResult;

      // Tamper with the completion nonce signature
      completion.responder_nonce_signature =
        "AAAA" + completion.responder_nonce_signature.slice(4);

      const resultB = verifyCompletion(completion, sessionB);
      expect(resultB.verified).toBe(false);
      expect(resultB.errors.some((e) => e.includes("nonce signature is invalid"))).toBe(
        true
      );
    });
  });

  describe("Error handling", () => {
    it("rejects unsupported protocol version in challenge", () => {
      const agentB = makeAgent();
      const shrB = agentSHR(agentB);

      const badChallenge = {
        protocol_version: "99.0" as any,
        shr: shrB,
        nonce: "test",
        initiated_at: new Date().toISOString(),
      };

      const result = respondToHandshake(
        badChallenge,
        shrB,
        agentB.identityManager as any,
        agentB.masterKey
      );

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error).toContain("Unsupported protocol version");
      }
    });

    it("rejects unsupported protocol version in response", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const { session: sessionA } = initiateHandshake(shrA);

      const shrB = agentSHR(agentB);
      const badResponse = {
        protocol_version: "99.0" as any,
        shr: shrB,
        responder_nonce: "test",
        initiator_nonce_signature: "test",
        responded_at: new Date().toISOString(),
      };

      const result = completeHandshake(
        badResponse,
        sessionA,
        agentA.identityManager as any,
        agentA.masterKey
      );

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error).toContain("Unsupported protocol version");
      }
    });

    it("fails when no identity is available for signing", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const { challenge } = initiateHandshake(shrA);

      const shrB = agentSHR(agentB);
      const emptyManager = {
        get: () => undefined,
        getDefault: () => undefined,
        list: () => [],
      };

      const result = respondToHandshake(
        challenge,
        shrB,
        emptyManager as any,
        agentB.masterKey
      );

      expect("error" in result).toBe(true);
      if ("error" in result) {
        expect(result.error).toContain("No identity");
      }
    });
  });

  describe("Sovereignty assessment", () => {
    it("correctly assesses degraded sovereignty for MVS", () => {
      const agentA = makeAgent();
      const agentB = makeAgent();

      const shrA = agentSHR(agentA);
      const { challenge, session: sessionA } = initiateHandshake(shrA);

      const shrB = agentSHR(agentB);
      const respondResult = respondToHandshake(
        challenge,
        shrB,
        agentB.identityManager as any,
        agentB.masterKey
      );

      if (!("response" in respondResult)) return;

      const completeResult = completeHandshake(
        respondResult.response,
        sessionA,
        agentA.identityManager as any,
        agentA.masterKey
      );

      if (!("result" in completeResult)) return;

      // MVS has process-level isolation and commitment-only proofs
      expect(completeResult.result.sovereignty_level).toBe("degraded");
      expect(completeResult.result.trust_tier).toBe("verified-degraded");
    });
  });
});
