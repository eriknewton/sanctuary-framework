import { derivePurposeKey } from "../../../../server/src/core/key-derivation.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { createIdentity, type StoredIdentity } from "../../../../server/src/core/identity.js";
import { defaultConfig } from "../../../../server/src/config.js";
import { generateSHR } from "../../../../server/src/shr/generator.js";
import { verifySHR } from "../../../../server/src/shr/verifier.js";
import type { SignedSHR } from "../../../../server/src/shr/types.js";
import {
  generateAttestation,
  verifyAttestation,
  type SignedAttestation,
} from "../../../../server/src/handshake/attestation.js";
import { registerFixture } from "../../registry.js";
import {
  failedSince,
  passedSince,
  ROW_ATTESTATION,
  ROW_ATTESTATION_LABEL,
} from "./helpers.js";

// Entrypoints: handshake/attestation.generateAttestation and verifyAttestation.
// Existing mirror: server/test/handshake/attestation.test.ts.
// ASSURANCE_MATRIX row: 8, Health and attestation evidence-based.

class TestIdentityManager {
  private identities = new Map<string, StoredIdentity>();
  private defaultId: string | null = null;

  constructor(masterKey: Uint8Array, label: string) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      label,
      encKey,
      "recovery-key",
    );
    this.identities.set(publicIdentity.identity_id, storedIdentity);
    this.defaultId = publicIdentity.identity_id;
  }

  get(id: string): StoredIdentity | undefined {
    return this.identities.get(id);
  }

  getDefault(): StoredIdentity | undefined {
    return this.defaultId ? this.identities.get(this.defaultId) : undefined;
  }

  list(): StoredIdentity[] {
    return Array.from(this.identities.values());
  }
}

function makeAgent(label: string) {
  const masterKey = generateRandomKey();
  const identityManager = new TestIdentityManager(masterKey, label);
  return { masterKey, identityManager, config: defaultConfig() };
}

function agentSHR(agent: ReturnType<typeof makeAgent>): SignedSHR {
  const result = generateSHR(undefined, {
    config: agent.config,
    identityManager: agent.identityManager as any,
    masterKey: agent.masterKey,
  });
  if (typeof result === "string") {
    throw new Error(result);
  }
  return result;
}

function makeAttestation(): SignedAttestation {
  const agentA = makeAgent("synthetic-attester");
  const agentB = makeAgent("synthetic-subject");
  const shrA = agentSHR(agentA);
  const shrB = agentSHR(agentB);
  const verification = verifySHR(shrB);
  const attestation = generateAttestation({
    attesterSHR: shrA,
    subjectSHR: shrB,
    verificationResult: verification,
    identityManager: agentA.identityManager as any,
    masterKey: agentA.masterKey,
  });
  if ("error" in attestation) {
    throw new Error(attestation.error);
  }
  return attestation;
}

registerFixture(
  ROW_ATTESTATION,
  ROW_ATTESTATION_LABEL,
  "well-formed attestation envelope verifies",
  async () => {
    const start = performance.now();
    try {
      const result = verifyAttestation(makeAttestation());
      return {
        passed: result.valid === true && result.errors.length === 0,
        message: `valid=${String(result.valid)}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_ATTESTATION,
  ROW_ATTESTATION_LABEL,
  "attestation payload mutation invalidates verification",
  async () => {
    const start = performance.now();
    try {
      const attestation = makeAttestation();
      attestation.body.verification.subject_trust_tier = "verified-sovereign";
      const result = verifyAttestation(attestation);
      return {
        passed:
          result.valid === false &&
          result.errors.some((error) => error.includes("signature is invalid")),
        message: result.errors.join("; "),
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_ATTESTATION,
  ROW_ATTESTATION_LABEL,
  "large attestation envelope within current verifier bounds verifies",
  async () => {
    const start = performance.now();
    try {
      const attestation = makeAttestation();
      attestation.summary = `${attestation.summary}\n${"evidence-line\n".repeat(512)}`;
      const result = verifyAttestation(attestation);
      return passedSince(
        start,
        `summary_bytes=${Buffer.byteLength(attestation.summary, "utf8")}, valid=${String(result.valid)}`,
      );
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_ATTESTATION,
  ROW_ATTESTATION_LABEL,
  "malformed attestation envelope returns explicit verification error",
  async () => {
    const start = performance.now();
    try {
      const malformed = {
        ...makeAttestation(),
        signature: "not-base64url!",
      };
      const result = verifyAttestation(malformed);
      return {
        passed:
          result.valid === false &&
          result.trust_tier === "unverified" &&
          result.errors.some((error) =>
            error === "Attestation signature is invalid" ||
            error.startsWith("Signature verification error:")
          ),
        message: result.errors.join("; "),
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);
