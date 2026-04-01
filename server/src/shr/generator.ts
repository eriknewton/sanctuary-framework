/**
 * Sanctuary MCP Server — SHR Generator
 *
 * Generates a Sovereignty Health Report from current server state,
 * signs it with a specified identity, and returns the complete signed SHR.
 */

import type { SanctuaryConfig } from "../config.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import type {
  SHRBody,
  SignedSHR,
  SHRDegradation,
  DegradationCode,
} from "./types.js";
import { canonicalizeForSigning } from "./types.js";
import { sign } from "../core/identity.js";
import { toBase64url, stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";

/** Default SHR validity window: 1 hour */
const DEFAULT_VALIDITY_MS = 60 * 60 * 1000;

export interface SHRGeneratorOptions {
  config: SanctuaryConfig;
  identityManager: IdentityManager;
  masterKey: Uint8Array;
  /** Override validity window (milliseconds). Default: 1 hour. */
  validityMs?: number;
}

/**
 * Generate and sign a Sovereignty Health Report.
 *
 * @param identityId - Which identity to sign with (defaults to primary)
 * @param opts - Generator dependencies
 * @returns The signed SHR, or an error string
 */
export function generateSHR(
  identityId: string | undefined,
  opts: SHRGeneratorOptions
): SignedSHR | string {
  const { config, identityManager, masterKey, validityMs } = opts;

  // Resolve signing identity
  const identity = identityId
    ? identityManager.get(identityId)
    : identityManager.getDefault();

  if (!identity) {
    return "No identity available for signing. Create an identity first.";
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + (validityMs ?? DEFAULT_VALIDITY_MS));

  // Assess degradations
  const degradations: SHRDegradation[] = [];

  if (config.execution.environment === "local-process") {
    degradations.push({
      layer: "l2",
      code: "PROCESS_ISOLATION_ONLY" as DegradationCode,
      severity: "warning",
      description: "Process-level isolation only (no TEE)",
      mitigation: "TEE support planned for a future release",
    });
    degradations.push({
      layer: "l2",
      code: "SELF_REPORTED_ATTESTATION" as DegradationCode,
      severity: "warning",
      description: "Attestation is self-reported (no hardware root of trust)",
      mitigation: "TEE attestation planned for a future release",
    });
  }

  if (config.disclosure.proof_system === "commitment-only") {
    degradations.push({
      layer: "l3",
      code: "COMMITMENT_ONLY" as DegradationCode,
      severity: "info",
      description: "Commitment schemes only (no ZK proofs)",
      mitigation: "ZK proof support planned for future release",
    });
  }

  // Build the SHR body
  const body: SHRBody = {
    shr_version: "1.0",
    implementation: {
      sanctuary_version: config.version,
      node_version: process.versions.node,
      generated_by: "sanctuary-mcp-server",
    },
    instance_id: identity.identity_id,
    generated_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    layers: {
      l1: {
        status: "active",
        encryption: config.state.encryption,
        key_custody: "self",
        integrity: config.state.integrity,
        identity_type: config.state.identity_provider,
        state_portable: true,
      },
      l2: {
        status: config.execution.environment === "local-process"
          ? "degraded"
          : "active",
        isolation_type: config.execution.environment,
        attestation_available: config.execution.attestation,
      },
      l3: {
        status: config.disclosure.proof_system === "commitment-only"
          ? "degraded"
          : "active",
        proof_system: config.disclosure.proof_system,
        selective_disclosure: config.disclosure.proof_system !== "commitment-only",
      },
      l4: {
        status: "active",
        reputation_mode: config.reputation.mode,
        attestation_format: config.reputation.attestation_format,
        reputation_portable: true,
      },
    },
    capabilities: {
      handshake: true,
      shr_exchange: true,
      reputation_verify: true,
      encrypted_channel: false, // Not yet implemented
    },
    degradations,
  };

  // Canonical serialization for signing
  const canonical = canonicalizeForSigning(body);
  const payload = stringToBytes(canonical);

  // Sign with the identity's private key
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const signatureBytes = sign(
    payload,
    identity.encrypted_private_key,
    encryptionKey
  );

  return {
    body,
    signed_by: identity.public_key,
    signature: toBase64url(signatureBytes),
  };
}
