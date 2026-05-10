/**
 * NodeRoster defensive capability check (full-sweep #95).
 *
 * Defense-in-depth: NodeRoster.add() rejects certificates with reserved
 * capability bits set, even though primary cert verification (verifyCertChain)
 * is the canonical gate. This catches bugs where a caller bypasses or
 * forgets the chain verification step.
 */

import { describe, it, expect } from "vitest";

import { NodeRoster } from "../../src/mesh/lifecycle/node-roster.js";
import { MeshReservedCapabilityBitError } from "../../src/mesh/errors.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
} from "../../src/mesh/constants.js";
import type { NodeIdentityCertificate } from "../../src/mesh/types.js";

function makeCert(overrides: Partial<NodeIdentityCertificate> = {}): NodeIdentityCertificate {
  return {
    schema_version: "sanctuary-fed-v0.1",
    signature_scheme: "ed25519-v1",
    node_id: "node-test-001",
    node_pubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    node_mode: "full",
    fortress_id: "fortress-test",
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      principal_id: "principal-test",
      principal_pubkey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
      principal_signature: "fakesig",
    },
    issued_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("NodeRoster.add() defensive capability check (#95)", () => {
  it("rejects certificate with reserved capability bits set", () => {
    const roster = new NodeRoster({ fortress_id: "fortress-test" });
    // Bit 3 (0x08) is reserved per spec S10.2
    const cert = makeCert({ capabilities: CAP_STANDARD_FORTRESS_NODE | 0x08 });

    expect(() => roster.add(cert)).toThrow(MeshReservedCapabilityBitError);
  });

  it("accepts certificate with only valid capability bits", () => {
    const roster = new NodeRoster({ fortress_id: "fortress-test" });
    const cert = makeCert({ capabilities: CAP_STANDARD_FORTRESS_NODE });

    expect(() => roster.add(cert)).not.toThrow();
  });
});
