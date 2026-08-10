/**
 * Federation Tools tests
 *
 * Covers: list/register/remove peers, handshake verification gate,
 * trust evaluation, federation status aggregation.
 * Not covered: real handshake protocol, network I/O.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { createFederationTools } from "../../src/federation/tools.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey, randomBytes } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  generateIdentityId,
  publicKeyToDid,
} from "../../src/core/identity.js";
import { canonicalizeForSigning } from "../../src/shr/types.js";
import {
  toBase64url,
  stringToBytes,
} from "../../src/core/encoding.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import type { HandshakeResult } from "../../src/handshake/types.js";
import type { SignedSHR } from "../../src/shr/types.js";

function setup() {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const handshakeResults = new Map<string, HandshakeResult>();
  // Empty (no identities saved) but REAL — identityManager is a required
  // constructor param now (AGENTS.md rule 3: an optional security dependency
  // that gates a trust property must be required). None of this file's fixed
  // SHRs correspond to a saved local identity, so the local-custody check
  // never fires here; that path is covered by handshake-forgery-remediation.
  // test.ts's M3 self-vouch test and the class-binding inventory suite.
  const identityManager = new IdentityManager(storage, generateRandomKey());
  const { tools, registry } = createFederationTools(auditLog, handshakeResults, identityManager);
  const findTool = (name: string) => tools.find(t => t.name === name)!;
  return { tools, registry, handshakeResults, findTool };
}

/**
 * Build a self-consistent SHR signed by a fresh keypair, then a handshake
 * result around it. With M3 in effect, the peer's DID must derive from the
 * SHR signing key, so we return that derived DID for callers to use.
 */
function makeSignedHandshake(verified: boolean): {
  result: HandshakeResult;
  instanceId: string;
  derivedDid: string;
} {
  const priv = randomBytes(32);
  const pub = ed25519.getPublicKey(priv);
  const instanceId = generateIdentityId(pub);
  const derivedDid = publicKeyToDid(pub);

  const body = {
    shr_version: "1.0" as const,
    implementation: {
      sanctuary_version: "0.9.0",
      node_version: "20.0.0",
      generated_by: "sanctuary-mcp-server",
    },
    instance_id: instanceId,
    generated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    layers: {
      l1: { status: "active" as const, encryption: "aes-256-gcm", key_custody: "self", integrity: "merkle-sha256", identity_type: "ed25519", state_portable: true },
      l2: { status: "active" as const, isolation_type: "tee", attestation_available: true },
      l3: { status: "active" as const, proof_system: "schnorr-pedersen", selective_disclosure: true },
      l4: { status: "active" as const, reputation_mode: "self-custodied", attestation_format: "eas-compatible", reputation_portable: true },
    },
    capabilities: { handshake: true, shr_exchange: true, reputation_verify: true, encrypted_channel: false },
    degradations: [],
  };
  const sig = ed25519.sign(stringToBytes(canonicalizeForSigning(body as any)), priv);
  const shr: SignedSHR = {
    body: body as any,
    signed_by: toBase64url(pub),
    signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };

  const result: HandshakeResult = {
    counterparty_id: instanceId,
    counterparty_shr: shr,
    verified,
    sovereignty_level: verified ? "full" : "minimal",
    trust_tier: verified ? "verified-sovereign" : "unverified",
    completed_at: new Date().toISOString(),
    expires_at: shr.body.expires_at,
    errors: [],
    // Federation registration requires a live 4-step handshake.
    liveness_proven: verified,
  };
  return { result, instanceId, derivedDid };
}

describe("Federation Tools", () => {
  describe("federation_peers — list", () => {
    it("returns empty list initially", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({ action: "list" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.peers).toEqual([]);
      expect(parsed.total).toBe(0);
    });
  });

  describe("federation_peers — register", () => {
    it("requires peer_id", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({ action: "register" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBeDefined();
    });

    it("rejects if no completed handshake", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: "unknown-peer",
        peer_did: "did:key:xyz",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toContain("No completed handshake");
    });

    it("rejects unverified handshake", async () => {
      const { findTool, handshakeResults } = setup();
      const { result: hs, instanceId } = makeSignedHandshake(false);
      handshakeResults.set(instanceId, hs);

      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: instanceId,
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toContain("not verified");
    });

    it("registers peer with verified handshake (DID derived from signing key)", async () => {
      const { findTool, handshakeResults } = setup();
      const { result: hs, instanceId, derivedDid } = makeSignedHandshake(true);
      handshakeResults.set(instanceId, hs);

      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: instanceId,
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.registered).toBe(true);
      expect(parsed.peer_did).toBe(derivedDid);
    });

    it("rejects a peer_did that does not match the handshake signing key (HS-3)", async () => {
      const { findTool, handshakeResults } = setup();
      const { result: hs, instanceId } = makeSignedHandshake(true);
      handshakeResults.set(instanceId, hs);

      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: instanceId,
        peer_did: "did:key:zImpersonatingSomeoneElse",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.registered).toBeUndefined();
      expect(parsed.error).toContain("does not match the key that signed the handshake");
    });
  });

  describe("federation_peers — remove", () => {
    it("requires peer_id", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({ action: "remove" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBeDefined();
    });

    it("returns removed: false for unknown peer", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({
        action: "remove",
        peer_id: "nonexistent",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.removed).toBe(false);
    });
  });

  describe("federation_status", () => {
    it("returns summary with zero peers", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_status").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.total_peers).toBe(0);
      expect(parsed.federation_ready).toBe(false);
    });
  });

  describe("federation_trust_evaluate", () => {
    it("evaluates trust for a peer", async () => {
      const { findTool, handshakeResults } = setup();
      const { result: hs, instanceId } = makeSignedHandshake(true);
      handshakeResults.set(instanceId, hs);

      // Register the peer first (DID is derived from the signing key)
      await findTool("federation_peers").handler({
        action: "register",
        peer_id: instanceId,
      });

      const result = await findTool("federation_trust_evaluate").handler({
        peer_id: instanceId,
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.trust_level).toBeDefined();
    });
  });
});
