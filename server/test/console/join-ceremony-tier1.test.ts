/**
 * Integration test — AC4 (join ceremony end-to-end, Tier 1 gated).
 *
 * Scenario: an operator receives a join request, reviews the candidate cert
 * in the console, approves, and the `JoinApprover` emits a shipped join-
 * approval certificate. The UI path MUST require an explicit operator
 * confirmation — no auto-approve path exists. This test drives that path.
 */

import { afterEach, describe, expect, it } from "vitest";

import { bootThreeModeDrill, type ThreeModeDrillHandle } from "../acceptance/three-mode-drill/harness.js";
import { MeshConsoleClient } from "../../src/console/index.js";
import type { JoinRequest } from "../../src/mesh/lifecycle/types.js";
import { toBase64url } from "../../src/core/encoding.js";
import { generateKeypair } from "../../src/core/identity.js";

let active: ThreeModeDrillHandle | null = null;

afterEach(async () => {
  if (active) {
    await active.teardown();
    active = null;
  }
});

function synthesizeJoinRequest(drill: ThreeModeDrillHandle): JoinRequest {
  const candidateKp = generateKeypair();
  return {
    bootstrap_token: {
      intended_node_id: "0123456789abcdef0123456789abcdef",
      intended_node_mode: "operator_cloud",
      fortress_id: drill.fortressId,
      issuing_principal: drill.root_principal_cert.principal_id,
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
      nonce: "test-nonce-" + Math.random().toString(36).slice(2, 10),
      signature: "test-signature", // drill-side only — not the wire path
    },
    node_pubkey: toBase64url(candidateKp.publicKey),
    node_mode: "operator_cloud",
    hkdf_salt_proof: "stub-proof",
  };
}

describe("WP-MVP-2 console — join ceremony Tier 1 (AC4)", () => {
  it(
    "operator-directed approval: pending → approved emits a certificate",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      const client = new MeshConsoleClient({
        node: drill.nodeA,
        pinnedMaster: drill.master_public,
        rootPrincipalCert: drill.root_principal_cert,
        rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
        nodePrivateKey: drill.nodeKpA.privateKey,
      });

      const approver = client.makeJoinApprover();
      const request = synthesizeJoinRequest(drill);

      // Fire the approver; it will surface a pending join to the UI and block.
      const approvalPromise = approver.requestApproval(request);

      // Give the pending-join broadcast a tick to register.
      await new Promise((r) => setTimeout(r, 10));

      const pending = client.pendingJoinsSnapshot();
      expect(pending).toHaveLength(1);
      expect(pending[0]!.candidate_node_mode).toBe("operator_cloud");
      expect(pending[0]!.candidate_node_id).toBe(
        request.bootstrap_token.intended_node_id
      );

      // Operator explicit approval.
      const requestId = pending[0]!.request_id;
      client.resolveJoinDecision({ request_id: requestId, approved: true });

      const result = await approvalPromise;
      expect(result.approved).toBe(true);
      expect(result.certificate).toBeTruthy();
      expect(result.certificate?.node_mode).toBe("operator_cloud");
      expect(result.certificate?.capabilities).toBe(1); // CAP_STANDARD_FORTRESS_NODE
      expect(result.certificate?.parent_chain.fortress_master_pubkey).toBe(
        drill.master_public.public_key
      );

      // After resolution the pending list MUST be empty — no lingering state.
      expect(client.pendingJoinsSnapshot()).toHaveLength(0);
    },
    40_000
  );

  it(
    "operator-directed denial surfaces the denial reason back to the requester",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      const client = new MeshConsoleClient({
        node: drill.nodeA,
        pinnedMaster: drill.master_public,
        rootPrincipalCert: drill.root_principal_cert,
        rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
        nodePrivateKey: drill.nodeKpA.privateKey,
      });

      const approver = client.makeJoinApprover();
      const request = synthesizeJoinRequest(drill);
      const approvalPromise = approver.requestApproval(request);

      await new Promise((r) => setTimeout(r, 10));
      const requestId = client.pendingJoinsSnapshot()[0]!.request_id;

      client.resolveJoinDecision({
        request_id: requestId,
        approved: false,
        denial_reason: "operator declined: attestation not verified",
      });

      const result = await approvalPromise;
      expect(result.approved).toBe(false);
      expect(result.certificate).toBeUndefined();
      expect(result.denial_reason).toContain("attestation not verified");
    },
    40_000
  );

  it(
    "resolveJoinDecision throws if no pending request matches the id (no silent drop)",
    async () => {
      active = await bootThreeModeDrill();
      const drill = active;

      const client = new MeshConsoleClient({
        node: drill.nodeA,
        pinnedMaster: drill.master_public,
        rootPrincipalCert: drill.root_principal_cert,
        rootPrincipalPrivateKey: drill.root_principal_keypair.privateKey,
        nodePrivateKey: drill.nodeKpA.privateKey,
      });

      expect(() =>
        client.resolveJoinDecision({
          request_id: "does-not-exist",
          approved: true,
        })
      ).toThrow(/no pending join request/);
    },
    40_000
  );
});
