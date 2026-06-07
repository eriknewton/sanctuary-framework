import { describe, expect, it } from "vitest";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { MeshSignatureError } from "../../src/mesh/errors.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import { verifySignedEvent } from "../../src/mesh/envelope.js";
import type { VerifyContext } from "../../src/mesh/envelope.js";
import { FORTRESS_EVENT_TYPES } from "../../src/fortress/constants.js";
import { packModeTransitionEvent } from "../../src/fortress/mode-transition-event.js";

function buildSigningFixture() {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  const nodeKeypair = generateKeypair();
  const nodeCert = issueNodeIdentityCertificate({
    node_id: "node-" + toBase64url(randomBytes(4)),
    node_pubkey: nodeKeypair.publicKey,
    node_mode: "local",
    fortress_id: master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: master.public.public_key,
      principal_id: "root",
      principal_pubkey: principalCert.principal_pubkey,
    },
    principal_private_key: principalKeypair.privateKey,
  });
  const verifyCtx: VerifyContext = {
    pinnedMasterPubkey: master.public,
    lookupNodeCert: (id) => (id === nodeCert.node_id ? nodeCert : undefined),
    lookupPrincipalCert: (id) =>
      id === principalCert.principal_id ? principalCert : undefined,
  };

  return { master, principalKeypair, principalCert, nodeKeypair, nodeCert, verifyCtx };
}

describe("packModeTransitionEvent", () => {
  it("maps payload fields and produces a verifiable signed mode transition event", () => {
    const f = buildSigningFixture();
    const preconditionsChecked = ["federation_join", "audit_replica_ready"];
    const before = Date.now();
    const event = packModeTransitionEvent({
      from_tier: "tier_1_private",
      to_tier: "tier_2_federated",
      fortress_id: f.master.public.fortress_id,
      reason: "join mesh",
      preconditions_checked: preconditionsChecked,
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 42,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });
    const after = Date.now();

    expect(event.payload.from_tier).toBe("tier_1_private");
    expect(event.payload.to_tier).toBe("tier_2_federated");
    expect(event.payload.fortress_id).toBe(f.master.public.fortress_id);
    expect(event.payload.reason).toBe("join mesh");
    expect(event.payload.preconditions_checked).toEqual(preconditionsChecked);

    expect(event.event_type).toBe(FORTRESS_EVENT_TYPES.MODE_TRANSITION);
    expect(event.event_type).toBe("fortress_mode_transition");

    expect(typeof event.payload.transitioned_at).toBe("string");
    expect(new Date(event.payload.transitioned_at).toISOString()).toBe(
      event.payload.transitioned_at
    );
    expect(event.payload.transitioned_at).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
    );
    expect(Date.parse(event.payload.transitioned_at)).toBeGreaterThanOrEqual(before);
    expect(Date.parse(event.payload.transitioned_at)).toBeLessThanOrEqual(after);

    expect(event.node_signature).toBeTruthy();
    expect(event.principal_signature).toBeTruthy();
    expect(event.fortress_id).toBe(f.master.public.fortress_id);
    expect(event.emitter_node).toBe(f.nodeCert.node_id);
    expect(event.emitter_principal).toBe(f.principalCert.principal_id);
    expect(event.monotonic_seq).toBe(42);
    expect(verifySignedEvent(event, f.verifyCtx).ok).toBe(true);
  });

  it("rejects a mode transition event whose payload was tampered after signing", () => {
    const f = buildSigningFixture();
    const event = packModeTransitionEvent({
      from_tier: "tier_1_private",
      to_tier: "tier_2_federated",
      fortress_id: f.master.public.fortress_id,
      reason: "join mesh",
      preconditions_checked: ["federation_join", "audit_replica_ready"],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 42,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });

    expect(verifySignedEvent(event, f.verifyCtx).ok).toBe(true);

    event.payload.reason = "tampered: " + event.payload.reason;

    // Defense-in-depth: a post-signing payload mutation is rejected (caught by the payload_hash coherence guard and/or the signature check). This pins the rejection behavior, not which specific guard fires first.
    expect(() => verifySignedEvent(event, f.verifyCtx)).toThrow(MeshSignatureError);
  });

  it("rejects a mode transition event whose node signature is corrupted (ed25519 verify)", () => {
    const f = buildSigningFixture();
    const event = packModeTransitionEvent({
      from_tier: "tier_1_private",
      to_tier: "tier_2_federated",
      fortress_id: f.master.public.fortress_id,
      reason: "join mesh",
      preconditions_checked: ["federation_join", "audit_replica_ready"],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 42,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
    });

    expect(verifySignedEvent(event, f.verifyCtx).ok).toBe(true);

    const sig = event.node_signature;
    const flipped = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
    event.node_signature = flipped;

    expect(() => verifySignedEvent(event, f.verifyCtx)).toThrow(MeshSignatureError);
  });

  it("allows principal_private_key to be omitted", () => {
    const f = buildSigningFixture();
    const event = packModeTransitionEvent({
      from_tier: "tier_2_federated",
      to_tier: "tier_1_private",
      fortress_id: f.master.public.fortress_id,
      reason: "withdraw",
      preconditions_checked: ["mesh_shutdown"],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 43,
      node_private_key: f.nodeKeypair.privateKey,
    });

    expect(event.node_signature).toBeTruthy();
    expect(event.principal_signature).toBeUndefined();
    expect(event.event_type).toBe(FORTRESS_EVENT_TYPES.MODE_TRANSITION);
    expect(event.event_type).toBe("fortress_mode_transition");
    expect(event.payload).toMatchObject({
      from_tier: "tier_2_federated",
      to_tier: "tier_1_private",
      fortress_id: f.master.public.fortress_id,
      reason: "withdraw",
    });
    expect(event.payload.preconditions_checked).toEqual(["mesh_shutdown"]);
    expect(verifySignedEvent(event, f.verifyCtx).ok).toBe(true);
  });

  it("passes causal_parents through to the signed event", () => {
    const f = buildSigningFixture();
    const causalParents = ["01HX4B8QYGMV8QK6P8AF0B3EHD", "01HX4B8R5CF3T8EW6GACT0V6PE"];
    const event = packModeTransitionEvent({
      from_tier: "tier_2_federated",
      to_tier: "tier_3_interop",
      fortress_id: f.master.public.fortress_id,
      reason: "enable adapters",
      preconditions_checked: ["adapter_registered"],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      monotonic_seq: 44,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
      causal_parents: causalParents,
    });

    expect(event.causal_parents).toEqual(causalParents);
    expect(verifySignedEvent(event, f.verifyCtx).ok).toBe(true);
  });
});
