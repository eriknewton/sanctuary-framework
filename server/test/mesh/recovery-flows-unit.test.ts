/**
 * WP-MVP-8 Recovery Flows — unit tests.
 *
 * Covers:
 *   - secret-bundle wrap/unwrap (AAD binding, cross-peer replay, cross-
 *     rotation replay, corrupt-ciphertext)
 *   - DMswitch grace-window evaluation (inside / outside / already-fired)
 *   - Ceremony propose/confirm paths: guardian verification, Key 8 operator-
 *     confirmation invariant, DMswitch grace enforcement
 *   - Ack subscription signature verification
 *
 * Integration (real three-mode drill) lives under
 * test/acceptance/three-mode-drill/recovery-flows.test.ts.
 */

import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";

import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
} from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import {
  issueGuardianRoster,
  signMasterRotationAsGuardian,
  type GuardianIdentity,
} from "../../src/mesh/guardian/index.js";
import {
  DMswitchGraceWindowActive,
  SecretBundleError,
  CeremonyError,
  CeremonyNotConfirmedError,
  evaluateDMswitchGraceWindow,
  enforceDMswitchGraceWindow,
  wrapMasterRotationBundle,
  unwrapMasterRotationBundle,
  deviceRecoveryQuorumInput,
  revokeQuorumInput,
  canonicalAuditPromoteQuorumInput,
  createMasterRotationAckSubscription,
  type MasterRotationAckMessage,
  RECOVERY_UNICAST_KINDS,
  type MasterRotationBundleEnvelope,
} from "../../src/mesh/recovery-flows/index.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Fixtures
// ═══════════════════════════════════════════════════════════════════════

interface Fixture {
  masterPublic: FortressMasterPublicKey;
  masterSecret: Uint8Array;
  rootCert: PrincipalCertificate;
  rootKp: ReturnType<typeof generateKeypair>;
  nodeKp: ReturnType<typeof generateKeypair>;
  nodeCert: NodeIdentityCertificate;
  nodeId: string;
  fortressId: string;
}

function buildFixture(nodeIdOverride?: string, nodeMode: "local" | "operator_cloud" | "sovereign_tee" = "local"): Fixture {
  const masterBundle = generateFortressMaster();
  const rootKp = generateKeypair();
  const rootCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: rootKp.publicKey,
    role: "root",
    fortress_id: masterBundle.public.fortress_id,
    master_private_key: masterBundle.private_key,
  });
  const nodeKp = generateKeypair();
  const nodeId =
    nodeIdOverride ?? "node-" + Array.from(nodeKp.publicKey.slice(0, 8)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const nodeCert = issueNodeIdentityCertificate({
    node_id: nodeId,
    node_pubkey: nodeKp.publicKey,
    node_mode: nodeMode,
    fortress_id: masterBundle.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: masterBundle.public.public_key,
      principal_id: rootCert.principal_id,
      principal_pubkey: rootCert.principal_pubkey,
    },
    principal_private_key: rootKp.privateKey,
    master_private_key: masterBundle.private_key,
  });
  return {
    masterPublic: masterBundle.public,
    masterSecret: masterBundle.private_key,
    rootCert,
    rootKp,
    nodeKp,
    nodeCert,
    nodeId,
    fortressId: masterBundle.public.fortress_id,
  };
}

function buildGuardians(count: number): Array<{ identity: GuardianIdentity; sk: Uint8Array }> {
  const out: Array<{ identity: GuardianIdentity; sk: Uint8Array }> = [];
  for (let i = 0; i < count; i++) {
    const kp = generateKeypair();
    out.push({
      identity: {
        guardian_id: "g" + i,
        public_key: toBase64url(kp.publicKey),
        kind: "human",
        invited_at: new Date().toISOString(),
      },
      sk: kp.privateKey,
    });
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
// Secret-bundle wrap/unwrap
// ═══════════════════════════════════════════════════════════════════════

describe("secret-bundle", () => {
  it("round-trips plaintext under the peer's old transport key (AAD holds)", () => {
    const fx = buildFixture("peer-alpha");
    const newMaster = generateFortressMaster();
    const rotatedAt = new Date().toISOString();
    const rootKp = generateKeypair();
    const newRootCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: rootKp.publicKey,
      role: "root",
      fortress_id: newMaster.public.fortress_id,
      master_private_key: newMaster.private_key,
    });
    const peerReIssuedKp = generateKeypair();
    const peerReIssued = issueNodeIdentityCertificate({
      node_id: fx.nodeId,
      node_pubkey: peerReIssuedKp.publicKey,
      node_mode: fx.nodeCert.node_mode,
      fortress_id: newMaster.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: newMaster.public.public_key,
        principal_id: newRootCert.principal_id,
        principal_pubkey: newRootCert.principal_pubkey,
      },
      principal_private_key: rootKp.privateKey,
      master_private_key: newMaster.private_key,
    });
    const envelope = wrapMasterRotationBundle({
      plaintext: {
        new_master_secret: toBase64url(newMaster.private_key),
        re_issued_self_cert: peerReIssued,
        new_root_principal_cert: newRootCert,
        rotated_at: rotatedAt,
        new_master_pubkey: newMaster.public.public_key,
      },
      old_fortress_master_secret: fx.masterSecret,
      target_node_id: fx.nodeId,
      target_node_mode: fx.nodeCert.node_mode,
      fortress_id: fx.fortressId,
    });
    expect(envelope.kind).toBe(RECOVERY_UNICAST_KINDS.MASTER_ROTATION_BUNDLE);
    expect(envelope.target_node_id).toBe(fx.nodeId);
    expect(envelope.rotated_at).toBe(rotatedAt);
    const pt = unwrapMasterRotationBundle({
      envelope,
      old_fortress_master_secret: fx.masterSecret,
      this_node_id: fx.nodeId,
      this_node_mode: fx.nodeCert.node_mode,
      this_fortress_id: fx.fortressId,
    });
    expect(pt.new_master_pubkey).toBe(newMaster.public.public_key);
    expect(pt.rotated_at).toBe(rotatedAt);
    expect(pt.re_issued_self_cert.node_id).toBe(fx.nodeId);
    expect(pt.re_issued_self_cert.parent_chain.fortress_master_pubkey).toBe(
      newMaster.public.public_key
    );
  });

  it("rejects cross-peer redirection: envelope targeted at peer B cannot unwrap on peer A", () => {
    const peerA = buildFixture("peer-A");
    const peerB = buildFixture("peer-B");
    // Both peers share a fortress-master so they can reach each other via the
    // shared master secret; force them to by copying peerA's master into B.
    // Instead, use a single fixture master for both: re-build peerB under
    // peerA's master so transport keys are derivable from the same secret.
    const sharedMasterBundle = generateFortressMaster();
    const rootKpShared = generateKeypair();
    const rootCertShared = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: rootKpShared.publicKey,
      role: "root",
      fortress_id: sharedMasterBundle.public.fortress_id,
      master_private_key: sharedMasterBundle.private_key,
    });
    const peerACert = issueNodeIdentityCertificate({
      node_id: "peer-A",
      node_pubkey: peerA.nodeKp.publicKey,
      node_mode: "local",
      fortress_id: sharedMasterBundle.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: sharedMasterBundle.public.public_key,
        principal_id: rootCertShared.principal_id,
        principal_pubkey: rootCertShared.principal_pubkey,
      },
      principal_private_key: rootKpShared.privateKey,
      master_private_key: sharedMasterBundle.private_key,
    });
    const peerBCert = issueNodeIdentityCertificate({
      node_id: "peer-B",
      node_pubkey: peerB.nodeKp.publicKey,
      node_mode: "local",
      fortress_id: sharedMasterBundle.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: sharedMasterBundle.public.public_key,
        principal_id: rootCertShared.principal_id,
        principal_pubkey: rootCertShared.principal_pubkey,
      },
      principal_private_key: rootKpShared.privateKey,
      master_private_key: sharedMasterBundle.private_key,
    });

    const newMaster = generateFortressMaster();
    const newRootKp = generateKeypair();
    const newRootCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: newRootKp.publicKey,
      role: "root",
      fortress_id: newMaster.public.fortress_id,
      master_private_key: newMaster.private_key,
    });
    void peerACert;
    const envelopeForB = wrapMasterRotationBundle({
      plaintext: {
        new_master_secret: toBase64url(newMaster.private_key),
        re_issued_self_cert: peerBCert,
        new_root_principal_cert: newRootCert,
        rotated_at: new Date().toISOString(),
        new_master_pubkey: newMaster.public.public_key,
      },
      old_fortress_master_secret: sharedMasterBundle.private_key,
      target_node_id: "peer-B",
      target_node_mode: "local",
      fortress_id: sharedMasterBundle.public.fortress_id,
    });

    // Peer A tries to unwrap an envelope targeted at peer B.
    expect(() =>
      unwrapMasterRotationBundle({
        envelope: envelopeForB,
        old_fortress_master_secret: sharedMasterBundle.private_key,
        this_node_id: "peer-A",
        this_node_mode: "local",
        this_fortress_id: sharedMasterBundle.public.fortress_id,
      })
    ).toThrow(SecretBundleError);
  });

  it("rejects cross-fortress delivery", () => {
    const fx = buildFixture("peer-alpha");
    const newMaster = generateFortressMaster();
    const rootKp = generateKeypair();
    const newRootCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: rootKp.publicKey,
      role: "root",
      fortress_id: newMaster.public.fortress_id,
      master_private_key: newMaster.private_key,
    });
    const peerReIssuedKp = generateKeypair();
    const peerReIssued = issueNodeIdentityCertificate({
      node_id: fx.nodeId,
      node_pubkey: peerReIssuedKp.publicKey,
      node_mode: "local",
      fortress_id: newMaster.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: newMaster.public.public_key,
        principal_id: newRootCert.principal_id,
        principal_pubkey: newRootCert.principal_pubkey,
      },
      principal_private_key: rootKp.privateKey,
      master_private_key: newMaster.private_key,
    });
    const env = wrapMasterRotationBundle({
      plaintext: {
        new_master_secret: toBase64url(newMaster.private_key),
        re_issued_self_cert: peerReIssued,
        new_root_principal_cert: newRootCert,
        rotated_at: new Date().toISOString(),
        new_master_pubkey: newMaster.public.public_key,
      },
      old_fortress_master_secret: fx.masterSecret,
      target_node_id: fx.nodeId,
      target_node_mode: fx.nodeCert.node_mode,
      fortress_id: fx.fortressId,
    });
    // Attempt unwrap against a DIFFERENT fortress_id.
    expect(() =>
      unwrapMasterRotationBundle({
        envelope: env,
        old_fortress_master_secret: fx.masterSecret,
        this_node_id: fx.nodeId,
        this_node_mode: fx.nodeCert.node_mode,
        this_fortress_id: "cross-fortress",
      })
    ).toThrow(SecretBundleError);
  });

  it("rejects tampered ciphertext (AAD authenticates)", () => {
    const fx = buildFixture("peer-alpha");
    const newMaster = generateFortressMaster();
    const rootKp = generateKeypair();
    const newRootCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: rootKp.publicKey,
      role: "root",
      fortress_id: newMaster.public.fortress_id,
      master_private_key: newMaster.private_key,
    });
    const peerReIssuedKp = generateKeypair();
    const peerReIssued = issueNodeIdentityCertificate({
      node_id: fx.nodeId,
      node_pubkey: peerReIssuedKp.publicKey,
      node_mode: "local",
      fortress_id: newMaster.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: newMaster.public.public_key,
        principal_id: newRootCert.principal_id,
        principal_pubkey: newRootCert.principal_pubkey,
      },
      principal_private_key: rootKp.privateKey,
      master_private_key: newMaster.private_key,
    });
    const env = wrapMasterRotationBundle({
      plaintext: {
        new_master_secret: toBase64url(newMaster.private_key),
        re_issued_self_cert: peerReIssued,
        new_root_principal_cert: newRootCert,
        rotated_at: new Date().toISOString(),
        new_master_pubkey: newMaster.public.public_key,
      },
      old_fortress_master_secret: fx.masterSecret,
      target_node_id: fx.nodeId,
      target_node_mode: fx.nodeCert.node_mode,
      fortress_id: fx.fortressId,
    });
    const tampered: MasterRotationBundleEnvelope = {
      ...env,
      ciphertext: {
        ...env.ciphertext,
        ct: flipFirstCharBase64url(env.ciphertext.ct),
      },
    };
    expect(() =>
      unwrapMasterRotationBundle({
        envelope: tampered,
        old_fortress_master_secret: fx.masterSecret,
        this_node_id: fx.nodeId,
        this_node_mode: fx.nodeCert.node_mode,
        this_fortress_id: fx.fortressId,
      })
    ).toThrow(SecretBundleError);
  });
});

function flipFirstCharBase64url(s: string): string {
  if (s.length === 0) return s;
  const c = s[0];
  // Base64url alphabet is A-Z, a-z, 0-9, -, _. Flip A→B, a→b, 0→1, - → _.
  const replacement =
    c === "A" ? "B" : c === "a" ? "b" : c === "0" ? "1" : c === "-" ? "_" : "A";
  return replacement + s.slice(1);
}

// ═══════════════════════════════════════════════════════════════════════
// DMswitch grace-window
// ═══════════════════════════════════════════════════════════════════════

describe("DMswitch grace-window", () => {
  it("blocks inside grace window", () => {
    const lastActivity = new Date().toISOString();
    const r = evaluateDMswitchGraceWindow({
      last_operator_activity_at: lastActivity,
      now_ms: Date.now(),
    });
    expect(r.blocked).toBe(true);
    expect(r.available_at).toBeDefined();
    expect(r.remaining_ms).toBeGreaterThan(0);
  });

  it("allows outside grace window (past 90d + 30d)", () => {
    const longAgo = new Date(
      Date.now() - 121 * 24 * 60 * 60 * 1000
    ).toISOString();
    const r = evaluateDMswitchGraceWindow({
      last_operator_activity_at: longAgo,
      now_ms: Date.now(),
    });
    expect(r.blocked).toBe(false);
  });

  it("allows when dmswitch_already_fired (per §3.6.1 guardian-revoke unlock)", () => {
    const r = evaluateDMswitchGraceWindow({
      last_operator_activity_at: new Date().toISOString(),
      now_ms: Date.now(),
      dmswitch_already_fired: true,
    });
    expect(r.blocked).toBe(false);
  });

  it("enforceDMswitchGraceWindow throws with remaining_ms when blocked", () => {
    const lastActivity = new Date().toISOString();
    try {
      enforceDMswitchGraceWindow({ last_operator_activity_at: lastActivity });
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(DMswitchGraceWindowActive);
      const err = e as DMswitchGraceWindowActive;
      expect(err.remaining_ms).toBeGreaterThan(0);
      expect(err.available_at).toBeDefined();
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Quorum-input shape helpers (canonical bytes convention)
// ═══════════════════════════════════════════════════════════════════════

describe("quorum-input builders", () => {
  it("deviceRecoveryQuorumInput binds lost → replacement identifiers in rotated_at", () => {
    const fx = buildFixture("lost-node");
    const replacementFx = buildFixture("replacement-node");
    const input = deviceRecoveryQuorumInput(
      {
        lost_node_id: fx.nodeId,
        replacement_node_cert: replacementFx.nodeCert,
        guardian_signatures: [],
      },
      fx.fortressId
    );
    expect(input.rotated_at).toContain("device_recovery:");
    expect(input.rotated_at).toContain(fx.nodeId);
    expect(input.rotated_at).toContain(replacementFx.nodeId);
    expect(input.old_master_pubkey).toBe("node:" + fx.nodeId);
    expect(input.new_master_pubkey.fortress_id).toBe(fx.fortressId);
  });

  it("revokeQuorumInput binds target + reason", () => {
    const input = revokeQuorumInput(
      {
        target_node_id: "compromised-1",
        reason: "non-monotonic envelope",
        guardian_signatures: [],
      },
      "fid-1"
    );
    expect(input.old_master_pubkey).toBe("node:compromised-1");
    expect(input.rotated_at).toContain("revoke:");
  });

  it("canonicalAuditPromoteQuorumInput binds current + new canonical ids", () => {
    const input = canonicalAuditPromoteQuorumInput(
      {
        current_canonical_node_id: "old-canon",
        new_canonical_node_id: "new-canon",
        guardian_signatures: [],
      },
      "fid-2"
    );
    expect(input.old_master_pubkey).toContain("old-canon");
    expect(input.rotated_at).toContain("new-canon");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Ack subscription
// ═══════════════════════════════════════════════════════════════════════

describe("master-rotation ack subscription", () => {
  it("accepts a well-signed installed ack and counts it toward waitFor", async () => {
    const guardians = buildGuardians(5);
    void guardians;
    const ackerKp = generateKeypair();
    const ackerNodeId = "node-acker";
    const fortressId = "fid-ack";
    const rotatedAt = new Date().toISOString();
    const newMasterKp = generateKeypair();
    const newMasterPubkey = toBase64url(newMasterKp.publicKey);
    const sub = createMasterRotationAckSubscription({
      fortress_id: fortressId,
      lookup_pre_rotation_pubkey: (id) =>
        id === ackerNodeId ? toBase64url(ackerKp.publicKey) : undefined,
    });
    const ack: MasterRotationAckMessage = signAck({
      kp: ackerKp,
      node_id: ackerNodeId,
      fortress_id: fortressId,
      rotated_at: rotatedAt,
      new_master_pubkey: newMasterPubkey,
      status: "installed",
    });
    sub.ingest(ack);
    const got = await sub.waitFor({
      rotated_at: rotatedAt,
      expected: [ackerNodeId],
      timeout_ms: 200,
    });
    expect(got.has(ackerNodeId)).toBe(true);
    expect(sub.acksFor(rotatedAt).size).toBe(1);
    sub.close();
  });

  it("rejects an ack with a bad signature", async () => {
    const ackerKp = generateKeypair();
    const otherKp = generateKeypair();
    const ackerNodeId = "node-acker";
    const fortressId = "fid-ack-2";
    const rotatedAt = new Date().toISOString();
    const newMasterPubkey = toBase64url(generateKeypair().publicKey);
    const sub = createMasterRotationAckSubscription({
      fortress_id: fortressId,
      lookup_pre_rotation_pubkey: (id) =>
        id === ackerNodeId ? toBase64url(ackerKp.publicKey) : undefined,
    });
    // Sign with the WRONG key.
    const ack = signAck({
      kp: otherKp,
      node_id: ackerNodeId,
      fortress_id: fortressId,
      rotated_at: rotatedAt,
      new_master_pubkey: newMasterPubkey,
      status: "installed",
    });
    sub.ingest(ack);
    const got = await sub.waitFor({
      rotated_at: rotatedAt,
      expected: [ackerNodeId],
      timeout_ms: 200,
    });
    expect(got.has(ackerNodeId)).toBe(false);
    expect(sub.acksFor(rotatedAt).size).toBe(0);
    sub.close();
  });

  it("does NOT count status=error acks as installed", async () => {
    const ackerKp = generateKeypair();
    const ackerNodeId = "node-acker";
    const fortressId = "fid-ack-3";
    const rotatedAt = new Date().toISOString();
    const newMasterPubkey = toBase64url(generateKeypair().publicKey);
    const sub = createMasterRotationAckSubscription({
      fortress_id: fortressId,
      lookup_pre_rotation_pubkey: (id) =>
        id === ackerNodeId ? toBase64url(ackerKp.publicKey) : undefined,
    });
    const ack = signAck({
      kp: ackerKp,
      node_id: ackerNodeId,
      fortress_id: fortressId,
      rotated_at: rotatedAt,
      new_master_pubkey: newMasterPubkey,
      status: "error",
    });
    ack.error_message = "install failed";
    sub.ingest(ack);
    // The ack is recorded, but waitFor only counts `installed` acks.
    const got = await sub.waitFor({
      rotated_at: rotatedAt,
      expected: [ackerNodeId],
      timeout_ms: 200,
    });
    expect(got.size).toBe(0);
    sub.close();
  });
});

function signAck(params: {
  kp: ReturnType<typeof generateKeypair>;
  node_id: string;
  fortress_id: string;
  rotated_at: string;
  new_master_pubkey: string;
  status: "installed" | "error";
}): MasterRotationAckMessage {
  const body = new TextEncoder().encode(
    JSON.stringify({
      kind: RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK,
      fortress_id: params.fortress_id,
      node_id: params.node_id,
      rotated_at: params.rotated_at,
      new_master_pubkey: params.new_master_pubkey,
      status: params.status,
    })
  );
  const sig = ed25519.sign(body, params.kp.privateKey);
  return {
    kind: RECOVERY_UNICAST_KINDS.MASTER_ROTATION_ACK,
    fortress_id: params.fortress_id,
    node_id: params.node_id,
    rotated_at: params.rotated_at,
    new_master_pubkey: params.new_master_pubkey,
    status: params.status,
    ack_signature: toBase64url(sig),
    signature_scheme: SIGNATURE_SCHEME_V1,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Ceremony shape: DeviceRecovery propose/confirm invariants
// ═══════════════════════════════════════════════════════════════════════

describe("DeviceRecoveryCeremony — propose/confirm Key 8 invariant", () => {
  // Helper: build a fixture + a replacement cert under the SAME fortress so
  // verifyCertChain does not reject on cross-operator isolation.
  function buildPair(): { fx: Fixture; replacementCert: NodeIdentityCertificate } {
    const fx = buildFixture("lost");
    const replacementKp = generateKeypair();
    const replacementId = "replacement";
    const replacementCert = issueNodeIdentityCertificate({
      node_id: replacementId,
      node_pubkey: replacementKp.publicKey,
      node_mode: "local",
      fortress_id: fx.fortressId,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: fx.masterPublic.public_key,
        principal_id: fx.rootCert.principal_id,
        principal_pubkey: fx.rootCert.principal_pubkey,
      },
      principal_private_key: fx.rootKp.privateKey,
      master_private_key: fx.masterSecret,
    });
    return { fx, replacementCert };
  }

  // Construct a minimal ceremony context against a synthetic MeshNode stub so
  // the test does not rely on the drill harness.
  it("propose() throws DMswitchGraceWindowActive when grace window active", async () => {
    const { fx, replacementCert } = buildPair();
    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: fx.fortressId,
      version: 1,
      master_private_key: fx.masterSecret,
    });
    // Recent activity → grace window active.
    const lastActivity = new Date(Date.now() - 60_000).toISOString();

    const { DeviceRecoveryCeremony } = await import(
      "../../src/mesh/recovery-flows/index.js"
    );

    expect(() =>
      DeviceRecoveryCeremony.propose({
        proposal: {
          lost_node_id: fx.nodeId,
          replacement_node_cert: replacementCert,
          guardian_signatures: [],
        },
        ctx: {
          node: (null as unknown) as never,
          root_principal_cert: fx.rootCert,
          pinned_master: fx.masterPublic,
          pinned_roster: roster,
          emit_ctx: (null as unknown) as never,
          fortress_master_secret: fx.masterSecret,
          dmswitch_input: { last_operator_activity_at: lastActivity },
        },
      })
    ).toThrow(DMswitchGraceWindowActive);
  });

  it("propose() verifies guardian quorum before returning ceremony record", async () => {
    const { fx, replacementCert } = buildPair();
    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: fx.fortressId,
      version: 1,
      master_private_key: fx.masterSecret,
    });
    // Pass ONE signature instead of 3 → quorum verification fails.
    const oneSig = signMasterRotationAsGuardian({
      input: deviceRecoveryQuorumInput(
        {
          lost_node_id: fx.nodeId,
          replacement_node_cert: replacementCert,
          guardian_signatures: [],
        },
        fx.fortressId
      ),
      guardian_id: guardians[0].identity.guardian_id,
      guardian_private_key: guardians[0].sk,
    });
    const longAgo = new Date(
      Date.now() - 200 * 24 * 60 * 60 * 1000
    ).toISOString();
    const { DeviceRecoveryCeremony } = await import(
      "../../src/mesh/recovery-flows/index.js"
    );
    expect(() =>
      DeviceRecoveryCeremony.propose({
        proposal: {
          lost_node_id: fx.nodeId,
          replacement_node_cert: replacementCert,
          guardian_signatures: [oneSig],
        },
        ctx: {
          node: (null as unknown) as never,
          root_principal_cert: fx.rootCert,
          pinned_master: fx.masterPublic,
          pinned_roster: roster,
          emit_ctx: (null as unknown) as never,
          fortress_master_secret: fx.masterSecret,
          dmswitch_input: { last_operator_activity_at: longAgo },
        },
      })
    ).toThrow(/quorum requires/);
  });

  it("execute() throws CeremonyNotConfirmedError before confirm() is called", async () => {
    const { fx, replacementCert } = buildPair();
    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: fx.fortressId,
      version: 1,
      master_private_key: fx.masterSecret,
    });
    const longAgo = new Date(
      Date.now() - 200 * 24 * 60 * 60 * 1000
    ).toISOString();
    const input = deviceRecoveryQuorumInput(
      {
        lost_node_id: fx.nodeId,
        replacement_node_cert: replacementCert,
        guardian_signatures: [],
      },
      fx.fortressId
    );
    const sigs = guardians
      .slice(0, 3)
      .map((g) =>
        signMasterRotationAsGuardian({
          input,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.sk,
        })
      );
    const { DeviceRecoveryCeremony } = await import(
      "../../src/mesh/recovery-flows/index.js"
    );
    const ceremony = DeviceRecoveryCeremony.propose({
      proposal: {
        lost_node_id: fx.nodeId,
        replacement_node_cert: replacementCert,
        guardian_signatures: sigs,
      },
      ctx: {
        node: (null as unknown) as never,
        root_principal_cert: fx.rootCert,
        pinned_master: fx.masterPublic,
        pinned_roster: roster,
        emit_ctx: (null as unknown) as never,
        fortress_master_secret: fx.masterSecret,
        dmswitch_input: { last_operator_activity_at: longAgo },
      },
    });
    await expect(ceremony.execute()).rejects.toBeInstanceOf(
      CeremonyNotConfirmedError
    );
    expect(ceremony.state).toBe("proposed");
  });

  it("confirm() rejects empty notes", async () => {
    const { fx, replacementCert } = buildPair();
    const guardians = buildGuardians(5);
    const roster = issueGuardianRoster({
      m: 3,
      n: 5,
      guardians: guardians.map((g) => g.identity),
      fortress_id: fx.fortressId,
      version: 1,
      master_private_key: fx.masterSecret,
    });
    const longAgo = new Date(
      Date.now() - 200 * 24 * 60 * 60 * 1000
    ).toISOString();
    const input = deviceRecoveryQuorumInput(
      {
        lost_node_id: fx.nodeId,
        replacement_node_cert: replacementCert,
        guardian_signatures: [],
      },
      fx.fortressId
    );
    const sigs = guardians
      .slice(0, 3)
      .map((g) =>
        signMasterRotationAsGuardian({
          input,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.sk,
        })
      );
    const { DeviceRecoveryCeremony } = await import(
      "../../src/mesh/recovery-flows/index.js"
    );
    const ceremony = DeviceRecoveryCeremony.propose({
      proposal: {
        lost_node_id: fx.nodeId,
        replacement_node_cert: replacementCert,
        guardian_signatures: sigs,
      },
      ctx: {
        node: (null as unknown) as never,
        root_principal_cert: fx.rootCert,
        pinned_master: fx.masterPublic,
        pinned_roster: roster,
        emit_ctx: (null as unknown) as never,
        fortress_master_secret: fx.masterSecret,
        dmswitch_input: { last_operator_activity_at: longAgo },
      },
    });
    expect(() => ceremony.confirm({ note: "" })).toThrow(CeremonyError);
    expect(() => ceremony.confirm({ note: "   " })).toThrow(CeremonyError);
    expect(ceremony.state).toBe("proposed");
  });
});
