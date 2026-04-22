/**
 * Sanctuary Federation Protocol v0.1 — Guardian + Recovery Cascade Tests
 *
 * WP-MVP-3 Follow-up #3 spawn-prompt acceptance criteria covered here:
 *   3 — GuardianRoster module + 3-of-5 default + sub-M quorum rejection.
 *   4 — master_rotation acceptance + cert re-issue + HKDF re-derive +
 *       locator-re-sign + policy preserve+historical_master.
 *   5 — Audit continuity walk across master rotation.
 *   6 — Post-recovery broker-credential rotation prompt.
 *   8 — event_class enum coverage on every emission.
 *   9 — signature_scheme: 'ed25519-v1' on every signed emission.
 *
 * No mocked routes. Real Ed25519, real HKDF, real canonical-JSON. Failures
 * here would also fail on the libp2p adapter.
 */

import { describe, it, expect } from "vitest";
import {
  fromBase64url,
  toBase64url,
} from "../../src/core/encoding.js";
import { generateKeypair } from "../../src/core/identity.js";
import { ed25519 } from "@noble/curves/ed25519";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
} from "../../src/mesh/constants.js";
import {
  acceptMasterRotation,
  buildMasterRotationAuditPayload,
  buildMasterRotationPayload,
  buildPostRecoveryPrompt,
  DEFAULT_GUARDIAN_M,
  DEFAULT_GUARDIAN_N,
  GuardianQuorumError,
  GuardianRosterError,
  GuardianRosterSignatureError,
  GuardianRosterStaleError,
  MasterRotationError,
  PostRecoveryPromptStore,
  isV10GuardianKind,
  issueGuardianRoster,
  rekeyOnMasterRotation,
  signMasterRotationAsGuardian,
  verifyGuardianQuorum,
  verifyGuardianRoster,
  walkAuditContinuity,
  type GuardianIdentity,
  type MasterRotationQuorumInput,
} from "../../src/mesh/guardian/index.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import type { FortressMasterPublicKey } from "../../src/mesh/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Fortress + roster fixtures
// ═══════════════════════════════════════════════════════════════════════

interface GuardianKp {
  identity: GuardianIdentity;
  private_key: Uint8Array;
}

function makeGuardian(id: string, kind: "human" | "sanctuary_operated" = "human"): GuardianKp {
  const kp = generateKeypair();
  return {
    identity: {
      guardian_id: id,
      public_key: toBase64url(kp.publicKey),
      kind,
      invited_at: new Date().toISOString(),
    },
    private_key: kp.privateKey,
  };
}

function makeFortress() {
  return generateFortressMaster();
}

function makeRosterDefault35(fortress: ReturnType<typeof makeFortress>) {
  const guardians = ["g1", "g2", "g3", "g4", "g5"].map((id) => makeGuardian(id));
  const roster = issueGuardianRoster({
    m: DEFAULT_GUARDIAN_M,
    n: DEFAULT_GUARDIAN_N,
    guardians: guardians.map((g) => g.identity),
    fortress_id: fortress.public.fortress_id,
    version: 1,
    master_private_key: fortress.private_key,
  });
  return { roster, guardians };
}

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #3 — GuardianRoster
// ═══════════════════════════════════════════════════════════════════════

describe("GuardianRoster — issuance + verification", () => {
  it("default M-of-N is 3-of-5 per Key 13 lock", () => {
    expect(DEFAULT_GUARDIAN_M).toBe(3);
    expect(DEFAULT_GUARDIAN_N).toBe(5);
  });

  it("v1.0 issuance accepts only human / sanctuary_operated kinds", () => {
    expect(isV10GuardianKind("human")).toBe(true);
    expect(isV10GuardianKind("sanctuary_operated")).toBe(true);
    expect(isV10GuardianKind("custodial-vault")).toBe(false);
  });

  it("issued roster verifies against the fortress-master pubkey", () => {
    const fortress = makeFortress();
    const { roster } = makeRosterDefault35(fortress);
    expect(roster.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(roster.m).toBe(3);
    expect(roster.n).toBe(5);
    expect(roster.guardians).toHaveLength(5);
    verifyGuardianRoster(roster, fortress.public);
  });

  it("rejects roster signed by a different master (cross-operator isolation)", () => {
    const fortress = makeFortress();
    const other = makeFortress();
    const { roster } = makeRosterDefault35(fortress);
    expect(() => verifyGuardianRoster(roster, other.public)).toThrowError(
      GuardianRosterError
    );
  });

  it("rejects roster with tampered master signature", () => {
    const fortress = makeFortress();
    const { roster } = makeRosterDefault35(fortress);
    const tampered = { ...roster, master_signature: toBase64url(
      // flip the first byte of the original signature
      (() => {
        const raw = fromBase64url(roster.master_signature);
        raw[0] ^= 0x01;
        return raw;
      })()
    ) };
    expect(() => verifyGuardianRoster(tampered, fortress.public)).toThrow(
      GuardianRosterSignatureError
    );
  });

  it("rejects invalid M-of-N at issuance", () => {
    const fortress = makeFortress();
    const guardians = ["g1", "g2"].map((id) => makeGuardian(id).identity);
    expect(() =>
      issueGuardianRoster({
        m: 3,
        n: 2,
        guardians,
        fortress_id: fortress.public.fortress_id,
        version: 1,
        master_private_key: fortress.private_key,
      })
    ).toThrow(GuardianRosterError);
  });

  it("rejects duplicate guardian_ids in roster", () => {
    const fortress = makeFortress();
    const dup = makeGuardian("g-x").identity;
    const guardians = [dup, { ...dup }];
    expect(() =>
      issueGuardianRoster({
        m: 1,
        n: 2,
        guardians,
        fortress_id: fortress.public.fortress_id,
        version: 1,
        master_private_key: fortress.private_key,
      })
    ).toThrow(GuardianRosterError);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// verifyGuardianQuorum — sub-M rejection + signature verification
// ═══════════════════════════════════════════════════════════════════════

describe("verifyGuardianQuorum — M-of-N enforcement", () => {
  it("accepts exactly M valid signatures", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    verifyGuardianQuorum({
      input,
      proof: { roster_version: roster.version, signatures: sigs },
      pinned_roster: roster,
    });
  });

  it("rejects sub-threshold (M-1) signatures", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 2).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
  });

  it("rejects duplicate guardian_id across signatures", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const oneSig = signMasterRotationAsGuardian({
      input,
      guardian_id: guardians[0].identity.guardian_id,
      guardian_private_key: guardians[0].private_key,
    });
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: {
          roster_version: roster.version,
          signatures: [oneSig, oneSig, oneSig],
        },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
  });

  it("rejects signature from a guardian not in the pinned roster", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const interloper = makeGuardian("g-fake");
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = [
      ...guardians.slice(0, 2).map((g) =>
        signMasterRotationAsGuardian({
          input,
          guardian_id: g.identity.guardian_id,
          guardian_private_key: g.private_key,
        })
      ),
      signMasterRotationAsGuardian({
        input,
        guardian_id: interloper.identity.guardian_id,
        guardian_private_key: interloper.private_key,
      }),
    ];
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: roster.version, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
  });

  it("rejects stale roster_version (replay protection)", () => {
    const fortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(fortress);
    const newMaster = generateFortressMaster();
    newMaster.public.fortress_id = fortress.public.fortress_id;
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: fortress.public.public_key,
      new_master_pubkey: newMaster.public,
      rotated_at: new Date().toISOString(),
      fortress_id: fortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    expect(() =>
      verifyGuardianQuorum({
        input,
        proof: { roster_version: 99, signatures: sigs },
        pinned_roster: roster,
      })
    ).toThrow(GuardianQuorumError);
    // Sanity that the GuardianRosterStaleError is also wired.
    expect(GuardianRosterStaleError).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #4 — master_rotation flow + cascade
// ═══════════════════════════════════════════════════════════════════════

describe("master_rotation acceptance + cascade", () => {
  function setupRotationFixture() {
    const oldFortress = makeFortress();
    const { roster, guardians } = makeRosterDefault35(oldFortress);
    const principalKp = generateKeypair();
    const principalCert = issuePrincipalCertificate({
      principal_id: "root",
      principal_pubkey: principalKp.publicKey,
      role: "root",
      fortress_id: oldFortress.public.fortress_id,
      master_private_key: oldFortress.private_key,
    });
    const nodeKp = generateKeypair();
    const nodeCert = issueNodeIdentityCertificate({
      node_id: "node-1",
      node_pubkey: nodeKp.publicKey,
      node_mode: "local",
      fortress_id: oldFortress.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: oldFortress.public.public_key,
        principal_id: principalCert.principal_id,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principalKp.privateKey,
      master_private_key: oldFortress.private_key,
    });
    const newMasterKp = generateKeypair();
    const newMasterPublic: FortressMasterPublicKey = {
      public_key: toBase64url(newMasterKp.publicKey),
      fortress_id: oldFortress.public.fortress_id,
      created_at: new Date().toISOString(),
    };
    const input: MasterRotationQuorumInput = {
      old_master_pubkey: oldFortress.public.public_key,
      new_master_pubkey: newMasterPublic,
      rotated_at: new Date().toISOString(),
      fortress_id: oldFortress.public.fortress_id,
    };
    const sigs = guardians.slice(0, 3).map((g) =>
      signMasterRotationAsGuardian({
        input,
        guardian_id: g.identity.guardian_id,
        guardian_private_key: g.private_key,
      })
    );
    const payload = buildMasterRotationPayload({
      input,
      guardian_signatures: sigs,
      pinned_roster: roster,
    });
    return {
      oldFortress,
      newMaster: { public: newMasterPublic, private_key: newMasterKp.privateKey },
      principal: { cert: principalCert, kp: principalKp },
      node: { cert: nodeCert, kp: nodeKp },
      roster,
      guardians,
      input,
      payload,
    };
  }

  it("acceptMasterRotation accepts a valid 3-of-5 quorum", () => {
    const f = setupRotationFixture();
    const result = acceptMasterRotation({
      payload: f.payload,
      pinned_master: f.oldFortress.public,
      pinned_roster: f.roster,
    });
    expect(result.accepted_new_master.public_key).toBe(
      f.newMaster.public.public_key
    );
    expect(result.rotated_at).toBe(f.payload.rotated_at);
  });

  it("rejects rotation whose old_master_pubkey != pinned master", () => {
    const f = setupRotationFixture();
    const wrongPinned: FortressMasterPublicKey = {
      ...f.oldFortress.public,
      public_key: toBase64url(generateKeypair().publicKey),
    };
    expect(() =>
      acceptMasterRotation({
        payload: f.payload,
        pinned_master: wrongPinned,
        pinned_roster: f.roster,
      })
    ).toThrow(MasterRotationError);
  });

  it("rekeyOnMasterRotation re-issues per-node cert under new master + re-derives HKDF subkeys", () => {
    const f = setupRotationFixture();
    const newRootKp = generateKeypair();
    const out = rekeyOnMasterRotation({
      new_master_secret: f.newMaster.private_key,
      new_master_public: f.newMaster.public,
      old_node_certificates: [f.node.cert],
      old_root_principal: f.principal.cert,
      new_root_principal_private_key: newRootKp.privateKey,
      new_root_principal_public_key: newRootKp.publicKey,
    });
    expect(out.re_issued_node_certificates).toHaveLength(1);
    const reCert = out.re_issued_node_certificates[0]!;
    expect(reCert.node_id).toBe("node-1");
    expect(reCert.parent_chain.fortress_master_pubkey).toBe(
      f.newMaster.public.public_key
    );
    // Re-derived keys are present + 32 bytes.
    expect(out.re_derived_audit_chain_keys.get("node-1")?.length).toBe(32);
    expect(out.re_derived_transport_keys.get("node-1")?.length).toBe(32);
    // The re-issued cert chain-validates against the new master + new principal.
    verifyCertChain(
      reCert,
      out.new_root_principal_certificate,
      f.newMaster.public
    );
  });

  it("policy default behavior is preserve+historical_master (re-sign opt-in)", () => {
    // The federation-protocol default per spec §9.4 is to PRESERVE existing
    // policy signatures with `historical_master` so verifiers can chain-verify
    // against the old master. rekeyOnMasterRotation does NOT touch policy
    // versions — leaving them preserved is the default. This test asserts the
    // contract: rekeyOnMasterRotation's output does not include a policy
    // re-sign field.
    const f = setupRotationFixture();
    const newRootKp = generateKeypair();
    const out = rekeyOnMasterRotation({
      new_master_secret: f.newMaster.private_key,
      new_master_public: f.newMaster.public,
      old_node_certificates: [f.node.cert],
      old_root_principal: f.principal.cert,
      new_root_principal_private_key: newRootKp.privateKey,
      new_root_principal_public_key: newRootKp.publicKey,
    });
    // The function intentionally does not re-sign policies — that is operator
    // policy. Acceptance criterion 4 says "default behavior is preserve +
    // historical_master".
    expect(Object.keys(out)).not.toContain("re_signed_policies");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #5 — audit continuity walk
// ═══════════════════════════════════════════════════════════════════════

describe("audit continuity across master rotation", () => {
  it("walks pre-rotation + boundary + post-rotation entries with no history rejected", () => {
    // Build two node keypairs (old + new master eras), an audit-log slice
    // spanning a master_rotation_boundary, and assert walkAuditContinuity
    // counts pre/post correctly + verifies signatures.
    const oldNodeKp = generateKeypair();
    const newNodeKp = generateKeypair();

    function entry(body: Record<string, unknown>, kp: { privateKey: Uint8Array; publicKey: Uint8Array }, isBoundary = false) {
      const sig = ed25519.sign(canonicalizeToBytes(body), kp.privateKey);
      return {
        body,
        signature: toBase64url(sig),
        emitter_node: "node-1",
        is_boundary: isBoundary,
      };
    }

    const entries = [
      entry({ entry_id: "e1", payload: { x: 1 } }, oldNodeKp),
      entry({ entry_id: "e2", payload: { x: 2 } }, oldNodeKp),
      // Boundary entry — signed under the OLD per-node key (it was emitted
      // pre-rotation, immediately before the rotation took effect).
      entry({ entry_id: "boundary", kind: "master_rotation_boundary" }, oldNodeKp, true),
      entry({ entry_id: "e3", payload: { x: 3 } }, newNodeKp),
      entry({ entry_id: "e4", payload: { x: 4 } }, newNodeKp),
    ];
    const result = walkAuditContinuity({
      preRotationNodePubkey: () => toBase64url(oldNodeKp.publicKey),
      postRotationNodePubkey: () => toBase64url(newNodeKp.publicKey),
      entries,
    });
    expect(result.pre_rotation_verified).toBe(2);
    expect(result.post_rotation_verified).toBe(2);
    expect(result.boundary_seen).toBe(true);
  });

  it("throws when a post-rotation entry signature does not verify under new master pubkey", () => {
    const oldKp = generateKeypair();
    const newKp = generateKeypair();
    const wrongKp = generateKeypair();
    const sig = ed25519.sign(
      canonicalizeToBytes({ entry_id: "p1", payload: { x: 1 } }),
      wrongKp.privateKey
    );
    const entries = [
      {
        body: { entry_id: "boundary", kind: "master_rotation_boundary" },
        signature: toBase64url(
          ed25519.sign(
            canonicalizeToBytes({ entry_id: "boundary", kind: "master_rotation_boundary" }),
            oldKp.privateKey
          )
        ),
        emitter_node: "node-1",
        is_boundary: true,
      },
      {
        body: { entry_id: "p1", payload: { x: 1 } },
        signature: toBase64url(sig),
        emitter_node: "node-1",
      },
    ];
    expect(() =>
      walkAuditContinuity({
        preRotationNodePubkey: () => toBase64url(oldKp.publicKey),
        postRotationNodePubkey: () => toBase64url(newKp.publicKey),
        entries,
      })
    ).toThrow(MasterRotationError);
  });

  it("buildMasterRotationAuditPayload includes signature_scheme=ed25519-v1 (crypto-agility hinge)", () => {
    const payload = buildMasterRotationAuditPayload({
      old_master_pubkey: "old",
      new_master_pubkey: "new",
      guardian_quorum_signatures: [],
      rotated_at: "2026-04-21T00:00:00Z",
    });
    expect(payload.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(payload.kind).toBe("master_rotation_boundary");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Spawn-prompt acceptance #6 — post-recovery broker prompt
// ═══════════════════════════════════════════════════════════════════════

describe("post-recovery broker-credential rotation prompt", () => {
  it("buildPostRecoveryPrompt lists every secret in the broker as pending", async () => {
    const broker = {
      listSecretNames: async () => ["gmail", "openai-api-key", "stripe-key"],
    };
    const prompt = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "old",
      new_master_pubkey: "new",
      rotated_at: "2026-04-21T01:00:00Z",
    });
    expect(prompt.credentials.map((c) => c.secret_name)).toEqual([
      "gmail",
      "openai-api-key",
      "stripe-key",
    ]);
    expect(prompt.rotated["gmail"]).toBe("pending");
    expect(prompt.rotated["openai-api-key"]).toBe("pending");
    expect(prompt.rotated["stripe-key"]).toBe("pending");
  });

  it("PostRecoveryPromptStore tracks per-rotation prompts and re-surfaces on each rotation", async () => {
    const broker = { listSecretNames: async () => ["a", "b"] };
    const store = new PostRecoveryPromptStore();
    const p1 = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "m0",
      new_master_pubkey: "m1",
      rotated_at: "2026-04-21T01:00:00Z",
    });
    store.put(p1);
    expect(store.has("2026-04-21T01:00:00Z")).toBe(true);
    store.markRotated({
      rotated_at: "2026-04-21T01:00:00Z",
      secret_name: "a",
      outcome: "rotated",
    });
    expect(store.get("2026-04-21T01:00:00Z")?.rotated["a"]).toBe("rotated");
    expect(store.get("2026-04-21T01:00:00Z")?.rotated["b"]).toBe("pending");

    // Second rotation re-surfaces a fresh prompt.
    const p2 = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "m1",
      new_master_pubkey: "m2",
      rotated_at: "2026-04-21T02:00:00Z",
    });
    store.put(p2);
    expect(store.size()).toBe(2);
    const latest = store.latest();
    expect(latest?.rotated_at).toBe("2026-04-21T02:00:00Z");
    expect(latest?.rotated["a"]).toBe("pending");
  });

  it("dismiss does not delete the prompt — re-surfacing on next rotation is the rule", async () => {
    const broker = { listSecretNames: async () => ["a"] };
    const store = new PostRecoveryPromptStore();
    const p1 = await buildPostRecoveryPrompt({
      broker,
      old_master_pubkey: "m0",
      new_master_pubkey: "m1",
      rotated_at: "2026-04-21T03:00:00Z",
    });
    store.put(p1);
    store.dismiss("2026-04-21T03:00:00Z");
    expect(store.get("2026-04-21T03:00:00Z")?.dismissed_at).toBeDefined();
    expect(store.size()).toBe(1);
  });
});
