import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  bytesToString,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { generateKeypair } from "../../src/core/identity.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  signFederationRootRotationCertificate,
  verifyCertChain,
} from "../../src/mesh/trust-root.js";
import {
  mintFederationTrustRootRecord,
  type FederationTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import * as joinerStore from "../../src/mesh/federation-joiner-trust-root-store.js";
import {
  FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO,
  FEDERATION_JOINER_TRUST_ROOT_KEY,
  FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
  FederationJoinerTrustRootStore,
  FederationJoinerTrustRootStoreError,
  adoptFederationJoinerPlannedRoot,
  joinerContextFromRecord,
  loadFederationJoinerTrustRoot,
  persistFederationJoinerTrustRoot,
  validateJoinerRecord,
  type FederationJoinerPlannedRootAdoptReissueResult,
  type FederationJoinerTrustRootAuditEvent,
  type FederationJoinerTrustRootRecord,
} from "../../src/mesh/federation-joiner-trust-root-store.js";
import type {
  FederationRootRotationCertificate,
  FortressMasterPublicKey,
  PrincipalCertificate,
  NodeIdentityCertificate,
} from "../../src/mesh/types.js";

async function testMasterKey(storage: MemoryStorage): Promise<Uint8Array> {
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `slice3a-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return masterKey;
}

/**
 * Build a real JOINER record by issuing a node cert off a freshly minted issuer
 * fortress. The joiner holds ONLY the issued cert, its own node key, the issuing
 * principal cert (public), and the pinned master (public). No issuer material.
 */
function buildJoinerRecord(opts?: {
  home?: FederationTrustRootRecord;
  joinerNodeId?: string;
}): {
  record: FederationJoinerTrustRootRecord;
  home: FederationTrustRootRecord;
} {
  const home = opts?.home ?? mintFederationTrustRootRecord({ nodeId: "home-mac" });
  const joinerNodeId = opts?.joinerNodeId ?? "joiner-linux";
  const node = generateKeypair();
  const principalPrivate = Uint8Array.from(home.issuing_principal_private_key);
  const masterPrivate = home.master_private_key
    ? Uint8Array.from(home.master_private_key)
    : undefined;
  if (!masterPrivate) throw new Error("home record must hold master private key");
  try {
    const issued = issueNodeIdentityCertificate({
      node_id: joinerNodeId,
      node_pubkey: node.publicKey,
      node_mode: "local",
      fortress_id: home.pinned_master_pubkey.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: home.pinned_master_pubkey.public_key,
        principal_id: home.issuing_principal_cert.principal_id,
        principal_pubkey: home.issuing_principal_cert.principal_pubkey,
      },
      principal_private_key: principalPrivate,
      master_private_key: masterPrivate,
    });
    return {
      home,
      record: {
        fortress_id: home.pinned_master_pubkey.fortress_id,
        node_id: joinerNodeId,
        pinned_master_pubkey: { ...home.pinned_master_pubkey },
        issuing_principal_cert: { ...home.issuing_principal_cert },
        local_node_cert: issued,
        local_node_private_key: Uint8Array.from(node.privateKey),
      },
    };
  } finally {
    node.privateKey.fill(0);
    principalPrivate.fill(0);
    masterPrivate.fill(0);
  }
}

/**
 * Build a GENUINE planned rotation: mint K2 + a K2 issuing principal, reissue
 * THIS joiner's node cert under K2 (same node key), and sign a K1->K2 rotation
 * certificate with the home fortress's OLD master private key. Returns the cert
 * plus a reissue callback that plays the shipped reissue-endpoint response.
 */
function buildPlannedRotation(opts: {
  current: FederationJoinerTrustRootRecord;
  home: FederationTrustRootRecord;
  rotationSerial?: number;
}): {
  rotationCert: FederationRootRotationCertificate;
  newPinnedMaster: FortressMasterPublicKey;
  newIssuingPrincipalCert: PrincipalCertificate;
  reissuedNodeCert: NodeIdentityCertificate;
  reissue: () => Promise<FederationJoinerPlannedRootAdoptReissueResult>;
  newIssuingPrincipalPrivateKey: Uint8Array;
} {
  const serial = opts.rotationSerial ?? 1;
  const k2 = generateFortressMaster();
  const k2Principal = generateKeypair();
  const nodePubkey = fromBase64url(opts.current.local_node_cert.node_pubkey);
  const newPinnedMaster: FortressMasterPublicKey = {
    ...k2.public,
    fortress_id: opts.current.fortress_id,
  };
  if (!opts.home.master_private_key) {
    throw new Error("home record must hold master private key");
  }
  try {
    const newIssuingPrincipalCert = issuePrincipalCertificate({
      principal_id: opts.current.issuing_principal_cert.principal_id,
      principal_pubkey: k2Principal.publicKey,
      role: "root",
      fortress_id: opts.current.fortress_id,
      master_private_key: k2.private_key,
    });
    const reissuedNodeCert = issueNodeIdentityCertificate({
      node_id: opts.current.node_id,
      node_pubkey: nodePubkey,
      node_mode: opts.current.local_node_cert.node_mode,
      fortress_id: opts.current.fortress_id,
      capabilities: opts.current.local_node_cert.capabilities,
      parent_chain: {
        fortress_master_pubkey: newPinnedMaster.public_key,
        principal_id: newIssuingPrincipalCert.principal_id,
        principal_pubkey: newIssuingPrincipalCert.principal_pubkey,
      },
      principal_private_key: k2Principal.privateKey,
      master_private_key: k2.private_key,
    });
    const k1Private = Uint8Array.from(opts.home.master_private_key);
    let rotationCert: FederationRootRotationCertificate;
    try {
      rotationCert = signFederationRootRotationCertificate({
        fortress_id: opts.current.fortress_id,
        old_master_pubkey: opts.current.pinned_master_pubkey.public_key,
        new_master: newPinnedMaster,
        old_master_private_key: k1Private,
        rotation_serial: serial,
      });
    } finally {
      k1Private.fill(0);
    }
    return {
      rotationCert,
      newPinnedMaster,
      newIssuingPrincipalCert,
      reissuedNodeCert,
      newIssuingPrincipalPrivateKey: Uint8Array.from(k2Principal.privateKey),
      reissue: async () => ({
        ok: true,
        certificate: reissuedNodeCert,
        issuingPrincipalCert: newIssuingPrincipalCert,
        serverPinnedMaster: newPinnedMaster,
      }),
    };
  } finally {
    k2.private_key.fill(0);
    k2Principal.privateKey.fill(0);
    nodePubkey.fill(0);
  }
}

async function saveJoiner(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  record: FederationJoinerTrustRootRecord,
): Promise<void> {
  await persistFederationJoinerTrustRoot({
    storage,
    masterKey,
    pinnedMasterPubkey: record.pinned_master_pubkey,
    issuingPrincipalCert: record.issuing_principal_cert,
    localNodeCert: record.local_node_cert,
    localNodePrivateKey: record.local_node_private_key,
  });
}

function persisted(record: FederationJoinerTrustRootRecord) {
  return {
    fortress_id: record.fortress_id,
    node_id: record.node_id,
    pinned_master_pubkey: { ...record.pinned_master_pubkey },
    issuing_principal_cert: { ...record.issuing_principal_cert },
    local_node_cert: { ...record.local_node_cert },
    local_node_private_key: toBase64url(record.local_node_private_key),
  };
}

async function writeEncrypted(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  body: Record<string, unknown>,
): Promise<void> {
  const key = derivePurposeKey(masterKey, FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO);
  try {
    const encrypted = encrypt(stringToBytes(JSON.stringify(body)), key);
    await storage.write(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
      stringToBytes(JSON.stringify(encrypted)),
    );
  } finally {
    key.fill(0);
  }
}

describe("FederationJoinerTrustRootStore", () => {
  it("returns null when no joiner record is persisted (federation honestly off)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded).toBeNull();
  });

  it("has no mint path: a joiner record is only created from a real join", async () => {
    const { record } = buildJoinerRecord();
    const candidate = record as unknown as Record<string, unknown>;
    expect("master_secret" in candidate).toBe(false);
    expect("master_private_key" in candidate).toBe(false);
    expect("issuing_principal_private_key" in candidate).toBe(false);
  });

  it("persists, reloads, and only ever writes AEAD ciphertext (no plaintext key)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();

    const provisioned = await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
    });
    expect(provisioned.source).toBe("persisted");

    const raw = await storage.read(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    expect(raw).not.toBeNull();
    const rawText = bytesToString(raw!);
    expect(rawText).toContain('"alg":"aes-256-gcm"');
    expect(rawText).not.toContain(toBase64url(record.local_node_private_key));

    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.source).toBe("persisted");
    expect(loaded?.context.fortressId).toBe(record.fortress_id);
    expect(loaded?.context.nodeId).toBe(record.node_id);
  });

  it("the joiner context is a NON-ISSUER: no issuer accessors, no approver (b)", async () => {
    const { record } = buildJoinerRecord();
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const provisioned = await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
    });
    const ctx = provisioned.context as unknown as Record<string, unknown>;
    expect("getIssuingPrincipalPrivateKey" in ctx).toBe(false);
    expect("getFortressMasterSecret" in ctx).toBe(false);
    expect("getMasterPrivateKey" in ctx).toBe(false);
    expect("approver" in ctx).toBe(false);
    expect(typeof provisioned.context.getLocalNodePrivateKey).toBe("function");
    expect(provisioned.context.issuingPrincipalCert).toBeDefined();
    expect(provisioned.context.localNodeCert).toBeDefined();
  });

  it("cross-operator isolation: a record written under operator A fails closed under operator B (c)", async () => {
    const storageA = new MemoryStorage();
    const masterA = await testMasterKey(storageA);
    const { record } = buildJoinerRecord();
    await persistFederationJoinerTrustRoot({
      storage: storageA,
      masterKey: masterA,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
    });

    const masterB = await testMasterKey(new MemoryStorage());
    const audit: FederationJoinerTrustRootAuditEvent[] = [];
    const loaded = await loadFederationJoinerTrustRoot({
      storage: storageA,
      masterKey: masterB,
      audit: (event) => {
        audit.push(event);
      },
    });
    expect(loaded).toBeNull();
    expect(audit[0]).toEqual(
      expect.objectContaining({
        operation: "federation_joiner_trust_root_load",
        result: "failure",
      }),
    );
  });

  it("AEAD tamper rejection: flipping a ciphertext byte fails closed (c)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const store = new FederationJoinerTrustRootStore(storage, masterKey);
    await store.save(record);

    const raw = await storage.read(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    const payload = JSON.parse(bytesToString(raw!)) as { ct: string };
    const ctChars = payload.ct.split("");
    ctChars[0] = ctChars[0] === "A" ? "B" : "A";
    payload.ct = ctChars.join("");
    await storage.write(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
      stringToBytes(JSON.stringify(payload)),
    );

    await expect(
      new FederationJoinerTrustRootStore(storage, masterKey).load(),
    ).rejects.toBeInstanceOf(FederationJoinerTrustRootStoreError);

    const audit: FederationJoinerTrustRootAuditEvent[] = [];
    const loaded = await loadFederationJoinerTrustRoot({
      storage,
      masterKey,
      audit: (event) => audit.push(event),
    });
    expect(loaded).toBeNull();
    expect(audit[0]?.result).toBe("failure");
  });

  it("HARD-REFUSES a persisted blob that carries issuer material (a)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const body = {
      ...persisted(record),
      master_secret: toBase64url(randomBytes(32)),
    };
    await writeEncrypted(storage, masterKey, body);

    await expect(
      new FederationJoinerTrustRootStore(storage, masterKey).load(),
    ).rejects.toThrow(/must not contain issuer material/);

    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded).toBeNull();
  });

  it.each([
    "master_private_key",
    "issuing_principal_private_key",
  ])("HARD-REFUSES a blob smuggling %s (a)", async (field) => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const body = {
      ...persisted(record),
      [field]: toBase64url(randomBytes(32)),
    };
    await writeEncrypted(storage, masterKey, body);
    await expect(
      new FederationJoinerTrustRootStore(storage, masterKey).load(),
    ).rejects.toThrow(/must not contain issuer material/);
  });

  it("refuses to persist a cert that does NOT chain to the pinned master (out-of-band trust)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();

    const foreign = mintFederationTrustRootRecord({ nodeId: "foreign" });
    await expect(
      persistFederationJoinerTrustRoot({
        storage,
        masterKey,
        pinnedMasterPubkey: foreign.pinned_master_pubkey,
        issuingPrincipalCert: record.issuing_principal_cert,
        localNodeCert: record.local_node_cert,
        localNodePrivateKey: record.local_node_private_key,
      }),
    ).rejects.toThrow();
    expect(
      await storage.exists(
        FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
        FEDERATION_JOINER_TRUST_ROOT_KEY,
      ),
    ).toBe(false);
  });

  it("validateJoinerRecord rejects a node-key that does not match the cert", () => {
    const { record } = buildJoinerRecord();
    const tampered: FederationJoinerTrustRootRecord = {
      ...record,
      local_node_private_key: randomBytes(32),
    };
    expect(() => validateJoinerRecord(tampered)).toThrow(/does not match cert/);
  });

  it("validateJoinerRecord rejects a fortress_id mismatch with the pinned master", () => {
    const { record } = buildJoinerRecord();
    const tampered: FederationJoinerTrustRootRecord = {
      ...record,
      fortress_id: "some-other-fortress",
    };
    expect(() => validateJoinerRecord(tampered)).toThrow(/fortress_id/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Slice 3c-2 planned-rotation joiner auto-adopt
// ═══════════════════════════════════════════════════════════════════════

describe("adoptFederationJoinerPlannedRoot (planned auto-adopt)", () => {
  it("verifies a genuine K1-signed rotation cert and re-pins K2 (happy path)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);
    const rotation = buildPlannedRotation({ current: record, home });

    const adopted = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: rotation.rotationCert,
      expectedPinnedMaster: rotation.newPinnedMaster,
      reissue: rotation.reissue,
    });

    expect(adopted.adopted).toBe(true);
    if (!adopted.adopted) throw new Error("expected adoption");
    expect(adopted.previousPinnedMaster.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    expect(adopted.pinnedMaster.public_key).toBe(
      rotation.newPinnedMaster.public_key,
    );
    expect(adopted.rotationSerial).toBe(1);

    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      rotation.newPinnedMaster.public_key,
    );
    expect(loaded?.record.adopted_rotation_serial).toBe(1);
    // The re-pinned record chains to K2 and validates.
    verifyCertChain(
      loaded!.record.local_node_cert,
      loaded!.record.issuing_principal_cert,
      loaded!.record.pinned_master_pubkey,
    );
    expect(() => validateJoinerRecord(loaded!.record)).not.toThrow();
    // The node key is unchanged across the re-pin.
    expect(loaded?.record.local_node_cert.node_pubkey).toBe(
      record.local_node_cert.node_pubkey,
    );
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("A-full: refuses when the cert's new_master does not match the operator pin (forged K1->K2')", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);
    // A GENUINE K1-signed rotation cert to K2 (proves K1 authorized the
    // succession) -- but the operator expected a DIFFERENT new root out of band.
    // A K1 holder under an UNDETECTED compromise could forge exactly this cert;
    // the operator pin is what defeats it.
    const rotation = buildPlannedRotation({ current: record, home });
    const operatorExpected = generateFortressMaster();
    let reissueCalled = false;

    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: rotation.rotationCert,
      expectedPinnedMaster: {
        ...operatorExpected.public,
        fortress_id: record.fortress_id,
      },
      reissue: async () => {
        reissueCalled = true;
        return rotation.reissue();
      },
    });
    operatorExpected.private_key.fill(0);

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "adopted_root_mismatch_operator_pin",
      }),
    );
    // Fail closed BEFORE any network round.
    expect(reissueCalled).toBe(false);
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("LOW: an absent operator pin returns a clean held result, not a TypeError", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);
    const rotation = buildPlannedRotation({ current: record, home });
    let reissueCalled = false;

    // A direct JS caller passes no pin (the CLI makes it required, but the core
    // must fail closed-as-specified rather than throw).
    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: rotation.rotationCert,
      expectedPinnedMaster: undefined as unknown as FortressMasterPublicKey,
      reissue: async () => {
        reissueCalled = true;
        return rotation.reissue();
      },
    });

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "adopted_root_mismatch_operator_pin",
      }),
    );
    expect(reissueCalled).toBe(false);
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("rejects a rotation cert whose serial does not advance the adopted serial (replay)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    // Simulate a joiner that already adopted a planned rotation at serial 5.
    await new FederationJoinerTrustRootStore(storage, masterKey).save({
      ...record,
      adopted_rotation_serial: 5,
    });
    // A cert at serial 5 (equal, not advancing) must be rejected.
    const rotation = buildPlannedRotation({
      current: record,
      home,
      rotationSerial: 5,
    });

    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: rotation.rotationCert,
      expectedPinnedMaster: rotation.newPinnedMaster,
      reissue: rotation.reissue,
    });

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "rotation_cert_invalid",
      }),
    );
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    expect(loaded?.record.adopted_rotation_serial).toBe(5);
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("rejects a rotation cert signed by a master the joiner does not pin", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);

    // A rotation cert whose old_master is a FOREIGN fortress (not the pinned K1).
    const foreignHome = mintFederationTrustRootRecord({ nodeId: "attacker" });
    const foreign = buildJoinerRecord({ home: foreignHome, joinerNodeId: record.node_id });
    // Re-key the foreign joiner record onto our fortress_id so only the SIGNER
    // differs (not the fortress); the verify must reject on the signer mismatch.
    const foreignRotation = buildPlannedRotation({
      current: {
        ...foreign.record,
        fortress_id: record.fortress_id,
        pinned_master_pubkey: {
          ...foreignHome.pinned_master_pubkey,
          fortress_id: record.fortress_id,
        },
      },
      home: foreignHome,
    });

    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: foreignRotation.rotationCert,
      expectedPinnedMaster: foreignRotation.newPinnedMaster,
      reissue: foreignRotation.reissue,
    });

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "rotation_cert_invalid",
      }),
    );
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    foreignRotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("holds when the reissue endpoint reports the old root revoked (K1-holder-forged-cert defense)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);
    const rotation = buildPlannedRotation({ current: record, home });

    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: rotation.rotationCert,
      expectedPinnedMaster: rotation.newPinnedMaster,
      // The endpoint denies (e.g. old_root_revoked): fail closed to held.
      reissue: async () => ({ ok: false, reason: "denied" }),
    });

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "reissue_denied",
      }),
    );
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("refuses a HYBRID rotation cert LOUDLY (classical-only slice, no silent downgrade)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);
    const rotation = buildPlannedRotation({ current: record, home });
    const hybridCert = {
      ...rotation.rotationCert,
      // Presence of ANY hybrid binding must trip the classical-only refusal
      // BEFORE the classical signature is even checked.
      hybrid_rotation: { placeholder: true } as unknown,
    } as unknown as FederationRootRotationCertificate;

    let reissueCalled = false;
    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: hybridCert,
      expectedPinnedMaster: rotation.newPinnedMaster,
      reissue: async () => {
        reissueCalled = true;
        return rotation.reissue();
      },
    });

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "hybrid_rotation_unsupported",
      }),
    );
    // Refused before any network round.
    expect(reissueCalled).toBe(false);
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("refuses when the server echoes a different root than the rotation cert (constraint 4)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, home } = buildJoinerRecord();
    await saveJoiner(storage, masterKey, record);
    const rotation = buildPlannedRotation({ current: record, home });
    const attacker = generateFortressMaster();

    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: rotation.rotationCert,
      expectedPinnedMaster: rotation.newPinnedMaster,
      // Server tries to redirect to an attacker root in its response body.
      reissue: async () => ({
        ok: true,
        certificate: rotation.reissuedNodeCert,
        issuingPrincipalCert: rotation.newIssuingPrincipalCert,
        serverPinnedMaster: {
          ...attacker.public,
          fortress_id: record.fortress_id,
        },
      }),
    });
    attacker.private_key.fill(0);

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "server_root_mismatch",
      }),
    );
    rotation.newIssuingPrincipalPrivateKey.fill(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Slice 3c-2 compromise-rotation manual re-join (record-level)
// ═══════════════════════════════════════════════════════════════════════

describe("compromise manual re-join (persist records the dead K1)", () => {
  it("persists K2 with the dead K1 recorded revoked and the serial floor set", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    // The joiner record's pinned master IS the new K2 (a fresh join against K2).
    const { record } = buildJoinerRecord();
    const deadK1 = toBase64url(randomBytes(32));

    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
      revokedRootPubkeys: [deadK1],
      highestRevocationSerial: 7,
    });

    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    expect(loaded?.record.revoked_root_pubkeys?.has(deadK1)).toBe(true);
    expect(loaded?.record.highest_revocation_serial).toBe(7);
    expect(loaded?.context.revokedRootPubkeys.has(deadK1)).toBe(true);
    expect(loaded?.context.highestRevocationSerial).toBe(7);
  });

  it("a record whose pinned master is in its own revoked set fails validation", () => {
    const { record } = buildJoinerRecord();
    const selfRevoked: FederationJoinerTrustRootRecord = {
      ...record,
      revoked_root_pubkeys: new Set([record.pinned_master_pubkey.public_key]),
      highest_revocation_serial: 1,
    };
    expect(() => validateJoinerRecord(selfRevoked)).toThrow(
      /current pinned master is marked revoked/,
    );
  });

  it("refuses to persist a self-revoked master (a fortress cannot re-pin a root it revokes)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();

    await expect(
      persistFederationJoinerTrustRoot({
        storage,
        masterKey,
        pinnedMasterPubkey: record.pinned_master_pubkey,
        issuingPrincipalCert: record.issuing_principal_cert,
        localNodeCert: record.local_node_cert,
        localNodePrivateKey: record.local_node_private_key,
        revokedRootPubkeys: [record.pinned_master_pubkey.public_key],
        highestRevocationSerial: 1,
      }),
    ).rejects.toThrow(/current pinned master is marked revoked/);
    expect(
      await storage.exists(
        FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
        FEDERATION_JOINER_TRUST_ROOT_KEY,
      ),
    ).toBe(false);
  });

  it("is idempotent: re-running the re-join yields the same record and the floor never drops", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const deadK1 = toBase64url(randomBytes(32));

    for (let i = 0; i < 2; i++) {
      await persistFederationJoinerTrustRoot({
        storage,
        masterKey,
        pinnedMasterPubkey: record.pinned_master_pubkey,
        issuingPrincipalCert: record.issuing_principal_cert,
        localNodeCert: record.local_node_cert,
        localNodePrivateKey: record.local_node_private_key,
        revokedRootPubkeys: [deadK1, deadK1],
        highestRevocationSerial: 4,
      });
    }

    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    // Re-adding K1 is a no-op set add.
    expect([...(loaded?.record.revoked_root_pubkeys ?? [])]).toEqual([deadK1]);
    expect(loaded?.record.highest_revocation_serial).toBe(4);
  });

  it("MED: a lower-serial rejoin rerun is refused loudly; the monotonic floor never drops", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const deadK1 = toBase64url(randomBytes(32));
    // First re-join records the dead root at serial 5.
    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
      revokedRootPubkeys: [deadK1],
      highestRevocationSerial: 5,
    });
    // A stale rerun at serial 3 is REFUSED loudly; nothing lowers the floor.
    await expect(
      persistFederationJoinerTrustRoot({
        storage,
        masterKey,
        pinnedMasterPubkey: record.pinned_master_pubkey,
        issuingPrincipalCert: record.issuing_principal_cert,
        localNodeCert: record.local_node_cert,
        localNodePrivateKey: record.local_node_private_key,
        revokedRootPubkeys: [deadK1],
        highestRevocationSerial: 3,
      }),
    ).rejects.toThrow(/below the recorded anti-rollback floor/);
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.highest_revocation_serial).toBe(5);
    expect(loaded?.record.revoked_root_pubkeys?.has(deadK1)).toBe(true);
  });

  it("MED: successive re-joins UNION the revoked set and raise the floor (never replace)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const deadK1 = toBase64url(randomBytes(32));
    const deadKPrev = toBase64url(randomBytes(32));
    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
      revokedRootPubkeys: [deadKPrev],
      highestRevocationSerial: 2,
    });
    // A later, HIGHER-serial re-join naming a DIFFERENT dead root must keep the
    // earlier one (union, never replace) and raise the floor.
    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
      revokedRootPubkeys: [deadK1],
      highestRevocationSerial: 6,
    });
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.revoked_root_pubkeys?.has(deadKPrev)).toBe(true);
    expect(loaded?.record.revoked_root_pubkeys?.has(deadK1)).toBe(true);
    expect(loaded?.record.highest_revocation_serial).toBe(6);
  });

  it("MED-1: a persist over an UNREADABLE existing record fails closed (never resets the floor)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinerRecord();
    const deadK1 = toBase64url(randomBytes(32));
    // Seed a valid record: floor 5, {deadK1}.
    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
      revokedRootPubkeys: [deadK1],
      highestRevocationSerial: 5,
    });
    // Corrupt the at-rest ciphertext so load() THROWS (not returns null).
    const raw = await storage.read(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    const payload = JSON.parse(bytesToString(raw!)) as { ct: string };
    const ctChars = payload.ct.split("");
    ctChars[0] = ctChars[0] === "A" ? "B" : "A";
    payload.ct = ctChars.join("");
    const tampered = stringToBytes(JSON.stringify(payload));
    await storage.write(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
      tampered,
    );
    // A rejoin at a LOWER serial must FAIL CLOSED, not overwrite / lower the floor.
    await expect(
      persistFederationJoinerTrustRoot({
        storage,
        masterKey,
        pinnedMasterPubkey: record.pinned_master_pubkey,
        issuingPrincipalCert: record.issuing_principal_cert,
        localNodeCert: record.local_node_cert,
        localNodePrivateKey: record.local_node_private_key,
        revokedRootPubkeys: [toBase64url(randomBytes(32))],
        highestRevocationSerial: 2,
      }),
    ).rejects.toThrow(/unreadable joiner record|cannot be decoded/i);
    // The corrupt blob is UNCHANGED (not overwritten with a lower floor).
    const after = await storage.read(
      FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
      FEDERATION_JOINER_TRUST_ROOT_KEY,
    );
    expect(bytesToString(after!)).toBe(bytesToString(tampered));
  });

  it("MED-2: concurrent persists serialize via the cross-process lock (union + max preserved)", async () => {
    // The cross-process lock only engages on a filesystem backend (it degrades to
    // a direct run on the in-memory rig), so this uses a real FilesystemStorage.
    const dir = await mkdtemp(join(tmpdir(), "joiner-lock-"));
    try {
      const storage = new FilesystemStorage(join(dir, "state"));
      const { masterKey } = await establishMaster({
        storage,
        passphrase: `lock-${randomBytes(6).toString("hex")}`,
        firstRun: { installMode: "headless", mintRecoveryKey: false },
      });
      const { record } = buildJoinerRecord();
      const deadA = toBase64url(randomBytes(32));
      const deadB = toBase64url(randomBytes(32));
      const base = {
        storage,
        masterKey,
        pinnedMasterPubkey: record.pinned_master_pubkey,
        issuingPrincipalCert: record.issuing_principal_cert,
        localNodeCert: record.local_node_cert,
        localNodePrivateKey: record.local_node_private_key,
      };
      // Two overlapping rejoin persists, each recording a DIFFERENT dead root at
      // the SAME serial (so neither is legitimately below-floor whichever wins the
      // lock first). The lock serializes the read-modify-write so the second sees
      // the first's write and UNIONs; without it, last-writer-wins would drop one
      // revoked key entirely.
      await Promise.all([
        persistFederationJoinerTrustRoot({
          ...base,
          revokedRootPubkeys: [deadA],
          highestRevocationSerial: 5,
        }),
        persistFederationJoinerTrustRoot({
          ...base,
          revokedRootPubkeys: [deadB],
          highestRevocationSerial: 5,
        }),
      ]);
      const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
      expect(loaded?.record.revoked_root_pubkeys?.has(deadA)).toBe(true);
      expect(loaded?.record.revoked_root_pubkeys?.has(deadB)).toBe(true);
      expect(loaded?.record.highest_revocation_serial).toBe(5);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Slice 3c-2 cross-class + retirement regression
// ═══════════════════════════════════════════════════════════════════════

describe("cross-class refusal + retired custody-core is gone", () => {
  it("after a compromise re-join, an old K1->K2' rotation cert is refused (K1 revoked locally)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    // Post-re-join state: joiner pins K2 (this record's home) with the dead K1
    // recorded in its revoked-root set.
    const { record } = buildJoinerRecord();
    // Mint a real (foreign) old master to play the compromised K1, sign a
    // K1->K2' rotation cert with it, and mark K1 revoked on the joiner.
    const k1Home = mintFederationTrustRootRecord({ nodeId: "old-issuer" });
    const k1Pub = k1Home.pinned_master_pubkey.public_key;
    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
      revokedRootPubkeys: [k1Pub],
      highestRevocationSerial: 9,
    });

    // Build a rotation cert SIGNED BY the revoked K1 (old_master_pubkey = K1).
    const attackerRotation = buildPlannedRotation({
      current: {
        ...record,
        pinned_master_pubkey: {
          ...k1Home.pinned_master_pubkey,
          fortress_id: record.fortress_id,
        },
      },
      home: k1Home,
    });

    const rejected = await adoptFederationJoinerPlannedRoot({
      storage,
      masterKey,
      rotationCert: attackerRotation.rotationCert,
      expectedPinnedMaster: attackerRotation.newPinnedMaster,
      reissue: attackerRotation.reissue,
    });

    expect(rejected).toEqual(
      expect.objectContaining({
        adopted: false,
        state: "held_old_trust",
        reason: "rotation_signer_revoked",
      }),
    );
    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded?.record.pinned_master_pubkey.public_key).toBe(
      record.pinned_master_pubkey.public_key,
    );
    attackerRotation.newIssuingPrincipalPrivateKey.fill(0);
  });

  it("the retired compromise auto-adopt custody-core is gone / unexported", () => {
    const surface = joinerStore as unknown as Record<string, unknown>;
    // The dangerous auto-adoption functions must no longer exist.
    expect(surface.adoptFederationJoinerCompromiseRoot).toBeUndefined();
    expect(
      surface.signFederationJoinerCompromiseRootAdoptionAttestation,
    ).toBeUndefined();
    // The wire/at-rest version string must be gone (it never rode any surface).
    expect(
      surface.FEDERATION_JOINER_COMPROMISE_ROOT_ADOPTION_EVENT_VERSION,
    ).toBeUndefined();
    // The kept additive fields remain part of the surface.
    expect(typeof surface.adoptFederationJoinerPlannedRoot).toBe("function");
    expect(typeof surface.persistFederationJoinerTrustRoot).toBe("function");
  });
});

interface TestDaemon {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  stop(): Promise<void>;
}

const running: TestDaemon[] = [];

afterEach(async () => {
  while (running.length > 0) {
    await running.pop()!.stop();
  }
});

async function startJoinerDaemon(
  context: ReturnType<typeof joinerContextFromRecord>,
): Promise<TestDaemon> {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, randomBytes(32));
  const port = 32000 + Math.floor(Math.random() * 20000);
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: `slice3a-${randomBytes(6).toString("hex")}`,
    auto_open: false,
  });
  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });
  dashboard.setFederationContext(context);
  await dashboard.start();
  const daemon = {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    stop: () => dashboard.stop(),
  };
  running.push(daemon);
  return daemon;
}

describe("joiner boot-wire (non-issuer context provisions /v1/federation reads)", () => {
  it("a persisted joiner record provisions a dashboard with a NON-ISSUER context", async () => {
    const { record } = buildJoinerRecord();
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await persistFederationJoinerTrustRoot({
      storage,
      masterKey,
      pinnedMasterPubkey: record.pinned_master_pubkey,
      issuingPrincipalCert: record.issuing_principal_cert,
      localNodeCert: record.local_node_cert,
      localNodePrivateKey: record.local_node_private_key,
    });

    const loaded = await loadFederationJoinerTrustRoot({ storage, masterKey });
    expect(loaded).not.toBeNull();

    const daemon = await startJoinerDaemon(loaded!.context);
    daemon.dashboard.setAutoAuthLocalhost(true);
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    const initRes = await fetch(`${daemon.baseUrl}/v1/session/init`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ client_pubkey: toBase64url(publicKey) }),
    });
    expect(initRes.status).toBe(200);
    const init = (await initRes.json()) as {
      challenge: string;
      challenge_id: string;
      attestation_ref: string;
    };
    const message = buildChallengeMessage(
      publicKey,
      fromBase64url(init.challenge),
      init.attestation_ref,
    );
    const completeRes = await fetch(`${daemon.baseUrl}/v1/session/complete`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: init.challenge_id,
        client_signature: toBase64url(ed25519.sign(message, privateKey)),
      }),
    });
    expect(completeRes.status).toBe(200);
    const token = ((await completeRes.json()) as { session_token: string })
      .session_token;

    const statusRes = await fetch(`${daemon.baseUrl}/v1/federation/status`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(statusRes.status).toBe(200);
    const status = (await statusRes.json()) as Record<string, unknown>;
    expect(status).toEqual(
      expect.objectContaining({
        provisioned: true,
        enabled: false,
        fortress_id: record.fortress_id,
        node_id: record.node_id,
      }),
    );
  });
});
