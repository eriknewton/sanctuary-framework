import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { establishMaster } from "../../src/core/master-custody.js";
import {
  bytesToString,
  stringToBytes,
  toBase64url,
} from "../../src/core/encoding.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { encrypt } from "../../src/core/encryption.js";
import { generateKeypair } from "../../src/core/identity.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { issueNodeIdentityCertificate } from "../../src/mesh/trust-root.js";
import {
  mintFederationTrustRootRecord,
  type FederationTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION,
  OPERATOR_CLOUD_SCOPE_VERSION,
  wrapNodePrivateKeyForCloud,
  type OperatorCloudJoinedNodeRecord,
} from "../../src/mesh/operator-cloud-provision.js";
import {
  NODE_TRUST_BOUNDARY_VERSION,
  OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
} from "../../src/mesh/node-posture.js";
import {
  OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO,
  OPERATOR_CLOUD_JOINED_NODE_KEY,
  OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
  OperatorCloudJoinedNodeStore,
  OperatorCloudJoinedNodeStoreError,
  operatorCloudContextFromRecord,
  persistOperatorCloudJoinedNode,
  provisionOrLoadOperatorCloudJoinedNode,
  validateJoinedNodeRecord,
  type OperatorCloudJoinedNodeAuditEvent,
} from "../../src/mesh/operator-cloud-joined-node-store.js";

/**
 * Keychain-free master seed (the approved unit-test seam). `establishMaster`
 * with the headless install mode + no recovery key never touches the macOS
 * login keychain and never boots a server. (HARD CARVE-OUT: these tests never
 * spawn a real Sanctuary server, never call the default-HOME keychain path.)
 */
async function testMasterKey(storage: MemoryStorage): Promise<Uint8Array> {
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `oc-slice3-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return masterKey;
}

/**
 * Build a real operator_cloud JOINED-NODE record: mint an issuer fortress,
 * issue an operator_cloud node cert chaining to its master, and wrap the node
 * private key under a per-node unseal key. The record holds ONLY the public
 * chain + the WRAPPED node key + scope/trust-boundary manifests. No issuer
 * material. Returns the raw node private key + unseal key so a test can assert
 * neither appears in cleartext at rest.
 */
function buildJoinedNodeRecord(opts?: {
  home?: FederationTrustRootRecord;
  nodeId?: string;
}): {
  record: OperatorCloudJoinedNodeRecord;
  home: FederationTrustRootRecord;
  nodePrivateKey: Uint8Array;
  cloudNodeUnsealKey: Uint8Array;
} {
  const home = opts?.home ?? mintFederationTrustRootRecord({ nodeId: "home-mac" });
  const nodeId = opts?.nodeId ?? "cloud-vm-1";
  const node = generateKeypair();
  const principalPrivate = Uint8Array.from(home.issuing_principal_private_key);
  const masterPrivate = home.master_private_key
    ? Uint8Array.from(home.master_private_key)
    : undefined;
  if (!masterPrivate) throw new Error("home record must hold master private key");
  const cloudNodeUnsealKey = randomBytes(32);
  try {
    const issued = issueNodeIdentityCertificate({
      node_id: nodeId,
      node_pubkey: node.publicKey,
      node_mode: "operator_cloud",
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
    const wrapped = wrapNodePrivateKeyForCloud({
      nodePrivateKey: node.privateKey,
      cloudNodeUnsealKey,
    });
    const record: OperatorCloudJoinedNodeRecord = {
      record_version: OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION,
      fortress_id: home.pinned_master_pubkey.fortress_id,
      node_id: nodeId,
      node_mode: "operator_cloud",
      pinned_master_pubkey: { ...home.pinned_master_pubkey },
      issuing_principal_cert: { ...home.issuing_principal_cert },
      local_node_cert: issued,
      wrapped_local_node_private_key: wrapped,
      scope_manifest: {
        scope_version: OPERATOR_CLOUD_SCOPE_VERSION,
        node_id: nodeId,
        agent_ids: ["agent-a"],
        namespaces: ["ns-a"],
        state_grant_ids: [],
      },
      trust_boundary: {
        version: NODE_TRUST_BOUNDARY_VERSION,
        posture: "provider_in_trust_boundary_not_tee",
        label: OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
        provider_in_trust_boundary: true,
        tee_attested: false,
      },
      disclosure_acknowledged_at: new Date().toISOString(),
    };
    return {
      record,
      home,
      nodePrivateKey: Uint8Array.from(node.privateKey),
      cloudNodeUnsealKey: Uint8Array.from(cloudNodeUnsealKey),
    };
  } finally {
    node.privateKey.fill(0);
    principalPrivate.fill(0);
    masterPrivate.fill(0);
    cloudNodeUnsealKey.fill(0);
  }
}

async function writeEncryptedBody(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  body: Record<string, unknown>,
): Promise<void> {
  const key = derivePurposeKey(masterKey, OPERATOR_CLOUD_JOINED_NODE_HKDF_INFO);
  try {
    const encrypted = encrypt(stringToBytes(JSON.stringify(body)), key);
    await storage.write(
      OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
      OPERATOR_CLOUD_JOINED_NODE_KEY,
      stringToBytes(JSON.stringify(encrypted)),
    );
  } finally {
    key.fill(0);
  }
}

describe("OperatorCloudJoinedNodeStore", () => {
  it("returns null when no joined-node record is persisted (federation honestly off)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const loaded = await provisionOrLoadOperatorCloudJoinedNode({
      storage,
      masterKey,
    });
    expect(loaded).toBeNull();
  });

  // Merge-bar test 1: round-trip persistence + no plaintext secret at rest.
  it("round-trips a record and only ever writes AEAD ciphertext (no plaintext node key or unseal key)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record, nodePrivateKey, cloudNodeUnsealKey } =
      buildJoinedNodeRecord();

    const provisioned = await persistOperatorCloudJoinedNode({
      storage,
      masterKey,
      record,
    });
    expect(provisioned.source).toBe("persisted");

    const raw = await storage.read(
      OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
      OPERATOR_CLOUD_JOINED_NODE_KEY,
    );
    expect(raw).not.toBeNull();
    const rawText = bytesToString(raw!);
    expect(rawText).toContain('"alg":"aes-256-gcm"');
    // Neither the raw node private key nor the per-node unseal key appears in
    // cleartext at rest.
    expect(rawText).not.toContain(toBase64url(nodePrivateKey));
    expect(rawText).not.toContain(toBase64url(cloudNodeUnsealKey));

    const loaded = await provisionOrLoadOperatorCloudJoinedNode({
      storage,
      masterKey,
    });
    expect(loaded?.source).toBe("persisted");
    expect(loaded?.context.fortressId).toBe(record.fortress_id);
    expect(loaded?.context.nodeId).toBe(record.node_id);
    expect(loaded?.context.nodeMode).toBe("operator_cloud");
    // The Option A trust-boundary disclosure survives the round trip.
    expect(loaded?.record.trust_boundary.provider_in_trust_boundary).toBe(true);
    expect(loaded?.record.trust_boundary.tee_attested).toBe(false);
  });

  // Merge-bar test 2: fail-closed on a present-but-corrupt record; distinct from
  // "no record" (raw === null -> null).
  it("fails closed on a corrupt record (load THROWS), distinct from no record (null)", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinedNodeRecord();
    const store = new OperatorCloudJoinedNodeStore(storage, masterKey);
    await store.save(record);

    const raw = await storage.read(
      OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
      OPERATOR_CLOUD_JOINED_NODE_KEY,
    );
    const payload = JSON.parse(bytesToString(raw!)) as { ct: string };
    const ctChars = payload.ct.split("");
    ctChars[0] = ctChars[0] === "A" ? "B" : "A";
    payload.ct = ctChars.join("");
    await storage.write(
      OPERATOR_CLOUD_JOINED_NODE_NAMESPACE,
      OPERATOR_CLOUD_JOINED_NODE_KEY,
      stringToBytes(JSON.stringify(payload)),
    );

    // present-but-undecryptable -> THROW (deny), never empty-and-accept.
    await expect(
      new OperatorCloudJoinedNodeStore(storage, masterKey).load(),
    ).rejects.toBeInstanceOf(OperatorCloudJoinedNodeStoreError);

    // The provision-or-load wrapper catches the throw and fails closed to null
    // (audited), but a corrupt record is NEVER silently treated as "no record":
    // the underlying store.load() throws.
    const audit: OperatorCloudJoinedNodeAuditEvent[] = [];
    const loaded = await provisionOrLoadOperatorCloudJoinedNode({
      storage,
      masterKey,
      audit: (event) => audit.push(event),
    });
    expect(loaded).toBeNull();
    expect(audit[0]?.result).toBe("failure");
  });

  // Merge-bar test 3: boot builds the operator_cloud context (non-issuer).
  it("builds a structurally-valid NON-ISSUER operator_cloud context (no issuer authority)", async () => {
    const { record } = buildJoinedNodeRecord();
    const context = operatorCloudContextFromRecord(record);
    const candidate = context as unknown as Record<string, unknown>;
    expect(context.nodeMode).toBe("operator_cloud");
    expect("getIssuingPrincipalPrivateKey" in candidate).toBe(false);
    expect("getFortressMasterSecret" in candidate).toBe(false);
    expect("getMasterPrivateKey" in candidate).toBe(false);
    expect("approver" in candidate).toBe(false);
    // The node private key is held WRAPPED, so the context exposes no raw node
    // private key accessor.
    expect("getLocalNodePrivateKey" in candidate).toBe(false);
    // It DOES carry the public chain for /sync/peer cert presentation.
    expect(context.issuingPrincipalCert).toBeDefined();
    expect(context.localNodeCert).toBeDefined();
    expect(context.localNodeCert.node_mode).toBe("operator_cloud");
  });

  it("the loaded context passes the non-issuer authority guard (no issuer escalation)", async () => {
    const { record } = buildJoinedNodeRecord();
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await persistOperatorCloudJoinedNode({ storage, masterKey, record });
    const loaded = await provisionOrLoadOperatorCloudJoinedNode({
      storage,
      masterKey,
    });
    expect(loaded).not.toBeNull();
    // Dynamically import the guard to avoid a wide import surface; it must NOT
    // throw for a clean operator_cloud non-issuer context.
    const { assertNonIssuerContextHasNoIssuerAuthority } = await import(
      "../../src/v1/federation.js"
    );
    expect(() =>
      assertNonIssuerContextHasNoIssuerAuthority(
        loaded!.context as never,
      ),
    ).not.toThrow();
  });

  it("cross-operator isolation: a record written under operator A fails closed under operator B", async () => {
    const storageA = new MemoryStorage();
    const masterA = await testMasterKey(storageA);
    const { record } = buildJoinedNodeRecord();
    await persistOperatorCloudJoinedNode({
      storage: storageA,
      masterKey: masterA,
      record,
    });

    const masterB = await testMasterKey(new MemoryStorage());
    const audit: OperatorCloudJoinedNodeAuditEvent[] = [];
    const loaded = await provisionOrLoadOperatorCloudJoinedNode({
      storage: storageA,
      masterKey: masterB,
      audit: (event) => audit.push(event),
    });
    expect(loaded).toBeNull();
    expect(audit[0]).toEqual(
      expect.objectContaining({
        operation: "operator_cloud_joined_node_load",
        result: "failure",
      }),
    );
  });

  it("HARD-REFUSES a persisted blob that carries issuer material", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const { record } = buildJoinedNodeRecord();
    const body = {
      ...record,
      pinned_master_pubkey: { ...record.pinned_master_pubkey },
      wrapped_local_node_private_key: { ...record.wrapped_local_node_private_key },
      master_secret: toBase64url(randomBytes(32)),
    };
    await writeEncryptedBody(storage, masterKey, body);

    await expect(
      new OperatorCloudJoinedNodeStore(storage, masterKey).load(),
    ).rejects.toThrow(/must not contain issuer material/);

    const loaded = await provisionOrLoadOperatorCloudJoinedNode({
      storage,
      masterKey,
    });
    expect(loaded).toBeNull();
  });

  it.each(["master_private_key", "issuing_principal_private_key"])(
    "HARD-REFUSES a blob smuggling %s",
    async (field) => {
      const storage = new MemoryStorage();
      const masterKey = await testMasterKey(storage);
      const { record } = buildJoinedNodeRecord();
      const body = {
        ...record,
        [field]: toBase64url(randomBytes(32)),
      };
      await writeEncryptedBody(storage, masterKey, body);
      await expect(
        new OperatorCloudJoinedNodeStore(storage, masterKey).load(),
      ).rejects.toThrow(/must not contain issuer material/);
    },
  );

  it("refuses a record whose node cert does NOT chain to the pinned master (out-of-band trust)", () => {
    const { record } = buildJoinedNodeRecord();
    const foreign = mintFederationTrustRootRecord({ nodeId: "foreign" });
    const tampered: OperatorCloudJoinedNodeRecord = {
      ...record,
      fortress_id: foreign.pinned_master_pubkey.fortress_id,
      pinned_master_pubkey: { ...foreign.pinned_master_pubkey },
    };
    expect(() => validateJoinedNodeRecord(tampered)).toThrow();
  });

  it("refuses a record whose node cert is not operator_cloud", () => {
    const home = mintFederationTrustRootRecord({ nodeId: "home-mac" });
    const node = generateKeypair();
    const principalPrivate = Uint8Array.from(home.issuing_principal_private_key);
    const masterPrivate = Uint8Array.from(home.master_private_key!);
    const unsealKey = randomBytes(32);
    try {
      // Issue a LOCAL-mode cert, then smuggle it into a record claiming
      // operator_cloud node_mode.
      const localCert = issueNodeIdentityCertificate({
        node_id: "cloud-vm-1",
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
      const record: OperatorCloudJoinedNodeRecord = {
        record_version: OPERATOR_CLOUD_JOINED_NODE_RECORD_VERSION,
        fortress_id: home.pinned_master_pubkey.fortress_id,
        node_id: "cloud-vm-1",
        node_mode: "operator_cloud",
        pinned_master_pubkey: { ...home.pinned_master_pubkey },
        issuing_principal_cert: { ...home.issuing_principal_cert },
        local_node_cert: localCert,
        wrapped_local_node_private_key: wrapNodePrivateKeyForCloud({
          nodePrivateKey: node.privateKey,
          cloudNodeUnsealKey: unsealKey,
        }),
        scope_manifest: {
          scope_version: OPERATOR_CLOUD_SCOPE_VERSION,
          node_id: "cloud-vm-1",
          agent_ids: [],
          namespaces: [],
          state_grant_ids: [],
        },
        trust_boundary: {
          version: NODE_TRUST_BOUNDARY_VERSION,
          posture: "provider_in_trust_boundary_not_tee",
          label: OPERATOR_CLOUD_TRUST_BOUNDARY_LABEL,
          provider_in_trust_boundary: true,
          tee_attested: false,
        },
        disclosure_acknowledged_at: new Date().toISOString(),
      };
      expect(() => validateJoinedNodeRecord(record)).toThrow(
        /node_mode must be operator_cloud/,
      );
    } finally {
      node.privateKey.fill(0);
      principalPrivate.fill(0);
      masterPrivate.fill(0);
      unsealKey.fill(0);
    }
  });
});
