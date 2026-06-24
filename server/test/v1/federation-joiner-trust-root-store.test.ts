import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
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
import { issueNodeIdentityCertificate } from "../../src/mesh/trust-root.js";
import {
  mintFederationTrustRootRecord,
  type FederationTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import {
  FEDERATION_JOINER_TRUST_ROOT_HKDF_INFO,
  FEDERATION_JOINER_TRUST_ROOT_KEY,
  FEDERATION_JOINER_TRUST_ROOT_NAMESPACE,
  FederationJoinerTrustRootStore,
  FederationJoinerTrustRootStoreError,
  loadFederationJoinerTrustRoot,
  persistFederationJoinerTrustRoot,
  validateJoinerRecord,
  type FederationJoinerTrustRootAuditEvent,
  type FederationJoinerTrustRootRecord,
} from "../../src/mesh/federation-joiner-trust-root-store.js";

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
    // The store exposes no mint export at all; loadFederationJoinerTrustRoot
    // never minted material is the structural guarantee. (a) confirms the
    // record holds NO issuer/master secret material.
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
    // The node private key never appears in cleartext at rest.
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
    // It DOES expose the public chain + its own node key for /sync/peer.
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

    // Operator B's master derives a different purpose key -> GCM auth fails.
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
    // Flip a character in the ciphertext body.
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
    // Smuggle a master_secret into the at-rest blob.
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

    // A different fortress's master is NOT the trust anchor this cert chains to.
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
    // Nothing was written on the refused persist.
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
  // The generalized non-issuer guard inside setFederationContext must ACCEPT a
  // local joiner context (no issuer accessors, no approver). If it carried any
  // issuer material this would throw.
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

    // This is the joiner half of the Slice 1 boot wiring: load-only.
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
        // Not enabled until the federation enable verb runs (Slice 3b).
        enabled: false,
        fortress_id: record.fortress_id,
        node_id: record.node_id,
      }),
    );
  });
});
