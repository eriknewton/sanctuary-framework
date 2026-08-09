import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
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
import {
  FEDERATION_TRUST_ROOT_HKDF_INFO,
  FEDERATION_TRUST_ROOT_KEY,
  FEDERATION_TRUST_ROOT_NAMESPACE,
  FederationTrustRootStore,
  mintFederationTrustRootRecord,
  provisionOrLoadFederationTrustRoot,
  type FederationTrustRootAuditEvent,
  type FederationTrustRootRecord,
} from "../../src/mesh/federation-trust-root-store.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { issueNodeIdentityCertificate } from "../../src/mesh/trust-root.js";
import {
  addOperatorAuthorizationFields,
  signOperatorPayload,
} from "../../src/v1/operator-signed.js";
import { FederationSyncStateStore } from "../../src/v1/federation-sync-state-store.js";
import { buildChallengeMessage } from "../../src/v1/ceremony.js";
import {
  pushSyncToPeer,
  recognizedPortableAgents,
  type PeerSyncIdentity,
} from "../../src/v1/federation-client.js";
import type { FederationContext, FederationEvent } from "../../src/v1/federation.js";
import { OPERATOR, stubIdentityManager } from "./rig.js";

interface TestDaemon {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  auditLog: AuditLog;
  stop(): Promise<void>;
}

const running: TestDaemon[] = [];

afterEach(async () => {
  while (running.length > 0) {
    await running.pop()!.stop();
  }
});

describe("FederationTrustRootStore", () => {
  it("does not mint without the explicit mint flag", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    const loaded = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
    });

    expect(loaded).toBeNull();
    expect(
      await storage.exists(FEDERATION_TRUST_ROOT_NAMESPACE, FEDERATION_TRUST_ROOT_KEY),
    ).toBe(false);
  });

  it("mints, persists, and reloads only AEAD ciphertext", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);

    const minted = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "mac-1",
    });
    expect(minted?.source).toBe("minted");
    expect(minted?.record.master_secret.length).toBe(32);
    expect(minted?.record.master_secret).not.toEqual(minted?.record.master_private_key);

    const raw = await storage.read(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
    );
    expect(raw).not.toBeNull();
    const rawText = bytesToString(raw!);
    expect(rawText).toContain('"alg":"aes-256-gcm"');
    expect(rawText).not.toContain(toBase64url(minted!.record.master_secret));
    expect(rawText).not.toContain(toBase64url(minted!.record.master_private_key!));
    expect(rawText).not.toContain(
      toBase64url(minted!.record.issuing_principal_private_key),
    );
    expect(rawText).not.toContain(toBase64url(minted!.record.local_node_private_key));

    const loaded = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
    });
    expect(loaded?.source).toBe("persisted");
    expect(loaded?.context.fortressId).toBe(
      loaded?.record.pinned_master_pubkey.fortress_id,
    );

    const firstSecret = loaded!.context.getFortressMasterSecret();
    firstSecret.fill(0);
    expect([...loaded!.context.getFortressMasterSecret()]).not.toEqual(
      new Array(32).fill(0),
    );
  });

  it("fails closed and audits when the ciphertext cannot decrypt", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
      stringToBytes(
        JSON.stringify({
          v: 1,
          alg: "aes-256-gcm",
          iv: "not-valid",
          ct: "not-valid",
          ts: new Date().toISOString(),
        }),
      ),
    );
    const auditEvents: FederationTrustRootAuditEvent[] = [];

    const loaded = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      audit: (event) => {
        auditEvents.push(event);
      },
    });

    expect(loaded).toBeNull();
    expect(auditEvents).toEqual([
      expect.objectContaining({
        operation: "federation_trust_root_load",
        result: "failure",
      }),
    ]);
  });

  it("rejects a record whose fortress_id disagrees with the pinned master", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    const record = mintFederationTrustRootRecord({ nodeId: "mac-1" });
    const bad = persistedRecord(record);
    bad.fortress_id = "foreign-fortress";
    await writeEncryptedPersistedRecord(storage, masterKey, bad);
    const auditEvents: FederationTrustRootAuditEvent[] = [];

    const loaded = await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      audit: (event) => {
        auditEvents.push(event);
      },
    });

    expect(loaded).toBeNull();
    expect(auditEvents[0]?.result).toBe("failure");
  });

  it("boots a real dashboard as provisioned and enables through OPERATOR_SIGNED", async () => {
    const storage = new MemoryStorage();
    const masterKey = await testMasterKey(storage);
    await provisionOrLoadFederationTrustRoot({
      storage,
      masterKey,
      mint: true,
      nodeId: "mac-1",
    });
    const loaded = await provisionOrLoadFederationTrustRoot({ storage, masterKey });
    expect(loaded).not.toBeNull();

    const daemon = await startDaemon(loaded!.context, { operatorIdentity: true });
    const token = await openLoopbackSession(daemon);
    const status = await getFederationStatus(daemon, token);
    expect(status).toEqual(
      expect.objectContaining({
        provisioned: true,
        enabled: false,
        fortress_id: loaded!.record.pinned_master_pubkey.fortress_id,
        node_id: "mac-1",
      }),
    );

    const enablePayload = addOperatorAuthorizationFields({
      idempotency_key: "slice1-enable",
    });
    const enable = await fetch(`${daemon.baseUrl}/v1/federation/enable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        ...enablePayload,
        operator_signature: toBase64url(
          signOperatorPayload(
            "/v1/federation/enable",
            enablePayload,
            OPERATOR.privateKey,
          ),
        ),
      }),
    });
    expect(enable.status).toBe(200);
    expect(await enable.json()).toEqual({ enabled: true });
    expect(await getFederationStatus(daemon, token)).toEqual(
      expect.objectContaining({ provisioned: true, enabled: true }),
    );
  });

  it("syncs over /sync/peer with the home context loaded from persisted state", async () => {
    const homeStorage = new MemoryStorage();
    const homeMasterKey = await testMasterKey(homeStorage);
    const home = await provisionOrLoadFederationTrustRoot({
      storage: homeStorage,
      masterKey: homeMasterKey,
      mint: true,
      nodeId: "mac-1",
    });
    expect(home).not.toBeNull();

    const peerStorage = new MemoryStorage();
    const peerMasterKey = await testMasterKey(peerStorage);
    const peerRecord = issuePeerRecord(home!.record, "linux-1");
    expect(peerRecord.master_private_key).toBeUndefined();
    await new FederationTrustRootStore(peerStorage, peerMasterKey).save(peerRecord);
    const peer = await provisionOrLoadFederationTrustRoot({
      storage: peerStorage,
      masterKey: peerMasterKey,
    });
    expect(peer?.context.getMasterPrivateKey?.()).toBeUndefined();

    const mac = await startDaemon(home!.context);
    const linux = await startDaemon(peer!.context);
    setFederationEnabled(mac.dashboard);
    setFederationEnabled(linux.dashboard);

    mac.dashboard.recordLocalAgentIdentity("agent-persisted-1", undefined);
    const linuxSession = await openLoopbackSession(linux);
    const macEvents = listFederationEvents(mac.dashboard);
    const result = await pushSyncToPeer(peerIdentity(home!.record), {
      peerUrl: linux.baseUrl,
      recipientNodeId: "linux-1",
      sessionToken: linuxSession,
      events: macEvents,
      syncHighWater: 1,
      isNodeRevoked: () => false,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.acceptedByPeer).toContain("mac-1:1");
    const linuxEvents = listFederationEvents(linux.dashboard);
    const recognized = recognizedPortableAgents(linuxEvents);
    expect(recognized.has("agent-persisted-1")).toBe(true);
  });
});

async function testMasterKey(storage: MemoryStorage): Promise<Uint8Array> {
  const { masterKey } = await establishMaster({
    storage,
    passphrase: `slice1-${randomBytes(6).toString("hex")}`,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
  });
  return masterKey;
}

async function startDaemon(
  context: FederationContext,
  opts?: { operatorIdentity?: boolean },
): Promise<TestDaemon> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const port = 32000 + Math.floor(Math.random() * 20000);
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: `slice1-${randomBytes(6).toString("hex")}`,
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
    ...(opts?.operatorIdentity
      ? { identityManager: stubIdentityManager(OPERATOR.publicKey) }
      : {}),
  });
  dashboard.setFederationContext(context);
  await dashboard.setFederationSyncStateStore(
    new FederationSyncStateStore({ storage, masterKey }),
  );
  await dashboard.start();
  const daemon = {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    auditLog,
    stop: () => dashboard.stop(),
  };
  running.push(daemon);
  return daemon;
}

async function openLoopbackSession(daemon: TestDaemon): Promise<string> {
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
  return ((await completeRes.json()) as { session_token: string }).session_token;
}

async function getFederationStatus(
  daemon: TestDaemon,
  token: string,
): Promise<Record<string, unknown>> {
  const res = await fetch(`${daemon.baseUrl}/v1/federation/status`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  expect(res.status).toBe(200);
  return (await res.json()) as Record<string, unknown>;
}

function setFederationEnabled(dashboard: DashboardApprovalChannel): void {
  (dashboard as unknown as { _federationEnabled: boolean })._federationEnabled = true;
}

function listFederationEvents(dashboard: DashboardApprovalChannel): FederationEvent[] {
  return (dashboard as unknown as {
    listFederationEvents(): FederationEvent[];
  }).listFederationEvents();
}

function issuePeerRecord(
  home: FederationTrustRootRecord,
  nodeId: string,
): FederationTrustRootRecord {
  const node = generateKeypair();
  const principalPrivate = Uint8Array.from(home.issuing_principal_private_key);
  const masterPrivate = home.master_private_key
    ? Uint8Array.from(home.master_private_key)
    : undefined;
  if (!masterPrivate) throw new Error("home record must hold master private key");
  try {
    const localNodeCert = issueNodeIdentityCertificate({
      node_id: nodeId,
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
      fortress_id: home.pinned_master_pubkey.fortress_id,
      node_id: nodeId,
      pinned_master_pubkey: { ...home.pinned_master_pubkey },
      master_secret: Uint8Array.from(home.master_secret),
      issuing_principal_cert: { ...home.issuing_principal_cert },
      issuing_principal_private_key: Uint8Array.from(
        home.issuing_principal_private_key,
      ),
      local_node_cert: localNodeCert,
      local_node_private_key: Uint8Array.from(node.privateKey),
    };
  } finally {
    node.privateKey.fill(0);
    principalPrivate.fill(0);
    masterPrivate.fill(0);
  }
}

function peerIdentity(record: FederationTrustRootRecord): PeerSyncIdentity {
  return {
    fortressId: record.pinned_master_pubkey.fortress_id,
    nodeId: record.node_id,
    nodeCert: { ...record.local_node_cert },
    issuingPrincipalCert: { ...record.issuing_principal_cert },
    nodePrivateKey: Uint8Array.from(record.local_node_private_key),
    pinnedMaster: { ...record.pinned_master_pubkey },
  };
}

function persistedRecord(record: FederationTrustRootRecord) {
  return {
    fortress_id: record.fortress_id,
    node_id: record.node_id,
    pinned_master_pubkey: { ...record.pinned_master_pubkey },
    master_secret: toBase64url(record.master_secret),
    ...(record.master_private_key
      ? { master_private_key: toBase64url(record.master_private_key) }
      : {}),
    issuing_principal_cert: { ...record.issuing_principal_cert },
    issuing_principal_private_key: toBase64url(
      record.issuing_principal_private_key,
    ),
    local_node_cert: { ...record.local_node_cert },
    local_node_private_key: toBase64url(record.local_node_private_key),
  };
}

async function writeEncryptedPersistedRecord(
  storage: MemoryStorage,
  masterKey: Uint8Array,
  record: ReturnType<typeof persistedRecord>,
): Promise<void> {
  const key = derivePurposeKey(masterKey, FEDERATION_TRUST_ROOT_HKDF_INFO);
  try {
    const encrypted = encrypt(stringToBytes(JSON.stringify(record)), key);
    await storage.write(
      FEDERATION_TRUST_ROOT_NAMESPACE,
      FEDERATION_TRUST_ROOT_KEY,
      stringToBytes(JSON.stringify(encrypted)),
    );
  } finally {
    key.fill(0);
  }
}
