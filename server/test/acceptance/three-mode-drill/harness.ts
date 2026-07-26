/**
 * Three-Mode Acceptance Drill — shared harness.
 *
 * Boots a fortress with three nodes simultaneously on one host, each in a
 * different v0.1 node_mode:
 *   - Node A: `local` mode, canonical audit node, disk-backed stores
 *   - Node B: `operator_cloud` mode, simulates NAT via static-peer config
 *     only (no mDNS, no AutoNAT per Follow-up #2 scope)
 *   - Node C: `sovereign_tee` mode, TEE attestation in mock (always-pass) mode
 *
 * Every node runs the real `Libp2pMeshTransport` (PR #34) over loopback TCP
 * with real Noise handshake + real gossipsub; per-node Ed25519 keys are
 * master-key-wrapped onto real `FileNodeKeyStore` + monotonic counters persist via
 * real `FileCounterStore`. The only mock in the harness is the TEE attestation
 * hash on node C's certificate (real TEE hardware integration is Phase 2 per
 * the MVP scope lock).
 *
 * After `bootThreeModeDrill` returns, the mesh is in steady-state:
 *   - All three transports are peered at the libp2p layer
 *   - Gossipsub has grafted across the three
 *   - Each node's `NodeRoster` contains all three nodes as `active`
 *   - Each node has verified the other two certs' chain back to the
 *     fortress-master
 *
 * The harness runs one join-style round of heartbeats at the end so peer
 * presence settles from `joining` to `active` the same way it does in a
 * production mesh. This matches the steady state §12.1 asserts on.
 *
 * Scope:
 *   - Sanctuary ↛ Concordia: no Concordia imports.
 *   - v0.1 extension discipline: no reserved extension envelope keys emitted;
 *     no reserved capability bits (3-7) set on any drill cert.
 *   - `signature_scheme: "ed25519-v1"` is preserved through every signed
 *     emission — the harness never strips or substitutes it.
 */

import { promises as fs } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { toBase64url } from "../../../src/core/encoding.js";
import { generateKeypair } from "../../../src/core/identity.js";
import { sha256 } from "@noble/hashes/sha256";
import {
  CAP_STANDARD_FORTRESS_NODE,
  DEFAULTS,
} from "../../../src/mesh/constants.js";
import { Libp2pMeshTransport } from "../../../src/mesh/libp2p-transport/index.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  verifyCertChain,
} from "../../../src/mesh/trust-root.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../../src/mesh/types.js";
import {
  FileCounterStore,
  FileNodeKeyStore,
  MeshNode,
  createAutoApproveJoinApprover,
  wrapNodePrivateKey,
} from "../../../src/mesh/lifecycle/index.js";

/**
 * Mock TEE attestation hash for node C. v0.1 sovereign_tee nodes carry a
 * `tee_attestation_hash` on their NodeIdentityCertificate; real TEE hardware
 * integration (GCP Confidential VMs AMD SEV-SNP per thesis §3 L1) is a Phase
 * 2 concern. The harness uses a constant so the cert chain is deterministic.
 * The test suite's `TEE_ATTESTATION_MODE` env opt is documented in the pilot
 * onboarding README; see scripts/three-mode-drill-README.md.
 */
export const MOCK_TEE_ATTESTATION_HASH = toBase64url(
  sha256(new TextEncoder().encode("mock-tee-attestation-always-pass-v0.1"))
);

export interface ThreeModeDrillOptions {
  /**
   * Optional pre-built tmpdir. If absent, the harness mkdtemps one under the
   * OS tmp root and cleans it on teardown.
   */
  tmpdir?: string;
  /**
   * Stub the TEE attestation hash on node C's cert. Default `true` — set to
   * `false` only when a real-TEE host is wired, which is out of v1.0 scope.
   */
  teeMockMode?: boolean;
}

export interface ThreeModeDrillHandle {
  /** Scratch tmpdir root — torn down on `teardown()`. */
  tmpdir: string;
  /** 128-bit hex fortress-id, stable for the drill's lifetime. */
  fortressId: string;
  master_public: FortressMasterPublicKey;
  master_private_key: Uint8Array;
  root_principal_keypair: ReturnType<typeof generateKeypair>;
  root_principal_cert: PrincipalCertificate;
  nodeA: MeshNode;
  nodeB: MeshNode;
  nodeC: MeshNode;
  transportA: Libp2pMeshTransport;
  transportB: Libp2pMeshTransport;
  transportC: Libp2pMeshTransport;
  nodeIdA: string;
  nodeIdB: string;
  nodeIdC: string;
  nodeCertA: NodeIdentityCertificate;
  nodeCertB: NodeIdentityCertificate;
  nodeCertC: NodeIdentityCertificate;
  nodeKpA: ReturnType<typeof generateKeypair>;
  nodeKpB: ReturnType<typeof generateKeypair>;
  nodeKpC: ReturnType<typeof generateKeypair>;
  /** Tear down all three transports and remove the scratch tmpdir. */
  teardown: () => Promise<void>;
}

/**
 * ONE shared budget for "a gossipsub message published on one node has been
 * received and dispatched on another", used instead of a per-call-site magic
 * number.
 *
 * Sizing rationale: locally these settle in well under 2s; a shared CI runner
 * under concurrent job load is the slow case, so CI gets a deliberately
 * generous multiple. This is HEADROOM ONLY. Raising it can only ever fix a
 * genuinely-slow wait -- if a wait can never become true (a wrong or racy
 * condition), no budget rescues it and the right fix is at the call site, not
 * here. Do not reach for this constant to silence a wait that fails
 * deterministically.
 */
export const GOSSIP_SETTLE_MS = process.env.CI ? 60_000 : 20_000;

/**
 * Poll `check` until it returns truthy or the deadline expires. Throws a
 * descriptive error on timeout so a flaky libp2p boot shows up clearly in
 * vitest output instead of as an opaque assertion failure downstream.
 *
 * `check` is awaited and its rejections are NOT swallowed: a throwing check
 * propagates immediately rather than being retried until the deadline, so the
 * timeout message never stands in for a real error.
 */
export async function waitFor(
  check: () => boolean | Promise<boolean>,
  timeoutMs: number = 10_000,
  stepMs: number = 50,
  label: string = "condition"
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  // One last look: the condition may have become true during the final sleep,
  // and reporting a timeout without re-checking would be its own timing flake.
  if (await check()) return;
  throw new Error(`waitFor: ${label} did not hold within ${timeoutMs}ms`);
}

/**
 * Construct the full three-mode drill: boots the fortress, brings up three
 * real libp2p MeshNodes with disk-backed stores, admits the peers all around,
 * and runs one round of heartbeats so peer presence settles to `active`.
 *
 * On return, the mesh is ready for any §12 criterion 1-7 test.
 */
export async function bootThreeModeDrill(
  opts: ThreeModeDrillOptions = {}
): Promise<ThreeModeDrillHandle> {
  const tmpdir =
    opts.tmpdir ??
    (await fs.mkdtemp(path.join(os.tmpdir(), "three-mode-drill-")));
  const teeMock = opts.teeMockMode ?? true;

  const dirA = path.join(tmpdir, "nodeA");
  const dirB = path.join(tmpdir, "nodeB");
  const dirC = path.join(tmpdir, "nodeC");
  for (const d of [dirA, dirB, dirC]) {
    await fs.mkdir(d, { recursive: true, mode: 0o700 });
  }

  // ── 1. Fortress genesis (offline operator action) ───────────────────────
  const fortressMaster = generateFortressMaster();
  const rootKp = generateKeypair();
  const rootCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: rootKp.publicKey,
    role: "root",
    fortress_id: fortressMaster.public.fortress_id,
    master_private_key: fortressMaster.private_key,
  });

  // Pre-generate each node's keypair so we can seed the libp2p transport
  // with the right Ed25519 seed before any MeshNode is constructed. The
  // transport's peer-id is derived directly from this seed; Noise handshake
  // proves possession.
  const nodeKpA = generateKeypair();
  const nodeKpB = generateKeypair();
  const nodeKpC = generateKeypair();

  const nodeIdA = hexNodeIdFromPubkey(nodeKpA.publicKey);
  const nodeIdB = hexNodeIdFromPubkey(nodeKpB.publicKey);
  const nodeIdC = hexNodeIdFromPubkey(nodeKpC.publicKey);

  // Each cert is issued by the root principal and counter-signed by the
  // fortress-master. v0.1 capability bit 0 only (CAP_STANDARD_FORTRESS_NODE).
  const nodeCertA = issueNodeIdentityCertificate({
    node_id: nodeIdA,
    node_pubkey: nodeKpA.publicKey,
    node_mode: "local",
    fortress_id: fortressMaster.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: fortressMaster.public.public_key,
      principal_id: rootCert.principal_id,
      principal_pubkey: rootCert.principal_pubkey,
    },
    principal_private_key: rootKp.privateKey,
    master_private_key: fortressMaster.private_key,
  });
  const nodeCertB = issueNodeIdentityCertificate({
    node_id: nodeIdB,
    node_pubkey: nodeKpB.publicKey,
    node_mode: "operator_cloud",
    fortress_id: fortressMaster.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: fortressMaster.public.public_key,
      principal_id: rootCert.principal_id,
      principal_pubkey: rootCert.principal_pubkey,
    },
    principal_private_key: rootKp.privateKey,
    master_private_key: fortressMaster.private_key,
  });
  const nodeCertC = issueNodeIdentityCertificate({
    node_id: nodeIdC,
    node_pubkey: nodeKpC.publicKey,
    node_mode: "sovereign_tee",
    fortress_id: fortressMaster.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: fortressMaster.public.public_key,
      principal_id: rootCert.principal_id,
      principal_pubkey: rootCert.principal_pubkey,
    },
    principal_private_key: rootKp.privateKey,
    master_private_key: fortressMaster.private_key,
    tee_attestation_hash: teeMock ? MOCK_TEE_ATTESTATION_HASH : undefined,
  });

  // Sanity: every cert MUST chain to the pinned master here in the harness;
  // callers should never see a drill booted with a bad chain.
  verifyCertChain(nodeCertA, rootCert, fortressMaster.public);
  verifyCertChain(nodeCertB, rootCert, fortressMaster.public);
  verifyCertChain(nodeCertC, rootCert, fortressMaster.public);

  // ── 2. Bring up node A (local mode, canonical audit) ────────────────────
  const { node: nodeA, transport: transportA } = await bootNode({
    nodeId: nodeIdA,
    nodeKp: nodeKpA,
    nodeCert: nodeCertA,
    nodeMode: "local",
    isCanonicalAudit: true,
    staticPeers: [],
    dir: dirA,
    fortressMasterPublic: fortressMaster.public,
    fortressMasterPrivate: fortressMaster.private_key,
    rootCert,
    rootPrivateKey: rootKp.privateKey,
  });

  // ── 3. Bring up node B (operator_cloud; static peer = A only) ───────────
  const { node: nodeB, transport: transportB } = await bootNode({
    nodeId: nodeIdB,
    nodeKp: nodeKpB,
    nodeCert: nodeCertB,
    nodeMode: "operator_cloud",
    isCanonicalAudit: false,
    staticPeers: [transportMultiaddr(transportA)],
    dir: dirB,
    fortressMasterPublic: fortressMaster.public,
    fortressMasterPrivate: fortressMaster.private_key,
    rootCert,
    rootPrivateKey: rootKp.privateKey,
  });

  // ── 4. Bring up node C (sovereign_tee; static peers = A, B) ─────────────
  const { node: nodeC, transport: transportC } = await bootNode({
    nodeId: nodeIdC,
    nodeKp: nodeKpC,
    nodeCert: nodeCertC,
    nodeMode: "sovereign_tee",
    isCanonicalAudit: false,
    staticPeers: [
      transportMultiaddr(transportA),
      transportMultiaddr(transportB),
    ],
    dir: dirC,
    fortressMasterPublic: fortressMaster.public,
    fortressMasterPrivate: fortressMaster.private_key,
    rootCert,
    rootPrivateKey: rootKp.privateKey,
  });

  // ── 5. Admit peers on every side; register transport-layer mappings ─────
  nodeA.admitPeerCertificate({
    certificate: nodeCertB,
    issuing_principal_cert: rootCert,
  });
  nodeA.admitPeerCertificate({
    certificate: nodeCertC,
    issuing_principal_cert: rootCert,
  });
  nodeB.admitPeerCertificate({
    certificate: nodeCertA,
    issuing_principal_cert: rootCert,
  });
  nodeB.admitPeerCertificate({
    certificate: nodeCertC,
    issuing_principal_cert: rootCert,
  });
  nodeC.admitPeerCertificate({
    certificate: nodeCertA,
    issuing_principal_cert: rootCert,
  });
  nodeC.admitPeerCertificate({
    certificate: nodeCertB,
    issuing_principal_cert: rootCert,
  });

  const maA = transportMultiaddr(transportA);
  const maB = transportMultiaddr(transportB);
  const maC = transportMultiaddr(transportC);

  await transportA.registerPeer(nodeIdB, toBase64url(nodeKpB.publicKey), [maB]);
  await transportA.registerPeer(nodeIdC, toBase64url(nodeKpC.publicKey), [maC]);
  await transportB.registerPeer(nodeIdA, toBase64url(nodeKpA.publicKey), [maA]);
  await transportB.registerPeer(nodeIdC, toBase64url(nodeKpC.publicKey), [maC]);
  await transportC.registerPeer(nodeIdA, toBase64url(nodeKpA.publicKey), [maA]);
  await transportC.registerPeer(nodeIdB, toBase64url(nodeKpB.publicKey), [maB]);

  // ── 6. Wait for libp2p pairwise connection + gossipsub graft ────────────
  await waitFor(
    () => {
      return (
        transportA._libp2p().getPeers().length >= 2 &&
        transportB._libp2p().getPeers().length >= 2 &&
        transportC._libp2p().getPeers().length >= 2
      );
    },
    20_000,
    100,
    "libp2p pairwise connections"
  );
  // Gossipsub heartbeat is ~1s; give it one full graft cycle.
  await new Promise((r) => setTimeout(r, 1500));

  // ── 7. Emit one heartbeat from each node; wait for peer presence ─ ──────
  //   Promotes `joining` → `active` in every peer's roster via
  //   `recordHeartbeat` — the same transition production uses when a newly-
  //   joined node sends its first heartbeat.
  await nodeA.emitHeartbeat();
  await nodeB.emitHeartbeat();
  await nodeC.emitHeartbeat();

  await waitFor(
    () => {
      return (
        nodeA.getRoster().presenceOf(nodeIdB) === "active" &&
        nodeA.getRoster().presenceOf(nodeIdC) === "active" &&
        nodeB.getRoster().presenceOf(nodeIdA) === "active" &&
        nodeB.getRoster().presenceOf(nodeIdC) === "active" &&
        nodeC.getRoster().presenceOf(nodeIdA) === "active" &&
        nodeC.getRoster().presenceOf(nodeIdB) === "active"
      );
    },
    15_000,
    100,
    "peer presence converges to active"
  );

  async function teardown(): Promise<void> {
    for (const t of [transportA, transportB, transportC]) {
      try {
        await t.stop();
      } catch {
        // Best-effort — individual transport shutdown must not block cleanup.
      }
    }
    await fs.rm(tmpdir, { recursive: true, force: true });
  }

  return {
    tmpdir,
    fortressId: fortressMaster.public.fortress_id,
    master_public: fortressMaster.public,
    master_private_key: fortressMaster.private_key,
    root_principal_keypair: rootKp,
    root_principal_cert: rootCert,
    nodeA,
    nodeB,
    nodeC,
    transportA,
    transportB,
    transportC,
    nodeIdA,
    nodeIdB,
    nodeIdC,
    nodeCertA,
    nodeCertB,
    nodeCertC,
    nodeKpA,
    nodeKpB,
    nodeKpC,
    teardown,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Private helpers
// ═══════════════════════════════════════════════════════════════════════

interface BootNodeParams {
  nodeId: string;
  nodeKp: ReturnType<typeof generateKeypair>;
  nodeCert: NodeIdentityCertificate;
  nodeMode: "local" | "operator_cloud" | "sovereign_tee";
  isCanonicalAudit: boolean;
  staticPeers: string[];
  dir: string;
  fortressMasterPublic: FortressMasterPublicKey;
  fortressMasterPrivate: Uint8Array;
  rootCert: PrincipalCertificate;
  rootPrivateKey: Uint8Array;
}

interface BootNodeResult {
  node: MeshNode;
  transport: Libp2pMeshTransport;
}

async function bootNode(params: BootNodeParams): Promise<BootNodeResult> {
  const transport = await Libp2pMeshTransport.start({
    ed25519_seed: params.nodeKp.privateKey,
    fortress_id: params.fortressMasterPublic.fortress_id,
    config: {
      listen: ["/ip4/127.0.0.1/tcp/0"],
      mdns: false,
      dht: false,
      static_peers: params.staticPeers,
    },
  });
  transport.setOwnNodeId(params.nodeId);

  const keyStore = new FileNodeKeyStore(path.join(params.dir, "nodekeys"));
  const counters = new FileCounterStore(
    path.join(params.dir, "counters"),
    params.nodeId
  );
  await keyStore.init();
  await counters.init();

  // Persist the per-node wrapped private key so bootFromPersistedState can
  // unwrap it — this mirrors production, where the key lives on disk from
  // the join ceremony forward.
  await keyStore.save(
    params.nodeId,
    wrapNodePrivateKey({
      node_private_key: params.nodeKp.privateKey,
      fortress_master_secret: params.fortressMasterPrivate,
      node_id: params.nodeId,
    })
  );

  const approver = createAutoApproveJoinApprover({
    pinned_master_pubkey: params.fortressMasterPublic,
    issuing_principal_cert: params.rootCert,
    issuing_principal_private_key: params.rootPrivateKey,
    master_private_key: params.fortressMasterPrivate,
  });

  const node = new MeshNode(
    {
      node_id: params.nodeId,
      node_mode: params.nodeMode,
      fortress_id: params.fortressMasterPublic.fortress_id,
      pinned_master_pubkey: params.fortressMasterPublic,
      system_principal_id: params.rootCert.principal_id,
      is_canonical_audit_node: params.isCanonicalAudit,
      heartbeat_interval_ms: DEFAULTS.HEARTBEAT_INTERVAL_MS,
      heartbeat_missed_threshold: DEFAULTS.HEARTBEAT_MISSED_THRESHOLD,
    },
    {
      transport,
      approver,
      key_store: keyStore,
      counters,
      fortress_master_secret: params.fortressMasterPrivate,
    }
  );
  node.registerPrincipal(params.rootCert);
  await node.bootFromPersistedState({
    certificate: params.nodeCert,
    issuing_principal_cert: params.rootCert,
  });

  return { node, transport };
}

function transportMultiaddr(t: Libp2pMeshTransport): string {
  const addrs = t.listenAddresses();
  const ma = addrs.find((m) => m.toString().includes("127.0.0.1"));
  if (!ma) {
    throw new Error("harness: no 127.0.0.1 listen addr on transport");
  }
  const s = ma.toString();
  return s.includes("/p2p/") ? s : `${s}/p2p/${t.peerId().toString()}`;
}

/**
 * Derive a 128-bit hex node_id deterministically from the Ed25519 public key
 * — matches the §11 pick "128-bit hex fortress-id never re-used" shape while
 * keeping the drill deterministic (same seed → same node_id across reruns).
 */
function hexNodeIdFromPubkey(pubkey: Uint8Array): string {
  const digest = sha256(pubkey).slice(0, 16);
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
