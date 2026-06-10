/**
 * Three-Mode Drill — per-node runtime.
 *
 * Run from the worktree root, one invocation per node:
 *   cd server && npx tsx scripts/three-mode-drill/node.ts <DRILL_DIR> <ROLE>
 *     where ROLE = A | B | C
 *
 * Reads the materials seeded by `seed.ts`, brings up a Libp2pMeshTransport on
 * 127.0.0.1, boots a MeshNode from the persisted certificate + wrapped key,
 * writes its multiaddr to `<DRILL_DIR>/nodeX/multiaddr.txt` on listen, polls
 * for the other two nodes' multiaddrs to appear, admits their certs, and
 * then maintains a 2-second status heartbeat into
 * `<DRILL_DIR>/status/<ROLE>.json` until the process is killed.
 *
 * Node A is the canonical audit node. Nodes B and C dial A as their static
 * peer; B dials A, C dials A and B. This sequential bring-up is what the
 * `three-mode-drill-onboard.sh` orchestrator drives.
 *
 * This runtime is demo-grade — passphrase-less unwrapping is read from
 * `seed.bin`; the production fortress ingests these materials through the
 * fortress instead. See `scripts/three-mode-drill-README.md` for the operator-
 * facing explanation.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";

import { toBase64url } from "../../src/core/encoding.js";
import { DEFAULTS } from "../../src/mesh/constants.js";
import { Libp2pMeshTransport } from "../../src/mesh/libp2p-transport/index.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";
import {
  FileCounterStore,
  FileNodeKeyStore,
  MeshNode,
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/index.js";

type Role = "A" | "B" | "C";

async function readJson<T>(p: string): Promise<T> {
  const bytes = await fs.readFile(p, "utf8");
  return JSON.parse(bytes) as T;
}
async function readBytes(p: string): Promise<Uint8Array> {
  return new Uint8Array(await fs.readFile(p));
}

async function waitForFile(p: string, timeoutMs = 60_000, stepMs = 200) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await fs.access(p);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, stepMs));
    }
  }
  throw new Error(`timed out waiting for ${p}`);
}

interface PeerEntry {
  role: Role;
  id: string;
  pubkey: string;
  mode: "local" | "operator_cloud" | "sovereign_tee";
  cert: NodeIdentityCertificate;
}

async function main() {
  const drillDir = process.argv[2];
  const role = (process.argv[3] ?? "") as Role;
  if (!drillDir || !["A", "B", "C"].includes(role)) {
    console.error(
      "usage: node.ts <DRILL_DIR> <ROLE>\n  ROLE must be one of A, B, C"
    );
    process.exit(2);
  }

  const nodeDir = path.join(drillDir, `node${role}`);
  const statusDir = path.join(drillDir, "status");
  await fs.mkdir(statusDir, { recursive: true, mode: 0o700 });

  // ── 1. Load fortress + self materials ───────────────────────────────
  const fortressPublic = await readJson<FortressMasterPublicKey>(
    path.join(drillDir, "fortress", "public.json")
  );
  const fortressMaster = await readBytes(
    path.join(drillDir, "fortress", "master.bin")
  );
  const rootCert = await readJson<PrincipalCertificate>(
    path.join(drillDir, "fortress", "root-cert.json")
  );
  const rootPriv = await readBytes(
    path.join(drillDir, "fortress", "root-priv.bin")
  );
  const self = await readJson<{
    role: Role;
    id: string;
    mode: "local" | "operator_cloud" | "sovereign_tee";
    cert: NodeIdentityCertificate;
  }>(path.join(nodeDir, "node.json"));
  const selfSeed = await readBytes(path.join(nodeDir, "seed.bin"));
  const peers = await readJson<PeerEntry[]>(path.join(drillDir, "peers.json"));

  // ── 2. Launch libp2p transport ──────────────────────────────────────
  //   Node A starts with no static peers; B dials A; C dials A and B.
  const staticPeers: string[] = [];
  if (role === "B") staticPeers.push(await readMultiaddr(drillDir, "A"));
  if (role === "C") {
    staticPeers.push(await readMultiaddr(drillDir, "A"));
    staticPeers.push(await readMultiaddr(drillDir, "B"));
  }

  const transport = await Libp2pMeshTransport.start({
    ed25519_seed: selfSeed,
    fortress_id: fortressPublic.fortress_id,
    config: {
      listen: ["/ip4/127.0.0.1/tcp/0"],
      mdns: false,
      dht: false,
      static_peers: staticPeers,
    },
  });
  transport.setOwnNodeId(self.id);

  // Publish our multiaddr so the next-role process can dial us.
  const myMultiaddr = pickLoopbackMultiaddr(transport);
  await fs.writeFile(
    path.join(nodeDir, "multiaddr.txt"),
    myMultiaddr + "\n",
    { mode: 0o644 }
  );
  console.log(`node${role}: listening on ${myMultiaddr}`);

  // ── 3. Boot MeshNode from persisted state ───────────────────────────
  const keyStore = new FileNodeKeyStore(path.join(nodeDir, "nodekeys"));
  const counters = new FileCounterStore(
    path.join(nodeDir, "counters"),
    self.id
  );
  await keyStore.init();
  await counters.init();
  // Re-wrap + save the private key into the FileNodeKeyStore shape, so
  // bootFromPersistedState can unwrap it using the same fortress-master.
  const wrappedFromSeed = await readJson<{
    v: number;
    alg: string;
    iv: string;
    ct: string;
    ts: string;
  }>(path.join(nodeDir, "node-wrapped.json"));
  await keyStore.save(self.id, wrappedFromSeed);

  const node = new MeshNode(
    {
      node_id: self.id,
      node_mode: self.mode,
      fortress_id: fortressPublic.fortress_id,
      pinned_master_pubkey: fortressPublic,
      system_principal_id: rootCert.principal_id,
      is_canonical_audit_node: role === "A",
      heartbeat_interval_ms: DEFAULTS.HEARTBEAT_INTERVAL_MS,
      heartbeat_missed_threshold: DEFAULTS.HEARTBEAT_MISSED_THRESHOLD,
    },
    {
      transport,
      approver: createAutoApproveJoinApprover({
        pinned_master_pubkey: fortressPublic,
        issuing_principal_cert: rootCert,
        issuing_principal_private_key: rootPriv,
        master_private_key: fortressMaster,
      }),
      key_store: keyStore,
      counters,
      fortress_master_secret: fortressMaster,
    }
  );
  node.registerPrincipal(rootCert);
  await node.bootFromPersistedState({
    certificate: self.cert,
    issuing_principal_cert: rootCert,
  });

  // ── 4. Admit the other two peers' certs + register transport maps ──
  for (const peer of peers) {
    if (peer.role === role) continue;
    node.admitPeerCertificate({
      certificate: peer.cert,
      issuing_principal_cert: rootCert,
    });
    // Static-peer multiaddr for unicast dial — for A, these materialize
    // only once B and C come up.
    const peerMa = await waitForMultiaddr(drillDir, peer.role);
    await transport.registerPeer(peer.id, peer.pubkey, [peerMa]);
  }

  // ── 5. Steady-state heartbeat + status emit ─────────────────────────
  // One heartbeat advertises us as active so peers' rosters promote us
  // from joining to active on their next recordHeartbeat.
  await node.emitHeartbeat();

  const statusPath = path.join(statusDir, `${role}.json`);
  const heartbeatTimer = setInterval(async () => {
    try {
      await node.emitHeartbeat();
    } catch {
      /* transport might be tearing down */
    }
  }, 5_000);
  const statusTimer = setInterval(async () => {
    const presence: Record<string, string | undefined> = {};
    for (const p of peers) {
      presence[p.role] = node.getRoster().presenceOf(p.id);
    }
    await fs.writeFile(
      statusPath,
      JSON.stringify(
        {
          role,
          node_id: self.id,
          mode: self.mode,
          roster_size: node.getRoster().size(),
          presence,
          is_canonical_audit: role === "A",
          ts: new Date().toISOString(),
        },
        null,
        2
      )
    );
  }, 1_000);

  const shutdown = async () => {
    clearInterval(heartbeatTimer);
    clearInterval(statusTimer);
    try {
      await transport.stop();
    } catch {
      /* best-effort */
    }
    console.log(`node${role}: stopped`);
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  // Keep-alive — the script idles here, heartbeating + status-emitting.
  // The bash orchestrator signals SIGTERM when the drill is done.
}

async function readMultiaddr(drillDir: string, role: Role): Promise<string> {
  const p = path.join(drillDir, `node${role}`, "multiaddr.txt");
  await waitForFile(p, 60_000);
  return (await fs.readFile(p, "utf8")).trim();
}

async function waitForMultiaddr(
  drillDir: string,
  role: Role
): Promise<string> {
  return await readMultiaddr(drillDir, role);
}

function pickLoopbackMultiaddr(transport: Libp2pMeshTransport): string {
  const addrs = transport.listenAddresses();
  const ma = addrs.find((m) => m.toString().includes("127.0.0.1"));
  if (!ma) throw new Error("no 127.0.0.1 listen addr");
  const s = ma.toString();
  return s.includes("/p2p/") ? s : `${s}/p2p/${transport.peerId().toString()}`;
}

main().catch((e) => {
  console.error("node runtime failed:", e);
  process.exit(1);
});
