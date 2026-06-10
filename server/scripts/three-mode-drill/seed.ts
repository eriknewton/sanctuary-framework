/**
 * Three-Mode Drill — fortress-seed step.
 *
 * Run from the worktree root:
 *   cd server && npx tsx scripts/three-mode-drill/seed.ts <DRILL_DIR>
 *
 * Creates the fortress-master keypair, issues the root principal certificate,
 * generates per-node keypairs + NodeIdentityCertificates (local, operator_cloud,
 * sovereign_tee), writes the whole materials tree to `<DRILL_DIR>/`:
 *
 *   <DRILL_DIR>/fortress/public.json     — FortressMasterPublicKey
 *   <DRILL_DIR>/fortress/master.bin      — master private seed (32 bytes)
 *   <DRILL_DIR>/fortress/root-cert.json  — root PrincipalCertificate
 *   <DRILL_DIR>/fortress/root-priv.bin   — root principal private seed
 *   <DRILL_DIR>/peers.json               — per-node { id, pubkey, cert, mode }
 *   <DRILL_DIR>/nodeA/node.json          — { id, mode, cert }
 *   <DRILL_DIR>/nodeA/node-wrapped.json  — master-key-wrapped Ed25519 seed
 *   <DRILL_DIR>/nodeA/seed.bin           — node Ed25519 seed (demo-only)
 *   (… same for nodeB, nodeC)
 *
 * `master.bin`, `root-priv.bin`, and `seed.bin` are demo-only — a pilot
 * operator running the real sovereign fortress would NEVER dump these to
 * disk unencrypted. They live in the operator's encrypted state store, unlocked by the
 * Argon2id passphrase. The drill script writes them so the per-node `node.ts`
 * runtime can pick them up without a passphrase-prompt step; the README
 * spells this out as the single most important deviation from production.
 */

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { sha256 } from "@noble/hashes/sha256";

import { toBase64url } from "../../src/core/encoding.js";
import { generateKeypair } from "../../src/core/identity.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import { wrapNodePrivateKey } from "../../src/mesh/lifecycle/index.js";

const MOCK_TEE_ATTESTATION_HASH = toBase64url(
  sha256(new TextEncoder().encode("mock-tee-attestation-always-pass-v0.1"))
);

type NodeMode = "local" | "operator_cloud" | "sovereign_tee";

function hexNodeIdFromPubkey(pubkey: Uint8Array): string {
  const digest = sha256(pubkey).slice(0, 16);
  return Array.from(digest)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function main() {
  const drillDir = process.argv[2];
  if (!drillDir) {
    console.error("usage: seed.ts <DRILL_DIR>");
    process.exit(2);
  }

  await fs.mkdir(path.join(drillDir, "fortress"), {
    recursive: true,
    mode: 0o700,
  });
  for (const n of ["nodeA", "nodeB", "nodeC"]) {
    await fs.mkdir(path.join(drillDir, n), { recursive: true, mode: 0o700 });
  }

  // Fortress genesis.
  const fortress = generateFortressMaster();
  const rootKp = generateKeypair();
  const rootCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: rootKp.publicKey,
    role: "root",
    fortress_id: fortress.public.fortress_id,
    master_private_key: fortress.private_key,
  });

  await fs.writeFile(
    path.join(drillDir, "fortress", "public.json"),
    JSON.stringify(fortress.public, null, 2)
  );
  await fs.writeFile(
    path.join(drillDir, "fortress", "master.bin"),
    fortress.private_key,
    { mode: 0o600 }
  );
  await fs.writeFile(
    path.join(drillDir, "fortress", "root-cert.json"),
    JSON.stringify(rootCert, null, 2)
  );
  await fs.writeFile(
    path.join(drillDir, "fortress", "root-priv.bin"),
    rootKp.privateKey,
    { mode: 0o600 }
  );

  // Per-node keypairs + certs.
  const specs: Array<{ role: "A" | "B" | "C"; mode: NodeMode }> = [
    { role: "A", mode: "local" },
    { role: "B", mode: "operator_cloud" },
    { role: "C", mode: "sovereign_tee" },
  ];

  const peers: Array<{
    role: string;
    id: string;
    pubkey: string;
    mode: NodeMode;
    cert: unknown;
  }> = [];

  for (const spec of specs) {
    const kp = generateKeypair();
    const nodeId = hexNodeIdFromPubkey(kp.publicKey);
    const cert = issueNodeIdentityCertificate({
      node_id: nodeId,
      node_pubkey: kp.publicKey,
      node_mode: spec.mode,
      fortress_id: fortress.public.fortress_id,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: fortress.public.public_key,
        principal_id: rootCert.principal_id,
        principal_pubkey: rootCert.principal_pubkey,
      },
      principal_private_key: rootKp.privateKey,
      master_private_key: fortress.private_key,
      tee_attestation_hash:
        spec.mode === "sovereign_tee" ? MOCK_TEE_ATTESTATION_HASH : undefined,
    });
    const wrapped = wrapNodePrivateKey({
      node_private_key: kp.privateKey,
      fortress_master_secret: fortress.private_key,
      node_id: nodeId,
    });

    const dir = path.join(drillDir, `node${spec.role}`);
    await fs.writeFile(
      path.join(dir, "node.json"),
      JSON.stringify(
        { role: spec.role, id: nodeId, mode: spec.mode, cert },
        null,
        2
      )
    );
    await fs.writeFile(
      path.join(dir, "node-wrapped.json"),
      JSON.stringify(wrapped, null, 2),
      { mode: 0o600 }
    );
    await fs.writeFile(path.join(dir, "seed.bin"), kp.privateKey, {
      mode: 0o600,
    });

    peers.push({
      role: spec.role,
      id: nodeId,
      pubkey: toBase64url(kp.publicKey),
      mode: spec.mode,
      cert,
    });
  }

  await fs.writeFile(
    path.join(drillDir, "peers.json"),
    JSON.stringify(peers, null, 2)
  );

  console.log(`seed: fortress_id=${fortress.public.fortress_id}`);
  console.log(`seed: wrote materials to ${drillDir}`);
  for (const p of peers) {
    console.log(`seed: node${p.role} mode=${p.mode} id=${p.id}`);
  }
}

main().catch((e) => {
  console.error("seed failed:", e);
  process.exit(1);
});
