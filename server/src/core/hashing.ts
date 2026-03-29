/**
 * Sanctuary MCP Server — Hashing and Merkle Trees
 *
 * SHA-256 hashing for integrity verification.
 * Merkle trees for namespace-level state integrity.
 */

import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { toBase64url, concatBytes, stringToBytes } from "./encoding.js";

/**
 * Compute SHA-256 hash of data.
 */
export function hash(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * Compute SHA-256 hash and return as base64url string.
 */
export function hashToString(data: Uint8Array): string {
  return toBase64url(hash(data));
}

/**
 * Compute HMAC-SHA256.
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

// ─── Merkle Tree ─────────────────────────────────────────────────────────────

export interface MerkleNode {
  hash: string; // base64url SHA-256
  left?: MerkleNode;
  right?: MerkleNode;
  key?: string; // Leaf nodes store the state key
}

export interface MerkleProof {
  leaf: string;
  path: Array<{
    hash: string;
    position: "left" | "right";
  }>;
  root: string;
}

/**
 * Build a Merkle tree from a set of key-hash pairs.
 * Keys are sorted lexicographically for deterministic ordering.
 *
 * @param entries - Map of state key → content hash (base64url)
 * @returns Root node of the Merkle tree
 */
export function buildMerkleTree(
  entries: Map<string, string>
): MerkleNode | null {
  if (entries.size === 0) return null;

  // Sort keys for deterministic tree construction
  const sortedKeys = Array.from(entries.keys()).sort();

  // Create leaf nodes: H(key || content_hash)
  let nodes: MerkleNode[] = sortedKeys.map((key) => {
    const contentHash = entries.get(key)!;
    const leafData = concatBytes(
      stringToBytes(key),
      stringToBytes(contentHash)
    );
    return {
      hash: hashToString(leafData),
      key,
    };
  });

  // Build tree bottom-up
  while (nodes.length > 1) {
    const nextLevel: MerkleNode[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      const left = nodes[i]!;
      if (i + 1 < nodes.length) {
        const right = nodes[i + 1]!;
        const parentData = concatBytes(
          stringToBytes(left.hash),
          stringToBytes(right.hash)
        );
        nextLevel.push({
          hash: hashToString(parentData),
          left,
          right,
        });
      } else {
        // Odd node — promote directly
        nextLevel.push(left);
      }
    }
    nodes = nextLevel;
  }

  return nodes[0] ?? null;
}

/**
 * Generate a Merkle proof for a specific key.
 *
 * @param entries - All key-hash pairs in the namespace
 * @param targetKey - The key to generate a proof for
 * @returns MerkleProof or null if key not found
 */
export function generateMerkleProof(
  entries: Map<string, string>,
  targetKey: string
): MerkleProof | null {
  if (!entries.has(targetKey)) return null;

  const sortedKeys = Array.from(entries.keys()).sort();
  const targetIndex = sortedKeys.indexOf(targetKey);
  if (targetIndex === -1) return null;

  // Create leaf hashes
  const leafHashes: string[] = sortedKeys.map((key) => {
    const contentHash = entries.get(key)!;
    const leafData = concatBytes(
      stringToBytes(key),
      stringToBytes(contentHash)
    );
    return hashToString(leafData);
  });

  const path: MerkleProof["path"] = [];
  let currentIndex = targetIndex;
  let currentLevel = leafHashes;

  while (currentLevel.length > 1) {
    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i]!;
      if (i + 1 < currentLevel.length) {
        const right = currentLevel[i + 1]!;

        // If our target is at this pair, record the sibling
        if (i === currentIndex || i + 1 === currentIndex) {
          if (currentIndex === i) {
            path.push({ hash: right, position: "right" });
          } else {
            path.push({ hash: left, position: "left" });
          }
        }

        const parentData = concatBytes(
          stringToBytes(left),
          stringToBytes(right)
        );
        nextLevel.push(hashToString(parentData));
      } else {
        // Odd node — promote directly, no sibling to record
        nextLevel.push(left);
      }
    }
    currentIndex = Math.floor(currentIndex / 2);
    currentLevel = nextLevel;
  }

  const root = buildMerkleTree(entries);

  return {
    leaf: leafHashes[targetIndex]!,
    path,
    root: root?.hash ?? "",
  };
}

/**
 * Verify a Merkle proof.
 *
 * @param proof - The proof to verify
 * @returns true if the proof is valid
 */
export function verifyMerkleProof(proof: MerkleProof): boolean {
  let currentHash = proof.leaf;

  for (const step of proof.path) {
    const left =
      step.position === "left" ? step.hash : currentHash;
    const right =
      step.position === "right" ? step.hash : currentHash;
    const parentData = concatBytes(
      stringToBytes(left),
      stringToBytes(right)
    );
    currentHash = hashToString(parentData);
  }

  return currentHash === proof.root;
}

/**
 * Compute the Merkle root for a set of entries.
 * Convenience function that builds the tree and returns just the root hash.
 */
export function computeMerkleRoot(entries: Map<string, string>): string {
  const tree = buildMerkleTree(entries);
  return tree?.hash ?? "";
}
