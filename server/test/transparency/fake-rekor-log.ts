/**
 * Synthetic Rekor transparency-log fixture for PR-3 anchor-verification
 * tests (synthetic-fixture rule: no test touches the network).
 *
 * Unlike the minimal canned responses in anchoring.test.ts, this fixture
 * is a REAL miniature log: it maintains an RFC 6962 Merkle tree over
 * submitted entry bodies, produces genuine inclusion proofs, signs
 * checkpoint notes and signed entry timestamps with a P-256 log key, and
 * serves both the POST (submit) and GET (fetch entry) shapes of the Rekor
 * API through a FetchLike transport. The anchor verifier therefore runs
 * the exact arithmetic and signature checks it would run against the
 * public log, against evidence this fixture can also deliberately
 * corrupt.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";

import { canonicalJson } from "../../src/audit/chain.js";
import type { FetchLike } from "../../src/transparency/rekor-client.js";

const SPKI_P256_PREFIX_HEX =
  "3059301306072a8648ce3d020106082a8648ce3d030107034200";

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function concat(...parts: Uint8Array[]): Uint8Array {
  return new Uint8Array(Buffer.concat(parts.map((part) => Buffer.from(part))));
}

function leafHash(body: Uint8Array): Uint8Array {
  return sha256(concat(new Uint8Array([0x00]), body));
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export function merkleRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  if (leaves.length === 1) return leaves[0]!;
  const k = largestPowerOfTwoBelow(leaves.length);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

export function inclusionProof(m: number, leaves: Uint8Array[]): Uint8Array[] {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  if (m < k) {
    return [...inclusionProof(m, leaves.slice(0, k)), merkleRoot(leaves.slice(k))];
  }
  return [...inclusionProof(m - k, leaves.slice(k)), merkleRoot(leaves.slice(0, k))];
}

interface StoredEntry {
  uuid: string;
  index: number;
  bodyB64: string;
  integratedTime: number;
}

export class FakeRekorLog {
  readonly origin = "rekor.fixture.test - 1066";
  private readonly privateKey = p256.utils.randomPrivateKey();
  private readonly publicPoint = p256.getPublicKey(this.privateKey, false);
  private readonly leaves: Uint8Array[] = [];
  private readonly entries = new Map<string, StoredEntry>();
  /** Unix seconds stamped onto new entries; tests can move it. */
  integratedTime = 1_760_000_000;

  publicKeyDer(): Uint8Array {
    return concat(
      new Uint8Array(Buffer.from(SPKI_P256_PREFIX_HEX, "hex")),
      this.publicPoint
    );
  }

  publicKeyPem(): string {
    const b64 = Buffer.from(this.publicKeyDer()).toString("base64");
    const lines = b64.match(/.{1,64}/g) ?? [];
    return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
  }

  logId(): string {
    return toHex(sha256(this.publicKeyDer()));
  }

  private signDer(messageHash: Uint8Array): Uint8Array {
    return p256.sign(messageHash, this.privateKey, { lowS: true }).toDERRawBytes();
  }

  private signedNote(treeSize: number, root: Uint8Array): string {
    const text = `${this.origin}\n${treeSize}\n${Buffer.from(root).toString("base64")}\n`;
    const der = this.signDer(sha256(new TextEncoder().encode(text)));
    const name = this.origin.split(" ")[0]!;
    const hint = sha256(
      concat(new TextEncoder().encode(`${name}\n`), this.publicKeyDer())
    ).slice(0, 4);
    const blob = Buffer.from(concat(hint, der)).toString("base64");
    return `${text}\n\u2014 ${name} ${blob}\n`;
  }

  private entryResponse(entry: StoredEntry): Record<string, unknown> {
    const treeSize = this.leaves.length;
    const root = merkleRoot(this.leaves);
    const proof = inclusionProof(entry.index, this.leaves);
    const setPayload = canonicalJson({
      body: entry.bodyB64,
      integratedTime: entry.integratedTime,
      logID: this.logId(),
      logIndex: entry.index,
    });
    const set = this.signDer(sha256(new TextEncoder().encode(setPayload)));
    return {
      [entry.uuid]: {
        body: entry.bodyB64,
        integratedTime: entry.integratedTime,
        logID: this.logId(),
        logIndex: entry.index,
        verification: {
          inclusionProof: {
            checkpoint: this.signedNote(treeSize, root),
            hashes: proof.map((hash) => toHex(hash)),
            logIndex: entry.index,
            rootHash: toHex(root),
            treeSize,
          },
          signedEntryTimestamp: Buffer.from(set).toString("base64"),
        },
      },
    };
  }

  /** Append a raw body (canonical JSON string) to the log. */
  append(bodyJson: string): StoredEntry {
    const bodyBytes = new TextEncoder().encode(bodyJson);
    const bodyB64 = Buffer.from(bodyBytes).toString("base64");
    const uuid = toHex(leafHash(bodyBytes));
    const existing = this.entries.get(uuid);
    if (existing) return existing;
    const entry: StoredEntry = {
      uuid,
      index: this.leaves.length,
      bodyB64,
      integratedTime: this.integratedTime,
    };
    this.leaves.push(leafHash(bodyBytes));
    this.entries.set(uuid, entry);
    return entry;
  }

  /**
   * Append an unrelated foreign entry so trees grow past powers of two and
   * anchor entries sit at interesting indices.
   */
  appendNoise(seed: string): void {
    this.append(canonicalJson({ foreign: true, seed }));
  }

  /** FetchLike transport implementing POST submit and GET fetch-entry. */
  fetchLike(): FetchLike {
    return async (url, init) => {
      if (init.method === "POST" && url.endsWith("/api/v1/log/entries")) {
        const entry = this.append(canonicalJson(JSON.parse(init.body ?? "{}")));
        return {
          status: 201,
          headers: { get: () => null },
          text: async () => JSON.stringify(this.entryResponse(entry)),
        };
      }
      const match = /\/api\/v1\/log\/entries\/([0-9a-f]+)$/.exec(url);
      if (init.method === "GET" && match) {
        const entry = this.entries.get(match[1]!);
        if (!entry) {
          return {
            status: 404,
            headers: { get: () => null },
            text: async () => JSON.stringify({ message: "no such entry" }),
          };
        }
        return {
          status: 200,
          headers: { get: () => null },
          text: async () => JSON.stringify(this.entryResponse(entry)),
        };
      }
      return {
        status: 500,
        headers: { get: () => null },
        text: async () => "unexpected request",
      };
    };
  }
}
