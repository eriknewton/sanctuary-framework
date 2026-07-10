/**
 * Sanctuary MCP Server - Law-firm Evidence Pack: signing + manifest
 *
 * Copyright 2026 Erik Newton
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hashes and signs every emitted file with the fortress primary Ed25519
 * identity and builds the signed manifest, reusing the exact discipline of the
 * EU AI Act bundle generator (`compliance/eu_ai_act/generator.ts`): SHA-256 the
 * bytes, Ed25519-sign the hash, record the signer DID + public key in the
 * manifest, and sign the canonical JSON of the manifest body. No new keys, no
 * new crypto. The small signer helper is written here (not imported) so this
 * module does not couple to the compliance module's internals, exactly as the
 * compliance generator mirrors `reputation_publish` rather than importing it.
 */

import { sign } from "../core/identity.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { hash } from "../core/hashing.js";
import { toBase64url, stringToBytes } from "../core/encoding.js";
import type { StoredIdentity } from "../core/identity.js";
import type {
  EvidencePackFile,
  EvidencePackManifest,
  QuarterWindow,
} from "./types.js";
import { PACK_DISCLAIMER } from "./sections.js";

/** Lowercase hex of a byte array (auditors verify with `sha256sum`). */
function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

/** Deterministic canonical JSON (recursively sorted keys, no whitespace). */
export function canonicalJSON(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  const obj = value as Record<string, unknown>;
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortKeys(obj[key]);
  }
  return sorted;
}

/** A minimal content signer bound to one identity + master key. */
export interface PackSigner {
  signContent: (content: string) => string;
  sha256Hex: (content: string) => string;
}

/**
 * Build a signer over the fortress primary identity. The private key is
 * decrypted transiently inside `sign()` (see `core/identity.ts`) and never
 * retained here.
 */
export function makePackSigner(
  signer: StoredIdentity,
  masterKey: Uint8Array
): PackSigner {
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  return {
    signContent: (content: string) => {
      const digest = hash(stringToBytes(content));
      const sig = sign(digest, signer.encrypted_private_key, encryptionKey);
      return toBase64url(sig);
    },
    sha256Hex: (content: string) => bytesToHex(hash(stringToBytes(content))),
  };
}

/** Hash + sign one file, producing a signed {@link EvidencePackFile}. */
export function signFile(
  filename: string,
  content: string,
  contentType: EvidencePackFile["content_type"],
  ds: PackSigner
): EvidencePackFile {
  return {
    filename,
    content,
    content_type: contentType,
    sha256: ds.sha256Hex(content),
    signature: ds.signContent(content),
  };
}

/**
 * Build and sign the pack manifest over the given signed files. Mirrors the EU
 * AI Act bundle's `buildManifest`: the body is assembled without the signature,
 * signed over canonical JSON, and the signature is appended.
 */
export function buildPackManifest(params: {
  productName: string;
  firmName: string;
  window: QuarterWindow;
  generatedAt: string;
  signer: StoredIdentity;
  files: EvidencePackFile[];
  /** The machine-readable coverage union (determinable, or not with a reason). */
  coverage: EvidencePackManifest["coverage"];
  ds: PackSigner;
}): EvidencePackManifest {
  const body: Omit<EvidencePackManifest, "manifest_signature"> = {
    pack_version: "0.1-preview",
    slice: "walking-skeleton-v1",
    product_name: params.productName,
    firm_name: params.firmName,
    quarter_label: params.window.label,
    period_start: params.window.start_inclusive,
    period_end_exclusive: params.window.end_exclusive,
    generated_at: params.generatedAt,
    signer: {
      did: params.signer.did,
      public_key_base64url: params.signer.public_key,
    },
    files: params.files.map((f) => ({
      filename: f.filename,
      content_type: f.content_type,
      sha256: f.sha256,
      signature: f.signature,
    })),
    coverage: params.coverage,
    disclaimer: PACK_DISCLAIMER,
  };

  const manifestSignature = params.ds.signContent(canonicalJSON(body));
  return { ...body, manifest_signature: manifestSignature };
}
