/**
 * Sanctuary Verifiable Transparency, external anchoring format (PR-2).
 *
 * An anchor publishes a SALTED COMMITMENT to one enforcement checkpoint in
 * a public append-only transparency log (Sigstore Rekor), so that a
 * dishonest operator (or an attacker who owns the host) cannot later
 * withhold the newest checkpoints or present divergent histories without
 * the public log contradicting them.
 *
 * PRIVACY INVARIANTS (hard constraint #1 in CLAUDE.md):
 *   - Anchoring is OPT-IN and OFF by default. Nothing here performs I/O;
 *     the orchestration layer (anchoring.ts) refuses to transmit anything
 *     unless the operator recorded explicit consent.
 *   - HASH-ONLY anchors. What leaves the machine is exactly:
 *       1. a 32-byte SHA-256 commitment digest (salted, domain-separated),
 *       2. an ECDSA P-256 signature over the commitment preimage,
 *       3. the derived anchoring public key (a per-fortress pseudonym).
 *     The fortress id, checkpoint counter, checkpoint hash, enforcement
 *     counts, policy hashes, and audit metadata NEVER appear in the
 *     anchor: they are inputs to the salted hash only. Without the local
 *     salt the published digest reveals nothing but existence and timing.
 *   - The anchoring key is NOT the checkpoint signing key. It is derived
 *     from the fortress master key for this single purpose (HKDF purpose
 *     string registered in docs/hkdf-info-string-registry.md), exists only
 *     transiently in memory, and signs only commitment preimages. The
 *     Ed25519 checkpoint custody key never touches the anchor path, so
 *     anchors do not link to the published checkpoint-verification key.
 *
 * Rekor's `hashedrekord` entry type carries (digest, signature, public
 * key) and never the underlying data, which is exactly the hash-only
 * posture. ECDSA P-256 over SHA-256 is used because hashedrekord requires
 * a signature scheme verifiable against the digest alone (pure Ed25519 is
 * not; Rekor rejects it for this entry type).
 *
 * This module is PURE: types + derivation + serialization + signing math.
 * No network, no storage, no process state.
 */

import { createHash } from "node:crypto";

import { p256 } from "@noble/curves/p256";

import { canonicalJson, sha256Hex } from "../audit/chain.js";
import { stringToBytes } from "../core/encoding.js";
import { derivePurposeKey } from "../core/key-derivation.js";

/**
 * CROSS-FILE CONTRACT. Must match `ANCHOR_SCHEMA_VERSION` in
 * `transparency/anchor-verify.ts`, which re-types it rather than importing it
 * (that module is part of the offline standalone-verifier surface).
 */
export const TRANSPARENCY_ANCHOR_SCHEMA_VERSION = 1;

/**
 * Domain separator for the salted commitment preimage.
 *
 * CROSS-FILE CONTRACT. Must match `ANCHOR_COMMITMENT_DOMAIN` in
 * `transparency/anchor-verify.ts`, AND the preimage composition below
 * (`DOMAIN \n salt \n counter \n checkpointHash`) must match the one that file
 * rebuilds when it recomputes a commitment. Failure mode of a drift: the
 * verifier recomputes a different digest and reports the anchor as NOT
 * matching its checkpoint, which is exactly the signal a real rollback
 * produces, so a stale mirror is indistinguishable from an attack.
 */
export const TRANSPARENCY_ANCHOR_COMMITMENT_DOMAIN =
  "sanctuary.transparency.anchor-commitment.v1";

/**
 * HKDF purpose string (info to derivePurposeKey) for the dedicated
 * anchoring signature key. Registered in docs/hkdf-info-string-registry.md.
 */
export const TRANSPARENCY_ANCHOR_SIGNING_PURPOSE =
  "transparency-anchor-signing-v1";

/**
 * HKDF purpose string for the MAC key that authenticates the anchoring
 * config (so a host-level tamperer cannot silently enable transmission or
 * silently disable anchoring). Registered in the same registry.
 */
export const TRANSPARENCY_ANCHOR_CONFIG_MAC_PURPOSE =
  "transparency-anchor-config-mac-v1";

/** Domain prefix for the config MAC bytes. */
export const TRANSPARENCY_ANCHOR_CONFIG_MAC_DOMAIN =
  "sanctuary.transparency.anchor-config.v1\n";

/** The default public transparency log. */
export const DEFAULT_REKOR_URL = "https://rekor.sigstore.dev";

const HEX64 = /^[0-9a-f]{64}$/;

// ---- Salted commitment ------------------------------------------------------

/**
 * The exact bytes the published digest commits to. The salt is a
 * per-fortress 32-byte random value generated at enable time and stored
 * ONLY locally (handed to verifiers inside a bundle the operator chooses
 * to share). Domain separation prevents cross-protocol reuse of the
 * digest; the counter binds the commitment to one specific checkpoint.
 */
export function anchorCommitmentPreimage(input: {
  saltHex: string;
  counter: number;
  checkpointHash: string;
}): Uint8Array {
  if (!HEX64.test(input.saltHex)) {
    throw new Error("anchor salt must be 64 lowercase hex characters");
  }
  if (!Number.isSafeInteger(input.counter) || input.counter <= 0) {
    throw new Error("anchor counter must be a positive safe integer");
  }
  if (!HEX64.test(input.checkpointHash)) {
    throw new Error("anchor checkpoint hash must be 64 lowercase hex characters");
  }
  return stringToBytes(
    `${TRANSPARENCY_ANCHOR_COMMITMENT_DOMAIN}\n${input.saltHex}\n${input.counter}\n${input.checkpointHash}`
  );
}

/** SHA-256 hex of the commitment preimage: the only data published. */
export function anchorCommitmentDigestHex(preimage: Uint8Array): string {
  return createHash("sha256").update(preimage).digest("hex");
}

// ---- Dedicated anchoring key ------------------------------------------------

export interface AnchorSigningKey {
  /** 32-byte P-256 private scalar. Caller MUST zero after use. */
  privateKey: Uint8Array;
  /** 65-byte uncompressed public point (the fortress's anchor pseudonym). */
  publicKey: Uint8Array;
}

/**
 * Derive the per-fortress anchoring key from the master key. Deterministic
 * (re-derivable at any time; nothing new is persisted), domain-separated
 * from every other purpose key, and never the Ed25519 custody key. The
 * astronomically rare derivation outside the P-256 scalar range retries
 * with an appended counter.
 */
export function deriveAnchorSigningKey(masterKey: Uint8Array): AnchorSigningKey {
  for (let attempt = 0; attempt < 8; attempt++) {
    const purpose =
      attempt === 0
        ? TRANSPARENCY_ANCHOR_SIGNING_PURPOSE
        : `${TRANSPARENCY_ANCHOR_SIGNING_PURPOSE}/retry-${attempt}`;
    const candidate = derivePurposeKey(masterKey, purpose);
    if (p256.utils.isValidPrivateKey(candidate)) {
      return {
        privateKey: candidate,
        publicKey: p256.getPublicKey(candidate, false),
      };
    }
    candidate.fill(0);
  }
  // 8 consecutive out-of-range 256-bit HKDF outputs: probability ~2^-256.
  throw new Error("anchor signing key derivation failed (out of range)");
}

/**
 * SPKI PEM encoding of the uncompressed P-256 public point, the format
 * Rekor expects in `spec.signature.publicKey.content`.
 */
export function anchorPublicKeyPem(publicKey: Uint8Array): string {
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new Error("anchor public key must be a 65-byte uncompressed P-256 point");
  }
  // SPKI prefix for id-ecPublicKey + prime256v1 with a 65-byte BIT STRING.
  // Must match `SPKI_P256_PREFIX_HEX` in `transparency/anchor-verify.ts`, which
  // strips exactly this prefix back off when it parses the PEM this function
  // writes. 26 prefix bytes + the 65-byte point = the 91-byte DER length that
  // file's parser checks for.
  const prefix = Buffer.from(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200",
    "hex"
  );
  const der = Buffer.concat([prefix, Buffer.from(publicKey)]);
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}

/** ECDSA P-256 / SHA-256 signature over the preimage, DER-encoded. */
export function signAnchorPreimage(
  privateKey: Uint8Array,
  preimage: Uint8Array
): Uint8Array {
  const digest = createHash("sha256").update(preimage).digest();
  return p256.sign(digest, privateKey, { lowS: true }).toDERRawBytes();
}

// ---- Rekor hashedrekord proposal ---------------------------------------------

/**
 * The exact JSON document POSTed to Rekor. Audit it here: the only
 * fortress-derived values are the salted digest, the signature bytes, and
 * the derived public key. Nothing else crosses the boundary.
 */
export interface HashedRekordProposal {
  apiVersion: "0.0.1";
  kind: "hashedrekord";
  spec: {
    data: { hash: { algorithm: "sha256"; value: string } };
    signature: {
      content: string;
      publicKey: { content: string };
    };
  };
}

export function buildHashedRekordProposal(input: {
  digestHex: string;
  signatureDer: Uint8Array;
  publicKeyPem: string;
}): HashedRekordProposal {
  if (!HEX64.test(input.digestHex)) {
    throw new Error("anchor digest must be 64 lowercase hex characters");
  }
  return {
    apiVersion: "0.0.1",
    kind: "hashedrekord",
    spec: {
      data: { hash: { algorithm: "sha256", value: input.digestHex } },
      signature: {
        content: Buffer.from(input.signatureDer).toString("base64"),
        publicKey: {
          content: Buffer.from(input.publicKeyPem, "utf8").toString("base64"),
        },
      },
    },
  };
}

// ---- Anchor config (MAC-authenticated, local only) ---------------------------

/** Operator-controlled anchoring configuration. Stored locally, MAC'd. */
export interface AnchorConfigData {
  enabled: boolean;
  /** 64-hex per-fortress commitment salt. Generated at first enable, kept
   * across disable/re-enable so earlier anchors stay verifiable. */
  salt: string;
  rekor_url: string;
  /** SSRF escape hatch for local/dev Rekor instances: when true, the URL
   * guard (https-only, no loopback/private/link-local/metadata addresses)
   * is bypassed. Set ONLY by passing --allow-unsafe-rekor-url at enable
   * time; never inherited across re-enables; recorded here (under the
   * config MAC), in the enable audit entry, and in `anchor status` output
   * so it can never be silently on. */
  allow_unsafe_url: boolean;
  /** Consent record: when the operator confirmed, and the SHA-256 of the
   * exact consent text they confirmed. */
  consent: {
    accepted_at: string;
    text_sha256: string;
  };
}

export function isAnchorConfigData(value: unknown): value is AnchorConfigData {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  const consent = candidate.consent as Record<string, unknown> | undefined;
  return (
    typeof candidate.enabled === "boolean" &&
    typeof candidate.salt === "string" &&
    HEX64.test(candidate.salt) &&
    typeof candidate.rekor_url === "string" &&
    candidate.rekor_url.length > 0 &&
    typeof candidate.allow_unsafe_url === "boolean" &&
    !!consent &&
    typeof consent === "object" &&
    typeof consent.accepted_at === "string" &&
    typeof consent.text_sha256 === "string" &&
    HEX64.test(consent.text_sha256 as string)
  );
}

/** Domain-separated MAC input for the config envelope. */
export function anchorConfigMacInput(data: AnchorConfigData): Uint8Array {
  return stringToBytes(
    TRANSPARENCY_ANCHOR_CONFIG_MAC_DOMAIN + canonicalJson(data)
  );
}

// ---- Anchor receipts (local evidence of every anchor action) -----------------

export interface RekorEntryRef {
  uuid: string;
  log_index: number;
  log_id: string;
  integrated_time: number;
  /** The canonical Rekor entry body (base64), kept verbatim so the PR-3
   * offline verifier can recompute the leaf hash and rebind the entry to
   * the commitment digest, the fortress anchoring key, and the P-256
   * signature with no network access. */
  body_b64?: string;
  /** Rekor's verification blob (inclusion proof + signed entry timestamp),
   * kept verbatim for the PR-3 offline inclusion-proof verifier. */
  verification?: Record<string, unknown>;
}

export interface AnchorReceiptBase {
  anchor_kind: "transparency-anchor-receipt";
  schema_version: typeof TRANSPARENCY_ANCHOR_SCHEMA_VERSION;
  counter: number;
  checkpoint_hash: string;
  commitment_digest: string;
  rekor_url: string;
}

export interface AnchoredReceipt extends AnchorReceiptBase {
  status: "anchored";
  anchored_at: string;
  rekor: RekorEntryRef;
}

export interface FailedAnchorReceipt extends AnchorReceiptBase {
  status: "failed";
  failed_at: string;
  error: string;
}

export type AnchorReceipt = AnchoredReceipt | FailedAnchorReceipt;

export function isAnchorReceipt(value: unknown): value is AnchorReceipt {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  if (
    candidate.anchor_kind !== "transparency-anchor-receipt" ||
    candidate.schema_version !== TRANSPARENCY_ANCHOR_SCHEMA_VERSION ||
    typeof candidate.counter !== "number" ||
    !Number.isSafeInteger(candidate.counter) ||
    candidate.counter <= 0 ||
    typeof candidate.checkpoint_hash !== "string" ||
    !HEX64.test(candidate.checkpoint_hash) ||
    typeof candidate.commitment_digest !== "string" ||
    !HEX64.test(candidate.commitment_digest) ||
    typeof candidate.rekor_url !== "string"
  ) {
    return false;
  }
  if (candidate.status === "anchored") {
    const rekor = candidate.rekor as Record<string, unknown> | undefined;
    return (
      typeof candidate.anchored_at === "string" &&
      !!rekor &&
      typeof rekor === "object" &&
      typeof rekor.uuid === "string" &&
      typeof rekor.log_index === "number" &&
      typeof rekor.log_id === "string" &&
      typeof rekor.integrated_time === "number"
    );
  }
  if (candidate.status === "failed") {
    return (
      typeof candidate.failed_at === "string" &&
      typeof candidate.error === "string"
    );
  }
  return false;
}

/** Hash of the consent text, recorded in the config envelope. */
export function consentTextSha256(text: string): string {
  return sha256Hex(text);
}
