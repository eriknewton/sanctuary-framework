/**
 * Broker daemon producer signatures for process-liveness evidence.
 *
 * This is intentionally separate from the fortress identity key. The broker
 * daemon owns a dedicated Ed25519 keypair under the broker policy directory and
 * publishes only the public half for read-side feature-health verification.
 */

import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { dirname, join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";

import { canonicalJson } from "../audit/chain.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import {
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
} from "./liveness-constants.js";

const ENCODER = new TextEncoder();

export const BROKER_PRODUCER_PUBKEY_RELPATH =
  "policy/broker/liveness-producer.pub" as const;
export const BROKER_PRODUCER_PRIVKEY_RELPATH =
  "policy/broker/liveness-producer.key" as const;
export const BROKER_PRODUCER_SEQ_RELPATH =
  "policy/broker/liveness-producer.seq" as const;

export const BROKER_PRODUCER_SIG_DOMAIN_PREFIX =
  "sanctuary.broker-mcp.liveness-producer.v1\n" as const;
export const BROKER_PRODUCER_SIG_KEY_ID_V1 =
  "broker-liveness-producer-v1" as const;
export const BROKER_PRODUCER_SIGNATURE_SCHEME_V1 = "ed25519-v1" as const;

export const BROKER_EVIDENCE_BASIS_DETAIL_KEY = "broker_evidence_basis" as const;
export const BROKER_EVIDENCE_BASIS_PRODUCER_SIGNED = "producer_signed" as const;
export const BROKER_PRODUCER_SIG_DETAIL_KEY = "broker_producer_sig" as const;
export const BROKER_PRODUCER_KID_DETAIL_KEY = "broker_producer_kid" as const;
export const BROKER_PRODUCER_SIGNATURE_SCHEME_DETAIL_KEY =
  "broker_producer_signature_scheme" as const;
export const BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY =
  "broker_producer_signed_canonical" as const;
export const BROKER_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY =
  "broker_producer_captured_at_ms" as const;

export type BrokerLivenessOperation =
  | typeof BROKER_DAEMON_HEARTBEAT_OPERATION
  | typeof BROKER_DAEMON_STAND_DOWN_OPERATION;

export interface BrokerProducerSignedBody {
  operation: BrokerLivenessOperation;
  captured_at: string;
  captured_at_unix_ms: number;
  seq: number;
}

export type BrokerProducerKeyLoad =
  | { status: "present"; keyB64url: string }
  | { status: "absent" }
  | { status: "unreadable"; reason: string };

export interface BrokerProducerSignatureInput {
  eventCanonicalJson: string;
  capturedAtUnixMs: number;
  seq: number;
  signatureB64url: string | null | undefined;
  keyId: string | null | undefined;
  signatureScheme: string | null | undefined;
}

export type BrokerProducerSignatureVerdict =
  | { ok: true }
  | { ok: false; reason: string };

export function resolveBrokerProducerPubKeyPath(storagePath: string): string {
  return join(storagePath, BROKER_PRODUCER_PUBKEY_RELPATH);
}

export function resolveBrokerProducerPrivKeyPath(storagePath: string): string {
  return join(storagePath, BROKER_PRODUCER_PRIVKEY_RELPATH);
}

export function resolveBrokerProducerSeqPath(storagePath: string): string {
  return join(storagePath, BROKER_PRODUCER_SEQ_RELPATH);
}

export async function loadBrokerProducerKey(
  storagePath: string,
): Promise<BrokerProducerKeyLoad> {
  const pubKeyPath = resolveBrokerProducerPubKeyPath(storagePath);
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await readFile(pubKeyPath));
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") return { status: "absent" };
    return {
      status: "unreadable",
      reason: `broker_producer_key_unreadable: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  if (bytes.length !== 32) {
    return {
      status: "unreadable",
      reason: `broker_producer_key_wrong_length: ${bytes.length} (expected 32) at ${pubKeyPath}`,
    };
  }
  return { status: "present", keyB64url: toBase64url(bytes) };
}

export class BrokerProducerSigner {
  private nextSeqValue: number;

  constructor(
    private readonly privateKey: Uint8Array,
    private readonly seqPath: string,
    readonly publicKeyB64url: string,
    initialSeq: number,
  ) {
    this.nextSeqValue = initialSeq + 1;
  }

  async signDetails(
    operation: BrokerLivenessOperation,
    capturedAtUnixMs: number,
  ): Promise<Record<string, unknown>> {
    const seq = this.nextSeqValue;
    this.nextSeqValue += 1;
    await persistSeq(this.seqPath, seq);
    return buildBrokerProducerSignedDetails({
      operation,
      capturedAtUnixMs,
      seq,
      privateKey: this.privateKey,
    });
  }
}

export async function loadOrCreateBrokerProducerSigner(
  storagePath: string,
): Promise<BrokerProducerSigner> {
  const privKeyPath = resolveBrokerProducerPrivKeyPath(storagePath);
  const pubKeyPath = resolveBrokerProducerPubKeyPath(storagePath);
  const seqPath = resolveBrokerProducerSeqPath(storagePath);
  await mkdir(dirname(privKeyPath), { recursive: true, mode: 0o700 });

  let privateKey: Uint8Array;
  try {
    privateKey = new Uint8Array(await readFile(privKeyPath));
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code !== "ENOENT") throw err;
    privateKey = ed25519.utils.randomPrivateKey();
    await writeRestrictedFile(privKeyPath, privateKey, 0o600);
  }
  if (privateKey.length !== 32) {
    throw new Error(
      `broker liveness private key at ${privKeyPath} is ${privateKey.length} bytes, expected 32`,
    );
  }

  const publicKey = ed25519.getPublicKey(privateKey);
  await writeRestrictedFile(pubKeyPath, publicKey, 0o644);
  const initialSeq = await readLastSeq(seqPath);
  return new BrokerProducerSigner(
    privateKey,
    seqPath,
    toBase64url(publicKey),
    initialSeq,
  );
}

export function brokerProducerSignedBody(
  operation: BrokerLivenessOperation,
  capturedAtUnixMs: number,
  seq: number,
): BrokerProducerSignedBody {
  return {
    operation,
    captured_at: new Date(capturedAtUnixMs).toISOString(),
    captured_at_unix_ms: capturedAtUnixMs,
    seq,
  };
}

export function brokerProducerSigningBytes(
  eventCanonicalJson: string,
  capturedAtUnixMs: number,
  seq: number,
): Uint8Array {
  return ENCODER.encode(
    `${BROKER_PRODUCER_SIG_DOMAIN_PREFIX}${eventCanonicalJson}\n${capturedAtUnixMs}\n${seq}`,
  );
}

export function buildBrokerProducerSignedDetails(input: {
  operation: BrokerLivenessOperation;
  capturedAtUnixMs: number;
  seq: number;
  privateKey: Uint8Array;
}): Record<string, unknown> {
  const canonical = canonicalJson(
    brokerProducerSignedBody(
      input.operation,
      input.capturedAtUnixMs,
      input.seq,
    ),
  );
  const sig = ed25519.sign(
    brokerProducerSigningBytes(canonical, input.capturedAtUnixMs, input.seq),
    input.privateKey,
  );
  return {
    seq: input.seq,
    [BROKER_EVIDENCE_BASIS_DETAIL_KEY]: BROKER_EVIDENCE_BASIS_PRODUCER_SIGNED,
    [BROKER_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
    [BROKER_PRODUCER_KID_DETAIL_KEY]: BROKER_PRODUCER_SIG_KEY_ID_V1,
    [BROKER_PRODUCER_SIGNATURE_SCHEME_DETAIL_KEY]:
      BROKER_PRODUCER_SIGNATURE_SCHEME_V1,
    [BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: canonical,
    [BROKER_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: input.capturedAtUnixMs,
  };
}

export function verifyBrokerProducerSignature(
  input: BrokerProducerSignatureInput,
  pinnedProducerKeyB64url: string,
): BrokerProducerSignatureVerdict {
  if (
    typeof input.signatureB64url !== "string" ||
    input.signatureB64url.length === 0
  ) {
    return { ok: false, reason: "broker_producer_signature_missing" };
  }
  if (input.keyId !== BROKER_PRODUCER_SIG_KEY_ID_V1) {
    return {
      ok: false,
      reason: `broker_producer_key_id_mismatch: ${String(input.keyId)}`,
    };
  }
  if (input.signatureScheme !== BROKER_PRODUCER_SIGNATURE_SCHEME_V1) {
    return {
      ok: false,
      reason: `broker_producer_signature_scheme_mismatch: ${String(
        input.signatureScheme,
      )}`,
    };
  }
  if (
    !Number.isSafeInteger(input.seq) ||
    !Number.isSafeInteger(input.capturedAtUnixMs)
  ) {
    return { ok: false, reason: "broker_producer_bad_binding_fields" };
  }
  try {
    const key = fromBase64url(pinnedProducerKeyB64url);
    if (key.length !== 32) {
      return { ok: false, reason: "broker_pinned_producer_key_wrong_length" };
    }
    const sig = fromBase64url(input.signatureB64url);
    if (sig.length !== 64) {
      return { ok: false, reason: "broker_producer_signature_wrong_length" };
    }
    const message = brokerProducerSigningBytes(
      input.eventCanonicalJson,
      input.capturedAtUnixMs,
      input.seq,
    );
    if (!ed25519.verify(sig, message, key)) {
      return { ok: false, reason: "broker_producer_signature_verification_failed" };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: `broker_producer_signature_verify_error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
}

export function brokerSignedCanonicalOperation(
  details: Record<string, unknown>,
): string | null {
  const canonical = details[BROKER_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  if (typeof canonical !== "string") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonical);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const op = (parsed as Record<string, unknown>).operation;
  return typeof op === "string" ? op : null;
}

export function brokerProducerMarkerDetails(
  signedDetails: Record<string, unknown>,
): Record<string, unknown> {
  return {
    source: "broker-server",
    ...signedDetails,
    [BROKER_DAEMON_AUDIT_PROVENANCE_KEY]: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
  };
}

async function readLastSeq(seqPath: string): Promise<number> {
  try {
    const raw = await readFile(seqPath, "utf8");
    const parsed = Number(raw.trim());
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
      throw new Error("invalid sequence");
    }
    return parsed;
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") return 0;
    throw err;
  }
}

async function persistSeq(seqPath: string, seq: number): Promise<void> {
  await writeRestrictedFile(seqPath, Buffer.from(`${seq}\n`, "utf8"), 0o600);
}

async function writeRestrictedFile(
  path: string,
  bytes: Uint8Array,
  mode: number,
): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, bytes, { mode });
  try {
    await chmod(path, mode);
  } catch {
    // Non-POSIX filesystems may not support chmod.
  }
}
