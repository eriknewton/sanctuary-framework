/**
 * Per-event producer-signature verification (Slice L1, consumer side).
 *
 * The Linux daemon signs every drained enforcement event with a key the
 * in-process TS server cannot reach (see
 * `castle-wall-daemon/src/ipc/producer_sig.rs`). This module verifies that
 * signature against the daemon's TOFU-pinned producer public key BEFORE the
 * audit consumer accepts the event as enforcement evidence.
 *
 * # Why this closes the in-process forgery hole
 *
 * Before Slice L1, an in-process TS module already holding the `AuditLog`
 * reference could append an `l1 egress_blocked` entry stamped with the
 * `cw_source` provenance marker, and it would hash-chain cleanly and render
 * the dashboard green — without the wall having done anything. The marker is a
 * plain string; nothing stops a co-located module from writing it.
 *
 * A producer signature cannot be forged that way: the signing key lives only
 * in the daemon process / a root-owned file. The in-process server holds only
 * the *public* key, which can verify but never sign. So a forged entry lacking
 * a valid producer signature fails verification here and is rejected as
 * enforcement evidence (fail closed).
 *
 * # Byte-exact cross-language contract
 *
 * `producerSigningBytes()` MUST be byte-identical to `producer_signing_bytes`
 * in the Rust daemon. The signed message is:
 *
 * ```text
 * DOMAIN_PREFIX                 (ends in '\n')
 * eventCanonicalJson '\n'
 * capturedAtUnixMs (decimal ASCII) '\n'
 * seq (decimal ASCII)
 * ```
 *
 * `eventCanonicalJson` is the exact canonical-JSON string the daemon committed
 * to its WAL and signed. The consumer verifies over that **same string** (not
 * a re-canonicalized object), so there is no re-encoding drift: the producer
 * and consumer hash identical bytes.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { ed25519 } from "@noble/curves/ed25519";

import {
  CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../constants.js";

const ENCODER = new TextEncoder();

/**
 * The canonical relative location, under a fortress storage path, of the
 * audit-producer public key the Linux daemon publishes. The daemon writes its
 * 32-byte verifying key world-readable here (see `producer_pub_key_path` in
 * `castle-wall-daemon/src/config.rs`, whose default `policy/egress` segment this
 * mirrors). Both the audit CONSUMER and the read-side posture/feature-health
 * READERS resolve the pinned key through this SINGLE constant so they can never
 * diverge onto different bases — "a reader must never read with a weaker basis
 * than the consumer wrote with" (Slice P).
 */
export const CASTLE_WALL_PRODUCER_PUBKEY_RELPATH = "policy/egress/audit-producer.pub";

/**
 * Resolve the absolute path to the published audit-producer public key for a
 * fortress rooted at `storagePath`. The daemon must be launched with its
 * `--producer-pub-key` (or `--policy-dir`) pointed at this same location so the
 * key it publishes is the key the in-process server pins (Slice P provisioning
 * contract). Centralizing the path here is what keeps the consumer and the
 * readers on one source of truth.
 */
export function resolveProducerPubKeyPath(storagePath: string): string {
  return join(storagePath, CASTLE_WALL_PRODUCER_PUBKEY_RELPATH);
}

/** The canonical relative location of the daemon-held audit-producer PRIVATE key. */
export const CASTLE_WALL_PRODUCER_PRIVKEY_RELPATH =
  "policy/egress/audit-producer.key";

/** The canonical relative location of the egress policy dir (daemon `--policy-dir`). */
export const CASTLE_WALL_POLICY_DIR_RELPATH = "policy/egress";

/**
 * The daemon-launch argv that BINDS the Linux daemon's key-publish location to
 * the fortress storage path the in-process TS server reads from — closing the
 * daemon↔TS path divergence (codex HIGH #2). Without this the daemon's default
 * `/var/lib/sanctuary/<id>/...` publish path and the TS `<storage_path>/...`
 * read path differ, so the TS side sees `absent` while the daemon signs and the
 * close silently never activates.
 *
 * Any launcher that starts the Linux daemon for a fortress MUST splice these
 * args (in addition to `--fortress-id`, `--socket-path`, etc.) so the published
 * `audit-producer.pub` lands at exactly `resolveProducerPubKeyPath(storagePath)`.
 * Deriving both halves here from ONE input is what makes the binding
 * correct-by-construction rather than a convention a launcher can forget.
 *
 * Mirrors the daemon's `--policy-dir`, `--producer-key`, `--producer-pub-key`
 * flags (`castle-wall-daemon/src/config.rs`).
 */
export function producerKeyDaemonLaunchArgs(storagePath: string): string[] {
  return [
    "--policy-dir",
    join(storagePath, CASTLE_WALL_POLICY_DIR_RELPATH),
    "--producer-key",
    join(storagePath, CASTLE_WALL_PRODUCER_PRIVKEY_RELPATH),
    "--producer-pub-key",
    resolveProducerPubKeyPath(storagePath),
  ];
}

/**
 * Outcome of attempting to load the fortress's pinned producer key from the
 * canonical path. The three states are kept DISTINCT on purpose — collapsing
 * "absent" and "unreadable" into a single `null` is exactly the fail-open the
 * Slice P contract forbids:
 *
 *   - `present`  — a valid 32-byte key was loaded. Both sides activate the
 *     producer-signed close.
 *   - `absent`   — no key file exists (ENOENT). The honest macOS / pre-provision
 *     floor: both sides stay on the channel-authenticity basis. NOT a failure.
 *   - `unreadable` — a key file EXISTS but could not be loaded (wrong length,
 *     permission error, malformed). A key is EXPECTED here, so silently
 *     dropping to the channel basis would let a reader run a weaker basis than a
 *     key-bearing consumer. The caller MUST fail honestly (surface
 *     degraded/not-armed), never fake-green and never channel-basis.
 */
export type ProducerKeyLoad =
  | { status: "present"; keyB64url: string }
  | { status: "absent" }
  | { status: "unreadable"; reason: string };

/**
 * Load the fortress's pinned producer key through the single canonical path,
 * distinguishing absent (channel basis is honest) from present-but-unreadable
 * (a key is expected — fail honestly). This is the SAFE-activation primitive
 * Slice P wires into both the consumer and the readers: an `absent` result is
 * the only one that legitimately yields the channel basis.
 */
export async function loadFortressProducerKey(
  storagePath: string
): Promise<ProducerKeyLoad> {
  const pubKeyPath = resolveProducerPubKeyPath(storagePath);
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await readFile(pubKeyPath));
  } catch (err) {
    const code =
      err && typeof err === "object" && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") {
      // No key published (macOS / pre-provision Linux): the channel basis is
      // the honest floor. This is the ONLY path to the channel basis.
      return { status: "absent" };
    }
    // The file exists but we could not read it (EACCES, EISDIR, ...). A key is
    // expected — do not pretend it is absent.
    return {
      status: "unreadable",
      reason: `producer_key_unreadable: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  if (bytes.length !== 32) {
    // A present-but-malformed key is expected-but-broken, not absent.
    return {
      status: "unreadable",
      reason: `producer_key_wrong_length: ${bytes.length} (expected 32) at ${pubKeyPath}`,
    };
  }
  return { status: "present", keyB64url: toBase64url(bytes) };
}

/** Encode bytes as unpadded base64url. */
export function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Load the daemon's published audit-producer public key from disk and return
 * it as base64url-no-pad. The file holds 32 raw Ed25519 verifying-key bytes
 * (the daemon writes it world-readable at `<policy_dir>/audit-producer.pub`).
 * Throws if the file is missing or not exactly 32 bytes — a caller that wants
 * L1 enforcement MUST get a valid key or fail, never silently degrade.
 */
export async function loadPinnedProducerKeyB64url(
  pubKeyPath: string
): Promise<string> {
  const bytes = new Uint8Array(await readFile(pubKeyPath));
  if (bytes.length !== 32) {
    throw new Error(
      `audit-producer public key at ${pubKeyPath} is ${bytes.length} bytes, expected 32`
    );
  }
  return toBase64url(bytes);
}

/** Decode an unpadded base64url string to bytes. Throws on malformed input. */
export function fromBase64url(s: string): Uint8Array {
  const normalized = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const pad = (4 - (normalized.length % 4)) % 4;
  const std = (normalized + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Compute the exact bytes the daemon signed for one enforcement event.
 * Mirror of the Rust `producer_signing_bytes`.
 */
export function producerSigningBytes(
  eventCanonicalJson: string,
  capturedAtUnixMs: number,
  seq: number
): Uint8Array {
  return ENCODER.encode(
    `${CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX}${eventCanonicalJson}\n${capturedAtUnixMs}\n${seq}`
  );
}

/** The signed-tuple + signature the consumer needs to verify one event. */
export interface ProducerSignatureInput {
  /** The exact canonical-JSON string the daemon signed (the WAL bytes). */
  eventCanonicalJson: string;
  /** Capture timestamp the signature is bound to (anti-replay). */
  capturedAtUnixMs: number;
  /** Monotonic WAL sequence the signature is bound to (anti-replay). */
  seq: number;
  /** base64url-no-pad of the 64-byte Ed25519 signature. */
  signatureB64url: string | null | undefined;
  /** Key id selecting the pinned producer public key. */
  keyId: string | null | undefined;
}

/** Result of a verification attempt. Verdicts are explicit; never "best effort". */
export type ProducerSignatureVerdict =
  | { ok: true }
  | { ok: false; reason: string };

/**
 * Verify a producer signature against a pinned producer public key.
 *
 * FAIL CLOSED: any missing field, length mismatch, key-id mismatch, malformed
 * encoding, or signature-verification failure returns `{ ok: false }`. A
 * thrown exception inside `@noble` is caught and converted to a failure — it
 * is never allowed to surface as an accept.
 *
 * @param pinnedProducerKeyB64url the TOFU-pinned producer public key
 *   (base64url-no-pad, 32 raw verifying-key bytes).
 */
export function verifyProducerSignature(
  input: ProducerSignatureInput,
  pinnedProducerKeyB64url: string,
  expectedKeyId: string = CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1
): ProducerSignatureVerdict {
  if (
    typeof input.signatureB64url !== "string" ||
    input.signatureB64url.length === 0
  ) {
    return { ok: false, reason: "producer_signature_missing" };
  }
  if (input.keyId !== expectedKeyId) {
    return {
      ok: false,
      reason: `producer_key_id_mismatch: ${String(input.keyId)}`,
    };
  }
  if (
    !Number.isSafeInteger(input.seq) ||
    !Number.isSafeInteger(input.capturedAtUnixMs)
  ) {
    return { ok: false, reason: "producer_signature_bad_binding_fields" };
  }
  try {
    const key = fromBase64url(pinnedProducerKeyB64url);
    if (key.length !== 32) {
      return { ok: false, reason: "pinned_producer_key_wrong_length" };
    }
    const sig = fromBase64url(input.signatureB64url);
    if (sig.length !== 64) {
      return { ok: false, reason: "producer_signature_wrong_length" };
    }
    const message = producerSigningBytes(
      input.eventCanonicalJson,
      input.capturedAtUnixMs,
      input.seq
    );
    if (!ed25519.verify(sig, message, key)) {
      return { ok: false, reason: "producer_signature_verification_failed" };
    }
    return { ok: true };
  } catch (err) {
    return {
      ok: false,
      reason: `producer_signature_verify_error: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
}
