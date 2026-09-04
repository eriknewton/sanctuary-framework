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
 * the dashboard green, without the wall having done anything. The marker is a
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

import {
  CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../constants.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../../core/crypto-suite-registry.js";
import { verify as verifyStrictEd25519 } from "../../core/identity.js";

const ENCODER = new TextEncoder();

/**
 * Legacy/test fortress-relative producer-public-key location. The hardened
 * Linux server profile uses `resolveLinuxSystemProducerPubKeyPath` instead so
 * its non-root broker can traverse to the public half without gaining access to
 * root-only policy/private-key state. macOS and hermetic fixtures retain this
 * relative layout, and their audit consumer/readers still share this one
 * constant so they cannot diverge onto different verification bases.
 */
export const CASTLE_WALL_PRODUCER_PUBKEY_RELPATH = "policy/egress/audit-producer.pub";
export const CASTLE_WALL_LINUX_STATE_ROOT = "/var/lib/sanctuary";
export const CASTLE_WALL_LINUX_RUNTIME_ROOT = "/run/sanctuary";

/**
 * Root-published producer public key for the pre-provisioned Linux service.
 * Only the public half lives in the broker-traversable runtime directory; the
 * private seed stays under the root-only `/var/lib/sanctuary` state tree.
 */
export function resolveLinuxSystemProducerPubKeyPath(fortressId: string): string {
  if (!/^[a-f0-9]{8,64}$/.test(fortressId)) {
    throw new Error("fortress id is outside the canonical lowercase-hex grammar");
  }
  return join(CASTLE_WALL_LINUX_RUNTIME_ROOT, fortressId, "audit-producer.pub");
}

/** Host-wide macOS custody directory owned by the root helper. */
export const CASTLE_WALL_MACOS_GLOBAL_PINNED_PUBKEY_DIR =
  "/Library/Application Support/Sanctuary";

/**
 * Host-wide macOS audit-producer public key. The root helper publishes this
 * file; macOS readers prefer it over the fortress-relative Linux path.
 */
export const CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH =
  `${CASTLE_WALL_MACOS_GLOBAL_PINNED_PUBKEY_DIR}/castle-audit-producer.pub`;

/**
 * Resolve the legacy fortress-relative producer-key path used by macOS and
 * test fixtures. Linux server activation must use
 * `resolveLinuxSystemProducerPubKeyPath`; it never trusts this caller-writable
 * tree as the producer-key authority.
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
 * Legacy/pure installer helper retained for macOS fixtures. The Linux runtime
 * launcher must not call it: the pre-provisioned server profile fixes all
 * privileged paths under `/var/lib/sanctuary/<fortress-id>` and rejects
 * overrides.
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
 * canonical path. The three states are kept DISTINCT on purpose: collapsing
 * "absent" and "unreadable" into a single `null` is exactly the fail-open the
 * Slice P contract forbids:
 *
 *   - `present`  - a valid 32-byte key was loaded. Both sides activate the
 *     producer-signed close.
 *   - `absent`   - no key file exists (ENOENT). The honest macOS / pre-provision
 *     floor: both sides stay on the channel-authenticity basis. NOT a failure.
 *   - `unreadable` - a key file EXISTS but could not be loaded (wrong length,
 *     permission error, malformed). A key is EXPECTED here, so silently
 *     dropping to the channel basis would let a reader run a weaker basis than a
 *     key-bearing consumer. The caller MUST fail honestly (surface
 *     degraded/not-armed), never fake-green and never channel-basis.
 */
export type ProducerKeyLoad =
  | { status: "present"; keyB64url: string }
  | { status: "absent" }
  | { status: "unreadable"; reason: string };

/** Platform/path override hooks for tests and non-default macOS helper layouts. */
export interface ProducerKeyLoadOptions {
  platform?: NodeJS.Platform;
  macosProducerPubKeyPath?: string;
  /** Explicit root-owned service key path for Linux server enforcement. */
  linuxProducerPubKeyPath?: string;
}

/**
 * Load the fortress's pinned producer key through the single canonical path,
 * distinguishing absent (channel basis is honest) from present-but-unreadable
 * (a key is expected; fail honestly). This is the SAFE-activation primitive
 * Slice P wires into both the consumer and the readers: an `absent` result is
 * the only one that legitimately yields the channel basis.
 *
 * macOS exception: the root helper publishes the audit-producer key host-wide
 * at `/Library/Application Support/Sanctuary/castle-audit-producer.pub`, not
 * only under one fortress storage path. On darwin, prefer that host-wide key;
 * fall back to the fortress-relative key only when the host-wide file is
 * absent. Present-but-unreadable remains fail-honest and does not fall back.
 */
export async function loadFortressProducerKey(
  storagePath: string,
  options: ProducerKeyLoadOptions = {},
): Promise<ProducerKeyLoad> {
  const platform = options.platform ?? process.platform;
  if (platform === "darwin") {
    const macosLoad = await loadProducerKeyFromPath(
      options.macosProducerPubKeyPath ??
        CASTLE_WALL_MACOS_AUDIT_PRODUCER_PUBKEY_PATH,
    );
    if (macosLoad.status !== "absent") return macosLoad;
  }
  if (platform === "linux" && options.linuxProducerPubKeyPath) {
    return loadProducerKeyFromPath(options.linuxProducerPubKeyPath);
  }
  return loadProducerKeyFromPath(resolveProducerPubKeyPath(storagePath));
}

async function loadProducerKeyFromPath(pubKeyPath: string): Promise<ProducerKeyLoad> {
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
    // expected; do not pretend it is absent.
    return {
      status: "unreadable",
      reason: `producer_key_unreadable: ${
        err instanceof Error ? err.message : String(err)
      }`,
    };
  }
  if (bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
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
 * (the server daemon writes it beneath the broker-traversable runtime directory;
 * legacy/test callers may still supply the fortress-relative path explicitly).
 * Throws if the file is missing or not exactly 32 bytes; a caller that wants
 * L1 enforcement MUST get a valid key or fail, never silently degrade.
 */
export async function loadPinnedProducerKeyB64url(
  pubKeyPath: string
): Promise<string> {
  const bytes = new Uint8Array(await readFile(pubKeyPath));
  if (bytes.length !== ED25519_PUBLIC_KEY_BYTES) {
    throw new Error(
      `audit-producer public key at ${pubKeyPath} is ${bytes.length} bytes, expected 32`
    );
  }
  return toBase64url(bytes);
}

/**
 * Strip a contiguous run of '=' from the END of a string in LINEAR time.
 *
 * This is the byte-for-byte equivalent of `.replace(/=+$/, "")` but without the
 * super-linear backtracking that regex exhibits: matching `=+$` against a long
 * run of '=' followed by a non-'=' char is O(n^2) (the engine re-tries the
 * anchored `$` after backtracking each '=' and restarts at every offset). A
 * single reverse scan is O(n) and produces the identical result for ALL inputs
 * (embedded '=' are preserved exactly as `=+$` leaves them; only the trailing
 * run is removed). See CodeQL `js/polynomial-redos`.
 */
function stripTrailingPadding(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 0x3d /* '=' */) end -= 1;
  return end === s.length ? s : s.slice(0, end);
}

/** Decode an unpadded base64url string to bytes. Throws on malformed input. */
export function fromBase64url(s: string): Uint8Array {
  const normalized = stripTrailingPadding(
    s.replace(/\+/g, "-").replace(/\//g, "_")
  );
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
 * thrown exception inside `@noble` is caught and converted to a failure; it
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
  // Defense-in-depth: bound the attacker-controlled blob BEFORE decoding it.
  // `fromBase64url` allocates ~3/4 of the input length, so a multi-megabyte
  // valid-base64 blob over daemon IPC would allocate megabytes only to be
  // rejected on the `sig.length !== 64` check below. A real 64-byte Ed25519
  // signature is 88 base64url chars padded / 86 unpadded; 128 leaves clear
  // headroom over any legitimate signature while capping the decode at a few
  // dozen bytes. This fails closed with the SAME verdict shape as any other
  // malformed signature: it neither throws nor leaks why.
  if (input.signatureB64url.length > 128) {
    return { ok: false, reason: "producer_signature_wrong_length" };
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
    if (key.length !== ED25519_PUBLIC_KEY_BYTES) {
      return { ok: false, reason: "pinned_producer_key_wrong_length" };
    }
    const sig = fromBase64url(input.signatureB64url);
    if (sig.length !== ED25519_SIGNATURE_BYTES) {
      return { ok: false, reason: "producer_signature_wrong_length" };
    }
    const message = producerSigningBytes(
      input.eventCanonicalJson,
      input.capturedAtUnixMs,
      input.seq
    );
    if (!verifyStrictEd25519(message, sig, key)) {
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
