/**
 * Sanctuary Federation Protocol v0.1 — Signed-Event Envelope
 *
 * Every federation message rides this envelope. Every message is signed by the
 * emitting node's per-node key and optionally by the authoring principal's key.
 *
 * Hard-gate invariants enforced here:
 * - Reserved extension_envelope keys (§10.1) rejected at pack time.
 * - Reserved event_type namespaces (§10.3) rejected at pack time.
 * - Reserved extension_envelope keys (§10.1) rejected at verify time.
 * - Reserved event_type namespaces (§10.3) rejected at verify time.
 * - Reserved capability bits (§10.2) rejected at verify time.
 * - Unknown extension_envelope keys IGNORED at verify time (forward-compat).
 * - Signatures cover extension_envelope bit-for-bit so v1.x-authored events
 *   with extension content verify on v0.1 receivers.
 *
 * Spec: §4.2, §10.1, §10.3.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { randomBytes } from "../core/random.js";
import { canonicalizeToBytes } from "./canonical-json.js";
import {
  isReservedEventType,
  isReservedExtensionKey,
  hasReservedCapabilityBits,
  PROTOCOL_VERSION,
} from "./constants.js";
import {
  MeshReservedCapabilityBitError,
  MeshReservedEventTypeError,
  MeshReservedExtensionKeyError,
  MeshSignatureError,
} from "./errors.js";
import type {
  ExtensionEnvelope,
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
  SignedEvent,
} from "./types.js";
import { verifyCertChain } from "./trust-root.js";
// a mesh envelope arrives off the wire and is `JSON.parse`d, so every field is
// attacker-controlled until this verifier accepts it; diagnostics go through
// the untrusted-diagnostic chokepoint (STATE-STORE-ERRMSG-INTERP-01).
import { describeUntrusted } from "../errors/index.js";

// ═══════════════════════════════════════════════════════════════════════
// Packing (emitter side)
// ═══════════════════════════════════════════════════════════════════════

export interface PackParams<Payload> {
  event_type: string;
  emitter_node: string;
  emitter_principal: string;
  fortress_id: string;
  causal_parents?: string[];
  payload: Payload;
  monotonic_seq: number;
  extension_envelope?: ExtensionEnvelope;
  node_private_key: Uint8Array;
  principal_private_key?: Uint8Array;
}

/**
 * Pack and sign a v0.1 SignedEvent.
 *
 * Throws MeshReservedEventTypeError if event_type is in a reserved v1.x namespace.
 * Throws MeshReservedExtensionKeyError if extension_envelope populates a reserved key.
 *
 * Both throws are load-bearing for acceptance criterion 10 (the hard gate).
 */
export function packSignedEvent<Payload>(
  params: PackParams<Payload>
): SignedEvent<Payload> {
  if (isReservedEventType(params.event_type)) {
    throw new MeshReservedEventTypeError(params.event_type);
  }
  const ext = params.extension_envelope ?? {};
  for (const key of Object.keys(ext)) {
    if (isReservedExtensionKey(key)) {
      throw new MeshReservedExtensionKeyError(key);
    }
  }

  const payloadBytes = canonicalizeToBytes(params.payload);
  const payload_hash = toBase64url(sha256(payloadBytes));
  const emitted_at = new Date().toISOString();
  const body: Omit<SignedEvent<Payload>, "node_signature" | "principal_signature"> = {
    protocol_version: PROTOCOL_VERSION,
    event_type: params.event_type,
    event_id: generateEventId(params.emitter_node, emitted_at),
    emitter_node: params.emitter_node,
    emitter_principal: params.emitter_principal,
    fortress_id: params.fortress_id,
    causal_parents: params.causal_parents ?? [],
    payload: params.payload,
    payload_hash,
    emitted_at,
    monotonic_seq: params.monotonic_seq,
    extension_envelope: ext,
  };
  const bytesToSign = canonicalizeToBytes(body);
  const nodeSig = ed25519.sign(bytesToSign, params.node_private_key);
  const evt: SignedEvent<Payload> = {
    ...body,
    node_signature: toBase64url(nodeSig),
  };
  if (params.principal_private_key) {
    const principalSig = ed25519.sign(bytesToSign, params.principal_private_key);
    evt.principal_signature = toBase64url(principalSig);
  }
  return evt;
}

/**
 * Event ids are ULIDs. Every numeric literal in the encoder below derives from
 * the ULID spec, so they are stated once here rather than repeated inline:
 *
 *   - the alphabet is Crockford base32, so it has 32 symbols and each symbol
 *     carries 5 bits (hence the `& 31` masks and the `>= 5` bit drain);
 *   - a ULID is 48 bits of timestamp + 80 bits of randomness = 128 bits, which
 *     is 26 base32 characters (ceil(128 / 5)), split 10 + 16;
 *   - 48 bits of timestamp is why the range guard is `0xffffffffffff`, and
 *     80 bits of randomness is why the draw is `randomBytes(10)`;
 *   - the random section therefore starts at character index 10.
 *
 * Monotonicity within a millisecond comes from incrementing the previous random
 * component rather than redrawing, so ids from one emitter sort in emit order.
 */
const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** 5 bits per Crockford base32 symbol. */
const ULID_BITS_PER_CHAR = 5;
/** 32 = the alphabet size, i.e. the base the timestamp section is written in. */
const ULID_RADIX = 2 ** ULID_BITS_PER_CHAR;
/** 31 = the low-5-bits mask used to pull one symbol out of a bit buffer. */
const ULID_CHAR_MASK = ULID_RADIX - 1;
/** 48-bit millisecond timestamp -> ceil(48 / 5) = 10 characters. */
const ULID_TIME_CHARS = 10;
/** 80 bits of randomness -> 10 bytes -> 80 / 5 = 16 characters. */
const ULID_RANDOM_BYTES = 10;
const ULID_RANDOM_CHARS = 16;
/** A ULID is the two sections concatenated: 10 + 16 = 26 characters. */
const ULID_CHARS = ULID_TIME_CHARS + ULID_RANDOM_CHARS;
/** 48 bits of millisecond timestamp; `2 ** 48 - 1` is the largest value it holds. */
const ULID_TIMESTAMP_BITS = 48;
const ULID_MAX_TIMESTAMP_MS = 2 ** ULID_TIMESTAMP_BITS - 1;
/** Byte width, named so the 8-bit shifts in the base32 encoder read as bytes. */
const BITS_PER_BYTE = 8;
/** 255 = the all-ones byte, the carry mask for the monotonic-random increment. */
const BYTE_MASK = 2 ** BITS_PER_BYTE - 1;
const lastUlidByEmitter = new Map<string, { timestampMs: number; random: Uint8Array }>();

function generateEventId(emitterNode: string, emittedAt: string): string {
  const parsedMs = Date.parse(emittedAt);
  const nowMs = Number.isFinite(parsedMs) ? parsedMs : Date.now();
  const previous = lastUlidByEmitter.get(emitterNode);
  const timestampMs =
    previous && nowMs <= previous.timestampMs ? previous.timestampMs : nowMs;
  const entropy =
    previous && timestampMs === previous.timestampMs
      ? incrementUlidRandom(previous.random)
      : randomBytes(ULID_RANDOM_BYTES);
  lastUlidByEmitter.set(emitterNode, {
    timestampMs,
    random: new Uint8Array(entropy),
  });
  return encodeUlid(timestampMs, entropy);
}

function incrementUlidRandom(previous: Uint8Array): Uint8Array {
  const next = new Uint8Array(previous);
  for (let i = next.length - 1; i >= 0; i--) {
    next[i] = (next[i] + 1) & BYTE_MASK;
    if (next[i] !== 0) return next;
  }
  throw new Error("ULID random component exhausted for emitter in one millisecond");
}

function encodeUlid(timestampMs: number, random: Uint8Array): string {
  if (timestampMs < 0 || timestampMs > ULID_MAX_TIMESTAMP_MS) {
    throw new Error(`ULID timestamp out of range: ${timestampMs}`);
  }
  let time = Math.floor(timestampMs);
  const chars = new Array<string>(ULID_CHARS);
  // Timestamp section, written least-significant symbol first.
  for (let i = ULID_TIME_CHARS - 1; i >= 0; i--) {
    chars[i] = ULID_ALPHABET[time & ULID_CHAR_MASK];
    time = Math.floor(time / ULID_RADIX);
  }

  // Random section: shift bytes in 8 bits at a time and drain 5-bit symbols.
  let bitBuffer = 0;
  let bitCount = 0;
  let out = ULID_TIME_CHARS;
  for (const byte of random) {
    bitBuffer = (bitBuffer << BITS_PER_BYTE) | byte;
    bitCount += BITS_PER_BYTE;
    while (bitCount >= ULID_BITS_PER_CHAR) {
      bitCount -= ULID_BITS_PER_CHAR;
      chars[out++] = ULID_ALPHABET[(bitBuffer >> bitCount) & ULID_CHAR_MASK];
    }
  }
  // 80 bits is an exact multiple of 5, so this tail never runs for a full-size
  // random section; it is kept so the encoder stays correct for a shorter one.
  if (bitCount > 0) {
    chars[out] =
      ULID_ALPHABET[(bitBuffer << (ULID_BITS_PER_CHAR - bitCount)) & ULID_CHAR_MASK];
  }
  return chars.join("");
}

// ═══════════════════════════════════════════════════════════════════════
// Verifying (receiver side)
// ═══════════════════════════════════════════════════════════════════════

export interface VerifyContext {
  /** Pinned fortress-master public key for THIS receiver's fortress. */
  pinnedMasterPubkey: FortressMasterPublicKey;
  /** Lookup: emitter_node → that node's NodeIdentityCertificate (must be in local roster). */
  lookupNodeCert: (nodeId: string) => NodeIdentityCertificate | undefined;
  /** Lookup: emitter_principal → that principal's cert. */
  lookupPrincipalCert: (
    principalId: string
  ) => PrincipalCertificate | undefined;
  /**
   * If true (default), reject envelopes whose fortress_id does not match the
   * pinned fortress. This is the cross-operator isolation invariant (§10.5).
   *
   * v1.x MSP extension handlers set this to false (they expect cross-fortress
   * events, and they validate trust via grant-based logic at a higher layer).
   */
  requireMatchingFortress?: boolean;
}

export interface VerifyResult {
  ok: boolean;
  /**
   * Reserved extension_envelope keys encountered during verification.
   * These are keys present on the envelope that ARE in the v1.x reserved set
   * (per Federation Protocol v0.1 spec §10.1). The v0.1 verifier records but
   * does not reject them, so a v1.x consumer can detect that a forward-compat
   * extension payload rode the envelope. Keys not in the reserved set pass
   * through silently per spec §10.1.
   * Empty when no reserved keys ride the envelope.
   */
  recognized_reserved_extension_keys: string[];
  /** Verified event. Same shape as the input; convenience return. */
  event: SignedEvent;
}

/**
 * Verify a v0.1 SignedEvent against the pinned trust root.
 *
 * Throws a named MeshEnvelopeError / MeshCertificateError subclass on failure.
 * Unknown extension_envelope keys that are not in the reserved set pass through
 * silently; reserved namespaces and capability bits are receive-side hard gates.
 */
export function verifySignedEvent(
  evt: SignedEvent,
  ctx: VerifyContext
): VerifyResult {
  if (evt.protocol_version !== PROTOCOL_VERSION) {
    throw new MeshSignatureError(
      `unknown protocol_version ${describeUntrusted(evt.protocol_version)}; v0.1 verifier accepts only ${PROTOCOL_VERSION}`
    );
  }
  const requireMatchingFortress = ctx.requireMatchingFortress ?? true;
  if (
    requireMatchingFortress &&
    evt.fortress_id !== ctx.pinnedMasterPubkey.fortress_id
  ) {
    throw new MeshSignatureError(
      `envelope fortress_id=${describeUntrusted(evt.fortress_id)} does not match pinned fortress ${ctx.pinnedMasterPubkey.fortress_id} — cross-operator isolation invariant`
    );
  }

  // payload_hash coherence check — prevents an attacker swapping payload after signing.
  const freshPayloadHash = toBase64url(
    sha256(canonicalizeToBytes(evt.payload))
  );
  if (freshPayloadHash !== evt.payload_hash) {
    throw new MeshSignatureError(
      `payload_hash mismatch — envelope payload does not match its declared hash`
    );
  }

  // Node signature — cert must be in local roster and chain to pinned master.
  const nodeCert = ctx.lookupNodeCert(evt.emitter_node);
  if (!nodeCert) {
    throw new MeshSignatureError(
      `emitter_node ${describeUntrusted(evt.emitter_node)} is not in local roster`
    );
  }
  if (hasReservedCapabilityBits(nodeCert.capabilities)) {
    throw new MeshReservedCapabilityBitError(nodeCert.capabilities);
  }
  const principalCert = ctx.lookupPrincipalCert(evt.emitter_principal);
  if (evt.principal_signature && !principalCert) {
    throw new MeshSignatureError(
      `emitter_principal ${describeUntrusted(evt.emitter_principal)} is not in local roster but a principal_signature is present`
    );
  }
  // Chain-validate every node cert, including system-principal events. The
  // certificate's issuer is authoritative for the node → principal hop.
  const issuerPrincipalCert = ctx.lookupPrincipalCert(
    nodeCert.parent_chain.principal_id
  );
  if (!issuerPrincipalCert) {
    throw new MeshSignatureError(
      `node cert issuer principal ${nodeCert.parent_chain.principal_id} is not in local roster`
    );
  }
  verifyCertChain(nodeCert, issuerPrincipalCert, ctx.pinnedMasterPubkey);

  // Rebuild the canonical body that was signed.
  const body: Omit<SignedEvent, "node_signature" | "principal_signature"> = {
    protocol_version: evt.protocol_version,
    event_type: evt.event_type,
    event_id: evt.event_id,
    emitter_node: evt.emitter_node,
    emitter_principal: evt.emitter_principal,
    fortress_id: evt.fortress_id,
    causal_parents: evt.causal_parents,
    payload: evt.payload,
    payload_hash: evt.payload_hash,
    emitted_at: evt.emitted_at,
    monotonic_seq: evt.monotonic_seq,
    extension_envelope: evt.extension_envelope,
  };
  const bytesToVerify = canonicalizeToBytes(body);

  const nodeOk = ed25519.verify(
    fromBase64url(evt.node_signature),
    bytesToVerify,
    fromBase64url(nodeCert.node_pubkey)
  );
  if (!nodeOk) {
    throw new MeshSignatureError(
      `node_signature does not verify against ${describeUntrusted(evt.emitter_node)}`
    );
  }

  if (evt.principal_signature && principalCert) {
    const principalOk = ed25519.verify(
      fromBase64url(evt.principal_signature),
      bytesToVerify,
      fromBase64url(principalCert.principal_pubkey)
    );
    if (!principalOk) {
      throw new MeshSignatureError(
        `principal_signature does not verify against ${describeUntrusted(evt.emitter_principal)}`
      );
    }
  }

  if (isReservedEventType(evt.event_type)) {
    throw new MeshReservedEventTypeError(evt.event_type);
  }

  // Forward-compat: keys not in the reserved set are silently passed through.
  // Reserved keys are hard-gated on receive so future semantics never enter
  // verified v0.1 state.
  const recognized_reserved_extension_keys: string[] = [];
  for (const key of Object.keys(evt.extension_envelope ?? {})) {
    if (isReservedExtensionKey(key)) {
      throw new MeshReservedExtensionKeyError(key);
    }
  }

  return { ok: true, recognized_reserved_extension_keys, event: evt };
}
