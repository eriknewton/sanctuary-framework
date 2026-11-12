import { randomBytes } from "node:crypto";
import { canonicalBytes, decodeCanonical, refuse, INERT_PAYLOAD_SCHEMA, SIGNER_HEADER_MAX_BYTES, UNLOCK_CHALLENGE_DOMAIN } from "./contract.js";
import { parseStrict } from "../smb/parse-strict.js";
import { createRecordSigner, type RecordRequest, type SigningGrant } from "./record-signer.js";
import { EncryptedIdentityProvider } from "./identity-provider.js";
import { strictVerify } from "./strict-verifier.js";
import type { StoredIdentity } from "../core/identity.js";

// Must match business_profile/signer_service.rs and custody.rs, and the service unit ExecStart.
export const SIGNER_BINARY = "/usr/libexec/sanctuary-business-signer";
export const LENGTH_BYTES = 4;
export const RESPONSE_MAX_BYTES = SIGNER_HEADER_MAX_BYTES;
export const NS_PER_MS = 1_000_000n;
const SELF_TEST_NONCE_BYTES = 32;
const ED25519_PUBLIC_BYTES = 32;
// This inert counter adapter establishes transport composition; later writers supply their own closed payload adapters.
export const INERT_COUNTER_SCHEMA = INERT_PAYLOAD_SCHEMA;
// Must match record-signer.ts: this complete frozen dispatch has no installed-business constructor.
export const INERT_SIGNABLE_ADAPTERS = Object.freeze([Object.freeze({kind: "counter", schema: INERT_COUNTER_SCHEMA})]);
export const INERT_RECORD_KIND = "counter";
export function publicFrame(value: unknown): Buffer {
  const body = Buffer.from(canonicalBytes(value));
  if (body.length > RESPONSE_MAX_BYTES) return refuse();
  const size = Buffer.alloc(LENGTH_BYTES); size.writeUInt32BE(body.length);
  return Buffer.concat([size, body]);
}
export function parsePublicFrame(frame: Uint8Array): Record<string, unknown> {
  if (frame.length < LENGTH_BYTES || frame.length > RESPONSE_MAX_BYTES + LENGTH_BYTES) return refuse();
  const bytes = Buffer.from(frame); const length = bytes.readUInt32BE();
  if (length + LENGTH_BYTES !== bytes.length) return refuse();
  const value = parseStrict(bytes.subarray(LENGTH_BYTES), RESPONSE_MAX_BYTES);
  if (!value || typeof value !== "object" || Array.isArray(value) || !Buffer.from(canonicalBytes(value)).equals(bytes.subarray(LENGTH_BYTES))) return refuse();
  return value as Record<string, unknown>;
}
/** Owns an encrypted provider solely inside the per-lease worker; only record signatures leave it. */
export function workerSigner(identity: StoredIdentity, key: Uint8Array, grant: SigningGrant, started: string) {
  const provider = new EncryptedIdentityProvider(identity, key, grant);
  try {
    // The internally generated self-test binds the same role and machine required by the private K1a provider.
    const body = canonicalBytes({ v: 1, role: grant.role, machine_id: grant.machine_id, epoch: grant.epoch, kid: grant.kid,
      grant_digest: "sha256:" + (awaitlessDigest(canonicalBytes(grant))), boot_id: readBootId(), lease_id: grant.lease_id,
      challenge_nonce: randomBytes(SELF_TEST_NONCE_BYTES).toString("hex"), started_boottime_ns: started });
    const message = Buffer.concat([Buffer.from(UNLOCK_CHALLENGE_DOMAIN), body]);
    const signature = provider.sign(message);
    try { if (!strictVerify(message, signature, decodeCanonical(grant.public_key, ED25519_PUBLIC_BYTES))) return refuse(); }
    finally { signature.fill(0); }
    const signer = createRecordSigner(grant, provider, INERT_SIGNABLE_ADAPTERS[0].schema, INERT_SIGNABLE_ADAPTERS[0].kind);
    return { signRecord: (request: RecordRequest) => signer.signRecord(request), close: () => provider.close() };
  } catch { provider.close(); return refuse(); }
}
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
function awaitlessDigest(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
function readBootId(): string { return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim().replaceAll("-", ""); }
