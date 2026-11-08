import { createHash } from "node:crypto";
import { z } from "zod";
import { jcs } from "../smb/jcs.js";
import { parseStrict } from "../smb/parse-strict.js";

// Must match identity-provider.ts: its allowlist selects one role domain and the three lifecycle domains.
// Contract pin: core/signing-domains.ts refuses this entire role set and the lifecycle domains below.
// Contract pin: scripts/generate-record-signer-contract.mjs emits this entire registry into business_profile/signer_contract.rs.
export const ROLE_REGISTRY = [
  {
    "role": "extension:linux-business-producer-v0",
    "domain": "sanctuary.linux-business.record.v0\n",
    "envelope_max_bytes": 4096,
    "record_kinds": [
      "append",
      "control",
      "counter",
      "terminal"
    ]
  },
  {
    "role": "extension:linux-business-policy-v0",
    "domain": "sanctuary.linux-business.policy.v0\n",
    "envelope_max_bytes": 4096,
    "record_kinds": [
      "policy"
    ]
  },
  {
    "role": "extension:linux-business-retrospective-v0",
    "domain": "sanctuary.linux-business.retrospective.v0\n",
    "envelope_max_bytes": 4096,
    "record_kinds": [
      "retrospective"
    ]
  },
  {
    "role": "extension:model-recorder-v0",
    "domain": "sanctuary.model-record.v0\n",
    "envelope_max_bytes": 8192,
    "record_kinds": [
      "record"
    ]
  },
  {
    "role": "extension:model-policy-v0",
    "domain": "sanctuary.model-policy.v0\n",
    "envelope_max_bytes": 8192,
    "record_kinds": [
      "policy"
    ]
  },
  {
    "role": "extension:model-session-v0",
    "domain": "sanctuary.model-session.v0\n",
    "envelope_max_bytes": 8192,
    "record_kinds": [
      "session"
    ]
  },
  {
    "role": "extension:model-extent-v0",
    "domain": "sanctuary.model-extent.v0\n",
    "envelope_max_bytes": 65536,
    "record_kinds": [
      "extent"
    ]
  },
  {
    "role": "evidence-pack:manifest-v0",
    "domain": "sanctuary.evidence-pack.manifest.k1.v1\n",
    "envelope_max_bytes": 65536,
    "record_kinds": [
      "manifest"
    ]
  }
] as const;
// Immutable kind arrays prevent callers from expanding the registered signing authority.
ROLE_REGISTRY.forEach(entry => { Object.freeze(entry.record_kinds); Object.freeze(entry); });
Object.freeze(ROLE_REGISTRY);
export type SigningRole = typeof ROLE_REGISTRY[number]["role"];
export const ROLE_SIGNATURE_SCHEME = "ed25519-k1-role-v1";
export const STRICT_PROFILE = "K1_ED25519_COFACTORLESS_STRICT_V1";
export const KID_DOMAIN = "sanctuary.k1.role-kid.v1\n";
export const PRODUCER_CUSTODY_BINDING_PURPOSE = "producer-custody-binding-v1";
export const PRODUCER_CUSTODY_BINDING_AAD = "sanctuary.producer-custody.binding.v1\n";
export const PRODUCER_DESCRIPTOR_DOMAIN = "sanctuary.producer-custody.descriptor.v1\n";
export const PRODUCER_ROTATION_DOMAIN = "sanctuary.producer-custody.rotation.v1\n";
export const UNLOCK_CHALLENGE_DOMAIN = "sanctuary.k1.unlock-self-test.v1\n";
export const CUSTODY_SIGNATURE_SCHEME = "ed25519-k1-custody-v1";
export const SIGNER_PROTOCOL = "sanctuary.record-signer.v1";
export const UNLOCK_TTL_MAX_SECONDS = 300;
export const UNLOCKING_DEADLINE_SECONDS = 30;
export const SIGNER_REQUEST_DEADLINE_MS = 1000;
export const LINUX_RECORD_DURABILITY_DEADLINE_MS = 1000;
export const FINAL_CONTROL_RECORDS = 4;
export const H_LEASE_REQUEST_SECONDS = 240;
export const MAC_K1_REQUEST_TIMEOUT_MS = 180000;
export const SIGNER_PREIMAGE_MAX_BYTES = 65536;
export const SIGNER_HEADER_MAX_BYTES = 1024;
// Four length bytes plus the maximum header and preimage form the complete frame.
export const SIGNER_FRAME_MAX_BYTES = SIGNER_HEADER_MAX_BYTES + SIGNER_PREIMAGE_MAX_BYTES + 4;
// A domain is at most 128 bytes, in addition to the bounded preimage.
export const SIGNER_DOMAIN_MAX_BYTES = 128;
export const SIGNER_MESSAGE_MAX_BYTES = SIGNER_PREIMAGE_MAX_BYTES + SIGNER_DOMAIN_MAX_BYTES;
export const SIGNER_CONNECTIONS_MAX = 4;
export const SIGNER_ACTIVE_MAX = 1;
export const SIGNER_QUEUE_MAX = 0;
export const SIGNER_PER_CALLER_ACTIVE_MAX = 1;
export const SIGNER_RATE_PER_SECOND = 256;
export const SIGNER_BURST_MAX = 256;
export const SIGNER_PER_CALLER_RATE_PER_SECOND = 128;
export const SIGNER_PER_CALLER_BURST_MAX = 128;
export const SIGNER_HANDSHAKE_DEADLINE_MS = 250;
export const SIGNER_IDLE_DEADLINE_MS = 1000;
export const SIGNER_EPOCHS_MAX = 256;
export const LIFECYCLE_FRAME_MAX_BYTES = 1024;
export const LIFECYCLE_CONNECTIONS_MAX = 2;
export const LIFECYCLE_ACTIVE_MAX = 1;
export const LIFECYCLE_QUEUE_MAX = 0;
export const LIFECYCLE_RATE_PER_SECOND = 1;
export const LIFECYCLE_BURST_MAX = 3;
export const SIGNER_UNLOCK_ATTEMPTS_PER_300_SECONDS = 3;

export function refuse(): never { throw new Error("K1_REFUSED"); }
export function roleEntry(role: string) {
  return ROLE_REGISTRY.find(entry => entry.role === role) ?? refuse();
}
export function canonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(jcs(value));
}
export function decodeCanonical(value: string, length?: number): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return refuse();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value || (length !== undefined && bytes.length !== length)) return refuse();
  return bytes;
}
// Must match role_kid in castle-wall-daemon/src/business_profile/mod.rs, including canonical key ordering.
export function roleKid(role: SigningRole, epoch: number, publicKey: string): string {
  roleEntry(role);
  if (!Number.isSafeInteger(epoch) || epoch < 1) return refuse();
  decodeCanonical(publicKey, 32);
  return "k1:sha256:" + createHash("sha256").update(KID_DOMAIN).update(canonicalBytes({v: 1, role, epoch, public_key: publicKey})).digest("hex");
}
export const safeInteger = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const hexId = z.string().regex(/^[a-f0-9]{32}$/);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const u64 = z.string().regex(/^(0|[1-9][0-9]*)$/).refine(value => BigInt(value) <= 18446744073709551615n);
// Contract pin: generated Rust COMMON_FIELDS and LINUX_FIELDS are checked as whole sets.
export const COMMON_FIELDS = ["signature_scheme", "role", "record_kind", "epoch", "kid", "identity_id", "machine_id", "payload"] as const;
export const LINUX_FIELDS = ["boot_id", "activation_id", "lease_id", "generation", "sequence", "prior_commitment", "captured_at_unix_ms", "captured_at_boottime_ns", "policy_digest", "runtime_digest", "config_digest"] as const;
const commonShape = {
  signature_scheme: z.literal(ROLE_SIGNATURE_SCHEME), role: z.enum(ROLE_REGISTRY.map(entry => entry.role) as [SigningRole, ...SigningRole[]]),
  epoch: safeInteger.min(1), kid: z.string().regex(/^k1:sha256:[a-f0-9]{64}$/), identity_id: hexId, machine_id: hexId,
};
const linuxShape = {
  boot_id: hexId, activation_id: hexId, lease_id: hexId, generation: safeInteger,
  sequence: safeInteger.min(1), prior_commitment: z.union([z.literal("GENESIS"), digest]),
  captured_at_unix_ms: safeInteger, captured_at_boottime_ns: u64,
  policy_digest: digest, runtime_digest: digest, config_digest: digest,
};
// Must match the expected kind passed by record-signer.ts, strict-verifier.ts and linux-business/producer-custody.ts.
/** Trusted adapters supply a closed payload schema; no payload schema arrives in a signing request. */
export function recordSchema(role: SigningRole, payloadSchema: z.ZodType, recordKind: string) {
  // The trusted adapter selects a registered signed kind, so overlapping payload schemas cannot substitute records.
  if (!(roleEntry(role).record_kinds as readonly string[]).includes(recordKind)) return refuse();
  return z.object({ ...commonShape, record_kind: z.literal(recordKind), ...(role.startsWith("extension:linux-business-") ? linuxShape : {}), payload: payloadSchema }).strict();
}
export type RecordBody = z.infer<ReturnType<typeof recordSchema>>;
export function parseRecord(bytes: Uint8Array, role: SigningRole, payloadSchema: z.ZodType, recordKind: string): RecordBody {
  try {
    const value = parseStrict(bytes, SIGNER_PREIMAGE_MAX_BYTES);
    const integersOnly = (item: unknown): boolean => {
      if (typeof item === "number") return Number.isSafeInteger(item);
      if (Array.isArray(item)) return item.every(integersOnly);
      if (item !== null && typeof item === "object") return Object.values(item).every(integersOnly);
      return true;
    };
    if (!integersOnly(value)) return refuse();
    const parsed = recordSchema(role, payloadSchema, recordKind).parse(value);
    if (parsed.role !== role || !Buffer.from(canonicalBytes(parsed)).equals(Buffer.from(bytes))) return refuse();
    return parsed;
  } catch { return refuse(); }
}
export function recordMessage(role: SigningRole, preimage: Uint8Array): Uint8Array {
  return Buffer.concat([Buffer.from(roleEntry(role).domain), preimage]);
}
export function checkEnvelopeSize(role: SigningRole, body: RecordBody, preimage: Uint8Array): void {
  const entry = roleEntry(role);
  const domainSize = Buffer.byteLength(entry.domain);
  // Unpadded base64url of a 64-byte Ed25519 signature has ceil(64 * 8 / 6) = 86 characters.
  const completeEnvelope = role.startsWith("extension:linux-business-")
    ? {body, signature: "A".repeat(86)} : {...body, signature: "A".repeat(86)};
  if (domainSize > SIGNER_DOMAIN_MAX_BYTES || domainSize + preimage.length > SIGNER_MESSAGE_MAX_BYTES ||
      canonicalBytes(completeEnvelope).length > entry.envelope_max_bytes) refuse();
}
