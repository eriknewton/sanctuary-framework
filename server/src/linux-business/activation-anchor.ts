import { createHash } from "node:crypto";
import { z } from "zod";
import protocol from "../signing/protocol-transitions.json";
import { canonicalBytes, refuse, safeInteger, roleKid, ROLE_REGISTRY } from "../signing/contract.js";
import { parseStrict } from "../smb/parse-strict.js";

// Must match activation_anchor.rs: these are proposal codecs, never persistence or authentication authority.
export const ANCHOR_VERSION = 1;
export const ANCHOR_MAX_BYTES = 65536;
// DRAIN_SCHEMA_BEGIN
// must match `drain_schema.json` via `scripts/generate-drain-contract.mjs`
export const DRAIN_SCHEMA_DIGEST = "sha256:a9ce79996945b09990ea8ab538bbe3288a19be4051db013238d14431bfc4254d";
export const ANCHOR_FIELDS = ["version","fortress_id","machine_id","role","enrollment_revision","descriptor_digest","roster_digest","custody_envelope_digest","retired","activation_id","boot_id","generation_high_water","reserved_sequence","committed_sequence","committed_digest","drained_sequence","drained_digest","transaction_id","recovery_required","recovery_reason","recovery_revision","reserved_body_digest"] as const;
const id = z.string().regex(/^[a-f0-9]{32}$/);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const reason = z.enum(["integrity","restart","storage_fault","counter_lost"]);
const anchorShape = z.object({
  version: z.literal(1),
  fortress_id: id,
  machine_id: id,
  role: z.literal("extension:linux-business-producer-v0"),
  enrollment_revision: safeInteger.min(1),
  descriptor_digest: digest,
  roster_digest: digest,
  custody_envelope_digest: digest,
  retired: z.boolean(),
  activation_id: id,
  boot_id: id,
  generation_high_water: safeInteger,
  reserved_sequence: safeInteger,
  committed_sequence: safeInteger,
  committed_digest: z.union([z.literal("GENESIS"), digest]),
  drained_sequence: safeInteger,
  drained_digest: z.union([z.literal("GENESIS"), digest]),
  transaction_id: id.nullable(),
  recovery_required: z.boolean(),
  recovery_reason: reason.nullable(),
  recovery_revision: safeInteger,
  reserved_body_digest: digest.nullable(),
}).strict();
const MESSAGE_KEYS = ["version","op","request_id","expected","next"] as const;
const BODY_DIGEST_RULE = {"ops":["RESERVE"],"conditional_op":"COMMIT","expected_null_field":"transaction_id"} as const;
const DESCRIPTOR_ROOT = {"version":"literal1","fortress_id":"id","machine_id":"id","identity_id":"id","epochs":"epochs"} as const;
const DESCRIPTOR_ENTRY = {"role":"registeredRole","epoch":"positiveInteger","kid":"kid","public_key":"key"} as const;
export const D_DESCRIPTOR_EPOCHS_MAX = 256;
export const D_DESCRIPTOR_MAX_BYTES = 65536;
export const D_EPOCH_MAX = 9007199254740991;
// DRAIN_SCHEMA_END
export const anchorSchema = anchorShape.superRefine((a, ctx) => {
  // High-water and latch consistency prevent a well-shaped proposal from erasing uncertainty.
  if (a.drained_sequence > a.committed_sequence || a.committed_sequence > a.reserved_sequence ||
      a.reserved_sequence - a.committed_sequence > 1 ||
      (a.reserved_body_digest === null) !== (a.reserved_sequence === a.committed_sequence) ||
      (a.committed_sequence === 0) !== (a.committed_digest === "GENESIS") ||
      (a.drained_sequence === 0) !== (a.drained_digest === "GENESIS") ||
      a.recovery_required !== (a.recovery_reason !== null) || (a.recovery_required && a.recovery_revision === 0))
    ctx.addIssue({code: z.ZodIssueCode.custom, message: "ANCHOR_REFUSED"});
});
export type ActivationAnchor = z.infer<typeof anchorSchema>;
// Must match protocol_transitions.rs: the recovery rule generates the entire denied operation set.
export const ANCHOR_OPS = Object.freeze([...protocol.anchor.ops]) as readonly [string, ...string[]];
export const LATCH_DENIED_OPS = Object.freeze(ANCHOR_OPS.filter(op => op !== protocol.anchor.recovery_op));
// Must match PREPARE_CHANGED_FIELDS in activation_anchor.rs and prepare_changed_fields in closure_vectors.json, which both languages pin as a whole set.
// reserved_body_digest is excluded: custody preparation cannot rewrite record evidence.
export const PREPARE_CHANGED_FIELDS = Object.freeze(["enrollment_revision", "transaction_id", "descriptor_digest", "roster_digest", "custody_envelope_digest"] as const);
// Must match DRAIN_TUPLE_FIELDS in activation_anchor.rs and drain_tuple_fields in closure_vectors.json, which both languages pin as a whole set; reconcile below is defined over exactly this set.
// reserved_body_digest is excluded: drain progress cannot rewrite a pending reservation.
export const DRAIN_TUPLE_FIELDS = Object.freeze(["reserved_sequence", "committed_sequence", "committed_digest", "drained_sequence", "drained_digest"] as const);
// DRAIN_MESSAGE_BEGIN
// must match `drain_schema.json` via `scripts/generate-drain-contract.mjs`
const messageSchema = z.object({
  version: z.literal(ANCHOR_VERSION),
  op: z.enum(ANCHOR_OPS),
  request_id: id,
  expected: anchorSchema.nullable(),
  next: anchorSchema.nullable(),
  body_digest: digest.optional(),
}).strict();
// DRAIN_MESSAGE_END
export type AnchorMessage = z.infer<typeof messageSchema>;
/** Consumers decode canonical bounded messages before authenticating their peer and persisting a proposal. */
export function decodeAnchorMessage(bytes: Uint8Array): AnchorMessage {
  const message = messageSchema.parse(parseStrict(bytes, ANCHOR_MAX_BYTES));
  const needsBody = (BODY_DIGEST_RULE.ops as readonly string[]).includes(message.op) ||
    (message.op === BODY_DIGEST_RULE.conditional_op && message.expected !== null && message.expected[BODY_DIGEST_RULE.expected_null_field] === null);
  // The message digest names the frozen body; the reducer checks it against the reservation.
  const keys: readonly string[] = needsBody ? [...MESSAGE_KEYS, "body_digest"] : MESSAGE_KEYS;
  if (!exactFields(message, keys) || (message.expected === null && message.op !== "PREPARE")) return refuse();
  // Canonical equality gives request retries one exact byte identity.
  if (!Buffer.from(canonicalBytes(message)).equals(Buffer.from(bytes)) || (message.op === "READ") !== (message.next === null)) return refuse();
  return message;
}
export function anchorDigest(anchor: ActivationAnchor): string {
  return "sha256:" + createHash("sha256").update(canonicalBytes(anchorSchema.parse(anchor))).digest("hex");
}
function equal(a: unknown, b: unknown): boolean { return Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b))); }
/** Pure compare-and-swap proposal checking; it neither acknowledges durability nor grants a lease. */
export type Prior = {absent: true} | ActivationAnchor;
export function observe(prior: Prior): {state: "ABSENT" | "PRESENT"; latched: boolean} {
  return "absent" in prior ? {state: "ABSENT", latched: false} : {state: "PRESENT", latched: prior.recovery_required};
}
export function proposeAnchor(current: Prior, message: AnchorMessage): ActivationAnchor {
  const m = decodeAnchorMessage(canonicalBytes(message));
  if ("absent" in current) {
    const next = anchorSchema.parse(m.next);
    // An absent slot can only be created by an attended provisioning prepare; no other operation may conjure history.
    if (m.op !== "PREPARE" || m.expected !== null || next.enrollment_revision !== 1 ||
        next.reserved_sequence !== 0 || next.committed_sequence !== 0 || next.drained_sequence !== 0 ||
        next.committed_digest !== "GENESIS" || next.drained_digest !== "GENESIS" || next.retired ||
        next.recovery_required || next.recovery_reason !== null || next.recovery_revision !== 0 ||
        next.transaction_id !== m.request_id || next.reserved_body_digest !== null) return refuse();
    return next;
  }
  const old = anchorSchema.parse(current);
  // The whole expected tuple binds the proposal to one observed anchor, including its sticky latch.
  if (!equal(old, m.expected)) return refuse();
  // A recovery latch freezes the observed tail and transaction until the named recovery path proves completion.
  if (old.recovery_required && LATCH_DENIED_OPS.includes(m.op)) return refuse();
  if (m.op === "READ") return old;
  const next = anchorSchema.parse(m.next);
  let changed: (keyof ActivationAnchor)[];
  switch (m.op) {
    case "RESERVE":
      // One outstanding reservation bounds uncertain signing work and prevents sequence reuse.
      if (old.retired || old.transaction_id !== null || old.reserved_sequence !== old.committed_sequence || old.reserved_body_digest !== null || next.reserved_sequence !== old.reserved_sequence + 1 || next.reserved_body_digest !== m.body_digest) return refuse();
      changed = ["reserved_sequence", "reserved_body_digest"]; break;
    case "COMMIT":
      // Only the reserved sequence or prepared custody transaction can become a commit proposal.
      if (old.transaction_id !== null) {
        // The prepared request owns custody completion, so another request cannot settle it.
        if (m.request_id !== old.transaction_id || next.transaction_id !== null) return refuse();
        changed = ["transaction_id"];
      } else {
        if (old.reserved_sequence !== old.committed_sequence + 1 || next.committed_sequence !== old.reserved_sequence || next.committed_digest === old.committed_digest ||
            // The reserved digest is evidence for this body only, never a different signed body.
            m.body_digest !== old.reserved_body_digest || next.reserved_body_digest !== null) return refuse();
        changed = ["committed_sequence", "committed_digest", "reserved_body_digest"];
      }
      break;
    case "DRAIN":
      // Contiguous drain progress preserves the exact committed tail without skipping a record.
      if (next.drained_sequence !== old.drained_sequence + 1 || next.drained_sequence > old.committed_sequence || next.drained_digest === old.drained_digest ||
          (next.drained_sequence === old.committed_sequence && next.drained_digest !== old.committed_digest)) return refuse();
      changed = ["drained_sequence", "drained_digest"]; break;
    case "PREPARE":
      // Consecutive custody revisions bind a transaction to one closed, settled anchor.
      if (old.retired || old.transaction_id !== null || old.reserved_sequence !== old.committed_sequence || old.reserved_body_digest !== null ||
          next.enrollment_revision !== old.enrollment_revision + 1 || next.transaction_id !== m.request_id) return refuse();
      changed = [...PREPARE_CHANGED_FIELDS]; break;
    case "LATCH":
      // Recovery revisions increase so a later proposal cannot erase an earlier integrity event.
      if (!next.recovery_required || next.recovery_revision !== old.recovery_revision + 1) return refuse();
      changed = ["recovery_required", "recovery_reason", "recovery_revision"]; break;
    case "ADVANCE_GENERATION":
    case "ADVANCE_ACTIVATION":
    case "ADVANCE_BOOT": {
      // New grant identities require a settled tail and a strictly increasing generation to prevent reuse.
      if (old.retired || old.transaction_id !== null || old.reserved_sequence !== old.committed_sequence || old.reserved_body_digest !== null ||
          old.drained_sequence !== old.committed_sequence || old.drained_digest !== old.committed_digest ||
          next.generation_high_water !== old.generation_high_water + 1) return refuse();
      changed = ["generation_high_water"];
      if (m.op !== "ADVANCE_GENERATION") {
        const field = m.op === "ADVANCE_ACTIVATION" ? "activation_id" : "boot_id";
        // An identity advance changes its named identity, and with the strictly increasing generation no (identity, generation) pair repeats.
        if (next[field] === old[field]) return refuse();
        // Must match activation_anchor.rs: fixed-length lowercase hex identities compare in numeric order and strictly increase, so an earlier activation can never return.
        if (m.op === "ADVANCE_ACTIVATION" && next.activation_id <= old.activation_id) return refuse();
        changed.push(field);
      }
      break;
    }
    case "RECOVERY_COMMIT":
      // Installed recovery evidence has no constructor in this slice, so proposals cannot clear a latch.
      return refuse();
    default: return refuse();
  }
  // Operation-specific fields are the only mutable part of the anchor proposal.
  for (const key of Object.keys(old) as (keyof ActivationAnchor)[]) if (!changed.includes(key) && !equal(old[key], next[key])) return refuse();
  return next;
}
export interface ReconciliationInput { custody: ActivationAnchor; drain: ActivationAnchor; outside_receipt_digest: string | null; original_tail_digest: string | null; }
/** Classification only: the caller must keep effects closed and cannot infer a completed recovery ceremony. */
export function reconcile(input: ReconciliationInput): "CONSISTENT" | "RECOVERY_REQUIRED" {
  // a custody-only rollback refuses; no total-host rollback protection is claimed.
  // Same-epoch recovery requires comparison with the last exported receipt from outside the restored failure domain; without that comparison it refuses and a new epoch is required.
  try {
    const custody = anchorSchema.parse(input.custody), drain = anchorSchema.parse(input.drain);
    if (input.outside_receipt_digest !== anchorDigest(drain) || input.original_tail_digest !== drain.committed_digest ||
        custody.recovery_required || drain.recovery_required || custody.retired || drain.retired ||
        custody.transaction_id !== null || drain.transaction_id !== null ||
        // A matching custody copy cannot certify records that the drain has not acknowledged, so every drained tuple field is settled at the committed tail.
        DRAIN_TUPLE_FIELDS.some(field => drain[field] !== drain[field.endsWith("_sequence") ? "committed_sequence" : "committed_digest"]) ||
        !equal(custody, drain)) return "RECOVERY_REQUIRED";
    return "CONSISTENT";
  } catch { return "RECOVERY_REQUIRED"; }
}
/** The anchor a recovery PREPARE steps from: the prior anchor carrying the reconciled drain's drained tuple, or null when the drain disagrees with the prior anchor anywhere else. */
export function recoveryPrepareBase(prior: ActivationAnchor, drain: ActivationAnchor): ActivationAnchor | null {
  // Must match recovery_prepare_base in activation_anchor.rs and the recover group in closure_vectors.json.
  try {
    const before = anchorSchema.parse(prior), after = anchorSchema.parse(drain);
    const drained: readonly string[] = DRAIN_TUPLE_FIELDS;
    // Outside the drained tuple the drain must be the prior anchor itself, so a recovery cannot carry in a foreign generation, identity or latch history.
    for (const key of Object.keys(before) as (keyof ActivationAnchor)[]) if (!drained.includes(key) && !equal(before[key], after[key])) return null;
    const base: Record<string, unknown> = {...before};
    for (const field of DRAIN_TUPLE_FIELDS) base[field] = after[field];
    return anchorSchema.parse(base);
  } catch { return null; }
}

function exactFields(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
}
export interface DescriptorEpoch {role: string; epoch: number; kid: string; public_key: Uint8Array;}
export interface Descriptor {fortress_id: string; machine_id: string; identity_id: string; epochs: DescriptorEpoch[];}
export type DescriptorRefusal = "SIZE" | "DIGEST" | "CANONICAL" | "SHAPE" | "ID" | "COUNT" | "ENTRY_SHAPE" | "ROLE" | "EPOCH" | "KEY" | "KID" | "ORDER";
function descriptorDomain(value: unknown, domain: string): boolean {
  switch (domain) {
    case "literal1": return value === 1;
    case "id": return id.safeParse(value).success;
    case "epochs": return Array.isArray(value);
    case "registeredRole": return ROLE_REGISTRY.some(r => r.role === value);
    case "positiveInteger": return typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value <= D_EPOCH_MAX;
    case "key": return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
    case "kid": return typeof value === "string" && /^k1:sha256:[a-f0-9]{64}$/.test(value);
    default: return false;
  }
}
/** The descriptor pin authenticates public history; parsed keys authorize only their own role and epoch. */
export function parseDescriptor(bytes: Uint8Array, pin: string): {ok: true; value: Descriptor} | {ok: false; stage: DescriptorRefusal} {
  const fail = (stage: DescriptorRefusal) => ({ok: false as const, stage});
  if (bytes.length > D_DESCRIPTOR_MAX_BYTES) return fail("SIZE");
  // Authenticate exact public evidence before interpreting any historical key.
  if ("sha256:" + createHash("sha256").update(bytes).digest("hex") !== pin) return fail("DIGEST");
  let v: unknown;
  try { v = parseStrict(bytes, D_DESCRIPTOR_MAX_BYTES); if (!Buffer.from(canonicalBytes(v)).equals(Buffer.from(bytes))) return fail("CANONICAL"); }
  catch { return fail("CANONICAL"); }
  if (!exactFields(v, Object.keys(DESCRIPTOR_ROOT)) || !descriptorDomain(v.version, DESCRIPTOR_ROOT.version) || !Array.isArray(v.epochs)) return fail("SHAPE");
  if (Object.entries(DESCRIPTOR_ROOT).filter(([, d]) => d === "id").some(([k, d]) => !descriptorDomain(v[k], d))) return fail("ID");
  if (v.epochs.length === 0 || v.epochs.length > D_DESCRIPTOR_EPOCHS_MAX) return fail("COUNT");
  const epochs: DescriptorEpoch[] = [];
  for (const entry of v.epochs) {
    if (!exactFields(entry, Object.keys(DESCRIPTOR_ENTRY))) return fail("ENTRY_SHAPE");
    for (const [key, stage] of [["role", "ROLE"], ["epoch", "EPOCH"], ["public_key", "KEY"], ["kid", "KID"]] as const)
      if (!descriptorDomain(entry[key], DESCRIPTOR_ENTRY[key])) return fail(stage);
    const role = entry.role as string, epoch = entry.epoch as number, kid = entry.kid as string;
    const public_key = Buffer.from(entry.public_key as string, "hex");
    // The role registry and decoded key, not the descriptor's hex spelling, determine the kid.
    if (roleKid(role as typeof ROLE_REGISTRY[number]["role"], epoch, public_key.toString("base64url")) !== kid) return fail("KID");
    const last = epochs.at(-1);
    if (last && (last.role > role || (last.role === role && last.epoch >= epoch))) return fail("ORDER");
    epochs.push({role, epoch, kid, public_key});
  }
  return {ok: true, value: {fortress_id: v.fortress_id as string, machine_id: v.machine_id as string, identity_id: v.identity_id as string, epochs}};
}
