import { createHash } from "node:crypto";
import { z } from "zod";
import protocol from "../signing/protocol-transitions.json";
import { canonicalBytes, refuse, safeInteger } from "../signing/contract.js";
import { parseStrict } from "../smb/parse-strict.js";

// Must match activation_anchor.rs: these are proposal codecs, never persistence or authentication authority.
export const ANCHOR_VERSION = 1;
export const ANCHOR_MAX_BYTES = 65536;
const id = z.string().regex(/^[a-f0-9]{32}$/);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const commitment = z.union([z.literal("GENESIS"), digest]);
const reason = z.enum(["integrity", "restart", "storage_fault", "counter_lost"]);
const anchorShape = z.object({
  version: z.literal(ANCHOR_VERSION), fortress_id: id, machine_id: id,
  role: z.literal("extension:linux-business-producer-v0"), enrollment_revision: safeInteger.min(1),
  descriptor_digest: digest, roster_digest: digest, custody_envelope_digest: digest, retired: z.boolean(),
  activation_id: id, boot_id: id, generation_high_water: safeInteger,
  reserved_sequence: safeInteger, committed_sequence: safeInteger, committed_digest: commitment,
  drained_sequence: safeInteger, drained_digest: commitment, transaction_id: id.nullable(),
  recovery_required: z.boolean(), recovery_reason: reason.nullable(), recovery_revision: safeInteger,
}).strict();
export const anchorSchema = anchorShape.superRefine((a, ctx) => {
  // High-water and latch consistency prevent a well-shaped proposal from erasing uncertainty.
  if (a.drained_sequence > a.committed_sequence || a.committed_sequence > a.reserved_sequence ||
      a.reserved_sequence - a.committed_sequence > 1 ||
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
export const PREPARE_CHANGED_FIELDS = Object.freeze(["enrollment_revision", "transaction_id", "descriptor_digest", "roster_digest", "custody_envelope_digest"] as const);
const messageSchema = z.object({version: z.literal(ANCHOR_VERSION), op: z.enum(ANCHOR_OPS), request_id: id,
  expected: anchorSchema, next: anchorSchema.nullable()}).strict();
export type AnchorMessage = z.infer<typeof messageSchema>;
/** Consumers decode canonical bounded messages before authenticating their peer and persisting a proposal. */
export function decodeAnchorMessage(bytes: Uint8Array): AnchorMessage {
  const message = messageSchema.parse(parseStrict(bytes, ANCHOR_MAX_BYTES));
  // Canonical equality gives request retries one exact byte identity.
  if (!Buffer.from(canonicalBytes(message)).equals(Buffer.from(bytes)) || (message.op === "READ") !== (message.next === null)) return refuse();
  return message;
}
export function anchorDigest(anchor: ActivationAnchor): string {
  return "sha256:" + createHash("sha256").update(canonicalBytes(anchorSchema.parse(anchor))).digest("hex");
}
function equal(a: unknown, b: unknown): boolean { return Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b))); }
/** Pure compare-and-swap proposal checking; it neither acknowledges durability nor grants a lease. */
export function proposeAnchor(current: ActivationAnchor, message: AnchorMessage): ActivationAnchor {
  const old = anchorSchema.parse(current);
  const m = decodeAnchorMessage(canonicalBytes(message));
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
      if (old.retired || old.transaction_id !== null || old.reserved_sequence !== old.committed_sequence || next.reserved_sequence !== old.reserved_sequence + 1) return refuse();
      changed = ["reserved_sequence"]; break;
    case "COMMIT":
      // Only the reserved sequence or prepared custody transaction can become a commit proposal.
      if (old.transaction_id !== null) {
        // The prepared request owns custody completion, so another request cannot settle it.
        if (m.request_id !== old.transaction_id || next.transaction_id !== null) return refuse();
        changed = ["transaction_id"];
      } else {
        if (old.reserved_sequence !== old.committed_sequence + 1 || next.committed_sequence !== old.reserved_sequence || next.committed_digest === old.committed_digest) return refuse();
        changed = ["committed_sequence", "committed_digest"];
      }
      break;
    case "DRAIN":
      // Contiguous drain progress preserves the exact committed tail without skipping a record.
      if (next.drained_sequence !== old.drained_sequence + 1 || next.drained_sequence > old.committed_sequence || next.drained_digest === old.drained_digest ||
          (next.drained_sequence === old.committed_sequence && next.drained_digest !== old.committed_digest)) return refuse();
      changed = ["drained_sequence", "drained_digest"]; break;
    case "PREPARE":
      // Consecutive custody revisions bind a transaction to one closed, settled anchor.
      if (old.retired || old.transaction_id !== null || old.reserved_sequence !== old.committed_sequence ||
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
      if (old.retired || old.transaction_id !== null || old.reserved_sequence !== old.committed_sequence ||
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
        // A matching custody copy cannot certify records that the drain has not acknowledged.
        drain.drained_sequence !== drain.committed_sequence || drain.drained_digest !== drain.committed_digest ||
        drain.reserved_sequence !== drain.committed_sequence || !equal(custody, drain)) return "RECOVERY_REQUIRED";
    return "CONSISTENT";
  } catch { return "RECOVERY_REQUIRED"; }
}
