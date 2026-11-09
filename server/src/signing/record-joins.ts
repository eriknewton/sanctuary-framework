import { z } from "zod";
import { verifyIndexedRecord, type BusinessPin, type OuterRecordIndex } from "../linux-business/producer-custody.js";
import type { RolePin } from "./strict-verifier.js";
import { createHash } from "node:crypto";
import { canonicalBytes, LINUX_FIELDS } from "./contract.js";
import { validateBusinessRecord } from "./linux-business-records.js";

// Must match records.rs and all three record_join_vectors.json consumers, including refusal precedence and retained state.
export const JOIN_HISTORY_MAX = 64; // The design caps retained replay evidence at sixty-four records, with no live eviction.
export const COUNTER_PERIOD_NS = 1_000_000_000n; // One second expressed in nanoseconds.
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type ObjectValue = { [key: string]: Json };
export interface JoinRecord { body: ObjectValue; outer: ObjectValue; }
export interface JoinState {
  pin: ObjectValue; grant: ObjectValue; policy: ObjectValue; anchor: ObjectValue;
  flow_state: { history: JoinRecord[] };
}
export interface JoinResult { refusal_code: string | null; final_state: JoinState; }
// Must match JOIN_STATE_SCHEMA in records.rs and state_schema in record_join_vectors.json, which both executors pin as a whole set.
export const JOIN_STATE_SCHEMA = Object.freeze({
  pin: {role: "text", epoch: "safe_u64", kid: "text", public_key: "text", identity_id: "id", machine_id: "id"},
  grant: {boot_id: "id", activation_id: "id", lease_id: "id", generation: "safe_u64", expires_ns: "u64_text"},
  policy: {policy_digest: "digest", runtime_digest: "digest", config_digest: "digest", agent_uids: "safe_u64_list", vendors: "vendor_list"},
  anchor: {sequence: "safe_u64", commitment: "commitment", lease_id: "id", generation: "safe_u64", captured_at_boottime_ns: "u64_text"},
  flow_state: {history: "history"},
} as const);
const U64_MAX = 18446744073709551615n; // 2^64 - 1.
const isObject = (v: unknown): v is ObjectValue => v !== null && typeof v === "object" && !Array.isArray(v);
const exactKeys = (v: unknown, keys: readonly string[]): v is ObjectValue => isObject(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const safeU64 = (v: unknown): boolean => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
// Must match state_token in records.rs: each token admits one exact representation.
const STATE_TOKENS: Record<string, (v: unknown) => boolean> = {
  text: v => typeof v === "string",
  // Thirty-two lowercase hex digits encode a sixteen-byte identifier; sixty-four encode a SHA-256 digest.
  id: v => typeof v === "string" && /^[a-f0-9]{32}$/.test(v),
  digest: v => typeof v === "string" && /^sha256:[a-f0-9]{64}$/.test(v),
  commitment: v => v === "GENESIS" || STATE_TOKENS.digest(v),
  safe_u64: safeU64,
  // Canonical decimal text only: no sign, whitespace, radix prefix, leading zero or u64 overflow.
  u64_text: v => typeof v === "string" && /^(0|[1-9][0-9]*)$/.test(v) && BigInt(v) <= U64_MAX,
  safe_u64_list: v => Array.isArray(v) && v.every(safeU64),
  vendor_list: v => Array.isArray(v) && v.every(e => exactKeys(e, ["address", "port"]) && typeof e.address === "string" && safeU64(e.port)),
  // Retained history holds only bounded, schema-valid records, so history lookups interpret the same values in both executors.
  history: v => Array.isArray(v) && v.length <= JOIN_HISTORY_MAX && v.every(e => exactKeys(e, ["body", "outer"]) && isObject(e.outer) && validateBusinessRecord(e.body)),
};
/** Parse the relying-party join state against the one shared state schema before any record field is read. */
export function joinStateValid(state: unknown): state is JoinState {
  const schema = JOIN_STATE_SCHEMA as Record<string, Record<string, string>>;
  return exactKeys(state, Object.keys(schema)) && Object.entries(schema).every(([name, fields]) =>
    exactKeys(state[name], Object.keys(fields)) && Object.entries(fields).every(([key, token]) => STATE_TOKENS[token]((state[name] as ObjectValue)[key])));
}
const get = (value: Json | undefined, path: string): Json | undefined => {
  for (const key of path.split(".")) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
    value = value[key];
  }
  return value;
};
const equal = (a: unknown, b: unknown): boolean => a !== undefined && b !== undefined && Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b)));
const integer = (v: Json | undefined): bigint => BigInt(v as string | number);
const countsLE = (a: Json | undefined, b: Json | undefined): boolean => ["original", "reply"].every(direction =>
  ["ip_bytes", "packets"].every(unit => integer(get(a, `${direction}.${unit}`)) <= integer(get(b, `${direction}.${unit}`))));
const sameContext = (a: Json | undefined, b: Json | undefined) => equal(get(a, "payload.context"), get(b, "payload.context"));
/** Hash the exact canonical signed envelope, including its signature, after caller-side signature verification. */
export function joinCommitment(record: JoinRecord): string {
  return "sha256:" + createHash("sha256").update(canonicalBytes({body: record.body, signature: record.outer.signature})).digest("hex");
}
/** Pure history validation only; the caller owns checkpoint authentication and signature verification. */
export function advance(state: JoinState, record: JoinRecord): JoinResult {
  const fail = (refusal_code: string): JoinResult => ({refusal_code, final_state: state});
  try {
    // Must match records.rs advance: malformed relying-party state refuses before any record field is read, so INPUT precedes SCHEMA.
    if (!joinStateValid(state)) return fail("INPUT");
    const b = (isObject(record) ? record.body : undefined) as ObjectValue, history = state.flow_state.history;
    const prior = (sequence: Json | undefined, kind: string) => history.find(r => r.body.sequence === sequence && r.body.record_kind === kind)?.body;
    // Generated validation owns every intra-record predicate before history values are interpreted.
    if (!validateBusinessRecord(b)) return fail("SCHEMA");
    const p = b.payload;
    // The outer index must match every indexed signed field so storage cannot relabel an authentic body.
    const index = LINUX_FIELDS.filter(key => !key.endsWith("_digest"));
    if (!isObject(record.outer) || !equal(Object.keys(record.outer).sort(), [...index, "machine_id", "signature"].sort()) ||
        [...index, "machine_id"].some(key => !equal(record.outer[key], b[key]))) return fail("OUTER");
    // The enrolled subject and reconciled grant bind the producer rather than trusting its self-description.
    if (["role", "epoch", "kid", "identity_id", "machine_id"].some(key => !equal(b[key], state.pin[key]))) return fail("PIN");
    // Grant identity and expiry bind each record to the relying session.
    if (["boot_id", "activation_id", "lease_id", "generation"].some(key => !equal(b[key], state.grant[key])) ||
        integer(b.captured_at_boottime_ns) > integer(state.grant.expires_ns)) return fail("GRANT");
    // Consecutive sequences and exact signed-envelope hashes prevent replay, omission and body-only chaining.
    if (integer(b.sequence) !== integer(state.anchor.sequence) + 1n || !equal(b.prior_commitment, state.anchor.commitment) ||
        integer(b.captured_at_boottime_ns) < integer(state.anchor.captured_at_boottime_ns)) return fail("CHAIN");
    // Policy and runtime commitments are supplied by the relying party and cannot be selected by a signed record.
    if (["policy_digest", "runtime_digest", "config_digest"].some(key => !equal(b[key], state.policy[key]))) return fail("POLICY");
    // Bounded retained evidence refuses exhaustion rather than evicting a still-replayable permit or reference.
    if (history.length >= JOIN_HISTORY_MAX) return fail("CAPACITY");
    const boundary = b.record_kind === "control" && get(p, "type") === "lease_boundary";
    const changedLease = !equal(b.lease_id, state.anchor.lease_id) || !equal(b.generation, state.anchor.generation);
    // Lease changes require an explicit boundary tied to the original checkpoint, including restart gaps.
    if (changedLease || boundary) {
      const genesis = state.anchor.sequence === 0;
      if (!boundary || (genesis ? get(p, "boundary") !== "activation_start" :
        get(p, "boundary") === "activation_start" || !changedLease || integer(b.generation) <= integer(state.anchor.generation) ||
        !equal(get(p, "previous_lease_id"), state.anchor.lease_id) || !equal(get(p, "previous_generation"), state.anchor.generation)) ||
        !equal(get(p, "previous_sequence"), state.anchor.sequence) || !equal(get(p, "previous_commitment"), state.anchor.commitment) ||
        // Must match records.rs: a restart gap covers the checkpoint at both ends, as a counter epoch change does.
        (get(p, "boundary") === "restart" && (integer(get(p, "gap.first_ns")) > integer(state.anchor.captured_at_boottime_ns) ||
          integer(get(p, "gap.last_ns")) < integer(state.anchor.captured_at_boottime_ns)))) return fail("BOUNDARY");
    }
    const context = get(p, "context"), flow = get(context, "flow");
    const opened = prior(get(flow, "open_sequence"), "open");
    const sameFlow = history.filter(r => equal(get(r.body, "payload.context.flow"), flow)).map(r => r.body);
    // Every contextual continuation names an earlier immutable open context and cannot continue after a terminal.
    if (context && b.record_kind !== "open" && (!opened || !sameContext(b, opened) || sameFlow.some(r => r.record_kind === "terminal"))) return fail("CONTEXT");
    if (b.record_kind === "open") {
      // An open owns its actual sequence so later references cannot alias a different flow.
      if (!equal(get(flow, "open_sequence"), b.sequence)) return fail("OPEN_SEQUENCE");
      if (get(p, "edge") === "agent_endpoint") {
        // The relying policy determines which agent may initiate the listener flow.
        if (!(state.policy.agent_uids as Json[]).includes(get(context, "actor_uid")!)) return fail("LISTENER");
      } else {
        const origin = prior(get(p, "origin_link_sequence"), "link");
        // Vendor opens require an earlier egress origin whose ingress identifies the endpoint actor.
        const ingress = prior(get(origin, "payload.link.ingress_sequence"), "link");
        if (!origin || get(origin, "payload.link.kind") !== "egress" || !ingress ||
            !equal(get(context, "actor_uid"), get(ingress, "payload.link.listener.uid")) ||
            !equal(get(context, "netns_inode"), get(origin, "payload.context.netns_inode"))) return fail("ORIGIN");
        // Only a pinned IPv4 TCP vendor destination can inherit the admitted origin.
        if (get(context, "original.family") !== "ipv4" || get(context, "original.protocol") !== "tcp" ||
            !(state.policy.vendors as Json[]).some(v => equal(get(v, "address"), get(context, "original.dst_ip")) && equal(get(v, "port"), get(context, "original.dst_port")))) return fail("VENDOR");
      }
    }
    if (b.record_kind === "link") {
      const agent = prior(get(p, "link.agent_flow.open_sequence"), "open");
      // A link authenticates its full agent flow against the earlier agent open rather than a sequence alone.
      if (!agent || get(agent, "payload.edge") !== "agent_endpoint" || !equal(get(agent, "payload.context.flow"), get(p, "link.agent_flow"))) return fail("AGENT_FLOW");
      if (get(p, "link.kind") === "ingress") {
        // Ingress evidence binds the observed listener to the earlier agent open, while the accepted socket remains a separate observation.
        if (!sameContext(b, agent) || !equal(get(p, "link.listener"), get(agent, "payload.listener"))) return fail("INGRESS");
      } else {
        const ingress = prior(get(p, "link.ingress_sequence"), "link");
        // Egress attribution comes from the referenced ingress and agent actor, never a caller-supplied uid alone.
        if (!ingress || get(ingress, "payload.link.kind") !== "ingress" ||
            !equal(get(ingress, "payload.link.agent_flow"), get(p, "link.agent_flow")) ||
            !equal(get(p, "link.origin_agent_uid"), get(agent, "payload.context.actor_uid"))) return fail("EGRESS");
      }
    }
    if (b.record_kind === "allowance") {
      const link = prior(get(p, "link_sequence"), "link");
      // Allowances inherit precisely the open's origin, preventing budget transfer across unrelated links.
      if (!link || (get(opened, "payload.edge") === "endpoint_vendor" ?
        !equal(get(p, "link_sequence"), get(opened, "payload.origin_link_sequence")) :
        get(link, "payload.link.kind") !== "ingress" || !sameContext(b, link))) return fail("ALLOWANCE_LINK");
      const previous = sameFlow.filter(r => r.record_kind === "allowance").at(-1);
      // Ceilings are cumulative lifetime totals and cannot decrease when a new permit replaces an allowance.
      if (previous && !countsLE(get(previous, "payload.ceiling"), get(p, "ceiling"))) return fail("CUMULATIVE");
      // Permit identifiers remain reserved throughout retained history to prevent reuse across flows.
      if (history.some(r => r.body.record_kind === "allowance" && equal(get(r.body, "payload.permit_id"), get(p, "permit_id")))) return fail("PERMIT_UNIQUE");
      // An allowance cannot authorize packets after the relying grant's fixed expiry.
      if (integer(get(p, "expires_ns")) > integer(state.grant.expires_ns)) return fail("EXPIRY");
    }
    if (b.record_kind === "counter") {
      const allowance = prior(get(p, "allowance_sequence"), "allowance");
      // Counters consume only their own flow's allowance and never exceed its cumulative directional ceiling.
      if (!allowance || !sameContext(b, allowance)) return fail("COUNTER_ALLOWANCE");
      // Observed directional totals cannot exceed the referenced cumulative allowance.
      if (!countsLE(get(p, "totals"), get(allowance, "payload.ceiling"))) return fail("CEILING");
      const previous = sameFlow.filter(r => r.record_kind === "counter").at(-1);
      // A final observation closes the counter stream while periodic observations are rate-capped from open onward.
      if (get(previous, "payload.checkpoint") === "final") return fail("FINAL_CLOSED");
      // The periodic rate bound starts at open and repeats from the previous counter.
      if (get(p, "checkpoint") === "periodic" && integer(b.captured_at_boottime_ns) - integer((previous ?? opened)!.captured_at_boottime_ns) < COUNTER_PERIOD_NS) return fail("PERIODIC");
      if (previous) {
        // Same-epoch counters preserve both time and totals so an authentic producer cannot erase observed usage.
        if (integer(get(p, "window.last_ns")) < integer(get(previous, "payload.window.last_ns")) ||
            (equal(get(p, "counter_epoch"), get(previous, "payload.counter_epoch")) && !countsLE(get(previous, "payload.totals"), get(p, "totals")))) return fail("MONOTONE");
        // Epoch changes require an explicit incomplete interval covering the last trusted observation.
        if (!equal(get(p, "counter_epoch"), get(previous, "payload.counter_epoch")) &&
            (get(p, "complete") !== false || integer(get(p, "gap.first_ns")) > integer(get(previous, "payload.window.last_ns")) ||
            integer(get(p, "gap.last_ns")) < integer(get(previous, "payload.window.last_ns")))) return fail("EPOCH_GAP");
      }
    }
    if (b.record_kind === "terminal" && get(p, "final_counter_sequence") !== null) {
      const final = prior(get(p, "final_counter_sequence"), "counter");
      // Terminal evidence points to the same flow's final counter and cannot promote a periodic or incomplete observation.
      if (!final || !sameContext(b, final) || get(final, "payload.checkpoint") !== "final" ||
          (get(p, "effect") === "OBSERVED" && get(final, "payload.complete") !== true)) return fail("TERMINAL");
    }
    if (b.record_kind === "control" && get(p, "type") === "permit") {
      const allowance = prior(get(p, "allowance_sequence"), "allowance");
      // A permit consumes one existing allowance for the exact flow and identifier, once only.
      if (!allowance || !equal(get(p, "flow"), get(allowance, "payload.context.flow")) ||
          !equal(get(p, "permit_id"), get(allowance, "payload.permit_id"))) return fail("PERMIT_LINK");
      const issued = history.filter(r => get(r.body, "payload.type") === "permit" && equal(get(r.body, "payload.permit_id"), get(p, "permit_id")));
      // One issuance followed by at most one settlement prevents reuse of the reserved permit.
      if (get(p, "outcome") === "issued" ? issued.length !== 0 : issued.length !== 1 || get(issued[0]?.body, "payload.outcome") !== "issued") return fail("PERMIT_ONCE");
      // Issuance expires with its allowance while later settlement remains recordable.
      if (get(p, "outcome") === "issued" && integer(b.captured_at_boottime_ns) > integer(get(allowance, "payload.expires_ns"))) return fail("PERMIT_EXPIRED");
    }
    const next = structuredClone(state);
    next.anchor = {sequence: b.sequence, commitment: joinCommitment(record), lease_id: b.lease_id, generation: b.generation, captured_at_boottime_ns: b.captured_at_boottime_ns};
    next.flow_state.history.push(structuredClone(record));
    return {refusal_code: null, final_state: next};
  } catch { return fail("INPUT"); }
}

/** Verify the original signed body and index, then return only a fully admitted join state. */
export function verifyBusinessJoin(state: JoinState, record: JoinRecord): JoinResult {
  const result = advance(state, record);
  if (result.refusal_code !== null) return result;
  // Must match records.rs verify: the business pin is the enrolled subject plus the relying grant's activation, lease and generation.
  const pin: BusinessPin = {...(state.pin as unknown as RolePin), activation_id: state.grant.activation_id as string, lease_id: state.grant.lease_id as string, generation: state.grant.generation as number};
  const authentic = verifyIndexedRecord(canonicalBytes(record.body), record.outer.signature as string,
    pin, record.outer as unknown as OuterRecordIndex, z.unknown(), record.body.record_kind as string);
  // An accepted join carries producer evidence only after the independent strict verifier admits the original signature.
  return authentic ? result : {refusal_code: "AUTH", final_state: state};
}
