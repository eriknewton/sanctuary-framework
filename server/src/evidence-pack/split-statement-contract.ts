/** Closed, pure split-statement schema. Parsing provides structure, never authentication. */
import * as C from "./snapshot-contract.js";
import { AUDIT_CHECKPOINT_REQUIRED_KEYS, AUDIT_CHECKPOINT_OPTIONAL_KEYS, isAuditCheckpointRecord, type AuditCheckpointRecord } from "../audit/checkpoint-shape.js";
import { computeAuditRoot } from "../audit/chain.js";
// Must match EVIDENCE_SPLIT_STATEMENT_DOMAIN in core/signing-domains.ts, including raw-sign refusal.
import { EVIDENCE_SPLIT_STATEMENT_DOMAIN as MANIFEST_DOMAIN } from "../core/signing-domains.js";
import { extensionRolesAllowed } from "./snapshot-extensions.js";
export { MANIFEST_DOMAIN };
export const FORMAT = "SANCTUARY_EVIDENCE_SPLIT_STATEMENT_V1";
export const TRUST_FORMAT = "SANCTUARY_EVIDENCE_SPLIT_TRUST_V1";
export const RESULT_FORMAT = "SANCTUARY_EVIDENCE_SPLIT_VERIFICATION_V1";
export const RECEIPT_FORMAT = "SANCTUARY_EVIDENCE_SPLIT_RECEIPT_V1";
export const CENSUS_FORMAT = "SANCTUARY_EVIDENCE_SPLIT_CENSUS_V1";
export const CONTRACT = "operator-statement";
export const TOPOLOGY = "split";
export const CHAIN_IDS = ["operator", "daemon"] as const;
export type ChainId = typeof CHAIN_IDS[number];
export const PRESENTATION = "The daemon log is the operator's presentation.";
export const UNSIGNED_SENTENCE = "Its own audit checkpoints were not signed when its records were written, and signing this pack does not sign them.";
export const PASS_SENTENCE = "PASS: expected split-host statement bytes verified; both chains meet the operator-statement contract.";
export const MAX_EVIDENCE_RECORDS = C.MAX_RECORDS;
export const MAX_CENSUS_OBJECTS = 125000; // Separate object inventory allowance, including controls and exclusions.
export const MAX_SOURCE_OBJECTS = MAX_CENSUS_OBJECTS;
export const MAX_DECODED_CHECKPOINT_BYTES = C.MAX_PACK_BYTES;
export const MAX_LEAF_VISITS = C.MAX_KEYS * C.MAX_RECORDS;
export const MAX_SIGNATURE_ATTEMPTS = MAX_LEAF_VISITS;
export const MAX_FINDINGS = C.MAX_FILES; // 256 bounded diagnostics, independent of inventory size.
export const MAX_TEXT_BYTES = C.MAX_FILES; // 256 UTF-8 bytes per diagnostic text.
export const PIN_ROLE = { pack: C.PIN_ROLE.pack, operator: "audit-checkpoint:operator", daemon: "audit-checkpoint:daemon", transparency: C.PIN_ROLE.transparency } as const;
export const FIXED_FILES = { report: C.FIXED_FILES.report, pdf: C.FIXED_FILES.pdf, trust: C.FIXED_FILES.trust, recipient: C.FIXED_FILES.recipient, "audit-operator": ["audit-operator.jsonl", "application/jsonl"], "audit-daemon": ["audit-daemon.jsonl", "application/jsonl"], census: ["audit-census.json", "application/json"], transparency: C.FIXED_FILES.transparency } as const;
export const PARTIAL_CODES = ["source_incomplete", "source_changed", "source_limit", "source_unreadable", "missing_history", "pre_v2_history", "pruned_history", "unknown_source_object", "ambiguous_census", "controls_unavailable", "migration_unavailable", "checkpoint_mixed", "checkpoint_coverage_absent", "checkpoint_unsigned", "audit_tail_unanchored", "transparency_window_unavailable", "transparency_prefix_unverified", "transparency_absent", "extension_unverified"] as const;
export const HARD_CODES = [...Object.values(C.HARD), "source_control_invalid", "migration_invalid", "transparency_subject_mismatch", "chain_invalid", "checkpoint_invalid", "census_mismatch", "topology_ambiguous", "daemon_basis_unsupported"] as const;
export type PartialCode = typeof PARTIAL_CODES[number];
export type HardCode = typeof HARD_CODES[number];
export class SplitError extends Error { constructor(readonly code: HardCode) { super(code); } }
/** Closed findings prevent private source diagnostics crossing the public boundary. */
export function requireSplit(ok: unknown, code: HardCode = "nested_invalid"): asserts ok { if (!ok) throw new SplitError(code); }
type Parser<T> = (value: unknown) => T;
type Output<P> = P extends Parser<infer T> ? T : never;
function record<S extends Record<string, Parser<unknown>>>(shape: S): Parser<{ readonly [K in keyof S]: Output<S[K]> }> {
  return value => {
    const row = C.object(value, Object.keys(shape));
    // Every field is constructed by its own parser, so consumers never receive unchecked elements.
    const parsed = Object.fromEntries(Object.entries(shape).map(([key, parse]) => [key, parse(row[key])]));
    return Object.freeze(parsed) as { readonly [K in keyof S]: Output<S[K]> };
  };
}
function literal<const T extends string | number | boolean>(expected: T): Parser<T> { return value => { requireSplit(value === expected); return expected; }; }
function enumeration<const T extends readonly string[]>(values: T): Parser<T[number]> { return value => { requireSplit(typeof value === "string" && values.includes(value)); return value; }; }
function nullable<T>(parse: Parser<T>): Parser<T | null> { return value => value === null ? null : parse(value); }
function list<T>(parse: Parser<T>, maximum: number): Parser<readonly T[]> { return value => { C.array(value, maximum); return Object.freeze(value.map(parse)); }; }
const uint: Parser<number> = value => { C.integer(value); return value; };
const positive: Parser<number> = value => { C.integer(value, true); return value; };
const text: Parser<string> = value => { C.text(value); C.cap(C.utf8(value).length, MAX_TEXT_BYTES); return value; };
const pattern = (regex: RegExp): Parser<string> => value => { C.text(value, regex); return value; };
const hex = pattern(C.HEX), digest = pattern(C.DIGEST), fortress = pattern(/^fortress-[0-9a-f]{16}$/);
const time: Parser<string> = value => { C.timestamp(value); return value; };
const key: Parser<string> = value => { C.publicKey(value); return value as string; };
const signature: Parser<string> = value => { C.base64(value, C.SIGNATURE_BYTES); return value as string; };
const name: Parser<string> = value => { C.safeName(value); return value; };
const partial = enumeration(PARTIAL_CODES), hard = enumeration(HARD_CODES), chainId = enumeration(CHAIN_IDS);
const hashOrGenesis: Parser<string> = value => value === "GENESIS" ? value : hex(value);
const reason = enumeration(["unreadable", "missing_history", "no_checkpoints", "source_limit"] as const);
export type UnevaluatedReason = Output<typeof reason>;
const basis = enumeration(["all_pinned", "unsigned_present", "signed_with_errors"] as const);
const range = record({ first: positive, last: positive });
const coverage = nullable(record({ checkpointed: nullable(range), tail: nullable(range) }));
const chainFields = {
  chain_id: chainId, state: enumeration(["included", "empty", "unavailable", "invalid"] as const),
  historical_signatures: nullable(basis), signatures_evaluated: (value: unknown) => { requireSplit(typeof value === "boolean"); return value; },
  signatures_unevaluated_reason: nullable(reason), checkpoint_count: nullable(uint), unsigned_count: nullable(uint), signatures_verified: nullable(uint), entries_verified: nullable(uint), tail_entries: nullable(uint), coverage, partial_reasons: list(partial, PARTIAL_CODES.length),
};
/** Result and receipt readers use the same basis/coverage parser as recipient verification. */
export function parseChainResult(value: unknown) {
  const r = record(chainFields)(value);
  requireSplit(r.signatures_evaluated ? r.historical_signatures !== null && r.signatures_unevaluated_reason === null : r.historical_signatures === null && r.signatures_unevaluated_reason !== null);
  if (r.coverage) for (const span of [r.coverage.checkpointed, r.coverage.tail]) if (span) requireSplit(span.first <= span.last);
  return r;
}
export type ChainResult = ReturnType<typeof parseChainResult>;
function chainPair<T extends { readonly chain_id: ChainId }>(parse: Parser<T>): Parser<readonly [T,T]> {
  return value => { const rows = list(parse, CHAIN_IDS.length)(value); requireSplit(rows.length === CHAIN_IDS.length && rows.every((row,i) => row.chain_id === CHAIN_IDS[i])); return Object.freeze([rows[0], rows[1]]); };
}
const chainResults = chainPair(parseChainResult);
/** Human surfaces consume recomputed chain results, including explicit unsigned counts and coverage. */
export function renderChains(chains: readonly ChainResult[]) {
  const showRange = (span: Output<typeof range> | null) => span ? `${span.first}-${span.last}` : "none";
  const showBasis = (c: ChainResult) => c.signatures_evaluated ? c.historical_signatures + (c.state === "empty" ? "(empty)" : "") : `not_evaluated(${c.signatures_unevaluated_reason})`;
  const daemon = chains.find(c => c.chain_id === "daemon");
  return { historical_signatures: `HISTORICAL_SIGNATURES=${chains.map(c => `${c.chain_id}:${showBasis(c)}`).join(",")}`, coverage: chains.map(c => `COVERAGE=${c.chain_id}:checkpointed=${c.coverage ? showRange(c.coverage.checkpointed) : "unknown"},tail=${c.coverage ? showRange(c.coverage.tail) : "unknown"};unsigned=${c.unsigned_count ?? "unknown"},verified=${c.signatures_verified ?? "unknown"}`), sentences: daemon?.historical_signatures === "all_pinned" ? [PRESENTATION] : [PRESENTATION, UNSIGNED_SENTENCE] };
}
const rendered = record({ historical_signatures: text, coverage: list(text, CHAIN_IDS.length), sentences: list(text, CHAIN_IDS.length) });
const identity = record({ identity_id: pattern(C.IDENTITY_ID), public_key_base64url: key });
const extent = record({ entry_count: uint, first_sequence: nullable(positive), last_sequence: nullable(positive), head_hash: nullable(hex), checkpoint_count: uint, first_checkpoint_sequence: nullable(positive), last_checkpoint_sequence: nullable(positive), merkle_root: hex });
const transparencyExtent = record({ checkpoint_count: positive, first_counter: positive, last_counter: positive, last_checkpoint_payload_sha256: hex, fortress_id: fortress });
function component<T>(filename: string, parseExtent: Parser<T>) {
  const included = record({ state: literal("included"), filename: literal(filename), extent: parseExtent });
  const empty = record({ state: literal("empty_verified"), reason: literal("no_records") });
  const failed = record({ state: literal("read_failed"), reason: partial });
  return (value: unknown) => { const r = C.object(value, ["state"], ["filename", "extent", "reason"]); return r.state === "included" ? included(value) : r.state === "empty_verified" ? empty(value) : failed(value); };
}
const components = record({ operator: component(FIXED_FILES["audit-operator"][0], extent), daemon: component(FIXED_FILES["audit-daemon"][0], extent), census: record({ state: literal("included"), filename: literal(FIXED_FILES.census[0]) }), transparency: component(FIXED_FILES.transparency[0], transparencyExtent) });
const file = record({ filename: name, content_type: text, size_bytes: uint, sha256: hex, role: enumeration([...Object.keys(FIXED_FILES), "extension"]) });
const extension = record({ id: pattern(C.EXTENSION_ID), filenames: list(name, C.MAX_FILES), signing_roles: list(text, C.MAX_KEYS) });
const manifestSchema = record({ format: literal(FORMAT), contract: literal(CONTRACT), topology: literal(TOPOLOGY), fortress_id: fortress, signature_scheme: literal(C.SIGNATURE_SCHEME), hash_algorithm: literal(C.HASH_ALGORITHM), export_id: pattern(C.UUID), generated_at: time, source_revision: pattern(C.REVISION), signer: identity, files: list(file, C.MAX_FILES - 1), components, extensions: list(extension, C.MAX_FILES), manifest_signature: signature });
/** Parse the bounded envelope before any listed payload is opened. */
export function parseManifestEnvelope(bytes: Uint8Array) {
  const value = C.parseSnapshotJSON(bytes, C.MAX_MANIFEST_BYTES);
  requireSplit(value !== null && typeof value === "object" && !Array.isArray(value), "manifest_invalid");
  requireSplit((value as Record<string, unknown>).format === FORMAT, "unsupported_format");
  return value as Record<string, unknown>;
}
/** Validate exact file roles and component inventories after manifest authentication. */
export function parseManifest(value: unknown) {
  const m = manifestSchema(value); let previous = "", total = 0;
  const counts = new Map<string,number>();
  for (const row of m.files) {
    requireSplit(row.filename > previous && row.filename !== C.MANIFEST_FILENAME, "file_set_mismatch"); previous = row.filename;
    C.cap(row.size_bytes, C.MAX_FILE_BYTES); total += row.size_bytes; C.cap(total, C.MAX_PACK_BYTES);
    counts.set(row.role, (counts.get(row.role) ?? 0) + 1);
    if (row.role === "extension") requireSplit(row.content_type === C.EXTENSION_MIME);
    else { const fixed = FIXED_FILES[row.role as keyof typeof FIXED_FILES]; requireSplit(fixed && row.filename === fixed[0] && row.content_type === fixed[1] && row.size_bytes > 0); }
  }
  for (const role of ["report","pdf","trust","recipient","census"]) requireSplit(counts.get(role) === 1);
  for (const id of CHAIN_IDS) requireSplit((counts.get(`audit-${id}`) ?? 0) === (m.components[id].state === "included" ? 1 : 0));
  requireSplit((counts.get("transparency") ?? 0) === (m.components.transparency.state === "included" ? 1 : 0));
  const ids = new Set<string>(), names = new Set<string>();
  for (const e of m.extensions) {
    requireSplit(!ids.has(e.id) && e.filenames.length > 0 && e.signing_roles.length > 0 && new Set(e.signing_roles).size === e.signing_roles.length && extensionRolesAllowed(e.id,[...e.signing_roles])); ids.add(e.id);
    for (const n of e.filenames) { requireSplit(!names.has(n) && m.files.some(f => f.filename === n && f.role === "extension")); names.add(n); }
  }
  requireSplit(names.size === (counts.get("extension") ?? 0));
  return m;
}
export type Manifest = ReturnType<typeof parseManifest>;
/** Sign the complete B body in its own domain; the V0 contract stays closed. */
export function manifestSigningBytes(value: Record<string, unknown>): Uint8Array { const body = { ...value }; delete body.manifest_signature; return C.utf8(MANIFEST_DOMAIN + C.canonicalSnapshotJSON(body)); }
/** B reuses the V0 key-row leaf validator, with a closed mapping for chain-specific roles. */
export function parseTrust(bytes: Uint8Array) {
  const r = C.object(C.parseSnapshotJSON(bytes,C.MAX_TRUST_BYTES), ["format","contract","topology","fortress_id","keys"]);
  requireSplit(r.format === TRUST_FORMAT, "unsupported_format"); requireSplit(r.contract === CONTRACT && r.topology === TOPOLOGY); const fortress_id = fortress(r.fortress_id);
  C.array(r.keys,C.MAX_KEYS); let previous = "";
  const keys = r.keys.map(candidate => {
    const row = C.object(candidate,["role","key_id","algorithm","public_key_base64url","fingerprint","rotation_evidence"]);
    C.text(row.role); requireSplit(Object.values(PIN_ROLE).includes(row.role as never) || row.role.startsWith(C.PIN_ROLE.extension));
    const role = row.role; const mapped: Record<string, unknown> & { role: string } = { ...row, role: role === PIN_ROLE.operator || role === PIN_ROLE.daemon ? C.PIN_ROLE.audit : role };
    // The leaf parser needs one pack key; a temporary public-only pack row supplies that schema context.
    const pack: Record<string, unknown> & { role: string } = { ...mapped, role: C.PIN_ROLE.pack, rotation_evidence: { kind: C.ROTATION.history, identity_id: "0".repeat(32), current_public_key: mapped.public_key_base64url, history: [] } };
    const rows = mapped.role === C.PIN_ROLE.pack ? [mapped] : [mapped,pack].sort((a,b) => (a.role+":"+a.key_id).localeCompare(b.role+":"+b.key_id));
    const parsed = C.parseTrustDescriptor(C.utf8(JSON.stringify({format:C.TRUST_FORMAT,keys:rows}))).keys.find(k => k.role === mapped.role)!;
    const order = role+":"+parsed.key_id; requireSplit(order > previous,"pin_invalid"); previous = order;
    return Object.freeze({ ...parsed, role });
  });
  requireSplit(keys.filter(k => k.role === PIN_ROLE.pack).length === 1 && keys.filter(k => k.role === PIN_ROLE.transparency).length <= 1,"pin_invalid");
  return Object.freeze({ format: TRUST_FORMAT, contract: CONTRACT, topology: TOPOLOGY, fortress_id, keys: Object.freeze(keys) });
}
export type Trust = ReturnType<typeof parseTrust>;
/** Shared producer keys must match AUDIT_CHECKPOINT_REQUIRED_KEYS and AUDIT_CHECKPOINT_OPTIONAL_KEYS in audit/checkpoint-shape.ts. */
export function parsePersistedCheckpoint(bytes: Uint8Array): Readonly<AuditCheckpointRecord> {
  const row = C.object(C.parseSnapshotJSON(bytes,C.MAX_JSONL_LINE_BYTES),AUDIT_CHECKPOINT_REQUIRED_KEYS,AUDIT_CHECKPOINT_OPTIONAL_KEYS);
  requireSplit(isAuditCheckpointRecord(row) && row.checkpoint_kind === "audit-checkpoint","checkpoint_invalid");
  C.integer(row.checkpoint_sequence,true); C.integer(row.from_sequence,true); C.integer(row.previous_checkpoint_sequence);
  requireSplit(row.from_sequence <= row.checkpoint_sequence && row.previous_checkpoint_sequence < row.checkpoint_sequence,"checkpoint_invalid"); C.timestamp(row.signed_at);
  if (row.unsigned) requireSplit(row.signature === null && row.signer_kid === null && row.signature_algorithm === null && !Object.hasOwn(row,"public_key"),"checkpoint_invalid");
  else { requireSplit(row.signature_algorithm === C.ALGORITHM,"checkpoint_invalid"); C.base64(row.signature,C.SIGNATURE_BYTES); C.text(row.signer_kid); if (row.public_key !== undefined) C.publicKey(row.public_key); }
  if (row.unsigned_reason !== undefined) text(row.unsigned_reason);
  return Object.freeze(row);
}
const entrySchema = record({ type: literal("entry"), seq: positive, schema_version: literal(2), prev_hash: hashOrGenesis, entry_hash: hex, timestamp: time, encrypted_payload_bytes: (v: unknown) => { C.base64(v); return v as string; } }); // 2 is the existing V2 entry wire version.
export type Entry = Output<typeof entrySchema>;
export type AuditLine = { readonly record: Entry | { readonly type: "checkpoint"; readonly persisted_base64url: string; readonly checkpoint: Readonly<AuditCheckpointRecord> }; readonly sha256: string; readonly index: number };
/** One request owns all counters; exporters and recipients charge the same aggregate work. */
export class Budget {
  records = 0; decoded = 0; leaves = 0; signatures = 0;
  charge(kind: "records" | "decoded" | "leaves" | "signatures", count: number): void {
    C.integer(count); const caps = { records: MAX_EVIDENCE_RECORDS, decoded: MAX_DECODED_CHECKPOINT_BYTES, leaves: MAX_LEAF_VISITS, signatures: MAX_SIGNATURE_ATTEMPTS };
    // Charge before allocation or work so the first excess unit is never performed.
    requireSplit(count <= caps[kind] - this[kind],"limit_exceeded"); this[kind] += count;
  }
}
/** Decode every JSONL element once, preserving original checkpoint bytes and physical line hashes. */
export function parseAudit(bytes: Uint8Array, budget: Budget): readonly AuditLine[] {
  C.cap(bytes.length,C.MAX_FILE_BYTES); const lines: AuditLine[] = []; let start = 0;
  for (let i=0;i<=bytes.length;i++) {
    if (i !== bytes.length && bytes[i] !== 10) continue;
    if (i === start && i === bytes.length) break;
    budget.charge("records",1); const raw = bytes.subarray(start,i); C.cap(raw.length,C.MAX_JSONL_LINE_BYTES); start=i+1;
    const value = C.parseSnapshotJSON(raw,C.MAX_JSONL_LINE_BYTES);
    const row = C.object(value,["type"],[...C.AUDIT_FIELDS.entry.required.filter(k => k !== "type"),"persisted_base64url"]);
    let parsed: AuditLine["record"];
    if (row.type === "entry") parsed = entrySchema(row);
    else {
      C.object(row,["type","persisted_base64url"]); requireSplit(row.type === "checkpoint"); C.text(row.persisted_base64url,C.BASE64URL);
      budget.charge("decoded",Math.floor(row.persisted_base64url.length * 3 / 4)); // Unpadded base64url expands by exactly this floor.
      parsed = Object.freeze({type:"checkpoint",persisted_base64url:row.persisted_base64url,checkpoint:parsePersistedCheckpoint(C.base64(row.persisted_base64url))});
    }
    lines.push(Object.freeze({record:parsed,sha256:C.sha256Hex(raw),index:lines.length}));
  }
  requireSplit(lines.length > 0); return Object.freeze(lines);
}
/** Every window scalar is validated before assignment, including the exact empty-window shape. */
export function parseTransparency(bytes: Uint8Array, budget: Budget) {
  const bundle = C.parseTransparency(bytes); budget.charge("records",bundle.checkpoints.length);
  for (const cp of bundle.checkpoints) {
    const a = cp.audit; C.integer(a.entry_count); C.integer(a.lowest_sequence); C.integer(a.highest_sequence); hex(a.merkle_root);
    if (a.entry_count === 0) requireSplit(a.lowest_sequence === 0 && a.highest_sequence === 0 && a.head_hash === "GENESIS" && a.merkle_root === computeAuditRoot([]));
    else { C.integer(a.lowest_sequence,true); C.integer(a.highest_sequence,true); requireSplit(a.highest_sequence >= a.lowest_sequence && a.highest_sequence - a.lowest_sequence + 1 === a.entry_count); hex(a.head_hash); }
    positive(cp.counter); fortress(cp.fortress_id); hashOrGenesis(cp.previous_checkpoint_hash); text(cp.signer_kid);
    uint(cp.policy.rules_count); hex(cp.policy.rules_sha256); if (cp.policy.manifest_sha256 !== null) hex(cp.policy.manifest_sha256);
    text(cp.daemon.version); hex(cp.daemon.binary_sha256); uint(cp.enforcement.total_allowed); uint(cp.enforcement.total_blocked);
    for (const rule of cp.enforcement.rules) { text(rule.rule_label); uint(rule.allowed); uint(rule.blocked); }
  }
  return bundle;
}
/** Must match SOURCE_NAMESPACES consumed by audit/split-evidence-registry.ts. */
export const SOURCE_NAMESPACES = ["state","_audit","_audit_checkpoints","_audit_integrity_alert","_audit_migration","_audit-daemon","_audit-daemon_checkpoints","_audit-daemon_meta","_meta","_transparency_checkpoints"] as const;
const namespace = enumeration(SOURCE_NAMESPACES);
const namespaceRow = record({ namespace, state: enumeration(["listed","absent","unreadable","invalid"] as const), listed_count: nullable(uint) });
const output = nullable(record({filename:enumeration([FIXED_FILES["audit-operator"][0],FIXED_FILES["audit-daemon"][0],FIXED_FILES.transparency[0]] as const),record_index:uint,record_sha256:hex}));
const objectRow = record({namespace,name_digest:hex,kind:enumeration(["entry","checkpoint","control","excluded","unsupported"] as const),read_state:enumeration(["read","absent","unreadable","invalid"] as const),source_sha256:nullable(hex),output});
const censusChain = record({chain_id:chainId,census_state:enumeration(["complete","empty","unavailable","incomplete"] as const),source_entries:nullable(uint),source_checkpoints:nullable(uint),exported_entries:nullable(uint),exported_checkpoints:nullable(uint),skipped:nullable(uint),controls_state:enumeration(["operator_checked","unavailable","invalid"] as const),controls_issues:list(partial,PARTIAL_CODES.length)});
const migrationChecked = record({state:literal("operator_checked"),sealed_base_sequence:uint,sealed_tip_sequence:uint,sealed_tip_entry_hash:hashOrGenesis,daemon_namespace:literal("_audit-daemon"),daemon_genesis_entry_hash:hex,genesis_binding:literal("operator_checked")});
const unavailable = record({state:literal("unavailable"),reason:partial});
const invalid = record({state:literal("invalid"),reason:hard});
const floorChecked = record({state:literal("operator_checked"),highest_counter:uint});
function stateOf(v: unknown) { requireSplit(v !== null && typeof v === "object" && !Array.isArray(v)); return (v as Record<string,unknown>).state; }
const migration = (v: unknown) => stateOf(v) === "operator_checked" ? migrationChecked(v) : stateOf(v) === "invalid" ? invalid(v) : unavailable(v);
const floor = (v: unknown) => stateOf(v) === "operator_checked" ? floorChecked(v) : stateOf(v) === "absent" ? record({state:literal("absent")})(v) : stateOf(v) === "invalid" ? invalid(v) : unavailable(v);
const censusSchema = record({format:literal(CENSUS_FORMAT),export_id:pattern(C.UUID),fortress_id:fortress,observed_from:time,observed_to:time,state:enumeration(["complete","incomplete"] as const),namespaces:list(namespaceRow,MAX_CENSUS_OBJECTS),objects:list(objectRow,MAX_CENSUS_OBJECTS),chains:chainPair(censusChain),migration,transparency_floor:floor,issues:list(partial,PARTIAL_CODES.length)});
/** Parse bounded operator testimony without treating its assertions as independent verification. */
export function parseCensus(bytes: Uint8Array) {
  const c = censusSchema(C.parseSnapshotJSON(bytes,C.MAX_FILE_BYTES)); requireSplit(c.observed_from <= c.observed_to,"census_mismatch");
  requireSplit(new Set(c.namespaces.map(n => n.namespace)).size === c.namespaces.length,"census_mismatch");
  if(c.state === "complete") requireSplit(c.namespaces.length === SOURCE_NAMESPACES.length,"census_mismatch");
  let previous = "";
  for (const row of c.objects) {
    // Must match readSplitSource in audit/split-evidence-source.ts; chain rows require an attempted read, excluded names never carry values.
    if(row.kind==="entry"||row.kind==="checkpoint")requireSplit(row.read_state==="read"||row.read_state==="unreadable","census_mismatch");
    if(row.kind==="excluded"||row.kind==="unsupported")requireSplit(row.read_state==="absent","census_mismatch");
    const key = row.namespace+":"+row.name_digest; requireSplit(key > previous,"census_mismatch"); previous=key; requireSplit((row.read_state === "read") === (row.source_sha256 !== null),"census_mismatch"); }
  for (const row of c.namespaces) requireSplit((row.state === "listed") === (row.listed_count !== null),"census_mismatch");
  if (c.state === "complete") requireSplit(c.issues.length === 0 && c.namespaces.every(n => n.state === "listed" || n.state === "absent") && c.chains.every(r => r.census_state === "complete" || r.census_state === "empty"),"census_mismatch");
  for (const row of c.chains) if (row.census_state === "complete" || row.census_state === "empty") requireSplit([row.source_entries,row.source_checkpoints,row.exported_entries,row.exported_checkpoints].every(v => v !== null) && row.skipped === 0 && row.controls_state === "operator_checked" && row.controls_issues.length === 0,"census_mismatch");
  return c;
}
export type Census = ReturnType<typeof parseCensus>;
const parsedBrand: unique symbol = Symbol("parsed split statement");
export interface ParsedSplitStatement { readonly [parsedBrand]: true; readonly manifest: Manifest; readonly trust: Trust; readonly census: Census; readonly operator: readonly AuditLine[]; readonly daemon: readonly AuditLine[]; readonly transparency: ReturnType<typeof parseTransparency> | null; readonly budget: Budget }
export type SplitParseResult = { kind: "parsed"; value: ParsedSplitStatement } | { kind: "rejected"; code: HardCode; location: "pack" };
/** All consumers, including a future importer, share this typed element boundary. */
export function parseSplitStatement(manifest: unknown, trust: Uint8Array, files: ReadonlyMap<string,Uint8Array>, budget = new Budget()): SplitParseResult {
  try {
    const m = parseManifest(manifest), t = parseTrust(trust);
    const need = (filename: string) => { const bytes=files.get(filename); requireSplit(bytes,"file_set_mismatch"); return bytes; };
    const readChain = (id: ChainId) => m.components[id].state === "included" ? parseAudit(need(FIXED_FILES[`audit-${id}`][0]),budget) : [];
    return {kind:"parsed",value:Object.freeze({[parsedBrand]:true as const,manifest:m,trust:t,census:parseCensus(need(FIXED_FILES.census[0])),operator:readChain("operator"),daemon:readChain("daemon"),transparency:m.components.transparency.state === "included" ? parseTransparency(need(FIXED_FILES.transparency[0]),budget) : null,budget})};
  } catch (error) { return {kind:"rejected",code:error instanceof SplitError ? error.code : error instanceof C.SnapshotError ? error.code : "nested_invalid",location:"pack"}; }
}
const finding = record({code:hard,state:enumeration(Object.values(C.STATES)),filename:nullable(name)});
const assignments = list(record({counter:positive,chain_id:chainId}),MAX_EVIDENCE_RECORDS);
const resultSchema = record({format:literal(RESULT_FORMAT),contract:literal(CONTRACT),status:enumeration(["PASS","PARTIAL","FAIL"] as const),exit_code:uint,accepted:(v:unknown)=>{requireSplit(typeof v === "boolean");return v;},snapshot_integrity:enumeration(Object.values(C.INTEGRITY)),export_id:nullable(pattern(C.UUID)),manifest_digest:nullable(digest),verifier_source_revision:(v:unknown)=>{requireSplit(typeof v === "string" && v.length <= C.MAX_NAME_BYTES);return v;},findings:list(finding,MAX_FINDINGS),findings_total:uint,findings_truncated:(v:unknown)=>{requireSplit(typeof v === "boolean");return v;},partial_reasons:list(partial,PARTIAL_CODES.length),chains:chainResults,transparency_assignments:assignments,nested:record({operator:nullable(parseChainResult),daemon:nullable(parseChainResult),transparency:nullable(record({verdict:enumeration(["PASS","PARTIAL","FAIL"] as const),checkpoints_verified:uint,window_findings:list(record({code:literal("transparency_window_unavailable"),counter:positive}),MAX_FINDINGS),window_findings_total:uint,window_findings_truncated:(v:unknown)=>{requireSplit(typeof v === "boolean");return v;},not_checked:list(text,MAX_FINDINGS)}))}),not_checked:list(text,MAX_FINDINGS)});
/** Serialized status is data only; this parser never constructs a verified capability. */
export function parseResult(value: unknown) {
  const r=resultSchema(value);
  // Must match verifySplitTransparency in split-statement-nested.ts; bounded diagnostics retain their full count.
  const t=r.nested.transparency;
  if(t)requireSplit(t.window_findings.length===Math.min(t.window_findings_total,MAX_FINDINGS)&&t.window_findings_truncated===(t.window_findings_total>MAX_FINDINGS));
  if(r.status!=="FAIL")C.text(r.verifier_source_revision,C.REVISION); requireSplit(r.accepted === (r.status === "PASS") && r.exit_code === (r.status === "PASS" ? C.EXIT_PASS : r.status === "PARTIAL" ? C.EXIT_PARTIAL : C.EXIT_FAIL));
  requireSplit(r.status === "FAIL" ? r.findings.length > 0 : r.findings.length === 0); requireSplit(r.status === "PARTIAL" ? r.partial_reasons.length > 0 : r.partial_reasons.length === 0); return r;
}
export type Result = ReturnType<typeof parseResult>;
/** Receipt and result chain fields share their parser, preventing presentation drift. */
// Must match exportSnapshot in snapshot-export-cli.ts; pack_path uses MAX_TEXT_BYTES before STAGE.
export function parseReceipt(value: unknown) {
  const r=record({format:literal(RECEIPT_FORMAT),export_id:pattern(C.UUID),manifest_digest:digest,source_revision:pattern(C.REVISION),trust_descriptor_sha256:digest,pack_path:text,status:enumeration(["PASS","PARTIAL"] as const),pack_key_fingerprint:digest,contract:literal(CONTRACT),chains:chainResults,rendered})(value);
  requireSplit(C.canonicalSnapshotJSON(r.rendered) === C.canonicalSnapshotJSON(renderChains(r.chains))); return r;
}
