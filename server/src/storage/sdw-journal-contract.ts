/** Bounded SDW journal records; this module creates no journal or storage authority. */
import { z } from "zod";
import {
  SDW_MAX_STAGED_BYTES, SDW_JOURNAL_NAMESPACES, SdwStorageError,
  sdwGenerationSchema as generationSchema, sdwEpochsSchema as epochsSchema,
  type SdwAdmissionToken, type SdwEpochs, type SdwGeneration,
} from "./sdw-fence.js";
export {
  SDW_MAX_STAGED_BYTES, SDW_JOURNAL_NAMESPACES, SDW_MAX_PENDING_CALLS,
  SDW_READ_RETRIES, SDW_LOCK_WAIT_MS, SDW_JOURNAL_NAMESPACE,
  SDW_NAMESPACE_MUTATION_LOCK, SdwStorageError,
} from "./sdw-fence.js";
export type { SdwAdmissionToken, SdwEpochs, SdwGeneration, SdwDecision, SdwStorageReason } from "./sdw-fence.js";

import { hash } from "../core/hashing.js";
import { verify } from "../core/identity.js";
import { INTERNAL_RECEIPT_SIGNING_DOMAIN_PREFIX } from "../core/signing-domains.js";
import {
  SDW_CATALOG_NAMESPACE, SDW_DOCUMENT_CORPUS_NAMESPACE, SDW_META_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE, SDW_VECTOR_MEMORY_NAMESPACE, SDW_WORKING_STATE_NAMESPACE,
  type SdwNamespace,
} from "../sdw/records.js";
import { encodeFilesystemStorageName, filesystemStorageNameRoundTrips } from "./filesystem-name-codec.js";
import type { StorageBackend } from "./interface.js";

// Must match the ciphertext/record import ceilings in sdw/import.ts.

export const SDW_MAX_RECORDS = 100_000;
export const SDW_PAGE_RECORDS = 256;
export const SDW_MAX_PAGES = Math.ceil(SDW_MAX_RECORDS / SDW_PAGE_RECORDS);
export const SDW_MAX_KEY_ENCODED_BYTES = 255 - ".enc".length;
export const SDW_MAX_DESCRIPTOR_BYTES = 1024;
export const SDW_MAX_PAGE_BYTES = 256 * 1024;
export const SDW_MAX_PLAN_BYTES = 128 * 1024;
export const SDW_MAX_RECEIPT_BYTES = 16 * 1024;
export const SDW_MAX_MARKER_BYTES = 4 * 1024;
export const SDW_MAX_GENERATION_BYTES = 4 * 1024;
// Five controls: PREPARED, COMMIT, APPLIED, RETIRED and generation; temps are extra.
export const SDW_MAX_METADATA_BYTES = SDW_MAX_PAGES * SDW_MAX_PAGE_BYTES +
  SDW_MAX_PLAN_BYTES + SDW_MAX_RECEIPT_BYTES + 5 * SDW_MAX_MARKER_BYTES;



export const SDW_CLEANUP_BATCH_FILES = 256;
export const SDW_MAX_JOURNAL_DEPTH = 3;
// Layout allowance for directories, controls and the reusable temporary files.
export const SDW_MAX_JOURNAL_ENTRIES = SDW_MAX_RECORDS + SDW_MAX_PAGES + 32;

export const SDW_JOURNAL_TEMP = ".tmp";

/** Bit positions in affected_mask, also the canonical epoch/coverage order. */
// Must match isSdwNamespace in sdw/write-gate.ts; pinned here only because that
// higher-level module is outside this packet's scope. Full-set parity is tested.
const journalNamespaces: ReadonlySet<string> = new Set([SDW_CATALOG_NAMESPACE, SDW_DOCUMENT_CORPUS_NAMESPACE, SDW_META_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE, SDW_VECTOR_MEMORY_NAMESPACE, SDW_WORKING_STATE_NAMESPACE]);
export type SdwJournalName = "generation" | "plan.json" | "receipt.bin" |
  "PREPARED" | "COMMIT" | "APPLIED" | "RETIRED";
function invalid(): never { throw new SdwStorageError("storage_plan_invalid", "none"); }
function requireValid(condition: unknown): asserts condition { if (!condition) invalid(); }

// JSON nesting is independent of on-disk depth: envelope/body/pages/entry needs
// five containers; twelve leaves room for these fixed v1 shapes, never recursion from disk.
const MAX_JSON_DEPTH = 12;
// Each v1 object has at most sixteen fields; the longest array is the page index.
const MAX_OBJECT_FIELDS = 16;
const MAX_JSON_NODES = MAX_OBJECT_FIELDS * (SDW_MAX_PAGES + 1);
const MAX_ID_BYTES = 256;
const ED25519_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const hashSchema = z.string().regex(/^[0-9a-f]{64}$/);
const transactionSchema = z.string().regex(/^[0-9a-f]{32}$/);
const idSchema = z.string().min(1).max(MAX_ID_BYTES).refine(v => Buffer.byteLength(v) <= MAX_ID_BYTES);
const timestampSchema = z.string().datetime();
const integer = (max: number) => z.number().int().min(0).max(max).refine(Number.isSafeInteger);
const encodedBytes = (length: number) => z.string()
  .length(Math.ceil(length * 8 / 6)) // unpadded base64url carries six bits per character
  .regex(/^[A-Za-z0-9_-]+$/)
  .refine(v => Buffer.from(v, "base64url").length === length && Buffer.from(v, "base64url").toString("base64url") === v);
const keySchema = z.string().min(1).max(SDW_MAX_KEY_ENCODED_BYTES).refine(v =>
  !v.includes("\0") && v !== "." && v !== ".." && filesystemStorageNameRoundTrips(v) &&
  Buffer.byteLength(encodeFilesystemStorageName(v)) <= SDW_MAX_KEY_ENCODED_BYTES);
const namespaceSchema = z.custom<SdwNamespace>(v => typeof v === "string" && journalNamespaces.has(v));
const namespacesSchema = z.array(namespaceSchema).min(1).max(SDW_JOURNAL_NAMESPACES.length)
  .refine(v => v.every((ns, i) => i === 0 || v[i - 1]! < ns));
const entrySchema = z.object({
  ordinal: integer(SDW_MAX_RECORDS - 1), namespace: namespaceSchema, key: keySchema,
  target_ciphertext_sha256: hashSchema, byte_length: integer(SDW_MAX_STAGED_BYTES).min(1),
}).strict();
const pageSchema = z.object({
  version: z.literal(1), transaction_id: transactionSchema, page: integer(SDW_MAX_PAGES - 1),
  entries: z.array(entrySchema).min(1).max(SDW_PAGE_RECORDS),
}).strict().superRefine((page, ctx) => {
  const targets = new Set<string>();
  page.entries.forEach((entry, index) => {
    const target = `${entry.namespace}\0${entry.key}`;
    if (entry.ordinal !== page.page * SDW_PAGE_RECORDS + index || targets.has(target) ||
      sdwCanonicalBytes(entry).length > SDW_MAX_DESCRIPTOR_BYTES) ctx.addIssue({ code: "custom", message: "invalid descriptor" });
    targets.add(target);
  });
});
const pageDescriptorSchema = z.object({
  page: integer(SDW_MAX_PAGES - 1), record_count: integer(SDW_PAGE_RECORDS).min(1),
  byte_length: integer(SDW_MAX_PAGE_BYTES).min(1), sha256: hashSchema,
}).strict();
const planBodySchema = z.object({
  version: z.literal(1), fortress_id: idSchema, identity_id: idSchema,
  signer_public_key: encodedBytes(ED25519_KEY_BYTES), transaction_id: transactionSchema,
  created_at: timestampSchema, namespaces: namespacesSchema,
  record_count: integer(SDW_MAX_RECORDS), staged_bytes: integer(SDW_MAX_STAGED_BYTES),
  receipt_sha256: hashSchema, receipt_byte_length: integer(SDW_MAX_RECEIPT_BYTES),
  pages: z.array(pageDescriptorSchema).max(SDW_MAX_PAGES),
}).strict().superRefine((body, ctx) => {
  if (body.pages.length !== Math.ceil(body.record_count / SDW_PAGE_RECORDS) ||
    body.pages.some((p, i) => p.page !== i || p.record_count !== Math.min(SDW_PAGE_RECORDS, body.record_count - i * SDW_PAGE_RECORDS)) ||
    (body.record_count === 0 ? body.staged_bytes !== 0 : body.staged_bytes < body.record_count)) {
    ctx.addIssue({ code: "custom", message: "invalid totals" });
  }
});
const receiptSchema = z.object({
  receipt_id: transactionSchema, receipt_type: z.literal("internal"),
  subject: z.enum(["sdw-storage-plan", "sdw-storage-commit", "sdw-storage-applied", "sdw-storage-retired"]),
  issued_at: timestampSchema, status: z.enum(["issued", "approved", "completed"]),
  // Must match normalizeInternalReceiptSigningPayload in cognitive/tools.ts:
  // that helper requires the algorithm-prefixed body digest, unlike disk hashes.
  body_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
}).strict();
const preparedSchema = z.object({
  version: z.literal(1), state: z.literal("PREPARED"),
  transaction_id: transactionSchema, plan_sha256: hashSchema,
}).strict();
const certificateBodySchema = z.object({
  version: z.literal(1), state: z.enum(["COMMIT", "APPLIED", "RETIRED"]),
  transaction_id: transactionSchema, plan_sha256: hashSchema,
  fortress_id: idSchema, identity_id: idSchema, signer_public_key: encodedBytes(ED25519_KEY_BYTES),
  epochs: epochsSchema, receipt_sha256: hashSchema, receipt_byte_length: integer(SDW_MAX_RECEIPT_BYTES),
}).strict();
const planSchema = z.object({ body: planBodySchema, attestation: receiptSchema, signature: encodedBytes(ED25519_SIGNATURE_BYTES) }).strict();
const certificateSchema = z.object({ body: certificateBodySchema, attestation: receiptSchema, signature: encodedBytes(ED25519_SIGNATURE_BYTES) }).strict();
/** All producers and readers use these typed parse results, never mirrored validators. */
export type SdwPlan = z.infer<typeof planSchema>;
export type SdwPlanBody = SdwPlan["body"];
export type SdwPlanPage = z.infer<typeof pageSchema>;
export type SdwPlanEntry = SdwPlanPage["entries"][number];
export type SdwCertificate = z.infer<typeof certificateSchema>;
export type SdwPrepared = z.infer<typeof preparedSchema>;
export type SdwSigningReceipt = z.infer<typeof receiptSchema>;
export interface SdwRecordTypes {
  plan: SdwPlan; page: SdwPlanPage; prepared: SdwPrepared;
  certificate: SdwCertificate; generation: SdwGeneration;
}
const schemas = { plan: planSchema, page: pageSchema, prepared: preparedSchema, certificate: certificateSchema, generation: generationSchema };
export const SDW_RECORD_BYTE_LIMITS = {
  plan: SDW_MAX_PLAN_BYTES, page: SDW_MAX_PAGE_BYTES, prepared: SDW_MAX_MARKER_BYTES,
  certificate: SDW_MAX_MARKER_BYTES, generation: SDW_MAX_GENERATION_BYTES,
} as const;

/** Sorted-key JSON matching cognitive/tools.ts canonicalJson; storage has no cognitive import. */
export function sdwCanonicalBytes(value: unknown, maxBytes = SDW_MAX_PAGE_BYTES): Uint8Array {
  requireValid(Number.isSafeInteger(maxBytes) && maxBytes >= 0 && maxBytes <= SDW_MAX_PAGE_BYTES);
  let bytes = 0;
  let nodes = 0;
  const chunks: string[] = [];
  const emit = (s: string) => {
    bytes += Buffer.byteLength(s);
    requireValid(bytes <= maxBytes);
    chunks.push(s);
  };
  const string = (s: string) => {
    // Charge escaped UTF-8 before allocating the escaped string. Lone surrogates
    // use JSON's six-byte \uXXXX form; valid surrogate pairs use four UTF-8 bytes.
    requireValid(s.length <= maxBytes - bytes);
    let encoded = 2; // JSON quotation marks
    for (let i = 0; i < s.length; i++) {
      const code = s.charCodeAt(i);
      if (code === 0x22 || code === 0x5c || [8, 9, 10, 12, 13].includes(code)) encoded += 2;
      else if (code < 0x20) encoded += 6;
      else if (code < 0x80) encoded++;
      else if (code < 0x800) encoded += 2;
      else if (code >= 0xd800 && code <= 0xdbff && s.charCodeAt(i + 1) >= 0xdc00 && s.charCodeAt(i + 1) <= 0xdfff) { encoded += 4; i++; }
      else if (code >= 0xd800 && code <= 0xdfff) encoded += 6;
      else encoded += 3;
      requireValid(encoded <= maxBytes - bytes);
    }
    requireValid(encoded <= maxBytes - bytes);
    emit(JSON.stringify(s));
  };
  const visit = (v: unknown, depth: number): void => {
    requireValid(++nodes <= MAX_JSON_NODES && depth <= MAX_JSON_DEPTH);
    if (v === null) return emit("null");
    if (typeof v === "string") return string(v);
    if (typeof v === "boolean") return emit(String(v));
    if (typeof v === "number") { requireValid(Number.isFinite(v)); return emit(JSON.stringify(v)); }
    requireValid(typeof v === "object" && v !== null);
    if (Array.isArray(v)) {
      requireValid(v.length <= SDW_MAX_PAGES);
      emit("[");
      for (let i = 0; i < v.length; i++) {
        requireValid(Object.hasOwn(v, i));
        if (i) emit(",");
        visit(v[i], depth + 1);
      }
      return emit("]");
    }
    requireValid(Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
    const keys = Object.keys(v);
    requireValid(keys.length <= MAX_OBJECT_FIELDS);
    emit("{");
    keys.sort().forEach((key, i) => { if (i) emit(","); string(key); emit(":"); visit((v as Record<string, unknown>)[key], depth + 1); });
    emit("}");
  };
  visit(value, 0);
  return Buffer.from(chunks.join(""), "utf8");
}

/** Parse bounded canonical UTF-8 before schema validation; duplicate keys cannot survive equality. */
export function parseSdwJournalRecord<K extends keyof SdwRecordTypes>(kind: K, bytes: Uint8Array): SdwRecordTypes[K] {
  const limit = SDW_RECORD_BYTE_LIMITS[kind];
  requireValid(bytes instanceof Uint8Array && bytes.byteLength <= limit);
  try {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    // Bound nesting BEFORE JSON.parse so adversarial depth cannot reach recursive validators.
    let depth = 0, quoted = false, escaped = false;
    for (const c of text) {
      if (quoted) { if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === '"') quoted = false; }
      else if (c === '"') quoted = true;
      else if (c === "{" || c === "[") requireValid(++depth <= MAX_JSON_DEPTH);
      else if (c === "}" || c === "]") requireValid(--depth >= 0);
    }
    const value: unknown = JSON.parse(text);
    // This rejects duplicate keys, whitespace, alternate escapes/numbers and invalid UTF-8.
    requireValid(Buffer.from(bytes).equals(sdwCanonicalBytes(value, limit)));
    const parsed = schemas[kind].safeParse(value);
    requireValid(parsed.success);
    const record = parsed.data as SdwRecordTypes[K];
    if (kind === "plan" || kind === "certificate") assertAttestation(record as SdwPlan | SdwCertificate);
    return record;
  } catch (cause) {
    if (cause instanceof SdwStorageError) throw cause;
    throw new SdwStorageError("storage_plan_invalid", "none", undefined, { cause });
  }
}
/** Hashes in journal records are lowercase hex without the internal receipt's algorithm prefix. */
export function sdwSha256(bytes: Uint8Array): string { return Buffer.from(hash(bytes)).toString("hex"); }

/** Reuse the existing receipt domain; byte parity is pinned by sdw-journal-plan.test.ts. */
export function sdwSigningBytes(receipt: SdwSigningReceipt): Uint8Array {
  return Buffer.concat([Buffer.from(`${INTERNAL_RECEIPT_SIGNING_DOMAIN_PREFIX}\n`), sdwCanonicalBytes(receipt, SDW_MAX_MARKER_BYTES)]);
}
/** Derive the exact semantic receipt for a plan/certificate, consumed by the internal signer. */
export function sdwSigningReceipt(body: SdwPlanBody | SdwCertificate["body"], issued_at: string): SdwSigningReceipt {
  const state = "state" in body ? body.state : "PLAN";
  const subjects = { PLAN: "sdw-storage-plan", COMMIT: "sdw-storage-commit", APPLIED: "sdw-storage-applied", RETIRED: "sdw-storage-retired" } as const;
  return {
    receipt_id: body.transaction_id, receipt_type: "internal", subject: subjects[state], issued_at,
    status: state === "PLAN" ? "issued" : state === "COMMIT" ? "approved" : "completed",
    body_hash: `sha256:${sdwSha256(sdwCanonicalBytes(body))}`,
  };
}
function assertAttestation(record: SdwPlan | SdwCertificate): void {
  const expected = sdwSigningReceipt(record.body, record.attestation.issued_at);
  requireValid(Buffer.from(sdwCanonicalBytes(expected)).equals(sdwCanonicalBytes(record.attestation)));
  if (!("state" in record.body)) requireValid(record.attestation.issued_at === record.body.created_at);
}

/** Trust is fortress primary authority, supplied independently of the journal's claimed key. */
export interface SdwPrimaryVerifier {
  readonly fortress_id: string;
  /**
   * Reject foreign/stored-only keys; accept prior keys only with authenticated primary history.
   * Rejections become storage_plan_invalid. If trust cannot be evaluated, explicitly throw
   * SdwStorageError with reason storage_capability_unavailable instead.
   */
  assertPlanSigner(identity_id: string, public_key: Uint8Array): Promise<void>;
}
/** Slice 2 must wire this required authority before any production journal creation. */
export interface SdwPrimarySigner extends SdwPrimaryVerifier {
  readonly identity_id: string;
  readonly public_key: Uint8Array;
  /** Revalidate current primary immediately before new COMMIT signing and publication. */
  assertCurrent(): Promise<void>;
  /** The implementation uses internal_receipt_sign and its critical audit at lock rank seven. */
  signReceipt(payload: SdwSigningReceipt): Promise<Uint8Array>;
}
/** Authenticate an already parsed signed record against injected primary history and its exact bytes. */
export async function verifySdwSignedRecord(record: SdwPlan | SdwCertificate, authority: SdwPrimaryVerifier): Promise<void> {
  // Reparse to reject mutated/cast objects at the trust boundary, using the SAME runtime schema.
  const kind = "state" in record.body ? "certificate" : "plan";
  const checked = parseSdwJournalRecord(kind, sdwCanonicalBytes(record, SDW_RECORD_BYTE_LIMITS[kind]));
  if (!authority || typeof authority.assertPlanSigner !== "function") throw new SdwStorageError("storage_capability_unavailable", "none");
  requireValid(checked.body.fortress_id === authority.fortress_id);
  const key = Buffer.from(checked.body.signer_public_key, "base64url");
  // A valid signature proves the claimed signer, not its right to authorize this fortress.
  try {
    await authority.assertPlanSigner(checked.body.identity_id, new Uint8Array(key));
  } catch (cause) {
    if (cause instanceof SdwStorageError) throw cause;
    // Only an explicit unavailable result denotes missing evidence; rejection is invalid trust.
    throw new SdwStorageError("storage_plan_invalid", "none", checked.body.transaction_id, { cause });
  }
  requireValid(verify(sdwSigningBytes(checked.attestation), Buffer.from(checked.signature, "base64url"), key));
}
/** Check the entire bounded page/receipt closure before any caller may apply an image. */
export function validateSdwPlanClosure(plan: SdwPlan, pages: readonly Uint8Array[], receipt: Uint8Array): SdwPlanPage[] {
  const checked = parseSdwJournalRecord("plan", sdwCanonicalBytes(plan, SDW_MAX_PLAN_BYTES));
  requireValid(pages.length === checked.body.pages.length && receipt.length <= SDW_MAX_RECEIPT_BYTES);
  requireValid(receipt.length === checked.body.receipt_byte_length && sdwSha256(receipt) === checked.body.receipt_sha256);
  let records = 0, bytes = 0;
  const targets = new Set<string>();
  const parsed: SdwPlanPage[] = [];
  for (const [index, raw] of pages.entries()) {
    const descriptor = checked.body.pages[index]!;
    requireValid(raw.length === descriptor.byte_length && raw.length <= SDW_MAX_PAGE_BYTES && sdwSha256(raw) === descriptor.sha256);
    const page = parseSdwJournalRecord("page", raw);
    requireValid(page.transaction_id === checked.body.transaction_id && page.page === index && page.entries.length === descriptor.record_count);
    for (const entry of page.entries) {
      const target = `${entry.namespace}\0${entry.key}`;
      requireValid(!targets.has(target) && checked.body.namespaces.includes(entry.namespace));
      targets.add(target);
      records++;
      bytes += entry.byte_length;
      requireValid(records <= SDW_MAX_RECORDS && bytes <= SDW_MAX_STAGED_BYTES);
    }
    parsed.push(page);
  }
  requireValid(records === checked.body.record_count && bytes === checked.body.staged_bytes);
  return parsed;
}
/** Bind a certificate to its expected role, exact signed root, receipt and observed epoch vector. */
export async function verifySdwCertificate(
  certificate: SdwCertificate, plan: SdwPlan, epochs: SdwEpochs,
  expectedState: SdwCertificate["body"]["state"], authority: SdwPrimaryVerifier,
): Promise<void> {
  certificate = parseSdwJournalRecord("certificate", sdwCanonicalBytes(certificate, SDW_MAX_MARKER_BYTES));
  // The primary's signature authenticates its stated role; the relying caller must bind that role.
  requireValid(certificate.body.state === expectedState);
  plan = parseSdwJournalRecord("plan", sdwCanonicalBytes(plan, SDW_MAX_PLAN_BYTES));
  const checkedEpochs = epochsSchema.safeParse(epochs);
  requireValid(checkedEpochs.success);
  epochs = checkedEpochs.data;
  // Snapshot all caller-owned inputs before the injected authority can yield.
  await verifySdwSignedRecord(certificate, authority);
  requireValid(certificate.body.transaction_id === plan.body.transaction_id &&
    certificate.body.fortress_id === plan.body.fortress_id &&
    certificate.body.plan_sha256 === sdwSha256(sdwCanonicalBytes(plan, SDW_MAX_PLAN_BYTES)) &&
    certificate.body.receipt_sha256 === plan.body.receipt_sha256 &&
    certificate.body.receipt_byte_length === plan.body.receipt_byte_length &&
    Buffer.from(sdwCanonicalBytes(certificate.body.epochs)).equals(sdwCanonicalBytes(epochs)));
}

/** Storage durability result, not import or audit workflow completion. */
export interface SdwApplied<T> {
  readonly status: "applied"; readonly transaction_id: string; readonly plan_sha256: string;
  readonly value: T; readonly receipt: Uint8Array;
}
/** An unresolved applied receipt retains the one slot until explicit delivery and retirement. */
export type SdwRecoveryResult = { status: "clean" } | { status: "discarded_prepared"; transaction_id?: string } |
  Omit<SdwApplied<never>, "value">;
/** Separate opt-in seam; no raw transaction capability is added to StorageBackend. */
export interface SdwStorageBoundaryCapabilities {
  withSdwReadScope<T>(op: () => Promise<T>): Promise<T>;
  withSdwWriteSet<T>(token: SdwAdmissionToken, options: {
    authority: SdwPrimarySigner; namespaces?: readonly SdwNamespace[]; signal?: AbortSignal;
  }, op: () => Promise<{ value: T; receipt: Uint8Array }>): Promise<SdwApplied<T>>;
  recoverSdwJournal(token: SdwAdmissionToken, authority: SdwPrimarySigner): Promise<SdwRecoveryResult>;
  retireSdwReceipt(token: SdwAdmissionToken, transaction_id: string, plan_sha256: string, authority: SdwPrimarySigner): Promise<void>;
}

/**
 * Admission implementation belongs to the fence packet; no token factory is exported here.
 * Defined here to keep the opt-in journal seam separate from the base StorageBackend contract.
 */
export type SdwJournalAdmission = <T>(
  storage: StorageBackend,
  op: (token: SdwAdmissionToken) => Promise<T>,
) => Promise<T>;

/** Fixed-width image names preserve ordinal order without accepting caller path components. */
export function sdwImageName(ordinal: number): string {
  requireValid(integer(SDW_MAX_RECORDS - 1).safeParse(ordinal).success);
  return `${String(ordinal).padStart(6, "0")}.bin`; // six decimal digits cover 0..99,999
}
/** Fixed-width page names preserve page order; page count is derived from the record cap. */
export function sdwPageName(page: number): string {
  requireValid(integer(SDW_MAX_PAGES - 1).safeParse(page).success);
  return `${String(page).padStart(4, "0")}.json`; // contract's four decimal page digits
}
/** Deterministic apply temp never ends in .enc and is recoverable from the signed plan. */
export function sdwApplyTempName(transaction_id: string, ordinal: number): string {
  requireValid(transactionSchema.safeParse(transaction_id).success);
  return `.sdw-${transaction_id}-${sdwImageName(ordinal).slice(0, -".bin".length)}.apply`;
}
