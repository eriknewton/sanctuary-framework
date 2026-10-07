/**
 * Scoped memory-grant data contract. This is a pure parser and transition
 * model, NOT an authorization boundary. A protected operator broker must own
 * the ledger and independently authenticate every field supplied to a check.
 */
import { posix as path } from "node:path";
import { parseIsoInstantWithOffset } from "../core/time.js";
import { CLAUDE_CODE_MEMORY_HARNESS } from "../sdw/adapters/claude-code-file-adapter.js";
import { CODEX_MEMORY_HARNESS } from "../sdw/adapters/codex-memory-file-adapter.js";

export const MEMORY_GRANT_SCHEMA_VERSION = 1 as const;
export const MAX_MEMORY_GRANT_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
export const MAX_MEMORY_GRANTS_PER_LEDGER = 1024;

const HARNESS_KINDS = new Set<string>([CLAUDE_CODE_MEMORY_HARNESS, CODEX_MEMORY_HARNESS]);
export type MemoryGrantHarness = typeof CLAUDE_CODE_MEMORY_HARNESS | typeof CODEX_MEMORY_HARNESS;
const IDENTIFIER = /^[A-Za-z0-9_:@+-]{1,256}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const GRANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export interface MemoryGrantSourceRoot {
  /** Trusted broker must verify this is realpath of the opened root. */
  readonly path: string;
  /** Decimal strings preserve POSIX device and inode values beyond JS precision. */
  readonly dev: string;
  readonly ino: string;
}

export interface MemoryGrantRecord {
  readonly schema_version: typeof MEMORY_GRANT_SCHEMA_VERSION;
  readonly grant_id: string;
  readonly fortress_id: string;
  readonly subject_agent_id: string;
  readonly subject_agent_uid: number;
  readonly harness: MemoryGrantHarness;
  readonly source_root: MemoryGrantSourceRoot;
  readonly owner_ref: string;
  readonly created_at: string;
  readonly expires_at: string;
  readonly revoked_at: string | null;
  /** A classifier waiver is never a delegable capability. */
  readonly classifier_override: false;
}

export interface MemoryGrantLedger {
  readonly schema_version: typeof MEMORY_GRANT_SCHEMA_VERSION;
  readonly grants: readonly MemoryGrantRecord[];
}

export interface MemoryGrantUse {
  readonly grant_id: string;
  readonly fortress_id: string;
  readonly subject_agent_id: string;
  readonly subject_agent_uid: number;
  readonly harness: MemoryGrantHarness;
  readonly source_root: MemoryGrantSourceRoot;
  readonly owner_ref: string;
  readonly classifier_override_requested: boolean;
}

function exactObject(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const actual = Reflect.ownKeys(value);
    return actual.length === keys.length && actual.every((key) => {
      if (typeof key !== "string" || !keys.includes(key)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && descriptor.enumerable && "value" in descriptor;
    });
  } catch {
    return false;
  }
}

function validNow(value: number): boolean {
  // Date's representable range is 8.64e15 ms; revocation serializes to ISO.
  return Number.isSafeInteger(value) && Math.abs(value) <= 8_640_000_000_000_000;
}

function timestamp(value: unknown): number | null {
  if (typeof value !== "string" || !ISO_UTC.test(value)) return null;
  const parsed = parseIsoInstantWithOffset(value);
  return parsed !== undefined && new Date(parsed).toISOString() === value ? parsed : null;
}

function identifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER.test(value);
}

function sourceRoot(value: unknown): value is MemoryGrantSourceRoot {
  if (!exactObject(value, ["path", "dev", "ino"])) return false;
  const root = value.path;
  // Lexical canonicality is necessary, but only broker-side realpath/fstat can
  // prove the path still names the intended inode at use and commit time.
  if (typeof root !== "string" || root.length > 4096 || !root.startsWith("/") || root === "/" ||
      root.includes("\0") || root.split("/").some((part) => part === "." || part === "..") ||
      path.normalize(root) !== root || root.endsWith("/")) return false;
  // Bound device/inode strings before regex work so a malformed ledger cannot
  // make parsing unbounded. The broker must compare them to fstat observations.
  return typeof value.dev === "string" && value.dev.length <= 20 && DECIMAL.test(value.dev) &&
    typeof value.ino === "string" && value.ino.length <= 20 && DECIMAL.test(value.ino) && value.ino !== "0";
}

export function parseMemoryGrantRecord(value: unknown): MemoryGrantRecord | null {
  if (!exactObject(value, [
    "schema_version", "grant_id", "fortress_id", "subject_agent_id",
    "subject_agent_uid", "harness", "source_root", "owner_ref",
    "created_at", "expires_at", "revoked_at", "classifier_override",
  ])) return null;
  const created = timestamp(value.created_at);
  const expires = timestamp(value.expires_at);
  const revoked = value.revoked_at === null ? null : timestamp(value.revoked_at);
  if (value.schema_version !== MEMORY_GRANT_SCHEMA_VERSION ||
      typeof value.grant_id !== "string" || !GRANT_ID.test(value.grant_id) ||
      !identifier(value.fortress_id) || !identifier(value.subject_agent_id) ||
      !Number.isSafeInteger(value.subject_agent_uid) || (value.subject_agent_uid as number) <= 0 ||
      (value.subject_agent_uid as number) >= 0xFFFFFFFF ||
      typeof value.harness !== "string" || !HARNESS_KINDS.has(value.harness) ||
      !sourceRoot(value.source_root) || !identifier(value.owner_ref) ||
      value.classifier_override !== false || created === null || expires === null ||
      expires <= created || expires - created > MAX_MEMORY_GRANT_LIFETIME_MS ||
      (value.revoked_at !== null && (revoked === null || revoked < created))) return null;
  return value as unknown as MemoryGrantRecord;
}

export function parseMemoryGrantLedger(value: unknown): MemoryGrantLedger | null {
  if (!exactObject(value, ["schema_version", "grants"]) ||
      value.schema_version !== MEMORY_GRANT_SCHEMA_VERSION || !Array.isArray(value.grants) ||
      value.grants.length > MAX_MEMORY_GRANTS_PER_LEDGER) return null;
  const ids = new Set<string>();
  for (const entry of value.grants) {
    const grant = parseMemoryGrantRecord(entry);
    if (grant === null || ids.has(grant.grant_id)) return null;
    ids.add(grant.grant_id);
  }
  return value as unknown as MemoryGrantLedger;
}

/** Pure insertion; provenance and custody of a new record belong to the broker. */
export function addMemoryGrant(ledgerValue: unknown, recordValue: unknown): MemoryGrantLedger | null {
  const ledger = parseMemoryGrantLedger(ledgerValue);
  const record = parseMemoryGrantRecord(recordValue);
  if (ledger === null || record === null || ledger.grants.length >= MAX_MEMORY_GRANTS_PER_LEDGER ||
      record.revoked_at !== null || ledger.grants.some((entry) => entry.grant_id === record.grant_id)) return null;
  return { schema_version: MEMORY_GRANT_SCHEMA_VERSION, grants: [...ledger.grants, record] };
}

/** Returns false for an unreadable, malformed, unknown, expired, or revoked grant. */
export function isMemoryGrantUseAllowed(ledgerValue: unknown, useValue: unknown, nowMs: number): boolean {
  const ledger = parseMemoryGrantLedger(ledgerValue);
  if (ledger === null || !validNow(nowMs) || !exactObject(useValue, [
    "grant_id", "fortress_id", "subject_agent_id", "subject_agent_uid", "harness",
    "source_root", "owner_ref", "classifier_override_requested",
  ])) return false;
  const use = useValue as unknown as MemoryGrantUse;
  if (use.classifier_override_requested !== false || !sourceRoot(use.source_root)) return false;
  const grant = ledger.grants.find((entry) => entry.grant_id === use.grant_id);
  if (grant === undefined || grant.revoked_at !== null) return false;
  const createdAt = timestamp(grant.created_at);
  const expiresAt = timestamp(grant.expires_at);
  if (createdAt === null || expiresAt === null || nowMs < createdAt || nowMs >= expiresAt) return false;
  // Every claimed use field must come from authenticated broker observations;
  // equality against caller-controlled values alone cannot confer authority.
  return grant.fortress_id === use.fortress_id &&
    grant.subject_agent_id === use.subject_agent_id &&
    grant.subject_agent_uid === use.subject_agent_uid &&
    grant.harness === use.harness &&
    grant.source_root.path === use.source_root.path &&
    grant.source_root.dev === use.source_root.dev &&
    grant.source_root.ino === use.source_root.ino &&
    grant.owner_ref === use.owner_ref;
}

/** Pure state transition; the broker must serialize this with vault commits. */
export function revokeMemoryGrant(ledgerValue: unknown, grantId: string, nowMs: number): MemoryGrantLedger | null {
  const ledger = parseMemoryGrantLedger(ledgerValue);
  if (ledger === null || !validNow(nowMs) ||
      !GRANT_ID.test(grantId)) return null;
  const grant = ledger.grants.find((entry) => entry.grant_id === grantId);
  if (grant === undefined || grant.revoked_at !== null) return null;
  const createdAt = timestamp(grant.created_at);
  if (createdAt === null || nowMs < createdAt) return null;
  const revokedAt = new Date(nowMs).toISOString();
  return {
    schema_version: MEMORY_GRANT_SCHEMA_VERSION,
    grants: ledger.grants.map((entry) => entry.grant_id === grantId
      ? { ...entry, revoked_at: revokedAt }
      : entry),
  };
}
