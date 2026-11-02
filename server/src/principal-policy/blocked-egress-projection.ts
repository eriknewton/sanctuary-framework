import { createHash } from "node:crypto";
import { parseIsoInstantWithOffset } from "../core/time.js";
import { BLOCKED_EGRESS_METADATA_MAX_BYTES, isBlockedEgressSubject, parseBlockedEgressMetadata, type BlockedEgressMetadata } from "../contracts/v1.1/blocked-egress.js";
import { HUB_BLOCKED_EGRESS_FORTRESS_MAX, HUB_BLOCKED_EGRESS_EMITTED_MAX } from "../hub/constants.js";
import { hubInboxSourceIdPrefix } from "../hub/inbox-sources.js";
/** Shared 30-day inbox default; must match the re-export in unified-inbox-store.ts. */
export const DEFAULT_UNIFIED_INBOX_RETENTION_DAYS = 30;

// Must match the public re-exports in unified-inbox-bridge.ts; one entry shape serves admission, persistence and workflow.
export type UnifiedInboxSourceClass =
  | "approval"
  | "sentinel_finding"
  | "blocked_egress"
  | "privacy_event"
  | "budget_warning"
  | "recovery_prompt"
  | "agent_error"
  // A genuine security-feature fault raised by the feature-health observability
  // layer (the 3 ratified fault classes only: castle_wall_fault /
  // feature_silently_off / plugin_failure_surge). See `feature-fault-raise.ts`.
  // Display-only / read-derived: it feeds NOTHING back into enforcement.
  | "feature_fault";

export type UnifiedInboxSeverity = "info" | "warn" | "alert" | "critical";
export type UnifiedInboxEntryState =
  | "active"
  | "archived"
  | "snoozed"
  | "dismissed";

export interface UnifiedInboxEntry {
  /** Optional structured block evidence; legacy entries have none. */
  blocked_egress?: BlockedEgressMetadata;
  /** Immutable admission identity and expiry for bounded projection restore and workflow persistence. */
  blocked_egress_admission?: BlockedEgressAdmissionRecord;
  /** Stable per-fortress inbox id (UUID v4). */
  inbox_id: string;
  /** Which producer class emitted this entry. */
  source_class: UnifiedInboxSourceClass;
  /**
   * Stable per-source identifier the bridge uses for deduplication.
   * Format conventions per class:
   *   approval         - aggregator entry's audit_log_entry_id
   *   sentinel_finding - finding_id
   *   blocked_egress   - `<audit-timestamp>:<decision_id>`
   *   privacy_event    - `<audit-timestamp>:<aggregation-window>`
   *   budget_warning   - `<bucket>:<threshold-iso>`
   *   recovery_prompt  - `<ceremony_id>:<recovery_class>`
   *   agent_error      - `<audit-timestamp>:<agent_id>:<error_class>`
   */
  source_event_id: string;
  /** Optional agent attribution for per-agent entries. */
  agent_id?: string;
  /** Severity tier - `critical` is rare; reserved for hard-cap / lockdown class. */
  severity: UnifiedInboxSeverity;
  /** Operator-friendly one-line summary. Bounded at 240 chars on persist. */
  summary: string;
  /** Operator drill-target URL; opens full source detail. */
  details_url: string;
  /** ISO 8601 timestamp of source event. */
  observed_at: string;
  /** ISO 8601 timestamp the operator (or auto-resolver) resolved it. */
  resolved_at?: string;
  /** Operator identity that resolved this entry, when applicable. */
  resolved_by?: string;
  /** Operator workflow state. Missing values from Psi-1/Psi-2 read as active. */
  state?: UnifiedInboxEntryState;
  /** ISO 8601 deadline. Snoozed entries re-enter active queries after this. */
  snoozed_until?: string;
  archived_at?: string;
  dismissed_at?: string;
  /** Stable fortress id stamped at emit. Multi-fortress isolation pivot. */
  fortress_id: string;
}

/** Design allowance per authenticated OS subject. */
export const BLOCKED_EGRESS_ORIGIN_MAX = 20;
/** One design allowance shared by every unsigned or legacy producer. */
export const BLOCKED_EGRESS_UNSIGNED_BUCKET_MAX = 20;
/** 16 KiB reserved for a future persisted proof, not a metadata field. */
export const BLOCKED_EGRESS_PROOF_RESERVE_BYTES = 16 * 1024;
/** 2 KiB metadata + 16 KiB proof + 2 KiB entry/admission overhead. */
export const BLOCKED_EGRESS_ENTRY_MAX_BYTES = BLOCKED_EGRESS_METADATA_MAX_BYTES + BLOCKED_EGRESS_PROOF_RESERVE_BYTES + 2 * 1024;
/** Independent 20 MiB ceiling, exceeding 1000 * 20 KiB (19.53125 MiB). */
export const BLOCKED_EGRESS_RETAINED_MAX_BYTES = 20 * 1024 * 1024;
/** Design limit on concurrent unsettled operations. */
export const BLOCKED_EGRESS_RESERVATIONS_MAX = 32;
const DAY_MS = 24 * 60 * 60 * 1000; // hours/day * minutes/hour * seconds/minute * milliseconds/second
export const BLOCKED_EGRESS_LIFETIME_MS = DEFAULT_UNIFIED_INBOX_RETENTION_DAYS * DAY_MS;
/** One minute; must match producerSigMaxSkewMs default in castle-wall/runtime/audit-consumer.ts. */
export const BLOCKED_EGRESS_FUTURE_SKEW_MS = 60 * 1000;
const DIGEST_HEX_CHARS = 32 * 2; // SHA-256 bytes * hex characters per byte

export type BlockedEgressIdentity =
  | { producer_key_digest: string; seq: number; body_digest: string }
  | { source_event_id: string; content_digest: string };
/** Persisted admission provenance consumed by restore and retention; never renew on retry. */
export interface BlockedEgressAdmissionRecord {
  version: 1;
  origin: string;
  identity: BlockedEgressIdentity;
  first_accepted_at: string;
  expires_at: string;
  encoded_bytes: number;
}
export type AdmissionParseResult = { ok: true; value: BlockedEgressAdmissionRecord } |
  { ok: false; reason: "shape" | "identity" | "time" | "size" };
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const digest = (v: unknown): v is string => typeof v === "string" && v.length === DIGEST_HEX_CHARS && /^[a-f0-9]+$/.test(v);
const keysAre = (v: Record<string, unknown>, keys: string[]) => Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));

/** One shared closed parser for encrypted reads, bridge caching and bounded restore. */
// Must match the parseBlockedEgressAdmissionRecord consumers in unified-inbox-store.ts and unified-inbox-bridge.ts.
export function parseBlockedEgressAdmissionRecord(raw: unknown): AdmissionParseResult {
  if (!object(raw) || !keysAre(raw, ["version", "origin", "identity", "first_accepted_at", "expires_at", "encoded_bytes"]) || raw.version !== 1 ||
      typeof raw.origin !== "string" || !(raw.origin === "unsigned" || (raw.origin.startsWith("subject:") && isBlockedEgressSubject(raw.origin.slice("subject:".length))))) return { ok: false, reason: "shape" };
  const id = raw.identity;
  if (!object(id)) return { ok: false, reason: "identity" };
  const signed = keysAre(id, ["producer_key_digest", "seq", "body_digest"]) && digest(id.producer_key_digest) && digest(id.body_digest) && Number.isSafeInteger(id.seq) && (id.seq as number) >= 0;
  const unsigned = keysAre(id, ["source_event_id", "content_digest"]) && typeof id.source_event_id === "string" && id.source_event_id.length > 0 && id.source_event_id.length <= BLOCKED_EGRESS_ENTRY_MAX_BYTES && digest(id.content_digest);
  if (!(raw.origin === "unsigned" ? unsigned : signed)) return { ok: false, reason: "identity" };
  const first = parseIsoInstantWithOffset(typeof raw.first_accepted_at === "string" ? raw.first_accepted_at : "");
  const expiry = parseIsoInstantWithOffset(typeof raw.expires_at === "string" ? raw.expires_at : "");
  if (first === undefined || expiry === undefined || expiry <= first || expiry - first > BLOCKED_EGRESS_LIFETIME_MS) return { ok: false, reason: "time" };
  if (!Number.isSafeInteger(raw.encoded_bytes) || (raw.encoded_bytes as number) <= 0 || (raw.encoded_bytes as number) > BLOCKED_EGRESS_ENTRY_MAX_BYTES) return { ok: false, reason: "size" };
  return { ok: true, value: { version: 1, origin: raw.origin, identity: { ...id } as BlockedEgressIdentity,
    first_accepted_at: raw.first_accepted_at as string, expires_at: raw.expires_at as string, encoded_bytes: raw.encoded_bytes as number } };
}

/** Identity omits body digest so conflicting reuse is detected, not given a second slot. */
export function blockedEgressIdentityKey(fortressId: string, identity: BlockedEgressIdentity): string {
  return JSON.stringify("producer_key_digest" in identity ? [fortressId, identity.producer_key_digest, identity.seq] : [fortressId, "unsigned", identity.source_event_id]);
}
export interface BlockedEgressCandidate {
  entry: UnifiedInboxEntry;
  /** Supplied only from the consumer mint; callers cannot turn stored metadata into new authority. */
  signedIdentity?: { producer_key_digest: string; seq: number; body_digest: string };
}
export type BlockedEgressRefusal = "invalid_time" | "future_time" | "expired" | "oversize" | "identity_conflict" | "invalid_identity" | "reservations_full" | "capacity" | "store_failed";
export type BlockedEgressAdmissionResult =
  | { kind: "admitted"; entry: UnifiedInboxEntry; evicted: UnifiedInboxEntry[] }
  | { kind: "duplicate"; entry: UnifiedInboxEntry }
  | { kind: "refused"; reason: BlockedEgressRefusal };
/** Structural storage port keeps admission independent of the encrypted store implementation. */
export interface BlockedEgressAdmissionStore {
  upsert(entry: UnifiedInboxEntry): Promise<unknown>;
  get(inboxId: string): Promise<(UnifiedInboxEntry & { encrypted_at_rest?: true; retention_until?: string }) | null>;
  delete(inboxId: string): Promise<boolean>;
  readBlockedEgressIndex(): Promise<string[]>;
  writeBlockedEgressIndex(ids: string[]): Promise<void>;
}
export type BlockedEgressSnapshotItem = UnifiedInboxEntry & { item_id: string };
export type BlockedEgressSnapshot = { generation: number; items: BlockedEgressSnapshotItem[] } &
  ({ presence: "complete"; presentIds: ReadonlySet<string> } | { presence: "unknown" });
type Retained = UnifiedInboxEntry & { blocked_egress_admission: BlockedEgressAdmissionRecord };
const hash = (v: string) => createHash("sha256").update(v).digest("hex");
const oldestFirst = (a: Retained, b: Retained) => a.blocked_egress_admission.first_accepted_at.localeCompare(b.blocked_egress_admission.first_accepted_at) || a.inbox_id.localeCompare(b.inbox_id);

/** Process-local admission ledger. Storage supplies durability, not a cross-process lock. */
export class BlockedEgressAdmissions {
  private entries = new Map<string, Retained>();
  private identities = new Map<string, Retained>();
  private durableIds = new Set<string>();
  private itemIds = new Map<string, string>();
  private generation = 0;
  private ready = false;
  private reservations = 0;
  private peakReservations = 0;
  private retiringBytes = 0;
  private expiryCleanupPending = false;
  private tail: Promise<void> = Promise.resolve();
  private failure: unknown;
  private failed = false;
  private restoring?: Promise<void>;
  private staged = new Map<string, Retained>();
  private priorItems: BlockedEgressSnapshotItem[] = [];
  private readonly lifetime: number;
  constructor(private readonly options: { fortressId: string; now: () => Date; store?: BlockedEgressAdmissionStore; retentionDays?: number }) {
    this.lifetime = Math.min(BLOCKED_EGRESS_LIFETIME_MS, (options.retentionDays ?? DEFAULT_UNIFIED_INBOX_RETENTION_DAYS) * DAY_MS);
  }

  /**
   * Continuing paths: a fresh bounded identity reserves capacity and joins the writer;
   * identical retained identity/body returns the original workflow and expiry unchanged;
   * an arrival during restore commits only after the complete restored generation.
   * Refusing paths: invalid/future/expired time, oversize encoding, identity conflict,
   * exhausted reservations/bytes and failed persistence publish no new admission.
   * Restore continues only with a complete read, omitting individually invalid records;
   * a thrown read keeps the prior generation with unknown presence.
   */
  admit(candidate: BlockedEgressCandidate): BlockedEgressAdmissionResult {
    const input = candidate.entry;
    // Bound the full encoding before hashing display fields or scheduling any storage operation.
    const encoding = JSON.stringify(input);
    if (Buffer.byteLength(encoding) + BLOCKED_EGRESS_PROOF_RESERVE_BYTES > BLOCKED_EGRESS_ENTRY_MAX_BYTES) return { kind: "refused", reason: "oversize" };
    const observed = parseIsoInstantWithOffset(input.observed_at);
    const now = this.options.now().getTime();
    if (observed === undefined) return { kind: "refused", reason: "invalid_time" };
    if (observed > now + BLOCKED_EGRESS_FUTURE_SKEW_MS) return { kind: "refused", reason: "future_time" };
    const expiry = Math.min(observed + BLOCKED_EGRESS_LIFETIME_MS, now + this.lifetime);
    if (expiry <= now) return { kind: "refused", reason: "expired" };
    const metadata = parseBlockedEgressMetadata(input.blocked_egress);
    const verified = candidate.signedIdentity && metadata.ok && metadata.value.attribution.state === "verified" && metadata.value.subject;
    const identity: BlockedEgressIdentity = verified ? { ...candidate.signedIdentity! } : {
      source_event_id: input.source_event_id,
      content_digest: "0".repeat(DIGEST_HEX_CHARS),
    };
    const record: BlockedEgressAdmissionRecord = { version: 1, origin: verified ? `subject:${metadata.value.subject}` : "unsigned", identity,
      first_accepted_at: new Date(now).toISOString(), expires_at: new Date(expiry).toISOString(), encoded_bytes: 1 };
    const entry: Retained = { ...input, ...(metadata.ok ? { blocked_egress: metadata.value } : {}), blocked_egress_admission: record };
    // Reserve proof bytes even while the dormant format has no persisted proof.
    record.encoded_bytes = Buffer.byteLength(JSON.stringify(entry)) + BLOCKED_EGRESS_PROOF_RESERVE_BYTES;
    record.encoded_bytes = Buffer.byteLength(JSON.stringify(entry)) + BLOCKED_EGRESS_PROOF_RESERVE_BYTES;
    if (record.encoded_bytes > BLOCKED_EGRESS_ENTRY_MAX_BYTES) return { kind: "refused", reason: "oversize" };
    if (!parseBlockedEgressAdmissionRecord(record).ok || input.fortress_id !== this.options.fortressId || input.source_class !== "blocked_egress") return { kind: "refused", reason: "invalid_identity" };
    if ("content_digest" in identity) identity.content_digest = hash(JSON.stringify([input.source_event_id, input.observed_at, input.severity, input.summary, input.agent_id ?? null, metadata.ok ? metadata.value : null]));
    const key = blockedEgressIdentityKey(this.options.fortressId, identity);
    const existing = this.identities.get(key) ?? this.staged.get(key);
    if (existing) {
      const prior = existing.blocked_egress_admission.identity;
      const same = "body_digest" in prior && "body_digest" in identity ? prior.body_digest === identity.body_digest : "content_digest" in prior && "content_digest" in identity && prior.content_digest === identity.content_digest;
      return same ? { kind: "duplicate", entry: existing } : { kind: "refused", reason: "identity_conflict" };
    }
    if (this.failed) return { kind: "refused", reason: "store_failed" };
    // Every retained blocked-event record and unsettled reservation consumes the same bounded capacity; timeout or cancellation does not release it before the underlying write settles.
    if (this.reservations >= BLOCKED_EGRESS_RESERVATIONS_MAX) return { kind: "refused", reason: "reservations_full" };
    const deferredCommit = this.restoring !== undefined;
    const evicted = deferredCommit ? [] : this.selectEvictions(entry, now);
    if (this.bytes() + record.encoded_bytes > BLOCKED_EGRESS_RETAINED_MAX_BYTES) return { kind: "refused", reason: "capacity" };
    this.reserve();
    const commit = () => {
      for (const victim of evicted) this.forget(victim);
      this.entries.set(entry.inbox_id, entry);
      this.identities.set(key, entry);
      this.itemIds.set(entry.inbox_id, hubInboxSourceIdPrefix("blocked_egress") + hash(key));
      this.commit();
    };
    if (deferredCommit) this.staged.set(key, entry); else commit();
    this.retiringBytes += evicted.reduce((sum, e) => sum + e.blocked_egress_admission.encoded_bytes, 0);
    this.enqueue(async () => {
      if (deferredCommit) {
        this.staged.delete(key);
        // Reconcile against the completed restore before publishing the next generation.
        const restored = this.identities.get(key);
        if (restored) return;
        evicted.push(...this.selectEvictions(entry, this.options.now().getTime()));
        this.retiringBytes += evicted.reduce((sum, e) => sum + e.blocked_egress_admission.encoded_bytes, 0);
        commit();
      }
      for (const victim of evicted) {
        await this.options.store?.delete(victim.inbox_id);
        this.durableIds.delete(victim.inbox_id);
      }
      if (evicted.length) await this.options.store?.writeBlockedEgressIndex([...this.durableIds]);
      this.durableIds.add(entry.inbox_id);
      await this.options.store?.writeBlockedEgressIndex([...this.durableIds]);
      await this.options.store?.upsert(entry);
    }, () => { this.retiringBytes -= evicted.reduce((sum, e) => sum + e.blocked_egress_admission.encoded_bytes, 0); });
    return { kind: "admitted", entry, evicted };
  }

  private selectEvictions(entry: Retained, now: number): Retained[] {
    const sorted = [...this.entries.values()].sort(oldestFirst);
    const expired = sorted.filter(e => parseIsoInstantWithOffset(e.blocked_egress_admission.expires_at)! <= now);
    const live = sorted.filter(e => !expired.includes(e));
    const origin = live.filter(e => e.blocked_egress_admission.origin === entry.blocked_egress_admission.origin);
    const cap = entry.blocked_egress_admission.origin === "unsigned" ? BLOCKED_EGRESS_UNSIGNED_BUCKET_MAX : BLOCKED_EGRESS_ORIGIN_MAX;
    // An origin at its quota replaces its own oldest retained incident; projection eviction never deletes the primary audit evidence.
    if (origin.length >= cap) expired.push(origin[0]!);
    // Must match HUB_BLOCKED_EGRESS_FORTRESS_MAX in hub/constants.ts; the overlay imports the same cap.
    else if (live.length >= HUB_BLOCKED_EGRESS_FORTRESS_MAX || this.bytes() + entry.blocked_egress_admission.encoded_bytes > BLOCKED_EGRESS_RETAINED_MAX_BYTES) expired.push(live[0]!);
    return expired;
  }

  /** Workflow updates retain the immutable admission identity and lifetime on the same writer. */
  update(entry: UnifiedInboxEntry): boolean {
    const prior = this.entries.get(entry.inbox_id);
    if (!prior || this.reservations >= BLOCKED_EGRESS_RESERVATIONS_MAX || this.failed) return false;
    const next = { ...entry, blocked_egress_admission: { ...prior.blocked_egress_admission } };
    next.blocked_egress_admission.encoded_bytes = Buffer.byteLength(JSON.stringify(next)) + BLOCKED_EGRESS_PROOF_RESERVE_BYTES;
    if (next.blocked_egress_admission.encoded_bytes > BLOCKED_EGRESS_ENTRY_MAX_BYTES || this.bytes() + next.blocked_egress_admission.encoded_bytes > BLOCKED_EGRESS_RETAINED_MAX_BYTES) return false;
    this.reserve();
    this.retiringBytes += prior.blocked_egress_admission.encoded_bytes;
    this.entries.set(entry.inbox_id, next);
    this.identities.set(blockedEgressIdentityKey(this.options.fortressId, next.blocked_egress_admission.identity), next);
    this.commit();
    this.enqueue(async () => { await this.options.store?.upsert(next); }, () => { this.retiringBytes -= prior.blocked_egress_admission.encoded_bytes; });
    return true;
  }

  remove(inboxId: string): boolean {
    const entry = this.entries.get(inboxId);
    if (!entry || this.reservations >= BLOCKED_EGRESS_RESERVATIONS_MAX || this.failed) return false;
    this.reserve();
    this.forget(entry);
    this.retiringBytes += entry.blocked_egress_admission.encoded_bytes;
    this.commit();
    this.enqueue(async () => {
      await this.options.store?.delete(inboxId);
      this.durableIds.delete(inboxId);
      await this.options.store?.writeBlockedEgressIndex([...this.durableIds]);
    }, () => { this.retiringBytes -= entry.blocked_egress_admission.encoded_bytes; });
    return true;
  }

  private pruneExpired(now: number): void {
    const expired = [...this.entries.values()].filter(entry => parseIsoInstantWithOffset(entry.blocked_egress_admission.expires_at)! <= now);
    this.expiryCleanupPending = expired.length > 0;
    if (!expired.length || this.reservations >= BLOCKED_EGRESS_RESERVATIONS_MAX || this.failed || this.restoring) return;
    this.expiryCleanupPending = false;
    this.reserve();
    const bytes = expired.reduce((sum, entry) => sum + entry.blocked_egress_admission.encoded_bytes, 0);
    for (const entry of expired) this.forget(entry);
    this.retiringBytes += bytes;
    this.commit();
    this.enqueue(async () => {
      for (const entry of expired) {
        await this.options.store?.delete(entry.inbox_id);
        this.durableIds.delete(entry.inbox_id);
      }
      await this.options.store?.writeBlockedEgressIndex([...this.durableIds]);
    }, () => { this.retiringBytes -= bytes; });
  }

  /** Read every retained record for the bridge cache, including ineligible legacy prose. */
  retained(): UnifiedInboxEntry[] { return [...this.entries.values()]; }

  snapshot(): BlockedEgressSnapshot {
    const now = this.options.now().getTime();
    this.pruneExpired(now);
    if (!this.ready || this.restoring) return { generation: this.generation, presence: "unknown", items: this.priorItems };
    const eligible = [...this.entries.values()].filter(e => e.blocked_egress && parseIsoInstantWithOffset(e.blocked_egress_admission.expires_at)! > now);
    const all = eligible.map(e => ({ ...e, item_id: this.itemIds.get(e.inbox_id)! }));
    all.sort((a, b) => parseIsoInstantWithOffset(b.observed_at)! - parseIsoInstantWithOffset(a.observed_at)! || a.item_id.localeCompare(b.item_id));
    // Must match HUB_BLOCKED_EGRESS_EMITTED_MAX in hub/constants.ts; capped records stay in complete presence.
    const items = all.slice(0, HUB_BLOCKED_EGRESS_EMITTED_MAX);
    this.priorItems = items;
    return { generation: this.generation, presence: "complete", items, presentIds: new Set(all.map(e => e.item_id)) };
  }

  restore(): Promise<void> {
    if (this.restoring) return this.restoring;
    if (this.ready) this.snapshot();
    if (this.reservations >= BLOCKED_EGRESS_RESERVATIONS_MAX) return Promise.reject(new Error("Blocked-egress restore capacity unavailable"));
    // Restore and any indexed cleanup share one reservation until their underlying I/O settles.
    this.reserve();
    const work = this.tail.then(async () => {
      const ids = await this.options.store?.readBlockedEgressIndex() ?? [];
      if (ids.length > HUB_BLOCKED_EGRESS_FORTRESS_MAX) throw new Error("Blocked-egress index capacity exceeded");
      const restored = new Map<string, Retained>();
      const excludedIds = new Set<string>();
      const identities = new Set<string>();
      const origins = new Map<string, number>();
      let bytes = 0;
      for (const id of ids) {
        const entry = await this.options.store?.get(id);
        if (!entry || entry.source_class === "blocked_egress") excludedIds.add(id);
        if (!entry || entry.source_class !== "blocked_egress" || entry.fortress_id !== this.options.fortressId) continue;
        const parsed = parseBlockedEgressAdmissionRecord(entry.blocked_egress_admission);
        if (!parsed.ok) continue;
        const record = parsed.value;
        const observed = parseIsoInstantWithOffset(entry.observed_at);
        const now = this.options.now().getTime();
        const expiry = parseIsoInstantWithOffset(record.expires_at)!;
        const first = parseIsoInstantWithOffset(record.first_accepted_at)!;
        if (observed === undefined || first > now + BLOCKED_EGRESS_FUTURE_SKEW_MS || observed > first + BLOCKED_EGRESS_FUTURE_SKEW_MS || expiry > Math.min(observed + BLOCKED_EGRESS_LIFETIME_MS, first + this.lifetime) || expiry <= now) continue;
        const metadata = parseBlockedEgressMetadata(entry.blocked_egress);
        if (record.origin !== "unsigned" && (!metadata.ok || metadata.value.attribution.state !== "verified" || record.origin !== `subject:${metadata.value.subject}`)) continue;
        const { encrypted_at_rest: _encrypted, retention_until: _retention, ...admitted } = entry;
        const encodedBytes = Buffer.byteLength(JSON.stringify(admitted)) + BLOCKED_EGRESS_PROOF_RESERVE_BYTES;
        if (encodedBytes > BLOCKED_EGRESS_ENTRY_MAX_BYTES || encodedBytes > record.encoded_bytes) continue;
        const key = blockedEgressIdentityKey(this.options.fortressId, record.identity);
        const originCount = origins.get(record.origin) ?? 0;
        const cap = record.origin === "unsigned" ? BLOCKED_EGRESS_UNSIGNED_BUCKET_MAX : BLOCKED_EGRESS_ORIGIN_MAX;
        if (identities.has(key) || originCount >= cap || bytes + record.encoded_bytes > BLOCKED_EGRESS_RETAINED_MAX_BYTES) continue;
        restored.set(id, { ...admitted, blocked_egress_admission: record });
        excludedIds.delete(id);
        identities.add(key); origins.set(record.origin, originCount + 1); bytes += record.encoded_bytes;
      }
      // A complete bounded read owns these indexed records; remove excluded projection keys before dropping their index references.
      // Continuing wrong-source records lose only their index reference, never their durable entry.
      for (const id of excludedIds) await this.options.store?.delete(id);
      if (restored.size !== ids.length) await this.options.store?.writeBlockedEgressIndex([...restored.keys()]);
      this.retiringBytes = 0;
      this.durableIds = new Set(restored.keys());
      this.itemIds = new Map([...restored.values()].map(e => [e.inbox_id, hubInboxSourceIdPrefix("blocked_egress") + hash(blockedEgressIdentityKey(this.options.fortressId, e.blocked_egress_admission.identity))]));
      this.entries = restored;
      this.identities = new Map([...restored.values()].map(e => [blockedEgressIdentityKey(this.options.fortressId, e.blocked_egress_admission.identity), e]));
      this.failure = undefined;
      this.failed = false;
      this.ready = true;
      this.commit();
    });
    this.restoring = work.then(() => { this.restoring = undefined; this.reservations--; }, error => { this.restoring = undefined; this.reservations--; this.ready = false; throw error; });
    const result = this.restoring;
    this.tail = result.catch(() => {});
    return result;
  }

  async settled(): Promise<void> { while (true) { const tail = this.tail; await tail; if (tail === this.tail) break; } if (this.failed) throw this.failure; }
  stats() {
    const origins: Record<string, number> = {};
    for (const e of this.entries.values()) origins[e.blocked_egress_admission.origin] = (origins[e.blocked_egress_admission.origin] ?? 0) + 1;
    return { retained: this.entries.size, origins, encodedBytes: this.bytes(), reservations: this.reservations, peakReservations: this.peakReservations, dedupRecords: this.identities.size };
  }
  private bytes(): number { return this.retiringBytes + [...this.entries.values(), ...this.staged.values()].reduce((sum, e) => sum + e.blocked_egress_admission.encoded_bytes, 0); }
  private forget(entry: Retained) { this.itemIds.delete(entry.inbox_id); this.entries.delete(entry.inbox_id); this.identities.delete(blockedEgressIdentityKey(this.options.fortressId, entry.blocked_egress_admission.identity)); }
  private reserve() { this.reservations++; this.peakReservations = Math.max(this.peakReservations, this.reservations); }
  private commit() {
    // Items and complete presence come from one committed generation; an incomplete or failed refresh reports unknown presence and never clears prior cards.
    this.generation++;
  }
  private enqueue(write: () => Promise<void>, success: () => void = () => {}) {
    this.tail = this.tail.then(async () => {
      try { if (this.failed) return; await write(); success(); } catch (error) { this.failure = error; this.failed = true; this.ready = false; }
      finally { this.reservations--; if (this.expiryCleanupPending) this.pruneExpired(this.options.now().getTime()); }
    });
  }
}
