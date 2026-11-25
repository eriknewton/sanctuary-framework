/**
 * Sanctuary MCP Server — Behavioral Baseline Tracker
 *
 * Tracks the agent's behavioral profile during a session and persists
 * it for cross-session anomaly detection. The baseline defines "normal"
 * so that deviations can trigger Tier 2 approval.
 *
 * Security invariants:
 * - Baseline is stored encrypted under L1 sovereignty
 * - Baseline changes are audit-logged
 * - Baseline is integrity-verified via L1 Merkle tree
 * - No MCP tool can directly modify the baseline
 */

import { createHash } from "node:crypto";
import { StorageEnumerationBoundError, type StorageBackend, type StrictDurabilityStorageCapabilities } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { SessionProfile } from "./types.js";

const BASELINE_NAMESPACE = "_principal";
const BASELINE_KEY = "session-baseline";

/**
 * Reserved namespace of per-namespace insert records, one record per namespace
 * a successful save has used. Must match the `_principal_ns` entry in
 * NAMESPACE_RECIPES in core/master-rotation.ts, the reserved-namespace pin in
 * test/structure/reserved-namespace-single-source.test.ts and the
 * `_principal_ns` row in server/reorg-surface-manifest.md.
 */
export const BASELINE_NS_NAMESPACE = "_principal_ns";

/**
 * 4,096 = 2^12, the same figure as the help schema's intent cap
 * (HELP_INTENT_SCHEMA_MAX_CHARS = 4 * HELP_INTENT_MAX_CHARS, agent-native/intent-classifier.ts);
 * it leaves room for a short namespace id plus the snapshot's JSON encryption envelope.
 */
export const BASELINE_NS_RECORD_MAX_BYTES = 4096;

/** At 4,096 bytes a record, boot reads at most 4 MiB of insert records, or loads none. */
export const BASELINE_NS_INSERT_LOAD_MAX = 1024;

/**
 * One minute, the same window as DENIAL_WINDOW_MS (agent-native/denial-ledger.ts),
 * so a failing namespace writes at most one row per minute.
 */
export const BASELINE_NS_FAILURE_ROW_INTERVAL_MS = 60_000;

/**
 * The ceiling on storage write calls one record() makes: one insert attempt for
 * this namespace, plus at most one retry of the same namespace when it was
 * pending; another namespace is never written.
 */
export const BASELINE_NS_MAX_WRITES_PER_RECORD = 2;

/**
 * Strict namespace lock an insert publishes under on a backend with strict durability. Taken with no
 * scaffold file, so the record namespace holds only records and the load bound counts records alone.
 */
const BASELINE_NS_INSERT_LOCK_FILE = "insert.lock";

type StrictInsertStorage = StorageBackend &
  Pick<StrictDurabilityStorageCapabilities, "withStrictNamespaceLock" | "writeIfAbsentStrict">;

function hasStrictInsert(storage: StorageBackend): storage is StrictInsertStorage {
  const candidate = storage as Partial<StrictInsertStorage>;
  return typeof candidate.withStrictNamespaceLock === "function" && typeof candidate.writeIfAbsentStrict === "function";
}

/** Insert record key: the lowercase hex SHA-256 of the UTF-8 bytes of "ns:" plus the namespace id. */
export function baselineNamespaceRecordKey(namespace: string): string {
  return createHash("sha256").update("ns:" + namespace, "utf8").digest("hex");
}

/** The one encryption path the snapshot and the insert records share: the purpose key, the JSON envelope, no AAD. */
function encodeBaselineRecord(plaintext: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
  return stringToBytes(JSON.stringify(encrypt(plaintext, encryptionKey)));
}

function decodeBaselineRecord(raw: Uint8Array, encryptionKey: Uint8Array): Uint8Array {
  const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
  return decrypt(encrypted, encryptionKey);
}

function isRecordableNamespace(namespace: string): boolean {
  // Internal (`_`-prefixed) namespaces are never new, as in recordNamespaceAccess.
  return namespace.length > 0 && !namespace.startsWith("_");
}

/** Closed outcome of the insert-record load; load_RECORD_SKIPPED is the per-record branch counted in `skipped`. */
export type BaselineInsertLoadState = "load_BOUNDED_NONE" | "load_COMPLETE";

export type BaselineInsertLoadCode =
  | "bounded_method_unavailable"
  | "enumeration_over_bound"
  | "enumeration_failed"
  | "records_skipped";

export interface BaselineLoadReport {
  inserts: {
    state: BaselineInsertLoadState;
    code?: BaselineInsertLoadCode;
    loaded: number;
    skipped: number;
  };
}

export class BaselineTracker {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private profile: SessionProfile;

  /** Sliding window: timestamps of tool calls per tool name (last 60s) */
  private callWindows: Map<string, number[]> = new Map();

  /** Sliding window: read counts per namespace (last 60s) */
  private readWindows: Map<string, number[]> = new Map();

  /** Sliding window: sign call timestamps (last 60s) */
  private signWindow: number[] = [];

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "principal-baseline");
    this.profile = {
      known_namespaces: [],
      known_counterparties: [],
      tool_call_counts: {},
      is_first_session: true,
      started_at: new Date().toISOString(),
    };
  }

  /**
   * Load the previous session's baseline from storage, then union the
   * per-namespace insert records into the known set.
   * If no snapshot exists, this is a first session; insert records never end it.
   */
  async load(): Promise<BaselineLoadReport> {
    await this.loadSnapshot();
    return { inserts: await this.loadInsertRecords() };
  }

  private async loadSnapshot(): Promise<void> {
    try {
      const raw = await this.storage.read(BASELINE_NAMESPACE, BASELINE_KEY);
      if (!raw) return;

      const saved: SessionProfile = JSON.parse(bytesToString(decodeBaselineRecord(raw, this.encryptionKey)));

      // Carry forward known namespaces and counterparties
      this.profile.known_namespaces = saved.known_namespaces ?? [];
      this.profile.known_counterparties = saved.known_counterparties ?? [];
      this.profile.is_first_session = false;
    } catch {
      // No prior baseline or corrupted — treat as first session
      this.profile.is_first_session = true;
    }
  }

  private async loadInsertRecords(): Promise<BaselineLoadReport["inserts"]> {
    const storage = this.storage;
    if (typeof storage.listKeysBounded !== "function" || typeof storage.readBounded !== "function") {
      return { state: "load_BOUNDED_NONE", code: "bounded_method_unavailable", loaded: 0, skipped: 0 };
    }
    let keys: string[];
    try {
      // Past the bound nothing is loaded, so the extra namespaces stay new and the gate keeps asking.
      keys = await storage.listKeysBounded(BASELINE_NS_NAMESPACE, BASELINE_NS_INSERT_LOAD_MAX);
    } catch (error) {
      const code = error instanceof StorageEnumerationBoundError ? "enumeration_over_bound" : "enumeration_failed";
      return { state: "load_BOUNDED_NONE", code, loaded: 0, skipped: 0 };
    }
    const known = new Set(this.profile.known_namespaces);
    let loaded = 0;
    let skipped = 0;
    for (const key of keys) {
      const namespace = await this.readInsertRecord(storage.readBounded.bind(storage), key);
      if (namespace === null) {
        // load_RECORD_SKIPPED: that namespace stays new.
        skipped++;
        continue;
      }
      loaded++;
      if (!known.has(namespace)) {
        known.add(namespace);
        this.profile.known_namespaces.push(namespace);
      }
    }
    return skipped > 0
      ? { state: "load_COMPLETE", code: "records_skipped", loaded, skipped }
      : { state: "load_COMPLETE", loaded, skipped };
  }

  private async readInsertRecord(
    readBounded: NonNullable<StorageBackend["readBounded"]>,
    key: string,
  ): Promise<string | null> {
    try {
      const raw = await readBounded(BASELINE_NS_NAMESPACE, key, BASELINE_NS_RECORD_MAX_BYTES);
      if (raw === null) return null;
      const namespace = bytesToString(decodeBaselineRecord(raw, this.encryptionKey));
      if (!isRecordableNamespace(namespace)) return null;
      // With no AAD, the key is the only binding, so a record is kept only when its plaintext hashes to its key.
      if (baselineNamespaceRecordKey(namespace) !== key) return null;
      return namespace;
    } catch {
      // An oversize record (StorageReadBoundError, refused before its body is read), a read failure
      // or an undecryptable record is skipped alike.
      return null;
    }
  }

  /**
   * Save the current baseline to storage (encrypted).
   * Called at session end or periodically. Writes only the `_principal`
   * snapshot; insert records in BASELINE_NS_NAMESPACE are never touched.
   */
  async save(): Promise<void> {
    this.profile.saved_at = new Date().toISOString();
    const serialized = stringToBytes(JSON.stringify(this.profile));
    await this.storage.write(
      BASELINE_NAMESPACE,
      BASELINE_KEY,
      encodeBaselineRecord(serialized, this.encryptionKey)
    );
  }

  /**
   * Record a tool call for baseline tracking.
   * Returns anomaly information if applicable.
   */
  recordToolCall(toolName: string): void {
    const now = Date.now();

    // Track total call count
    this.profile.tool_call_counts[toolName] =
      (this.profile.tool_call_counts[toolName] ?? 0) + 1;

    // Track call rate (60-second sliding window)
    if (!this.callWindows.has(toolName)) {
      this.callWindows.set(toolName, []);
    }
    const window = this.callWindows.get(toolName)!;
    window.push(now);

    // Prune entries older than 60 seconds
    const cutoff = now - 60_000;
    while (window.length > 0 && window[0]! < cutoff) {
      window.shift();
    }
  }

  /**
   * Record a namespace access.
   * @returns true if this is a new namespace (not in baseline)
   */
  isNewNamespace(namespace: string): boolean {
    // Non-mutating mirror of recordNamespaceAccess: would this namespace be
    // new? Internal (`_`-prefixed) namespaces are never "new". The gate uses
    // this to request approval WITHOUT committing, so a denied approval cannot
    // poison the baseline (the namespace is committed only on approval).
    if (namespace.startsWith("_")) return false;
    return !this.profile.known_namespaces.includes(namespace);
  }

  recordNamespaceAccess(namespace: string): boolean {
    // Skip internal namespaces — these are Sanctuary's own storage
    if (namespace.startsWith("_")) return false;

    const isNew = !this.profile.known_namespaces.includes(namespace);
    if (isNew) {
      this.profile.known_namespaces.push(namespace);
    }
    return isNew;
  }

  /**
   * Record a namespace read for bulk-read detection.
   * @returns the number of reads in the current 60-second window
   */
  recordNamespaceRead(namespace: string): number {
    const now = Date.now();

    if (!this.readWindows.has(namespace)) {
      this.readWindows.set(namespace, []);
    }
    const window = this.readWindows.get(namespace)!;
    window.push(now);

    // Prune entries older than 60 seconds
    const cutoff = now - 60_000;
    while (window.length > 0 && window[0]! < cutoff) {
      window.shift();
    }

    return window.length;
  }

  /**
   * Record a counterparty DID interaction.
   * @returns true if this is a new counterparty (not in baseline)
   */
  isNewCounterparty(did: string): boolean {
    // Non-mutating mirror of recordCounterparty (see isNewNamespace).
    return !this.profile.known_counterparties.includes(did);
  }

  recordCounterparty(did: string): boolean {
    const isNew = !this.profile.known_counterparties.includes(did);
    if (isNew) {
      this.profile.known_counterparties.push(did);
    }
    return isNew;
  }

  /**
   * Record a signing operation.
   * @returns the number of signs in the current 60-second window
   */
  recordSign(): number {
    const now = Date.now();
    this.signWindow.push(now);

    // Prune entries older than 60 seconds
    const cutoff = now - 60_000;
    while (this.signWindow.length > 0 && this.signWindow[0]! < cutoff) {
      this.signWindow.shift();
    }

    return this.signWindow.length;
  }

  /**
   * Get the current call rate for a tool (calls per minute).
   */
  getCallRate(toolName: string): number {
    return this.callWindows.get(toolName)?.length ?? 0;
  }

  /**
   * Get the average call rate across all tools in the baseline.
   */
  getAverageCallRate(): number {
    let total = 0;
    let count = 0;
    for (const window of this.callWindows.values()) {
      total += window.length;
      count++;
    }
    return count > 0 ? total / count : 0;
  }

  /** Whether this is the first session */
  get isFirstSession(): boolean {
    return this.profile.is_first_session;
  }

  /** Get a read-only view of the current profile */
  getProfile(): SessionProfile {
    // Snapshot the arrays, not just the top-level object. Callers (e.g. the
    // gate's anomaly context) capture these; if they held the live references,
    // a later recordNamespaceAccess/recordCounterparty (now deferred to the
    // post-approval commit) would mutate an already-captured/hashed payload.
    return {
      ...this.profile,
      known_namespaces: [...this.profile.known_namespaces],
      known_counterparties: [...this.profile.known_counterparties],
    };
  }
}

/** Named steps one record() call takes; returned in order so a caller or test can read the path. */
export type BaselineNamespaceInsertState =
  | "insert_PERSISTED"
  | "insert_ALREADY_PRESENT"
  | "insert_PENDING"
  | "insert_ROW_WRITTEN"
  | "insert_ROW_THROTTLED"
  | "insert_STDERR"
  | "insert_OVER_CAP";

export type BaselineNamespacePersistFailureCode = "absent_write_unavailable" | "write_failed";

export interface BaselineNamespaceInsertsDeps {
  storage: StorageBackend;
  masterKey: Uint8Array;
  auditLog: Pick<AuditLog, "appendCritical">;
  stderr: (line: string) => void;
  now: () => number;
}

/** Operator stderr lines; they carry no namespace id, error text, tier or rule. */
export const BASELINE_NS_INSERT_STDERR_LINE =
  "Sanctuary: a memory namespace could not be recorded for the next session, and the failure could not be audited.\n";
export const BASELINE_NS_OVER_CAP_STDERR_LINE =
  "Sanctuary: too many memory namespaces are waiting to be recorded; further failures this minute are not audited one by one.\n";

/**
 * Writes one insert record per namespace a successful save used, at once, so a
 * fresh BaselineTracker on the same storage knows it after a kill or beside a
 * second process. Records are per namespace, never a whole snapshot.
 */
export class BaselineNamespaceInserts {
  private readonly storage: StorageBackend;
  private readonly encryptionKey: Uint8Array;
  private readonly auditLog: Pick<AuditLog, "appendCritical">;
  private readonly stderr: (line: string) => void;
  private readonly now: () => number;
  /** Namespaces whose insert failed; capped at BASELINE_NS_INSERT_LOAD_MAX and drained only by flushPending(). */
  private readonly pending = new Set<string>();
  /**
   * Namespaces whose record this process has published or found present; an already-recorded namespace is not
   * inserted again. Capped at BASELINE_NS_INSERT_LOAD_MAX; past the cap a namespace re-runs its insert, which
   * finds its record present.
   */
  private readonly recorded = new Set<string>();
  /** Last failure-row time per namespace; capped at BASELINE_NS_INSERT_LOAD_MAX and pruned by age on every failure. */
  private readonly failureRowAt = new Map<string, number>();
  /** The store-wide over-cap stderr slot: one line per interval. */
  private overCapLineAt: number | undefined;

  constructor(deps: BaselineNamespaceInsertsDeps) {
    this.storage = deps.storage;
    // Insert records are encrypted under the same purpose key as the snapshot.
    this.encryptionKey = derivePurposeKey(deps.masterKey, "principal-baseline");
    this.auditLog = deps.auditLog;
    this.stderr = deps.stderr;
    this.now = deps.now;
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  get throttledCount(): number {
    return this.failureRowAt.size;
  }

  /** Record the namespace a successful save used. Never throws. */
  async record(namespace: string): Promise<BaselineNamespaceInsertState[]> {
    const states: BaselineNamespaceInsertState[] = [];
    try {
      if (!isRecordableNamespace(namespace)) return states;
      if (this.recorded.has(namespace)) {
        states.push("insert_ALREADY_PRESENT");
        return states;
      }
      const attempt = await this.insertOnce(namespace);
      if (attempt === "insert_PERSISTED" || attempt === "insert_ALREADY_PRESENT") {
        if (this.recorded.size < BASELINE_NS_INSERT_LOAD_MAX) this.recorded.add(namespace);
        // Only this namespace leaves the pending set; every other pending namespace waits for its own save or the flush.
        this.pending.delete(namespace);
        states.push(attempt);
        return states;
      }
      let wroteStderr = false;
      if (!this.pending.has(namespace)) {
        if (this.pending.size < BASELINE_NS_INSERT_LOAD_MAX) {
          this.pending.add(namespace);
          states.push("insert_PENDING");
        } else {
          states.push("insert_OVER_CAP");
          wroteStderr = this.writeOverCapLine(states);
        }
      } else {
        states.push("insert_PENDING");
      }
      const now = this.now();
      this.pruneFailureRows(now);
      if (this.failureRowAt.has(namespace)) {
        states.push("insert_ROW_THROTTLED");
        return states;
      }
      if (this.failureRowAt.size >= BASELINE_NS_INSERT_LOAD_MAX) {
        if (!states.includes("insert_OVER_CAP")) states.push("insert_OVER_CAP");
        if (!wroteStderr) this.writeOverCapLine(states);
        return states;
      }
      // The throttle entry is set before the append, so a failing append is still throttled per namespace per interval.
      this.failureRowAt.set(namespace, now);
      try {
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: "baseline_namespace_persist_failed",
          identity_id: "system",
          result: "failure",
          details: { code: attempt.failed, count: this.pending.size },
        });
        states.push("insert_ROW_WRITTEN");
      } catch {
        // One call writes at most one stderr line.
        if (!wroteStderr) {
          this.writeStderr(BASELINE_NS_INSERT_STDERR_LINE);
          states.push("insert_STDERR");
        }
      }
    } catch {
      // record() never throws: a namespace insert never changes the save's response.
    }
    return states;
  }

  /** Retry every pending namespace through record(). Never throws; the only place the pending set drains. */
  async flushPending(): Promise<void> {
    for (const namespace of [...this.pending]) {
      await this.record(namespace);
    }
  }

  private async insertOnce(
    namespace: string,
  ): Promise<"insert_PERSISTED" | "insert_ALREADY_PRESENT" | { failed: BaselineNamespacePersistFailureCode }> {
    // An insert record is created once and never overwritten, so two processes cannot drop each other's records.
    // A plain write is never a fallback.
    const storage = this.storage;
    const strict = hasStrictInsert(storage);
    if (!strict && typeof storage.writeIfAbsent !== "function") return { failed: "absent_write_unavailable" };
    const key = baselineNamespaceRecordKey(namespace);
    try {
      const data = encodeBaselineRecord(stringToBytes(namespace), this.encryptionKey);
      // The tracker counts a namespace as recorded only after a publication whose directory entry is durable:
      // where the backend offers strict durability, the record is published exclusively inside the strict
      // namespace lock, whose held descriptors make the record namespace's entry durable before the write
      // resolves. A backend with no strict variant and no directory durability keeps the plain absent-write.
      const created = strict
        ? await storage.withStrictNamespaceLock(
            BASELINE_NS_NAMESPACE,
            BASELINE_NS_INSERT_LOCK_FILE,
            () => storage.writeIfAbsentStrict(BASELINE_NS_NAMESPACE, key, data),
            { kernelBacked: true, scaffold: false },
          )
        : await storage.writeIfAbsent!(BASELINE_NS_NAMESPACE, key, data);
      return created ? "insert_PERSISTED" : "insert_ALREADY_PRESENT";
    } catch {
      return { failed: "write_failed" };
    }
  }

  private pruneFailureRows(now: number): void {
    // Map order is insertion order and entries are set at increasing times, so expired entries lead.
    for (const [namespace, at] of this.failureRowAt) {
      if (now - at < BASELINE_NS_FAILURE_ROW_INTERVAL_MS) break;
      this.failureRowAt.delete(namespace);
    }
  }

  private writeOverCapLine(states: BaselineNamespaceInsertState[]): boolean {
    const now = this.now();
    if (this.overCapLineAt !== undefined && now - this.overCapLineAt < BASELINE_NS_FAILURE_ROW_INTERVAL_MS) return false;
    this.overCapLineAt = now;
    this.writeStderr(BASELINE_NS_OVER_CAP_STDERR_LINE);
    states.push("insert_STDERR");
    return true;
  }

  private writeStderr(line: string): void {
    try {
      this.stderr(line);
    } catch {
      // The stderr line is the last report; nothing remains to tell.
    }
  }
}

/** Boot stderr line when no insert record was loaded; it names the closed code only. */
export function baselineInsertLoadNoneStderrLine(code: BaselineInsertLoadCode): string {
  return `Sanctuary: saved memory namespaces were not loaded (${code}); a namespace outside the saved baseline asks for approval again.\n`;
}

export const BASELINE_NS_SKIPPED_STDERR_LINE =
  "Sanctuary: some saved memory namespace records were skipped at load, and the audit row could not be written.\n";

/**
 * Report the insert-record load at boot: a load of none writes one system row and
 * exactly one stderr line; skipped records write one system row, or a stderr line
 * when that row fails. Never throws.
 */
export async function reportBaselineInsertLoad(
  report: BaselineLoadReport,
  auditLog: Pick<AuditLog, "appendCritical">,
  stderr: (line: string) => void,
): Promise<void> {
  const { inserts } = report;
  const writeLine = (line: string) => { try { stderr(line); } catch { /* the stderr line is the last report */ } };
  const row = (code: BaselineInsertLoadCode, count: number) => auditLog.appendCritical({
    layer: "l2",
    operation: "baseline_namespace_load_bounded",
    identity_id: "system",
    result: "failure",
    details: { code, count },
  });
  switch (inserts.state) {
    case "load_BOUNDED_NONE": {
      const code = inserts.code ?? "enumeration_failed";
      try { await row(code, 0); } catch { /* the stderr line below reports the load either way */ }
      writeLine(baselineInsertLoadNoneStderrLine(code));
      return;
    }
    case "load_COMPLETE": {
      if (inserts.skipped === 0) return;
      try { await row("records_skipped", inserts.skipped); } catch { writeLine(BASELINE_NS_SKIPPED_STDERR_LINE); }
      return;
    }
    default: {
      const unreachable: never = inserts.state;
      throw new Error(`unknown insert load state: ${String(unreachable)}`);
    }
  }
}
