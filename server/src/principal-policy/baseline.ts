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

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { stringToBytes, bytesToString } from "../core/encoding.js";
import type { SessionProfile } from "./types.js";

const BASELINE_NAMESPACE = "_principal";
const BASELINE_KEY = "session-baseline";

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
   * Load the previous session's baseline from storage.
   * If none exists, this is a first session.
   */
  async load(): Promise<void> {
    try {
      const raw = await this.storage.read(BASELINE_NAMESPACE, BASELINE_KEY);
      if (!raw) return;

      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const saved: SessionProfile = JSON.parse(bytesToString(decrypted));

      // Carry forward known namespaces and counterparties
      this.profile.known_namespaces = saved.known_namespaces ?? [];
      this.profile.known_counterparties = saved.known_counterparties ?? [];
      this.profile.is_first_session = false;
    } catch {
      // No prior baseline or corrupted — treat as first session
      this.profile.is_first_session = true;
    }
  }

  /**
   * Save the current baseline to storage (encrypted).
   * Called at session end or periodically.
   */
  async save(): Promise<void> {
    this.profile.saved_at = new Date().toISOString();
    const serialized = stringToBytes(JSON.stringify(this.profile));
    const encrypted = encrypt(serialized, this.encryptionKey);
    await this.storage.write(
      BASELINE_NAMESPACE,
      BASELINE_KEY,
      stringToBytes(JSON.stringify(encrypted))
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
