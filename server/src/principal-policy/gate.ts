/**
 * Sanctuary MCP Server — Approval Gate
 *
 * The three-tier approval gate sits between the MCP router and tool handlers.
 * Every tool call passes through the gate before execution.
 *
 * Evaluation order:
 * 1. Tier 1: Is this operation in the always-approve list? → Request approval.
 * 2. Tier 2: Does this call represent a behavioral anomaly? → Request approval.
 * 3. Tier 3 / default: Allow with audit logging.
 *
 * Security invariants:
 * - The gate cannot be bypassed — it wraps every tool handler.
 * - Denial responses do not reveal policy details to the agent.
 * - All gate decisions (approve, deny, allow) are audit-logged.
 */

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";
import { join } from "node:path";
import { CrossProcessLockError, withPathLock, kernelBackedCrossProcessLockPlatformSupported } from "../storage/cross-process-lock.js";
import { writeFileCustody } from "../storage/custody-fs.js";
import type { PrincipalPolicy, GateResult, ApprovalRequest, ApprovalResponse } from "./types.js";
import { fromBase64url, stringToBytes } from "../core/encoding.js";
import { HOLD_REASON_SUBJECT_MAX_CHARS } from "../hub/charter-approval-bridge.js";
import { HUB_APPROVAL_PREVIEW_MAX_FIELDS, HUB_APPROVAL_PASSAGE_MAX_UNITS, type HubApprovalPreviewArg } from "../contracts/v1.1/hub-events.js";
import type { ApprovalChannel } from "./approval-channel.js";
import { BaselineTracker } from "./baseline.js";
import {
  extractOperationName,
  FORCED_TIER3_OPERATIONS,
  NON_RELAXABLE_CLOUD_TIER1_OPERATIONS,
  NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS,
  NON_RELAXABLE_CASTLE_WALL_OBSERVE_TIER1_OPERATIONS,
  NON_RELAXABLE_ENFORCEMENT_EXPORT_TIER1_OPERATIONS,
  NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS,
  NON_RELAXABLE_EXIT_V2_MEMORY_TIER1_OPERATIONS,
  NON_RELAXABLE_MEMORY_PLAINTEXT_TIER1_OPERATIONS,
  NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS,
  NON_RELAXABLE_SDW_VAULT_TIER1_OPERATIONS,
  NON_RELAXABLE_VERASCORE_PUBLISH_TIER1_OPERATIONS,
} from "./loader.js";
import type { AuditLog } from "../operational/audit-log.js";
import { InjectionDetector, type DetectionResult } from "../security/injection-detector.js";
import { AGENT_VISIBLE_DENY_REASONS } from "./deny-vocabulary.js";
import {
  ApprovalProofStore,
  approvalEnvelopeHash,
  deriveTargetResource,
  normalizedArgsHash,
  resolveActiveSessionIdentity,
  type ApprovalRecord,
  type CanonicalApprovalEnvelope,
  type RiskTier,
  type SessionBinding,
} from "../agent-native/safety-base.js";

// Every allowed operation emits at most two metadata fields and one memory excerpt; subjects use the existing held-subject bound.
export const OPERATOR_PREVIEW_MAX_FIELDS = HUB_APPROVAL_PREVIEW_MAX_FIELDS;
// JSON needs at most six ASCII bytes per UTF-16 unit plus 128 bytes per closed field envelope.
// Preserve the original two-field budget and add only the bounded excerpt plus its envelope; two array brackets finish the bound.
export const OPERATOR_PREVIEW_MAX_BYTES = (OPERATOR_PREVIEW_MAX_FIELDS - 1) * (6 * HOLD_REASON_SUBJECT_MAX_CHARS + 128) + 2
  + 6 * HUB_APPROVAL_PASSAGE_MAX_UNITS + 128;

/** Build bounded operator display data from a closed per-operation field table, before summary truncation. */
export function buildOperatorPreview(operation: string, args: Record<string, unknown>): HubApprovalPreviewArg[] | undefined {
  const fields: HubApprovalPreviewArg[] = [];
  const subject = (field: "namespace" | "format" | "identity_id" | "type" | "destination_host", value: unknown) => {
    if (typeof value !== "string") return;
    // Identifiers are untrusted display data, not authority; the client must delimit and escape them as held subjects.
    fields.push({ kind: "subject", field, value: value.slice(0, HOLD_REASON_SUBJECT_MAX_CHARS),
      // Must match HubApprovalPreviewArg.subject in contracts/v1.1/hub-events.ts and approvalPreviewHtml in dashboard/v1_1/client.ts.
      truncated: value.length > HOLD_REASON_SUBJECT_MAX_CHARS });
  };
  const count = (kind: "byte_count" | "item_count", field: "memory" | "tags", value: unknown) => {
    if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) fields.push({ kind, field, value });
  };
  // Secret-named keys are never consulted: this exhaustive table reads only the named schema inputs.
  switch (operation) {
    case "memory_insert":
      count("byte_count", "memory", typeof args.text === "string" ? Buffer.byteLength(args.text, "utf8") : args.text_bytes);
      count("item_count", "tags", Array.isArray(args.tags) ? args.tags.length : args.tag_count);
      if (typeof args.text === "string") {
        let end = Math.min(args.text.length, HUB_APPROVAL_PASSAGE_MAX_UNITS);
        // A supplementary code point straddling the cap must remain whole, never a dangling high surrogate.
        if (end && args.text.codePointAt(end - 1)! > 0xffff) end--;
        // passage_excerpt must match types.ts, contracts/v1.1/hub-events.ts and dashboard/v1_1/client.ts; only the schema's text argument is read.
        fields.push({ kind: "passage_excerpt", field: "memory", value: args.text.slice(0, end), truncated: end < args.text.length });
      }
      break;
    case "state_export": subject("namespace", args.namespace); subject("format", args.format); break;
    case "reputation_export":
    case "sanctuary_export_identity_bundle": subject("identity_id", args.identity_id); break;
    case "reputation_publish":
      subject("type", args.type);
      // Only an explicitly supplied host is knowable here; server configuration may override the default destination.
      if (typeof args.verascore_url === "string") {
        try { subject("destination_host", new URL(args.verascore_url).hostname); } catch { /* Invalid destinations get no invented host. */ }
      }
      break;
    case "identity_sign":
      if (typeof args.payload === "string") {
        // Uses the exact core/encoding.ts functions and fallback used by identity_sign in cognitive/tools.ts.
        let bytes: Uint8Array;
        try { bytes = fromBase64url(args.payload); } catch { bytes = stringToBytes(args.payload); }
        fields.push({ kind: "byte_count", field: "payload", value: bytes.byteLength },
          { kind: "digest12", field: "payload", value: createHash("sha256").update(bytes).digest("hex").slice(0, 12) }); // 12 hex = 48 display bits, never verification evidence.
      }
      break;
    default: return undefined;
  }
  // Must match ApprovalRequest.operator_preview in types.ts and HubApprovalPendingItem in contracts/v1.1/hub-events.ts.
  return fields.length ? fields : undefined;
}

/** Callback invoked when an injection is detected, for dashboard broadcasting */
export type InjectionAlertCallback = (alert: {
  toolName: string;
  result: DetectionResult;
  timestamp: string;
}) => void;

/** Resolver for proxy tool tiers — provided by the ProxyRouter */
export type ProxyTierResolver = (toolName: string) => (1 | 2 | 3) | null;

// Runtime-classifier non-relaxable Tier-1 set. `memory_delete` plus the
// operator-cloud cloud-custody operations, the Governed File-Grant v1 mint
// operation, and the Castle Wall Observe / Learn Allow-List v1 promote
// operation, and the operator unattributed-disclosure surface, all spread from
// the SINGLE SOURCE OF TRUTH in loader.ts so
// this list and the loader's FORCED_TIER1_OPERATIONS cannot drift apart
// (Operator Cloud Slice 2 MED-1; a drift guard test pins the relationship).
// classifyRiskTier checks this list first, so even a policy file that lists
// these under Tier 3 still classifies them Tier 1 at runtime.
const FORCED_TIER1_OPERATIONS = [
  "memory_delete",
  ...NON_RELAXABLE_CLOUD_TIER1_OPERATIONS,
  ...NON_RELAXABLE_FILE_GRANT_TIER1_OPERATIONS,
  ...NON_RELAXABLE_CASTLE_WALL_OBSERVE_TIER1_OPERATIONS,
  ...NON_RELAXABLE_ENFORCEMENT_EXPORT_TIER1_OPERATIONS,
  ...NON_RELAXABLE_MEMORY_INTEGRITY_TIER1_OPERATIONS,
  ...NON_RELAXABLE_EXIT_V2_MEMORY_TIER1_OPERATIONS,
  ...NON_RELAXABLE_MEMORY_PLAINTEXT_TIER1_OPERATIONS,
  ...NON_RELAXABLE_STATE_DISCLOSURE_TIER1_OPERATIONS,
  ...NON_RELAXABLE_SDW_VAULT_TIER1_OPERATIONS,
  // Verascore publish: a Tier 3 listing in an on-disk policy was written by
  // Sanctuary's own pre-1.9.0 default, not chosen by the operator, so it is
  // not honored (see the set's comment in loader.ts).
  ...NON_RELAXABLE_VERASCORE_PUBLISH_TIER1_OPERATIONS,
] as const;

/**
 * Rung-1 point 3 (2026-08-22): a memory_ingest call that names at
 * least one allow_files path waives the secret classifier for that file, so
 * it must ALWAYS require operator approval, even when a hand-authored policy
 * relaxed the "memory_ingest" operation itself to Tier 3 (memory_ingest is in
 * DEFAULT_POLICY.tier1_always_approve but, unlike memory_delete above, is NOT
 * in FORCED_TIER1_OPERATIONS, so an operator who wants unattended plain
 * ingest can legitimately relax it). A waiver is never unattended: this is an
 * ARGUMENT-sensitive forced tier, deliberately separate from
 * FORCED_TIER1_OPERATIONS (an operation-name-only list) so a memory_ingest
 * call with no allow_files stays relaxable while one that carries allow_files
 * cannot be. Args here are the raw wire args (pre-handler-validation); a
 * malformed allow_files is treated as absent, since asAllowFiles in
 * memory-file-tools.ts denies the call before any write regardless of tier.
 */
function isForcedTier1MemoryIngestWaiver(
  operation: string,
  args: Record<string, unknown>,
): boolean {
  if (operation !== "memory_ingest") return false;
  const allowFiles = args.allow_files;
  return Array.isArray(allowFiles) && allowFiles.length > 0;
}

/**
 * Approval-lifecycle callback. Wired in v1.3 Upsilon-1 by the Cross-
 * Harness Approval Inbox aggregator. The gate fires this callback before
 * `channel.requestApproval()` (phase = "requested") and after the channel
 * resolves or fails (phase = "resolved"). The callback is fire-and-forget;
 * exceptions are swallowed so a broken aggregator never blocks the gate.
 *
 * The callback shape is import-free here so the principal-policy module
 * keeps no dependency on the aggregator (the aggregator imports the gate,
 * not vice versa).
 */
export type ApprovalEventCallback = (event: {
  phase: "requested" | "resolved";
  operation: string;
  tier: 1 | 2;
  reason: string;
  context: Record<string, unknown>;
  request_timestamp: string;
  resolution?: {
    decision: "approve" | "deny";
    decided_at: string;
    decided_by: string;
  };
  correlation_id: string;
  /**
   * Canonical normalized-args hash (`normalizedArgsHash`, identical to the
   * direct approval-proof envelope's `normalized_args_hash`). Folded into the
   * aggregator dedup key and the redirect-channel match key so two same-op
   * same-ms DIFFERENT-args requests resolve to two distinct inbox cards and
   * two distinct waiters (closes approval amplification). Absent on argless
   * escalation paths. See `ApprovalRequest.args_binding`.
   */
  args_binding?: string;
  /** Operator-card disambiguation label (`deriveTargetResource`). */
  target_resource?: string;
}) => void;

/** Closed invoked-tool to gate-operation map; must match the handoff in router.ts. */
// OWN_SCOPE_MEMORY_SAVES and OWN_SCOPE_SAVE_* must match the classification and allowance in hermes-memory-bridge/bridge-core.ts.
export const OWN_SCOPE_MEMORY_SAVES: Readonly<Record<string, string>> = Object.freeze({
  memory_insert: "memory_insert",
  sanctuary_remember: "state_write",
});
// Ten minutes, one save every five seconds sustained, and one MiB per window.
export const OWN_SCOPE_SAVE_WINDOW_MS = 10 * 60 * 1000;
export const OWN_SCOPE_SAVE_MAX_PER_WINDOW = 120;
export const OWN_SCOPE_SAVE_MAX_BYTES_PER_WINDOW = 1024 * 1024;
// Bound bookkeeping independently of how many caller identities are presented.
export const OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS = 256;

// One second bounds admission I/O, including lock contention, without bounding a human hold.
export const OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS = 1000;
// The independent round-3 read reported about 22 ms per uncached macOS admission.
// Budget 25 ms per admission (22 ms plus 3 ms scheduling headroom), even with cached filesystem checks.
// Deadline / cost bounds queued admissions, not guaranteed completions; each arrival still has its own deadline.
const OWN_SCOPE_SAVE_ADMISSION_BUDGET_MS = 25;
export const OWN_SCOPE_SAVE_MAX_QUEUED_ADMISSIONS = Math.floor(OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS / OWN_SCOPE_SAVE_ADMISSION_BUDGET_MS);
// Each tuple has a 64-hex caller digest, three safe integers and JSON punctuation;
// 160 bytes per tuple covers their maximum representation, plus array brackets.
export const OWN_SCOPE_SAVE_MAX_FILE_BYTES = OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS * 160 + 2;
const OWN_SCOPE_SAVE_FILE = "own-scope-save-quota.json";
const OWN_SCOPE_SAVE_LOCK = "own-scope-save-quota.lock";
type SaveWindow = { start: number; count: number; bytes: number };
type SaveQuotaResult = SaveWindow | { cause_class: string; lock_kind?: CrossProcessLockError["kind"] } | null;

export class ApprovalGate {
  private ownScopeSaveStateDirectory?: string;
  private ownScopeSaveTail: Promise<unknown> = Promise.resolve();
  private ownScopeSavePending = 0;
  private ownScopeSaveDiagnostics = { trackedCallers: 0, lastWork: 0, scannedEntries: 0 };

  /** Admission map operations and bounded file-validation work; contains no caller data. */
  getOwnScopeSaveQuotaDiagnostics(): { trackedCallers: number; lastWork: number; scannedEntries: number } {
    return { ...this.ownScopeSaveDiagnostics };
  }

  private ownScopeSaveHold(quota: NonNullable<SaveQuotaResult>): { reason: string; context: Record<string, unknown> } {
    // Literal reasons must match HOLD_REASON_TEMPLATES in hub/charter-approval-bridge.ts so every hold is recognized.
    if ("cause_class" in quota) {
      const context = { ...quota };
      return { reason: "memory save quota unavailable", context };
    }
    const context = { count: quota.count, bytes: quota.bytes, window_ms: OWN_SCOPE_SAVE_WINDOW_MS };
    return { reason: "memory save quota reached", context };
  }

  private async admitOwnScopeSave(caller: string, bytes: number): Promise<SaveQuotaResult> {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return { cause_class: "invalid_bytes" };
    // Missing persistence never grants unattended admission, including unwired constructors.
    if (!this.ownScopeSaveStateDirectory) return { cause_class: "storage_unconfigured" };
    // Timed-out waiters retain their bounded queue slots until the preceding I/O settles.
    if (this.ownScopeSavePending >= OWN_SCOPE_SAVE_MAX_QUEUED_ADMISSIONS + 1) return { cause_class: "admission_queue_full" };
    this.ownScopeSavePending++;
    const abort = new AbortController();
    const expires = performance.now() + OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS;
    let deadlineTimer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<SaveQuotaResult>((resolve) => {
      deadlineTimer = setTimeout(() => {
        abort.abort();
        resolve({ cause_class: "deadline" });
      }, OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS);
    });
    let causeClass = "lock";
    const checkDeadline = () => {
      // Monotonic elapsed time also closes a busy event loop's delayed timer callback.
      if (performance.now() >= expires) abort.abort();
      if (abort.signal.aborted) throw new Error("quota admission expired");
    };
    const reservation = this.ownScopeSaveTail.then(async () => {
      // A waiter whose arrival deadline elapsed must never start a reservation later.
      checkDeadline();
      return withPathLock(this.ownScopeSaveStateDirectory!, OWN_SCOPE_SAVE_LOCK, async () => {
        checkDeadline();
        const path = join(this.ownScopeSaveStateDirectory!, OWN_SCOPE_SAVE_FILE);
        this.ownScopeSaveDiagnostics = { trackedCallers: 0, lastWork: 0, scannedEntries: 0 };
        let rows: unknown = [];
        causeClass = "read";
        let file;
        try {
          file = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
        if (file) {
          try {
            const stat = await file.stat();
            causeClass = "invalid_state";
            if (!stat.isFile() || stat.size > OWN_SCOPE_SAVE_MAX_FILE_BYTES) throw new Error("quota file bound");
            // The descriptor read is capped even if the file grows after stat.
            const buffer = Buffer.alloc(OWN_SCOPE_SAVE_MAX_FILE_BYTES + 1);
            const { bytesRead } = await file.read(buffer, 0, buffer.length, 0);
            if (bytesRead > OWN_SCOPE_SAVE_MAX_FILE_BYTES) throw new Error("quota file bound");
            rows = JSON.parse(buffer.subarray(0, bytesRead).toString("utf8"));
          } finally { await file.close(); }
        }
        checkDeadline();
        causeClass = "invalid_state";
        if (!Array.isArray(rows) || rows.length > OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS) throw new Error("quota entry bound");
        const now = Date.now();
        const windows = new Map<string, SaveWindow>();
        const seen = new Set<string>();
        // Four tuple fields: SHA-256 caller digest, window start, save count and byte count.
        for (const row of rows) {
          this.ownScopeSaveDiagnostics.scannedEntries++;
          if (!Array.isArray(row) || row.length !== 4 || typeof row[0] !== "string" || !/^[a-f0-9]{64}$/.test(row[0])
            || seen.has(row[0]) || !row.slice(1).every(n => Number.isSafeInteger(n) && n >= 0)
            || row[2] > OWN_SCOPE_SAVE_MAX_PER_WINDOW || row[3] > OWN_SCOPE_SAVE_MAX_BYTES_PER_WINDOW) {
            throw new Error("invalid quota tuple");
          }
          seen.add(row[0]);
          // Prune only expired windows; a backward clock step moves the start to now without refunding usage.
          if (now - row[1] < OWN_SCOPE_SAVE_WINDOW_MS) windows.set(row[0], { start: Math.min(row[1], now), count: row[2], bytes: row[3] });
        }
        const key = createHash("sha256").update(caller).digest("hex");
        let window = windows.get(key);
        this.ownScopeSaveDiagnostics.lastWork++; // Admission lookup, excluding separately counted validation.
        if (!window) {
          if (windows.size >= OWN_SCOPE_SAVE_MAX_TRACKED_CALLERS) {
            // Active callers retain their reservations; identity churn cannot refund their budget.
            this.ownScopeSaveDiagnostics.trackedCallers = windows.size;
            return { cause_class: "caller_table_full" };
          }
          window = { start: now, count: 0, bytes: 0 };
          windows.set(key, window);
          this.ownScopeSaveDiagnostics.lastWork++;
        }
        // The quota file carries no MAC, so a same-uid actor can reset it; it is flood control, not a trust boundary.
        // A durable reservation under the shared lock precedes every unattended save;
        // failed or late saves spend quota conservatively and never refund stale headroom.
        const reached = window.count >= OWN_SCOPE_SAVE_MAX_PER_WINDOW || bytes > OWN_SCOPE_SAVE_MAX_BYTES_PER_WINDOW - window.bytes;
        if (!reached) { window.count++; window.bytes += bytes; }
        const encoded = JSON.stringify([...windows].map(([id, w]) => [id, w.start, w.count, w.bytes]));
        if (Buffer.byteLength(encoded) > OWN_SCOPE_SAVE_MAX_FILE_BYTES) throw new Error("quota file bound");
        checkDeadline();
        causeClass = "write";
        await writeFileCustody(path, encoded, { mode: 0o600, createParent: false });
        checkDeadline();
        this.ownScopeSaveDiagnostics.trackedCallers = windows.size;
        return reached ? { ...window } : null;
      }, { timeoutMs: OWN_SCOPE_SAVE_ADMISSION_DEADLINE_MS, abortSignal: abort.signal,
        // Kernel ownership dies with the process; unsupported hosts retain the O_EXCL fallback.
        kernelBacked: kernelBackedCrossProcessLockPlatformSupported(process.platform) });
    })
      .catch((error): SaveQuotaResult => {
        // Typed lock causes are operator recovery data; exception messages may contain private paths.
        const lockKind = error instanceof CrossProcessLockError ? error.kind : undefined;
        const lockCause = lockKind === "capability" ? "lock_capability" : lockKind === "scaffold-integrity" ? "lock_integrity" : "lock";
        return { cause_class: abort.signal.aborted ? "deadline" : lockKind ? lockCause : causeClass,
          ...(lockKind ? { lock_kind: lockKind } : {}) };
      })
      .finally(() => { this.ownScopeSavePending--; });
    this.ownScopeSaveTail = reservation;
    // A deadline returns a hold, but the lock and queue ordering remain until all
    // I/O settles; a late reservation cannot race another reader or authorize a save.
    try { return await Promise.race([reservation, deadline]); }
    finally { clearTimeout(deadlineTimer!); }
  }

  private policy: PrincipalPolicy;
  private baseline: BaselineTracker;
  private channel: ApprovalChannel;
  private auditLog: AuditLog;
  private injectionDetector: InjectionDetector;
  private onInjectionAlert?: InjectionAlertCallback;
  private onApprovalEvent?: ApprovalEventCallback;
  private proxyTierResolver?: ProxyTierResolver;
  private approvalProofStore: ApprovalProofStore;
  private currentSessionBinding?: () => SessionBinding | undefined;
  private currentAgentId?: () => string | undefined;

  constructor(
    policy: PrincipalPolicy,
    baseline: BaselineTracker,
    channel: ApprovalChannel,
    auditLog: AuditLog,
    injectionDetector?: InjectionDetector,
    onInjectionAlert?: InjectionAlertCallback,
    onApprovalEvent?: ApprovalEventCallback,
    options?: {
      /** Fortress-local quota directory; absence holds every own-memory save. */
      ownScopeSaveStateDirectory?: string;
      approvalProofStore?: ApprovalProofStore;
      currentSessionBinding?: () => SessionBinding | undefined;
      /**
       * The wrap-time agent id of the agent this server process serves
       * (`SANCTUARY_AGENT_ID`), the same supplier the router takes. Display
       * attribution and own-memory quota origin. Absence shares the bounded
       * agent:unknown bucket; tool arguments can never select the quota origin.
       */
      currentAgentId?: () => string | undefined;
    }
  ) {
    this.ownScopeSaveStateDirectory = options?.ownScopeSaveStateDirectory;
    this.policy = policy;
    this.baseline = baseline;
    this.channel = channel;
    this.auditLog = auditLog;
    this.injectionDetector = injectionDetector ?? new InjectionDetector();
    this.onInjectionAlert = onInjectionAlert;
    this.onApprovalEvent = onApprovalEvent;
    this.approvalProofStore = options?.approvalProofStore ?? new ApprovalProofStore();
    this.currentSessionBinding = options?.currentSessionBinding;
    this.currentAgentId = options?.currentAgentId;
  }

  /**
   * The hub id of the agent this server process is configured for, used as
   * the requester of a hold, or undefined. It names who asked, never the
   * operation's target.
   *
   * Rule-7 provenance: the value comes from the server-set `currentAgentId`
   * supplier and never from tool arguments, so an agent cannot name a different
   * agent as the requester of its own call. The `agent:` prefix must match the
   * router's `callerIdentity` in server/src/router.ts and `agent_id` in
   * `buildLocalAgentRecord` (server/src/wrap/cli.ts), so the card names the same
   * registry row the Agents screen lists. A throwing supplier yields no
   * attribution; own-memory quota accounting then uses the shared unknown bucket.
   */
  private requestingAgentId(): string | undefined {
    let raw: string | undefined;
    try {
      raw = this.currentAgentId?.();
    } catch {
      return undefined;
    }
    return typeof raw === "string" && raw.length > 0 ? `agent:${raw}` : undefined;
  }

  /**
   * Set the approval-event callback after construction. Used by the
   * Upsilon-1 wire-up when the aggregator is constructed alongside the
   * gate. The aggregator subscribes through this setter rather than the
   * constructor so existing call sites continue to work unchanged.
   */
  setApprovalEventCallback(cb: ApprovalEventCallback | undefined): void {
    this.onApprovalEvent = cb;
  }

  /**
   * Set the proxy tier resolver. Called after the proxy router is initialized.
   */
  setProxyTierResolver(resolver: ProxyTierResolver): void {
    this.proxyTierResolver = resolver;
  }

  /**
   * Evaluate a tool call against the Principal Policy.
   *
   * @param toolName - Full MCP tool name (e.g., "state_export")
   * @param args - Tool call arguments (for context extraction)
   * @returns GateResult indicating whether the call is allowed
   */
  async evaluate(
    toolName: string,
    args: Record<string, unknown>,
    approval?: { approval_ref: string },
    // Must match router.ts's server-owned operatorPreviewSource handoff. It supplies display data only, never enforcement evidence.
    operatorPreviewSource?: { operation: string; args: Record<string, unknown> },
    invokedToolName?: string
  ): Promise<GateResult> {
    const operation = extractOperationName(toolName);

    // Record the tool call in the baseline tracker
    this.baseline.recordToolCall(operation);

    // ── HABEAS PORT: forced-Tier-3 distress carve-out ─────────────────
    // The distress channel must be allowed BEFORE any layer that can deny:
    // injection blocking, anomaly escalation, and tier classification can
    // each route an operation into denial or an approval wait, and any of
    // them sitting in front of distress would let the policy layer (or a
    // dead approval channel) silence it. The payload itself is structurally
    // bounded by the tool (closed enums + truncated detail), every use is
    // audited, and the emission surface is rate-limited — so the carve-out
    // does not open a data lane. The injection scan still runs for its
    // SIGNAL value (flagged scans are audited) but never blocks here.
    // The carve-out requires the EXACT bare tool name — `toolName ===
    // operation` rejects legacy "sanctuary/"-prefixed and proxy-namespaced
    // spellings, so no aliased or namespaced caller can reach the forced
    // allow with a name that merely EXTRACTS to the distress operation
    // (codex round-1 finding 3).
    if (
      toolName === operation &&
      (FORCED_TIER3_OPERATIONS as readonly string[]).includes(operation)
    ) {
      const distressScan = this.injectionDetector.scan(toolName, args);
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: `gate_allow:${operation}`,
        identity_id: "system",
        result: "success",
        details: {
          tier: 3,
          operation,
          habeas_forced_tier3: true,
          ...(distressScan.flagged
            ? {
                injection_flagged: true,
                injection_confidence: distressScan.confidence,
                injection_signal_count: distressScan.signals.length,
              }
            : {}),
        },
      });
      return {
        allowed: true,
        tier: 3,
        reason: "Reserved habeas distress channel (always allowed, always audited)",
        approval_required: false,
      };
    }

    // ── Pre-check: Prompt injection detection ────────────────────────
    const injectionResult = this.injectionDetector.scan(toolName, args);
    if (injectionResult.flagged) {
      await this.auditLog.append("l2", `injection_detected:${operation}`, "system", {
        confidence: injectionResult.confidence,
        signals: injectionResult.signals.map(s => ({
          type: s.type,
          location: s.location,
          severity: s.severity,
        })),
        recommendation: injectionResult.recommendation,
      });

      // Notify dashboard if callback is registered
      if (this.onInjectionAlert) {
        this.onInjectionAlert({
          toolName,
          result: injectionResult,
          timestamp: new Date().toISOString(),
        });
      }

      if (injectionResult.recommendation === "block") {
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `gate_injection_block:${operation}`,
          identity_id: "system",
          result: "failure",
          details: {
            tier: 1,
            operation,
            injection_confidence: injectionResult.confidence,
            signal_count: injectionResult.signals.length,
          },
        });
        return {
          allowed: false,
          tier: 1,
          reason: AGENT_VISIBLE_DENY_REASONS.NOT_PERMITTED,
          approval_required: false,
        };
      }

      if (injectionResult.recommendation === "escalate") {
        return this.requestApproval(
          operation,
          1,
          `Potential prompt injection detected in "${operation}" (confidence: ${(injectionResult.confidence * 100).toFixed(0)}%, ${injectionResult.signals.length} signal(s))`,
          {
            operation,
            injection_detection: {
              confidence: injectionResult.confidence,
              signal_count: injectionResult.signals.length,
              signal_types: [...new Set(injectionResult.signals.map(s => s.type))],
            },
          },
          undefined,
          this.buildRequestBinding(operation, args, operatorPreviewSource)
        );
      }
    }

    // ── Proxy tools: tier determined by proxy router ─────────────────
    if (toolName.startsWith("proxy/") && this.proxyTierResolver) {
      const proxyTier = this.proxyTierResolver(toolName);
      if (proxyTier !== null) {
        if (proxyTier === 1) {
          return this.requestApproval(operation, 1, `Proxy tool "${toolName}" is configured as Tier 1 (always requires approval)`, {
            operation: toolName,
            proxy: true,
            args_summary: this.summarizeArgs(args),
          }, undefined, this.buildRequestBinding(operation, args, operatorPreviewSource));
        }

        if (proxyTier === 2) {
          // Check for anomalies specific to proxy calls
          const anomaly = this.detectAnomaly(operation, args);
          if (anomaly) {
            return this.requestApproval(operation, 2, `Proxy: ${anomaly.reason}`, {
              ...anomaly.context,
              proxy: true,
            }, anomaly.commit, this.buildRequestBinding(operation, args, operatorPreviewSource));
          }
        }

        // Tier 2 with no anomaly or Tier 3: allow with audit logging
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `gate_allow_proxy:${toolName}`,
          identity_id: "system",
          result: "success",
          details: {
            tier: proxyTier,
            operation: toolName,
            proxy: true,
          },
        });

        return {
          allowed: true,
          tier: proxyTier,
          reason: `Proxy operation allowed (Tier ${proxyTier})`,
          approval_required: false,
        };
      }
    }

    const classification = this.classifyOperation(toolName, args, { invokedToolName });
    if (classification.ownScopeSave) {
      const caller = this.requestingAgentId() ?? "agent:unknown";
      // Insert bytes come from memoryInsertApprovalArgs in sdw/memory-tools.ts;
      // remember's value is the unchanged string forwarded by rememberPrimitiveArgs.
      const bytes = operation === "memory_insert"
        ? ("text_bytes" in args ? (typeof args.text_bytes === "number" ? args.text_bytes : NaN) : Buffer.byteLength(typeof args.text === "string" ? args.text : "", "utf8"))
        : Buffer.byteLength(typeof args.value === "string" ? args.value : "", "utf8");
      const quota = await this.admitOwnScopeSave(caller, bytes);
      if (quota) {
        const unavailable = "cause_class" in quota;
        const details = unavailable ? { ...quota } : {
          count: quota.count, bytes: quota.bytes, requested_bytes: bytes,
          window_start: quota.start, window_ms: OWN_SCOPE_SAVE_WINDOW_MS,
        };
        await this.auditLog.appendCritical({ layer: "l2", operation: unavailable ? "memory_save_quota_unavailable" : "memory_save_quota_reached",
          identity_id: caller, result: "success", details });
        // A quota hold remains Tier 2 on proof retry; the original silent classification grants no authority.
        if (approval) return this.verifyApprovalProof(toolName, args, approval.approval_ref, { tier: 2 });
        // Bind this hold to the same normalized arguments as every other redirect-inbox request.
        const requestBinding = this.buildRequestBinding(operation, args, operatorPreviewSource);
        const hold = this.ownScopeSaveHold(quota);
        return this.requestApproval(operation, 2, hold.reason, hold.context, classification.observedAnomaly?.commit, requestBinding);
      }
      const anomaly = quota ? null : classification.observedAnomaly;
      if (anomaly) {
        const reasonClass = "namespace" in anomaly.context ? "new_namespace_access"
          : "counterparty_did" in anomaly.context ? "new_counterparty"
          : "is_first_session" in anomaly.context ? "first_session" : "frequency_spike";
        // Keep this observation outside gate_: evidence-pack/aggregate.ts counts that prefix as decisions and dashboard/aggregator.ts treats it as recent adjudications, so pairing it with this evaluation's gate_allow would count one allow twice.
        await this.auditLog.appendCritical({ layer: "l2", operation: `memory_save_anomaly_observed:${operation}`,
          identity_id: "system", result: "success", details: { reason_class: reasonClass, tier: 3 } });
        anomaly.commit?.();
      }
    }

    if (approval) {
      return this.verifyApprovalProof(toolName, args, approval.approval_ref, classification);
    }

    // Args-binding for the redirect-inbox approval path. Reuses the EXACT
    // normalization the direct approval-proof envelope binds
    // (`normalizedArgsHash` / `deriveTargetResource` from
    // agent-native/safety-base) so the `replace`-mode redirect channel gains
    // identical args-binding. Without this, the redirect path keyed every
    // approval solely on `<timestamp>:<operation>`, so two same-op same-ms
    // requests with different args (e.g. state_export of PUBLIC vs SECRET)
    // deduped to ONE inbox card with TWO waiters and a single benign
    // approval settled both — violating Invariant #3 (irreversible op
    // requires human approval of THAT op). The binding splits them into two
    // cards / two waiters so each is decided independently.
    const requestBinding = this.buildRequestBinding(operation, args, operatorPreviewSource);

    // ── Tier 1: Always requires approval ──────────────────────────────
    if (classification.tier === 1) {
      if (classification.unclassified) {
        await this.auditLog.appendCritical({
          layer: "l2",
          operation: `gate_unclassified:${operation}`,
          identity_id: "system",
          result: "success",
          details: {
            tier: 1,
            operation,
            warning: "Operation is not classified in any policy tier, defaulting to Tier 1 (require approval)",
          },
        });
      }
      return this.requestApproval(operation, 1, classification.reason, {
        operation,
        args_summary: this.summarizeArgs(args),
        ...(classification.unclassified ? { unclassified: true } : {}),
      }, undefined, requestBinding);
    }

    // ── Tier 2: Behavioral anomaly detection ──────────────────────────
    if (classification.tier === 2 && classification.anomaly) {
      return this.requestApproval(
        operation,
        2,
        classification.anomaly.reason,
        classification.anomaly.context,
        classification.anomaly.commit,
        requestBinding
      );
    }

    // ── Tier 3: Allow with audit logging (only for explicitly listed operations)
    if (classification.tier === 3) {
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: `gate_allow:${operation}`,
        identity_id: "system",
        result: "success",
        details: {
          tier: 3,
          operation,
        },
      });

      return {
        allowed: true,
        tier: 3,
        reason: "Operation allowed (Tier 3)",
        approval_required: false,
      };
    }

    return this.requestApproval(operation, 1, classification.reason, {
      operation,
      unclassified: true,
    }, undefined, requestBinding);
  }

  classifyRiskTier(toolName: string, args: Record<string, unknown>): RiskTier {
    return this.classifyOperation(toolName, args, { dryRun: true }).tier;
  }

  createApprovedProof(params: {
    toolName: string;
    args: Record<string, unknown>;
    session: SessionBinding;
    planHash?: `sha256:${string}`;
    stepId?: string;
    expiresAt?: string;
    auditId?: string;
  }): ApprovalRecord {
    const active = resolveActiveSessionIdentity(params.session);
    const riskTier = this.classifyRiskTier(params.toolName, params.args);
    const envelope: CanonicalApprovalEnvelope = {
      tool_name: extractOperationName(params.toolName),
      normalized_args_hash: normalizedArgsHash(params.args),
      requester_identity_fingerprint: active.requester_identity_fingerprint,
      target_resource: deriveTargetResource(extractOperationName(params.toolName), params.args),
      risk_tier: riskTier,
      ...(params.planHash ? { plan_hash: params.planHash } : {}),
      ...(params.stepId ? { step_id: params.stepId } : {}),
      expires_at: params.expiresAt ?? new Date(Date.now() + 5 * 60_000).toISOString(),
      nonce: randomBytes(16).toString("hex"),
      audit_id: params.auditId ?? `audit:approval:${Date.now()}`,
    };
    return this.approvalProofStore.createApproved(envelope);
  }

  private classifyOperation(
    toolName: string,
    args: Record<string, unknown>,
    options: { dryRun?: boolean; invokedToolName?: string } = {}
  ): {
    ownScopeSave?: boolean;
    observedAnomaly?: { reason: string; context: Record<string, unknown>; commit?: () => void } | null;
    tier: RiskTier;
    reason: string;
    anomaly?: { reason: string; context: Record<string, unknown>; commit?: () => void };
    unclassified?: boolean;
  } {
    const operation = extractOperationName(toolName);

    if ((FORCED_TIER1_OPERATIONS as readonly string[]).includes(operation)) {
      return {
        tier: 1,
        reason: `"${operation}" is a forced Tier 1 operation (always requires approval)`,
      };
    }

    if (isForcedTier1MemoryIngestWaiver(operation, args)) {
      return {
        tier: 1,
        reason:
          `"${operation}" names at least one allow_files path (a secret-classifier ` +
          `waiver) and is always Tier 1 regardless of policy (always requires approval)`,
      };
    }

    if (this.policy.tier1_always_approve.includes(operation)) {
      return {
        tier: 1,
        reason: `"${operation}" is a Tier 1 operation (always requires approval)`,
      };
    }

    // Remember ownership was checked by facadeMemoryNamespace in approvalTargetArgs before this gate.
    // Insert's fortress one-owner guard runs first in its handler and refuses a distinct identity before any adapter write.
    // Policy Tier 1 precedes this branch so explicit state_write holds and memory_save_approval: always are honored.
    if (options.invokedToolName && Object.hasOwn(OWN_SCOPE_MEMORY_SAVES, options.invokedToolName) &&
        OWN_SCOPE_MEMORY_SAVES[options.invokedToolName] === operation && this.policy.memory_save_approval !== "always") {
      return { tier: 3, reason: "own-scope memory save (Tier 3)", ownScopeSave: true,
        observedAnomaly: this.detectAnomaly(operation, args, options) };
    }

    const anomaly = this.detectAnomaly(operation, args, options);
    if (anomaly) {
      return { tier: 2, reason: anomaly.reason, anomaly };
    }

    if (this.policy.tier3_always_allow.includes(operation)) {
      return { tier: 3, reason: "Operation allowed (Tier 3)" };
    }

    // Description wording pin: a tool that reaches this fallback is Tier 2 on
    // a first session (detectAnomaly above, default first_session_policy
    // "approve") and Tier 1 here afterwards, so its MCP description says
    // "Requires operator approval under the default policy (not named in a
    // policy tier; the gate's safe default)" and never "Tier 1"; only a tool
    // in the policy Tier 1 list (checked before the detector) may say
    // "Tier 1". Must match test/structure/tool-descriptions-shape.test.ts
    // (b1)/(b2) and its first-session classifier witness.
    return {
      tier: 1,
      reason: `"${operation}" is not classified in any policy tier — requires approval (SEC-011 safe default)`,
      unclassified: true,
    };
  }

  private async verifyApprovalProof(
    toolName: string,
    args: Record<string, unknown>,
    approvalRef: string,
    classification: { tier: RiskTier }
  ): Promise<GateResult> {
    let active;
    try {
      active = resolveActiveSessionIdentity(this.currentSessionBinding?.());
    } catch {
      return this.denyProof(toolName, args, classification.tier);
    }

    const record = this.approvalProofStore.get(approvalRef);
    if (!record) {
      return this.denyProof(toolName, args, classification.tier);
    }

    const rebuilt: CanonicalApprovalEnvelope = {
      ...record.envelope,
      tool_name: extractOperationName(toolName),
      normalized_args_hash: normalizedArgsHash(args),
      requester_identity_fingerprint: active.requester_identity_fingerprint,
      target_resource: deriveTargetResource(extractOperationName(toolName), args),
      risk_tier: classification.tier,
    };

    // Approval-proof invariant: a bearer approval_ref is not authority by
    // itself. Rebuild the canonical envelope from THIS call before trusting it:
    // hash equality binds the current args hash / tier / target / requester,
    // "approved" rejects queued or denied records, absent plan_hash+step_id keeps
    // compound-plan proofs out of the direct-tool path, expiry bounds capture
    // replay, requester_fingerprint blocks cross-session proof theft, and nonce /
    // target_resource / tool_name equality reject field-splice substitutions.
    const proofMatches =
      approvalEnvelopeHash(rebuilt) === record.envelope_hash &&
      record.decision === "approved" &&
      record.envelope.plan_hash === undefined &&
      record.envelope.step_id === undefined &&
      Date.parse(record.envelope.expires_at) > Date.now() &&
      rebuilt.requester_identity_fingerprint === record.envelope.requester_identity_fingerprint &&
      rebuilt.nonce === record.envelope.nonce &&
      rebuilt.target_resource === record.envelope.target_resource &&
      rebuilt.tool_name === record.envelope.tool_name;

    if (!proofMatches) {
      return this.denyProof(toolName, args, classification.tier);
    }

    // Single-use replay invariant: every check above is read-only; this consume
    // is the linearization point. If another call already spent the same
    // approval_ref, deny instead of reusing a once-valid human approval.
    const consumed = this.approvalProofStore.consumeIfUnconsumed(approvalRef);
    if (!consumed) {
      return this.denyProof(toolName, args, classification.tier);
    }

    await this.auditLog.appendCritical({
      layer: "l2",
      operation: `gate_approval_proof:${extractOperationName(toolName)}`,
      identity_id: active.identity_id,
      result: "success",
      details: {
        tier: classification.tier,
        approval_ref: approvalRef,
        envelope_hash: record.envelope_hash,
      },
    });

    return {
      allowed: true,
      tier: classification.tier,
      reason: "Approval proof verified",
      approval_required: classification.tier !== 3,
      approval_response: {
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "human",
      },
    };
  }

  private async denyProof(
    toolName: string,
    args: Record<string, unknown>,
    tier: RiskTier
  ): Promise<GateResult> {
    await this.auditLog.appendCritical({
      layer: "l2",
      operation: `gate_deny:${extractOperationName(toolName)}`,
      identity_id: "system",
      result: "failure",
      details: {
        tier,
        approval_proof: "invalid",
        args_hash: normalizedArgsHash(args),
      },
    });
    return {
      allowed: false,
      tier,
      reason: AGENT_VISIBLE_DENY_REASONS.NOT_PERMITTED,
      approval_required: tier !== 3,
    };
  }

  /**
   * Detect Tier 2 behavioral anomalies.
   */
  private detectAnomaly(
    operation: string,
    args: Record<string, unknown>,
    options: { dryRun?: boolean } = {}
  ): { reason: string; context: Record<string, unknown>; commit?: () => void } | null {
    const config = this.policy.tier2_anomaly;

    // ── First session check ───────────────────────────────────────────
    if (this.baseline.isFirstSession && config.first_session_policy === "approve") {
      // On first session, only Tier 3 operations are auto-allowed
      if (!this.policy.tier3_always_allow.includes(operation)) {
        return {
          reason: `First session: "${operation}" has no established baseline`,
          context: { operation, is_first_session: true },
        };
      }
    }

    // ── New namespace access ──────────────────────────────────────────
    if (config.new_namespace_access === "approve") {
      const namespace = args.namespace as string | undefined;
      if (namespace && this.baseline.isNewNamespace(namespace)) {
        // Non-mutating check: do NOT record yet. The namespace is committed to
        // the baseline only if the operator APPROVES (see requestApproval's
        // onApprove). A denied probe must not poison the baseline and suppress
        // future anomaly detection for this namespace.
        return {
          reason: `First access to namespace "${namespace}" (not in session baseline)`,
          context: {
            operation,
            namespace,
            known_namespaces: this.baseline.getProfile().known_namespaces,
          },
          commit: () => {
            this.baseline.recordNamespaceAccess(namespace);
          },
        };
      }
    } else if (config.new_namespace_access === "log") {
      const namespace = args.namespace as string | undefined;
      if (namespace) {
        this.baseline.recordNamespaceAccess(namespace);
      }
    }

    // ── New counterparty ──────────────────────────────────────────────
    if (config.new_counterparty === "approve") {
      const counterpartyDid =
        (args.counterparty_did as string) ?? (args.agent_identity_id as string);
      if (counterpartyDid && this.baseline.isNewCounterparty(counterpartyDid)) {
        // Non-mutating check; commit the counterparty only on approval (see the
        // namespace branch) so a denied probe cannot poison the baseline.
        return {
          reason: `First interaction with counterparty "${counterpartyDid}"`,
          context: {
            operation,
            counterparty_did: counterpartyDid,
            known_counterparties: this.baseline.getProfile().known_counterparties,
          },
          commit: () => {
            this.baseline.recordCounterparty(counterpartyDid);
          },
        };
      }
    } else if (config.new_counterparty === "log") {
      const counterpartyDid = args.counterparty_did as string;
      if (counterpartyDid) {
        this.baseline.recordCounterparty(counterpartyDid);
      }
    }

    // ── Signing frequency ─────────────────────────────────────────────
    if (operation === "identity_sign") {
      const signCount = options.dryRun ? 0 : this.baseline.recordSign();
      if (signCount > config.max_signs_per_minute) {
        return {
          reason: `Signing frequency (${signCount}/min) exceeds limit (${config.max_signs_per_minute}/min)`,
          context: {
            operation,
            signs_per_minute: signCount,
            limit: config.max_signs_per_minute,
          },
        };
      }
    }

    // ── Bulk read detection ───────────────────────────────────────────
    if (operation === "state_read") {
      const namespace = args.namespace as string | undefined;
      if (namespace) {
        const readCount = options.dryRun ? 0 : this.baseline.recordNamespaceRead(namespace);
        if (readCount > config.bulk_read_threshold) {
          return {
            reason: `Bulk read detected: ${readCount} reads from "${namespace}" in 60 seconds (threshold: ${config.bulk_read_threshold})`,
            context: {
              operation,
              namespace,
              reads_in_window: readCount,
              threshold: config.bulk_read_threshold,
            },
          };
        }
      }
    }

    // ── Frequency spike ───────────────────────────────────────────────
    const callRate = this.baseline.getCallRate(operation);
    const avgRate = this.baseline.getAverageCallRate();
    if (
      avgRate > 0 &&
      callRate > avgRate * config.frequency_spike_multiplier
    ) {
      return {
        reason: `Frequency spike: "${operation}" at ${callRate}/min (${config.frequency_spike_multiplier}× above average ${avgRate.toFixed(1)}/min)`,
        context: {
          operation,
          current_rate: callRate,
          average_rate: avgRate,
          multiplier: config.frequency_spike_multiplier,
        },
      };
    }

    return null;
  }

  /**
   * Request approval from the human principal.
   *
   * Fail-closed contract (full-sweep #49): if the channel throws (network
   * down, callback unreachable, dashboard SSE peer dropped, webhook DNS
   * failure, etc.), the gate denies the operation and audit-logs the cause.
   * Channel-internal timeouts already resolve with decision: "deny" per
   * SEC-002; this catch covers the remaining "channel raised" path so an
   * unhandled rejection cannot turn into an indeterminate state at the gate.
   */
  private async requestApproval(
    operation: string,
    tier: 1 | 2,
    reason: string,
    context: Record<string, unknown>,
    onApprove?: () => void,
    // Args-binding for the redirect-inbox match/dedup key. `argsHash` is the
    // gate's `normalizedArgsHash` — the SAME normalization the direct
    // approval-proof envelope binds via `normalized_args_hash` — so the
    // `replace`-mode redirect path gains identical args-binding and two
    // same-op same-ms DIFFERENT-args requests resolve to two distinct cards
    // and two distinct waiters (closes approval amplification). Optional so
    // the argless escalation paths (e.g. injection-escalate) keep their
    // historic `<timestamp>:<operation>` key. `targetResource` is
    // display-only (operator card disambiguation).
    binding?: { argsHash: string; targetResource?: string; operator_preview?: HubApprovalPreviewArg[] }
  ): Promise<GateResult> {
    const requestTimestamp = new Date().toISOString();
    const requestingAgentId = this.requestingAgentId();
    const request: ApprovalRequest = {
      operation,
      tier,
      reason,
      context,
      timestamp: requestTimestamp,
      ...(binding ? { args_binding: binding.argsHash } : {}),
      // A typed field outside `context`, so no caller-built context key can
      // stand in for it; see requestingAgentId() for where the value comes from.
      ...(requestingAgentId ? { requesting_agent_id: requestingAgentId } : {}),
    };

    if (binding?.operator_preview) {
      // Non-enumerability keeps excerpts out of generic request serialization; the dashboard reads the property explicitly.
      // Must match ApprovalRequest.operator_preview in types.ts and charterApprovalRecord in dashboard.ts.
      Object.defineProperty(request, "operator_preview", { value: binding.operator_preview, configurable: true,
        enumerable: !binding.operator_preview.some(arg => arg.kind === "passage_excerpt") });
    }

    // Fire `requested` lifecycle to the aggregator before the channel
    // round-trip. The correlation_id pins the resolution to the same
    // pending entry. Listener exceptions are swallowed (gate stays
    // load-bearing; aggregator is additive observation).
    const correlationId = `${requestTimestamp}:${operation}:${Math.random().toString(16).slice(2, 6)}`;
    const approvalAuditId = `gate-approval-${randomBytes(16).toString("hex")}`;
    // Must match ApprovalRequest.approval_audit_id in types.ts: this is the gate's
    // decision identity, not caller evidence of approval; consumers still verify the settled result/audit.
    // Non-enumerability preserves existing serialized requests; immutability prevents callback substitution.
    Object.defineProperty(request, "approval_audit_id", { value: approvalAuditId });
    if (this.onApprovalEvent) {
      try {
        this.onApprovalEvent({
          phase: "requested",
          operation,
          tier,
          reason,
          context,
          request_timestamp: requestTimestamp,
          correlation_id: correlationId,
          ...(binding ? { args_binding: binding.argsHash } : {}),
          ...(binding?.targetResource
            ? { target_resource: binding.targetResource }
            : {}),
        });
      } catch {
        // Never let the aggregator break the gate.
      }
    }

    let response: ApprovalResponse;
    try {
      response = await this.channel.requestApproval(request);
    } catch (err) {
      const errMessage = err instanceof Error ? err.message : String(err);
      const decidedAt = new Date().toISOString();
      await this.auditLog.appendCritical({
        layer: "l2",
        operation: `gate_deny:${operation}`,
        identity_id: "system",
        result: "failure",
        details: {
          tier,
          reason,
          decided_by: "channel_failure",
          channel_error: errMessage,
          approval_audit_id: approvalAuditId,
          ...(binding ? { normalized_args_hash: binding.argsHash } : {}),
        },
      });
      if (this.onApprovalEvent) {
        try {
          this.onApprovalEvent({
            phase: "resolved",
            operation,
            tier,
            reason,
            context,
            request_timestamp: requestTimestamp,
            resolution: {
              decision: "deny",
              decided_at: decidedAt,
              decided_by: "channel_failure",
            },
            correlation_id: correlationId,
            ...(binding ? { args_binding: binding.argsHash } : {}),
            ...(binding?.targetResource
              ? { target_resource: binding.targetResource }
              : {}),
          });
        } catch {
          // swallow
        }
      }
      return {
        allowed: false,
        tier,
        reason: AGENT_VISIBLE_DENY_REASONS.REQUIRES_APPROVAL,
        approval_required: true,
        approval_response: {
          decision: "deny",
          decided_at: decidedAt,
          decided_by: "channel_failure",
        },
        approval_audit_id: approvalAuditId,
      };
    }

    // Audit log the decision
    await this.auditLog.appendCritical({
      layer: "l2",
      operation: `gate_${response.decision}:${operation}`,
      identity_id: "system",
      result: response.decision === "approve" ? "success" : "failure",
      details: {
        tier,
        reason,
        decided_by: response.decided_by,
        // This gate-minted id and the normalized argument hash make this exact
        // durable decision, rather than a caller's correlation token, the
        // approval provenance consumed by signed downstream artifacts.
        approval_audit_id: approvalAuditId,
        ...(binding ? { normalized_args_hash: binding.argsHash } : {}),
      },
    });

    // Fire `resolved` lifecycle to the aggregator. Castle-walking: the
    // gate's deny/accept logic is unchanged; this hook adds visibility,
    // not enforcement.
    if (this.onApprovalEvent) {
      try {
        this.onApprovalEvent({
          phase: "resolved",
          operation,
          tier,
          reason,
          context,
          request_timestamp: requestTimestamp,
          resolution: {
            decision: response.decision,
            decided_at: response.decided_at,
            decided_by: response.decided_by,
          },
          correlation_id: correlationId,
          ...(binding ? { args_binding: binding.argsHash } : {}),
          ...(binding?.targetResource
            ? { target_resource: binding.targetResource }
            : {}),
        });
      } catch {
        // swallow
      }
    }

    // Commit deferred baseline state ONLY on approval. detectAnomaly computes
    // "is new" without mutating; the namespace/counterparty is recorded here so
    // a DENIED approval cannot poison the baseline and suppress future anomaly
    // detection. Wrapped so a baseline error can never alter the gate verdict.
    if (response.decision === "approve" && onApprove) {
      try {
        onApprove();
      } catch {
        // Baseline commit is best-effort; never let it change the gate result.
      }
    }

    // Agent-facing denial reasons MUST NOT leak policy threshold values
    // (Sanctuary Invariant #7). The detailed `reason` flows into the audit
    // log and the out-of-band approval channel for the human reviewer; the
    // value returned to the caller becomes a generic string.
    return {
      allowed: response.decision === "approve",
      tier,
      reason: response.decision === "approve"
        ? `Approved by ${response.decided_by}`
        : AGENT_VISIBLE_DENY_REASONS.REQUIRES_APPROVAL,
      approval_required: true,
      approval_response: response,
      approval_audit_id: approvalAuditId,
    };
  }

  /**
   * Summarize tool arguments for the approval prompt.
   * Strips potentially large values to keep the prompt readable.
   */
  private summarizeArgs(args: Record<string, unknown>): Record<string, unknown> {
    // Hard Constraint #1: the approval context built from these args can be
    // sent to an external webhook / dashboard BEFORE approval, so it must
    // carry operation METADATA only, never secret content. Redact
    // secret-named fields, and summarize objects/arrays to shape so a nested
    // secret (e.g. an identity object's encrypted_private_key) cannot leak.
    const SENSITIVE_ARG_NAME =
      /pass(phrase|word)|secret|private_key|recovery_key|master_key|seed_phrase|mnemonic|credential/i;
    const summary: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(args)) {
      if (SENSITIVE_ARG_NAME.test(key)) {
        summary[key] = "[redacted]";
      } else if (typeof value === "string") {
        summary[key] = value.length > 100 ? value.slice(0, 100) + "..." : value;
      } else if (value !== null && typeof value === "object") {
        summary[key] = Array.isArray(value)
          ? `[array(${value.length})]`
          : `[object(${Object.keys(value as Record<string, unknown>).length} keys)]`;
      } else {
        summary[key] = value;
      }
    }
    return summary;
  }

  /**
   * Build the redirect-inbox args-binding for an approval request. The
   * `argsHash` (gate's `normalizedArgsHash`, identical to the direct
   * proof envelope's `normalized_args_hash`) is the security-load-bearing
   * field; `targetResource` is display-only. `deriveTargetResource` can
   * throw on a malformed state bundle, so it is wrapped — a bad bundle
   * degrades the operator card label but must never crash the gate or
   * weaken the hash binding.
   */
  private buildRequestBinding(
    operation: string,
    args: Record<string, unknown>,
    operatorPreviewSource?: { operation: string; args: Record<string, unknown> }
  ): { argsHash: string; targetResource?: string; operator_preview?: HubApprovalPreviewArg[] } {
    let targetResource: string | undefined;
    try {
      targetResource = deriveTargetResource(operation, args);
    } catch {
      targetResource = undefined;
    }
    // Raw handoff data is consumed only by the closed preview builder, never summarized, audited, bound into proofs or returned to the agent.
    // Only memory_insert needs raw text; every other preview retains its existing projected-argument behavior.
    const preview = operatorPreviewSource?.operation === "memory_insert" && operation === "memory_insert"
      ? buildOperatorPreview("memory_insert", operatorPreviewSource.args)
      : buildOperatorPreview(operation, args);
    return { argsHash: normalizedArgsHash(args), targetResource, operator_preview: preview };
  }

  /** Get the baseline tracker for saving at session end */
  getBaseline(): BaselineTracker {
    return this.baseline;
  }

  /** Get the injection detector for stats/configuration access */
  getInjectionDetector(): InjectionDetector {
    return this.injectionDetector;
  }
}
