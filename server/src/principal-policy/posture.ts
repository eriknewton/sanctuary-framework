/**
 * Sovereignty Posture Dashboard — Phase 1 gap endpoints.
 *
 * This module computes the four "gap" data shapes the Sovereignty Posture
 * Dashboard design (Review/Sanctuary/Sovereignty_Posture_Dashboard_Design_
 * 2026-06-12.md, adopt-as-amended 2026-06-12) confirmed were missing from the
 * server's HTTP surface:
 *
 *   G1 — detected-but-unwrapped agent roster (installed harnesses, by config
 *        file presence, that are NOT in the wrapped registry).
 *   G2 — "today's audit story" digest (counts by class/result/agent over a
 *        time window).
 *   G4 — Castle Wall arm state, ENFORCEMENT-EVIDENCED (never the daemon's
 *        self-reported belief or PID-liveness).
 *   G5 — per-agent effective reach (allowed destinations annotated by the
 *        layer that enforces each line).
 *
 * Design discipline baked in here (binding amendments from the design review):
 *
 *  - "Never fake green" (H3): the wall arm-state is derived from FRESH
 *    extension-originated verdict evidence in the audit log, not from a
 *    daemon's StatusResponse. Our own 06-10 / 06-11 drills proved the daemon's
 *    belief and the extension's actual enforcement diverge (a loaded daemon
 *    sitting behind an extension that silently rejected its manifest, a rebuilt
 *    extension that never deployed). When there is no recent enforcement
 *    evidence the arm-state renders `unknown`, never `armed`.
 *
 *  - `/v1`-compatible shapes (H2): every payload carries an `origin_machine`
 *    attribution field so the same shapes merge into the multi-machine console
 *    later without a schema break. Phase 1 is single-machine, so the value is
 *    always the local node id.
 *
 *  - Read-only and additive. Nothing here mutates state, performs a write, or
 *    bypasses an existing gate. Detection is config-file presence only (per
 *    review finding M1), never live process inspection.
 *
 * These functions are pure over their injected dependencies so they unit-test
 * without a live HTTP server or a running daemon.
 */

import type { AuditLog } from "../l2-operational/audit-log.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import type { AgentPlatform } from "../wrap/config-reader.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../castle-wall/constants.js";
import {
  reverifyEntryProducerSignature,
  enforcementEntryCounts,
  type VerifyProducerSignatureFn,
} from "./producer-reverify.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Castle Wall audit operations that constitute ENFORCEMENT EVIDENCE — i.e.
 * events that could only have been emitted by the enforcing extension/daemon
 * acting on a real flow or policy. These are written to the encrypted audit
 * log with `layer: "l1"` and `operation === <CastleWallEventType>` by
 * `castle-wall/runtime/audit-consumer.ts`.
 *
 * `egress_allowed` / `egress_blocked` / `operator_decision` prove the filter
 * adjudicated live traffic. `policy_loaded` proves the extension accepted a
 * manifest. We deliberately EXCLUDE pure lifecycle/diagnostic events
 * (`filter_started`, `filter_stopped`, `filter_crashed`, `provider_unbound`,
 * `no_wall_engaged`, ...) from the "armed" determination: a started filter is
 * not a filtering filter, which is exactly the divergence H3 forbids us from
 * papering over.
 */
export const CASTLE_WALL_ENFORCEMENT_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>([
      "egress_allowed",
      "egress_blocked",
      "operator_decision",
      "policy_loaded",
    ]),
  );

/**
 * Castle Wall audit operations that prove the wall is present but NOT
 * enforcing — they downgrade the arm state to a non-green "degraded" reading
 * rather than leaving it merely unknown.
 */
export const CASTLE_WALL_NOT_ENFORCING_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>([
      "filter_crashed",
      "provider_unbound",
      "no_wall_engaged",
      "external_firewall_clobber",
      "policy_validation_failed",
    ]),
  );

/** Default freshness window for "recent" enforcement evidence (10 minutes). */
export const DEFAULT_ENFORCEMENT_FRESHNESS_MS = 10 * 60 * 1000;

/** Default window for the "today's story" digest (24 hours). */
export const DEFAULT_DIGEST_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Clock-skew tolerance for "fresh" evidence. Evidence timestamped further than
 * this into the future is treated as INVALID (not fresh): a future-dated event
 * must not keep the wall green past the real freshness window. A small slack
 * accommodates legitimate clock drift between the extension and the dashboard.
 */
export const ENFORCEMENT_FUTURE_SKEW_MS = 60 * 1000;

/**
 * Arm-state verdicts. `armed` is the ONLY green value and is earned solely by
 * fresh enforcement evidence. `degraded` means the wall is present but recent
 * evidence shows it is not enforcing. `unknown` means we cannot prove
 * enforcement either way — it renders amber, never green.
 */
export type CastleWallArmState = "armed" | "degraded" | "unknown" | "not_installed";

export interface CastleWallVerdictCounts {
  allowed: number;
  blocked: number;
  operator_decisions: number;
}

/** G4 response shape. `/v1`-compatible via `origin_machine`. */
export interface CastleWallPosture {
  origin_machine: string;
  /** ENFORCEMENT-EVIDENCED arm state. Never sourced from daemon belief. */
  arm_state: CastleWallArmState;
  /** Platform the enforcement layer runs on. */
  platform: "macos" | "linux" | "other";
  /**
   * Why the arm-state reads as it does, in stable enum form. The UI renders
   * human copy from this; the field never leaks rule internals.
   */
  evidence_basis:
    | "fresh_enforcement_evidence"
    | "stale_evidence"
    | "no_evidence"
    | "not_enforcing_evidence"
    | "not_installed";
  /** ISO8601 of the most recent enforcement-evidence event, if any. */
  last_enforcement_evidence_at: string | null;
  /** Freshness window (ms) used to judge "recent". */
  freshness_window_ms: number;
  /** Verdict counts over the digest window. */
  verdict_counts: CastleWallVerdictCounts;
  /** True when an integrity finding tainted the audit read backing this. */
  audit_integrity_ok: boolean;
  /**
   * The CRYPTOGRAPHIC basis the green light rests on — surfaced honestly so the
   * UI never over-claims (never-overclaim ethos). This is independent of the
   * `arm_state` color: a wall can be `armed` on either basis.
   *
   *  - `producer_signed` — the fresh enforcement evidence backing `armed` had
   *    its daemon producer signature RE-verified at read time against the
   *    pinned key. The in-process forgery hole is closed for this read.
   *  - `channel_authenticated` — `armed` rests on the legacy channel basis
   *    (mutually-pinned IPC + tamper-evident chain) because no pinned producer
   *    key was available to this reader (macOS today, or Linux pre-provision).
   *    NOT per-producer authenticated — honestly labeled as such.
   *  - `not_applicable` — the wall is not `armed`, so no authenticity basis is
   *    asserted (unknown/degraded/not_installed).
   */
  producer_authenticity:
    | "producer_signed"
    | "channel_authenticated"
    | "not_applicable";
}

export interface BuildCastleWallPostureInput {
  auditLog: AuditLog;
  originMachine: string;
  platform?: NodeJS.Platform;
  now?: number;
  freshnessWindowMs?: number;
  digestWindowMs?: number;
  /**
   * The reader's pinned producer public key (base64url-no-pad), loaded from the
   * SAME source the audit consumer uses (`<policy_dir>/audit-producer.pub` via
   * `loadPinnedProducerKeyB64url`). When non-null, fresh enforcement evidence
   * must RE-verify its persisted producer signature against this key to count
   * toward `armed`; a `producer_signed`-claiming entry that fails re-verify
   * (forged) renders non-green. When null (macOS today / pre-provision), the
   * reader falls back to the channel-authenticated basis and labels the green
   * honestly — never as per-producer-authenticated. The impure caller MUST pass
   * the same key the consumer wrote with; never read with a weaker basis.
   */
  pinnedProducerKeyB64url?: string | null;
  /** Injectable verify fn for tests; defaults to the real Ed25519 verifier. */
  verifyProducerSignature?: VerifyProducerSignatureFn;
}

/**
 * G4 — Castle Wall arm state, enforcement-evidenced.
 *
 * The arm-state determination is intentionally conservative:
 *
 *   armed     ← at least one enforcement-evidence operation
 *               (egress_allowed/blocked, operator_decision, policy_loaded)
 *               appears within the freshness window.
 *   degraded  ← no fresh enforcement evidence, but a fresh "not enforcing"
 *               event (filter_crashed, provider_unbound, no_wall_engaged,
 *               external_firewall_clobber, policy_validation_failed) appears.
 *   unknown   ← neither (the honest default; renders amber, never green).
 *
 * `not_installed` is reserved for the obvious platform case and is not
 * inferred from absence-of-evidence (absence is `unknown`, by design).
 */
export async function buildCastleWallPosture(
  input: BuildCastleWallPostureInput,
): Promise<CastleWallPosture> {
  const now = input.now ?? Date.now();
  const freshnessWindowMs =
    input.freshnessWindowMs ?? DEFAULT_ENFORCEMENT_FRESHNESS_MS;
  const digestWindowMs = input.digestWindowMs ?? DEFAULT_DIGEST_WINDOW_MS;
  const platform = mapPlatform(input.platform ?? process.platform);
  const pinnedProducerKey = input.pinnedProducerKeyB64url ?? null;

  // Read the l1 (Castle Wall) slice over the digest window. The freshness
  // judgment is then made over the same entries by timestamp so a single read
  // serves both the arm-state and the verdict counts.
  const digestSince = new Date(now - digestWindowMs).toISOString();
  let entries;
  let integrityOk: boolean;
  try {
    const result = await input.auditLog.query({
      since: digestSince,
      layer: "l1",
      limit: 10_000,
    });
    entries = result.entries;
    integrityOk = result.integrity_findings.length === 0;
  } catch {
    // A failed/ tainted read must NOT be reported as armed. Fail closed to
    // unknown with integrity flagged.
    return {
      origin_machine: input.originMachine,
      arm_state: "unknown",
      platform,
      evidence_basis: "no_evidence",
      last_enforcement_evidence_at: null,
      freshness_window_ms: freshnessWindowMs,
      verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 },
      audit_integrity_ok: false,
      producer_authenticity: "not_applicable",
    };
  }

  const freshnessFloor = now - freshnessWindowMs;
  const verdictCounts: CastleWallVerdictCounts = {
    allowed: 0,
    blocked: 0,
    operator_decisions: 0,
  };
  let latestEnforcementMs: number | null = null;
  let latestNotEnforcingMs: number | null = null;
  // Track the authenticity basis of the MOST RECENT arm-eligible enforcement
  // entry, so the posture honestly reports whether the green light rests on a
  // re-verified producer signature or merely the channel basis.
  let latestEnforcementWasProducerSigned = false;

  for (const entry of entries) {
    const op = entry.operation;
    const ts = Date.parse(entry.timestamp);

    // PROVENANCE GATE (H3 teeth): an audit entry only counts as Castle Wall
    // enforcement evidence if it carries the audit consumer's provenance
    // marker. A different L1 producer that happens to reuse an operation name
    // like `egress_blocked` (no marker) can NEVER arm the wall — the marker is
    // stamped AFTER the event's own details are spread, so a forged
    // `event.details.cw_source` from the wire cannot survive into the entry.
    //
    // KNOWN BOUNDARY (disclosed, not closed in Phase 1): the marker is a plain
    // detail value, and `AuditLog.appendCritical` does not authenticate its
    // in-process caller. A *different in-process module* that is already
    // running inside the server could write an L1 entry with this marker and
    // arm the wall. That threat requires already-compromised server code and
    // applies equally to every audit operation (the audit log trusts its
    // in-process writers by construction). Making evidence provenance
    // cryptographically non-forgeable at the audit boundary is a cross-cutting
    // hardening tracked beyond this Phase-1 surface.
    const isCastleWall =
      isRecord(entry.details) &&
      entry.details[CASTLE_WALL_AUDIT_PROVENANCE_KEY] ===
        CASTLE_WALL_AUDIT_PROVENANCE_VALUE;

    if (!isCastleWall) continue;

    // SIGNATURE GATE (Slice R — the real close): the marker above is a cheap
    // pre-filter; it is forgeable by any in-process writer. The authority is the
    // producer signature, RE-verified here against the pinned key.
    //
    // When a pinned key IS configured (`keyPresent`), the audit CONSUMER never
    // persists genuine enforcement evidence on the channel basis — it rejects
    // unsigned enforcement evidence. So a key-bearing reader counts an
    // arm-eligible Castle Wall entry ONLY if it re-verifies as
    // `producer_signed_verified`; a `channel_authenticated`/absent-basis entry
    // (including a forged marker-only entry, or a `policy_loaded` entry the
    // daemon does not sign) does NOT count — fail closed (codex HIGH #1/#2).
    // When NO key is configured, the channel basis counts (the honest legacy /
    // macOS floor).
    const keyPresent = pinnedProducerKey !== null;
    const reResult = reverifyEntryProducerSignature(
      entry.details,
      pinnedProducerKey,
      input.verifyProducerSignature,
    );
    const isArmEligible = CASTLE_WALL_ENFORCEMENT_OPERATIONS.has(op);
    const isNotEnforcing = CASTLE_WALL_NOT_ENFORCING_OPERATIONS.has(op);
    // Only arm-eligible enforcement ops are gated by the signature. Not-enforcing
    // (fault) ops are NOT signed and must NEVER be dropped by the gate — they
    // fail toward RED/degraded (a dropped fault would leave a green-while-faulted
    // wall). They keep the channel/marker basis.
    if (isArmEligible && !enforcementEntryCounts(reResult.basis, keyPresent)) {
      continue;
    }

    // Display verdict counts over the digest window. For a re-verified
    // producer-signed entry the count is bound to the SIGNATURE (same rule as
    // the digest kernel counts — codex re-review): count by the SIGNED operation
    // (so a signed "allow" tuple stapled onto a "block" entry cannot mis-count)
    // and only when the signed capture time falls within the digest window (so a
    // replayed old tuple in a fresh entry does not inflate the count). For
    // channel-basis entries there is no signed op/time, so the entry op + the
    // arm-eligibility already established is used (the honest no-key floor).
    let countOp = op;
    let countThisEntry = true;
    if (reResult.basis === "producer_signed_verified") {
      const mapped = signedOperationFor(entry.details ?? {});
      const signedMs = reResult.signedCapturedAtMs;
      const inWindow =
        signedMs !== null && signedMs > now - digestWindowMs && signedMs <= now;
      if (mapped === null || !inWindow) countThisEntry = false;
      else countOp = mapped;
    }
    if (countThisEntry) {
      if (countOp === "egress_allowed") verdictCounts.allowed += 1;
      else if (countOp === "egress_blocked") verdictCounts.blocked += 1;
      else if (countOp === "operator_decision") verdictCounts.operator_decisions += 1;
    }

    // Freshness uses the SIGNATURE-BOUND capture time for a verified producer
    // signature (so a same-seq replay carrying an old signed timestamp cannot be
    // made fresh by forging the top-level audit timestamp — codex HIGH #3). For
    // channel-basis / fault entries there is no signed time, so the top-level
    // timestamp is used (the honest no-key floor). Future-dated evidence beyond a
    // small skew is rejected for arming either way.
    const armTs =
      reResult.signedCapturedAtMs !== null ? reResult.signedCapturedAtMs : ts;
    const tsValidForArm =
      !Number.isNaN(armTs) && armTs <= now + ENFORCEMENT_FUTURE_SKEW_MS;

    if (isArmEligible && tsValidForArm) {
      if (latestEnforcementMs === null || armTs > latestEnforcementMs) {
        latestEnforcementMs = armTs;
        latestEnforcementWasProducerSigned =
          reResult.basis === "producer_signed_verified";
      }
    }
    if (isNotEnforcing && tsValidForArm) {
      if (latestNotEnforcingMs === null || armTs > latestNotEnforcingMs) {
        latestNotEnforcingMs = armTs;
      }
    }
  }

  const hasFreshEnforcement =
    latestEnforcementMs !== null && latestEnforcementMs >= freshnessFloor;
  const hasFreshNotEnforcing =
    latestNotEnforcingMs !== null && latestNotEnforcingMs >= freshnessFloor;

  let armState: CastleWallArmState;
  let basis: CastleWallPosture["evidence_basis"];
  if (!integrityOk) {
    // A tainted audit read (integrity findings present) can NEVER render
    // green: the evidence we would judge "armed" from is itself untrustworthy.
    // Fail closed to unknown regardless of what verdict entries appear to say.
    // This is the "never fake green" invariant applied to the read path, not
    // just the daemon-belief path.
    armState = "unknown";
    basis = "no_evidence";
  } else if (hasFreshEnforcement) {
    armState = "armed";
    basis = "fresh_enforcement_evidence";
  } else if (hasFreshNotEnforcing) {
    armState = "degraded";
    basis = "not_enforcing_evidence";
  } else if (latestEnforcementMs !== null) {
    // Evidence exists but is older than the freshness window. Stale evidence
    // is NOT armed (the wall may have been disarmed since).
    armState = "unknown";
    basis = "stale_evidence";
  } else {
    armState = "unknown";
    basis = "no_evidence";
  }

  // Honest authenticity basis: only assert `producer_signed` when the wall is
  // actually `armed` AND the freshest arm-eligible evidence was a re-verified
  // producer signature. Anything else armed rests on the channel basis (the
  // honest macOS / no-key floor). Non-armed states assert no basis.
  let producerAuthenticity: CastleWallPosture["producer_authenticity"];
  if (armState !== "armed") {
    producerAuthenticity = "not_applicable";
  } else if (latestEnforcementWasProducerSigned) {
    producerAuthenticity = "producer_signed";
  } else {
    producerAuthenticity = "channel_authenticated";
  }

  return {
    origin_machine: input.originMachine,
    arm_state: armState,
    platform,
    evidence_basis: basis,
    last_enforcement_evidence_at:
      latestEnforcementMs !== null
        ? new Date(latestEnforcementMs).toISOString()
        : null,
    freshness_window_ms: freshnessWindowMs,
    verdict_counts: verdictCounts,
    audit_integrity_ok: integrityOk,
    producer_authenticity: producerAuthenticity,
  };
}

function mapPlatform(platform: NodeJS.Platform): "macos" | "linux" | "other" {
  if (platform === "darwin") return "macos";
  if (platform === "linux") return "linux";
  return "other";
}

/**
 * Map from the daemon's signed WAL `operation` vocabulary to the read-side
 * `operation` the digest counts. Mirrors `WAL_OPERATION_TO_EVENT_TYPE` in the
 * audit consumer. Used to bind a re-verified signed body's operation to the
 * entry it is filed under, so a signed "allow" tuple cannot be stapled onto a
 * "block" entry to mis-count kernel verdicts.
 */
const SIGNED_WAL_OP_TO_ENTRY_OP: Readonly<Record<string, string>> = Object.freeze({
  egress_approved: "egress_allowed",
  egress_blocked: "egress_blocked",
  egress_pending: "operator_decision",
});

/**
 * The read-side entry operation the persisted SIGNED canonical body attests to
 * (mapped from WAL vocabulary), or null on any parse failure / unknown op (fail
 * closed). The signed operation is authoritative for a re-verified entry, so
 * counting by it — rather than the forgeable top-level `entry.operation` —
 * defeats the staple-onto-wrong-slot attack. Only meaningful when the entry
 * re-verified as `producer_signed_verified`.
 */
function signedOperationFor(details: Record<string, unknown>): string | null {
  const canonical = details[CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY];
  if (typeof canonical !== "string") return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(canonical);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const signedOp = (parsed as Record<string, unknown>).operation;
  if (typeof signedOp !== "string") return null;
  return SIGNED_WAL_OP_TO_ENTRY_OP[signedOp] ?? null;
}

/**
 * True iff the persisted signed canonical body's `operation` maps to the audit
 * entry's `operation`. Fail closed on parse failure / mismatch.
 */
function signedOperationMatchesEntry(
  details: Record<string, unknown>,
  entryOperation: string,
): boolean {
  return signedOperationFor(details) === entryOperation;
}

// ── G2: today's audit story digest ──────────────────────────────────

export interface AuditDigest {
  origin_machine: string;
  window_start: string;
  window_end: string;
  total_operations: number;
  /** Operations whose recorded result was a failure (denials, blocks, errors). */
  failures: number;
  /** Castle Wall kernel-level egress blocks within the window. */
  kernel_blocks: number;
  /** Castle Wall kernel-level egress allows within the window. */
  kernel_allows: number;
  /** Approvals the operator granted within the window. */
  approvals_granted: number;
  /** Approvals the operator denied within the window. */
  approvals_denied: number;
  /** Per-agent operation counts (top contributors first). */
  by_agent: Array<{ identity_id: string; operations: number }>;
  /** Audit chain verification status for the banner (G3-cheap variant). */
  chain_verified: boolean;
  /** Number of integrity findings surfaced by the read (0 when verified). */
  integrity_finding_count: number;
}

export interface BuildAuditDigestInput {
  auditLog: AuditLog;
  originMachine: string;
  now?: number;
  windowMs?: number;
  /**
   * The reader's pinned producer public key (see `BuildCastleWallPostureInput`).
   * When non-null, a Castle Wall `egress_blocked`/`egress_allowed` entry only
   * counts toward `kernel_blocks`/`kernel_allows` if its producer signature
   * RE-verifies against this key; a forged `producer_signed`-claiming entry is
   * excluded. When null, kernel counts rest on the channel basis (legacy).
   */
  pinnedProducerKeyB64url?: string | null;
  /** Injectable verify fn for tests; defaults to the real Ed25519 verifier. */
  verifyProducerSignature?: VerifyProducerSignatureFn;
}

/**
 * G2 — "today's audit story". Server-side aggregation over the audit log.
 *
 * Counts are derived from the SAME query that surfaces integrity findings, so
 * the digest's `chain_verified` flag is honest: a tampered or unreadable chain
 * sets `chain_verified: false` rather than silently reporting clean counts.
 *
 * Approval grant/deny counts are inferred from the cross-harness approval
 * aggregator's `cross_harness_approval_resolved` audit operation, split by its
 * `details.decision` field (`approved` / `denied`); kernel block/allow counts
 * from the Castle Wall verdict operations.
 */
const APPROVAL_RESOLVED_OPERATION = "cross_harness_approval_resolved";
export async function buildAuditDigest(
  input: BuildAuditDigestInput,
): Promise<AuditDigest> {
  const now = input.now ?? Date.now();
  const windowMs = input.windowMs ?? DEFAULT_DIGEST_WINDOW_MS;
  const windowStart = new Date(now - windowMs).toISOString();
  const windowEnd = new Date(now).toISOString();
  const pinnedProducerKey = input.pinnedProducerKeyB64url ?? null;

  let entries;
  let integrityFindings;
  try {
    const result = await input.auditLog.query({
      since: windowStart,
      limit: 50_000,
    });
    entries = result.entries;
    integrityFindings = result.integrity_findings;
  } catch {
    // A tainted/unreadable read is reported as an unverified chain with zero
    // counts — never as a clean day.
    return {
      origin_machine: input.originMachine,
      window_start: windowStart,
      window_end: windowEnd,
      total_operations: 0,
      failures: 0,
      kernel_blocks: 0,
      kernel_allows: 0,
      approvals_granted: 0,
      approvals_denied: 0,
      by_agent: [],
      chain_verified: false,
      integrity_finding_count: 1,
    };
  }

  let totalOperations = 0;
  let failures = 0;
  let kernelBlocks = 0;
  let kernelAllows = 0;
  let approvalsGranted = 0;
  let approvalsDenied = 0;
  const perAgent = new Map<string, number>();
  const windowEndMs = now;

  for (const entry of entries) {
    // Bound the window's UPPER edge: the query only filters `since`, so a
    // future-dated entry would otherwise be counted in a digest whose
    // window_end is `now`. Skip anything past the window end (a parseable
    // timestamp later than now). Unparseable timestamps are kept (the chain's
    // own integrity machinery owns malformed-entry detection).
    const ts = Date.parse(entry.timestamp);
    if (!Number.isNaN(ts) && ts > windowEndMs) continue;

    totalOperations += 1;
    if (entry.result === "failure") failures += 1;

    // Kernel block/allow counts require Castle Wall provenance AND a re-verified
    // producer signature (same gate as the G4 arm-state). The provenance marker
    // is a cheap pre-filter; the producer signature is the authority. A forged
    // in-process entry (marker + claimed `producer_signed` but no valid sig)
    // fails re-verify and is NOT counted — closing the kernel-block inflation
    // hole. With no pinned key the count rests on the honest channel basis.
    const isCastleWallBlockOrAllow =
      isRecord(entry.details) &&
      entry.details[CASTLE_WALL_AUDIT_PROVENANCE_KEY] ===
        CASTLE_WALL_AUDIT_PROVENANCE_VALUE &&
      (entry.operation === "egress_blocked" ||
        entry.operation === "egress_allowed");
    let kernelCounts = !isCastleWallBlockOrAllow;
    if (isCastleWallBlockOrAllow) {
      const re = reverifyEntryProducerSignature(
        entry.details,
        pinnedProducerKey,
        input.verifyProducerSignature,
      );
      kernelCounts = enforcementEntryCounts(re.basis, pinnedProducerKey !== null);
      // For a re-verified producer-signed entry, bind the count to the SIGNATURE
      // rather than the forgeable top-level fields (codex re-review HIGH): (a)
      // the signed capture time must fall within the digest window, so a same-seq
      // replay of an OLD signed tuple into a fresh-timestamped entry does not
      // inflate today's kernel counts; (b) the signed canonical `operation` must
      // map to the entry's operation, so a signed "allow" tuple cannot be stapled
      // onto a "block" entry to mis-count. Channel-basis (no-key) entries have no
      // signed time/op, so they keep the top-level-timestamp window bound applied
      // above (the honest no-key floor).
      if (re.basis === "producer_signed_verified") {
        const signedMs = re.signedCapturedAtMs;
        const inWindow =
          signedMs !== null && signedMs > now - windowMs && signedMs <= windowEndMs;
        const opBound = signedOperationMatchesEntry(
          entry.details ?? {},
          entry.operation,
        );
        kernelCounts = kernelCounts && inWindow && opBound;
      }
    }
    if (isCastleWallBlockOrAllow && kernelCounts && entry.operation === "egress_blocked")
      kernelBlocks += 1;
    else if (isCastleWallBlockOrAllow && kernelCounts && entry.operation === "egress_allowed")
      kernelAllows += 1;
    else if (entry.operation === APPROVAL_RESOLVED_OPERATION) {
      // Split by the recorded decision; fall back to the entry result
      // (success = approved, failure = denied) when the detail is absent.
      const decision =
        typeof entry.details?.decision === "string"
          ? entry.details.decision
          : entry.result === "success"
            ? "approved"
            : "denied";
      if (decision === "approved") approvalsGranted += 1;
      else if (decision === "denied") approvalsDenied += 1;
    }

    perAgent.set(entry.identity_id, (perAgent.get(entry.identity_id) ?? 0) + 1);
  }

  const byAgent = Array.from(perAgent.entries())
    .map(([identity_id, operations]) => ({ identity_id, operations }))
    .sort((a, b) => b.operations - a.operations);

  return {
    origin_machine: input.originMachine,
    window_start: windowStart,
    window_end: windowEnd,
    total_operations: totalOperations,
    failures,
    kernel_blocks: kernelBlocks,
    kernel_allows: kernelAllows,
    approvals_granted: approvalsGranted,
    approvals_denied: approvalsDenied,
    by_agent: byAgent,
    chain_verified: integrityFindings.length === 0,
    integrity_finding_count: integrityFindings.length,
  };
}

// ── G1: detected-but-unwrapped agent roster ──────────────────────────

/**
 * Map from an `AgentPlatform` (config-detector vocabulary) to the
 * `LocalAgentRecord.harness` vocabulary (registry vocabulary). They are
 * adjacent enums that do not share string values, so the cross-reference that
 * decides "installed but unwrapped" needs this bridge.
 */
const PLATFORM_TO_HARNESS: Record<AgentPlatform, string> = {
  openclaw: "openclaw",
  "claude-code": "claude_code",
  cursor: "cursor",
  hermes: "hermes",
  cline: "cline",
  generic: "generic_mcp",
};

export interface DetectedHarness {
  /** Config-detector platform label. */
  platform: AgentPlatform;
  /** Registry-vocabulary harness kind. */
  harness: string;
  /** Config file path that proved the harness is installed. */
  config_path: string;
}

export interface UnwrappedAgentEntry {
  origin_machine: string;
  harness: string;
  platform: AgentPlatform;
  config_path: string;
  /** Always false here; the entry only exists because it is unwrapped. */
  protected: false;
  detection_method: "config_file_presence";
}

export interface UnwrappedRoster {
  origin_machine: string;
  /** Harnesses detected on the machine that have no wrapped registry record. */
  unwrapped: UnwrappedAgentEntry[];
  /** Detection method, surfaced so the UI can label honesty of the scan. */
  detection_method: "config_file_presence";
}

export interface BuildUnwrappedRosterInput {
  originMachine: string;
  /** Wrapped agents from the hub registry. */
  wrappedAgents: LocalAgentRecord[];
  /**
   * Installed harnesses detected by config-file presence. Injected so this
   * function stays pure and the scan (which touches the filesystem and is
   * itself audit-logged at the route layer) is testable in isolation.
   */
  detectedHarnesses: DetectedHarness[];
}

/**
 * G1 — detected-but-unwrapped roster.
 *
 * An installed harness is "unwrapped" when no wrapped registry record shares
 * its harness kind. This is intentionally coarse (harness-kind granularity,
 * not per-config-path): the registry tracks wraps by harness, and the demo
 * card's job is the honesty signal "you have Cursor installed and it is not
 * protected," not a per-instance inventory.
 */
export function buildUnwrappedRoster(
  input: BuildUnwrappedRosterInput,
): UnwrappedRoster {
  const wrappedHarnesses = new Set<string>(
    input.wrappedAgents.map((a) => a.harness),
  );
  const seen = new Set<string>();
  const unwrapped: UnwrappedAgentEntry[] = [];

  for (const detected of input.detectedHarnesses) {
    if (wrappedHarnesses.has(detected.harness)) continue;
    // De-dupe by harness kind so multiple config paths for one harness surface
    // as a single amber card.
    if (seen.has(detected.harness)) continue;
    seen.add(detected.harness);
    unwrapped.push({
      origin_machine: input.originMachine,
      harness: detected.harness,
      platform: detected.platform,
      config_path: detected.config_path,
      protected: false,
      detection_method: "config_file_presence",
    });
  }

  return {
    origin_machine: input.originMachine,
    unwrapped,
    detection_method: "config_file_presence",
  };
}

export { PLATFORM_TO_HARNESS };

// ── G5: per-agent effective reach ────────────────────────────────────

/**
 * The layer that physically/cooperatively enforces a reach line. The
 * distinction is the single most CISO-load-bearing fact in the product:
 * `castle_wall` lines are blocked by the operating system; `policy` lines are
 * cooperative (the agent agreed not to, enforced at the MCP boundary).
 */
export type ReachEnforcingLayer = "castle_wall" | "policy";

export interface ReachDestination {
  /** Destination predicate in plain form (host, host_pattern, ip, or cidr). */
  destination: string;
  /** Disposition: allow / prompt / deny. */
  disposition: "allow" | "prompt" | "deny";
  /** Which layer enforces this line. */
  enforcing_layer: ReachEnforcingLayer;
  /** Stable rule id for drill-down to the rule / audit reference. */
  rule_id: string;
}

export interface AgentEffectiveReach {
  origin_machine: string;
  agent_id: string;
  harness: string;
  /** Allowed/prompt/deny destinations, annotated by enforcing layer. */
  destinations: ReachDestination[];
  /**
   * True when the wall enforces default-deny for this agent (an empty or
   * allow-only ruleset). When false, the agent's egress is unrestricted by the
   * wall — surfaced in red by the UI (honesty about gaps).
   */
  default_deny: boolean;
  /** Whether a Castle Wall ruleset was found at all for this agent/fortress. */
  has_wall_policy: boolean;
}

/**
 * A reach rule as sourced from the Castle Wall allowlist (the only structured
 * destination predicate set the dashboard can read without the daemon). Kept
 * minimal and injected so this function is pure.
 */
export interface ReachRule {
  rule_id: string;
  /** Destination axes; at least one is present. */
  host?: string | string[];
  host_pattern?: string;
  ip?: string | string[];
  cidr?: string | string[];
  disposition: "allow" | "prompt" | "deny";
  /** When set, the rule is scoped to these agent ids; empty/absent = all. */
  agent_ids?: string[];
  enforcing_layer: ReachEnforcingLayer;
}

export interface BuildAgentReachInput {
  originMachine: string;
  agentId: string;
  harness: string;
  /** All reach rules visible for the fortress. */
  rules: ReachRule[];
}

/**
 * G5 — per-agent effective reach.
 *
 * Merges the visible reach rules into a per-destination list scoped to the
 * agent, annotating each with the layer that enforces it. A rule applies to
 * the agent when its `agent_ids` scope is empty/absent (all agents) or
 * explicitly names the agent.
 *
 * `default_deny` is true unless an explicit `deny`-free, allow-everything rule
 * is present — conservatively, any rule with a wildcard host that allows is
 * treated as defeating default-deny. With no wall ruleset at all,
 * `has_wall_policy` is false and `default_deny` is false (the wall is not
 * restricting this agent), so the UI surfaces the gap honestly in red.
 */
export function buildAgentReach(
  input: BuildAgentReachInput,
): AgentEffectiveReach {
  const applicable = input.rules.filter((r) => {
    if (!r.agent_ids || r.agent_ids.length === 0) return true;
    return r.agent_ids.includes(input.agentId);
  });

  // Whether a Castle Wall rule applies TO THIS AGENT — computed over the
  // agent-scoped `applicable` set, not all rules. A wall rule scoped to a
  // different agent must NOT make this agent report a wall policy (that would
  // be a false-green reach posture).
  const hasWallPolicy = applicable.some(
    (r) => r.enforcing_layer === "castle_wall",
  );

  const destinations: ReachDestination[] = [];
  let unrestrictedAllow = false;
  for (const rule of applicable) {
    const predicates = describeDestinations(rule);
    for (const predicate of predicates) {
      destinations.push({
        destination: predicate.destination,
        disposition: rule.disposition,
        enforcing_layer: rule.enforcing_layer,
        rule_id: rule.rule_id,
      });
      if (rule.disposition === "allow" && predicate.wildcard) {
        unrestrictedAllow = true;
      }
    }
  }

  // Stable sort: castle_wall (physically blocked) lines first, then policy,
  // then by destination string so the CISO reads the kernel-enforced reach at
  // the top.
  destinations.sort((a, b) => {
    if (a.enforcing_layer !== b.enforcing_layer) {
      return a.enforcing_layer === "castle_wall" ? -1 : 1;
    }
    return a.destination.localeCompare(b.destination);
  });

  // default_deny holds when there IS a wall policy AND no allow-everything
  // wildcard defeats it. No wall policy ⇒ the wall is not restricting this
  // agent ⇒ default_deny false (surfaced as a gap).
  const defaultDeny = hasWallPolicy && !unrestrictedAllow;

  return {
    origin_machine: input.originMachine,
    agent_id: input.agentId,
    harness: input.harness,
    destinations,
    default_deny: defaultDeny,
    has_wall_policy: hasWallPolicy,
  };
}

interface DestinationPredicate {
  destination: string;
  wildcard: boolean;
}

function describeDestinations(rule: ReachRule): DestinationPredicate[] {
  const out: DestinationPredicate[] = [];
  const pushHosts = (value: string | string[] | undefined) => {
    if (value === undefined) return;
    const arr = Array.isArray(value) ? value : [value];
    for (const host of arr) {
      out.push({ destination: host, wildcard: host === "*" || host === "0.0.0.0/0" });
    }
  };
  pushHosts(rule.host);
  pushHosts(rule.ip);
  pushHosts(rule.cidr);
  if (rule.host_pattern !== undefined) {
    out.push({
      destination: rule.host_pattern,
      wildcard: rule.host_pattern === "*" || rule.host_pattern === "*.*",
    });
  }
  if (out.length === 0) {
    // A rule with no destination axis (port-only) reaches "any host on port".
    out.push({ destination: "(any destination)", wildcard: true });
  }
  return out;
}
