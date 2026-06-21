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

import type { AuditLog } from "../operational/audit-log.js";
import type { LocalAgentRecord } from "../contracts/v1.1/local-agent-records.js";
import type { AgentPlatform } from "../wrap/config-reader.js";
import type { SovereigntyTier } from "../reputation/tiers.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
  CASTLE_WALL_HEARTBEAT_OPERATION,
  CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../castle-wall/constants.js";
import {
  reverifyEntryProducerSignature,
  enforcementEntryCounts,
  producerSignedDedupKey,
  type VerifyProducerSignatureFn,
} from "./producer-reverify.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Castle Wall audit operations that constitute ENFORCEMENT EVIDENCE, i.e.
 * events that could only have been emitted by the enforcing extension/daemon
 * acting on a real flow or operator decision. These are written to the
 * encrypted audit log with `layer: "l1"` and `operation === <CastleWallEventType>`
 * by `castle-wall/runtime/audit-consumer.ts`.
 *
 * `egress_allowed` / `egress_blocked` / `operator_decision` prove the filter
 * adjudicated live traffic. We deliberately EXCLUDE pure lifecycle/diagnostic
 * events (`filter_started`, `filter_stopped`, `filter_crashed`,
 * `provider_unbound`, `no_wall_engaged`, ...) from the "armed" determination: a
 * started filter is not a filtering filter, which is exactly the divergence H3
 * forbids us from papering over.
 *
 * `policy_loaded` is also EXCLUDED, on EVERY basis (no-key/channel and
 * key-present/producer-signed). It attests only "a manifest was accepted once,"
 * not "the wall is live-adjudicating now," so by itself it must never render the
 * banner green. A wall that loaded a policy but has adjudicated zero flows in
 * the freshness window renders `unknown` (amber), never `armed`. This is the
 * never-overclaim invariant applied to the no-key floor: previously a
 * `policy_loaded`-only wall armed on the channel basis (the now-closed
 * "SLICE R BOUNDARY" seam), which contradicted the sibling reader
 * `feature-health.ts:CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS`. Both readers now
 * consume THIS single frozen set as their one definition of live adjudication
 * (feature-health imports it as an alias), so no second, more-permissive color
 * model can drift back in. The write-side gate
 * (`castle-wall/runtime/audit-consumer.ts:ENFORCEMENT_EVIDENCE_EVENT_TYPES`,
 * i.e. which events REQUIRE a producer signature) is the same concept typed over
 * the event-type enum; it is kept in lockstep by a drift-guard test rather than
 * a shared object, since the two modules are deliberately not import-coupled
 * across the read/write boundary. (`policy_loaded` remains a recorded lifecycle
 * event in the audit vocabulary; only its eligibility to ARM the posture reader
 * is removed.) Slice M closes per-event authenticity on macOS; this slice closes
 * the no-key arm-set honesty residual.
 */
export const CASTLE_WALL_ENFORCEMENT_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>([
      "egress_allowed",
      "egress_blocked",
      "operator_decision",
    ]),
  );

/**
 * Castle Wall audit operations that prove the daemon is ALIVE but do NOT prove
 * it adjudicated a real flow (observability Slice 2). The periodic
 * `castle_wall_heartbeat` is the only member: it is written on an audit-cadence
 * interval by a running daemon as a DIRECT audit append, stamped with the
 * `cw_source` provenance marker. Unlike enforcement evidence it is NOT routed
 * through the signing audit consumer, so a genuine beat is CHANNEL-basis (marker
 * only, no producer signature) on every host — the reader gates it with
 * `livenessEntryCounts`, not the stricter enforcement gate, so the silent-death
 * alarm stays functional on a key-bearing (Linux) host (see `feature-health.ts`).
 *
 * This set is kept STRICTLY SEPARATE from `CASTLE_WALL_ENFORCEMENT_OPERATIONS`:
 * a heartbeat proves liveness, NOT live adjudication, so it may NEVER earn the
 * green `armed`/`active` light on its own. Its only job is to let a reader tell
 * an alive-but-idle wall from one that silently died in a quiet window — it
 * moves the ABSENCE-of-enforcement-evidence case from `unknown` toward an honest
 * dead-vs-idle distinction, and never moves the PRESENCE case to green. No
 * operation string appears in both this set and the enforcement set (asserted by
 * a disjointness test), so a heartbeat can never be mistaken for adjudication.
 */
export const CASTLE_WALL_LIVENESS_OPERATIONS: ReadonlySet<string> =
  Object.freeze(new Set<string>([CASTLE_WALL_HEARTBEAT_OPERATION]));

/**
 * Castle Wall audit operations that record an INTENTIONAL stand-down — the
 * operator deliberately stopped the wall (`filter_stopped`) or revoked its arm
 * lease (`arm_lease_revoked`). Both stop the liveness heartbeat on purpose, so
 * the resulting heartbeat-then-silent pattern is NOT a silent death.
 *
 * This set exists to fix a false-RED defect (observability Slice 2): without it
 * a deliberately-stopped wall reads `dead_no_heartbeat`/red for ~24h, because
 * "no fresh heartbeat after the producer was once running" looks identical to a
 * killed daemon. The silent-death reader (`feature-health.ts`) consults this set
 * BEFORE firing the alarm: a recent stand-down signal relabels the reading to an
 * honest non-fault `intentionally_stopped` (`unknown`, never green, never red).
 *
 * TRUST BASIS (load-bearing honesty note): a stand-down entry is a DIRECT
 * channel-basis audit append carrying the `cw_source` marker, the SAME trust
 * basis as the heartbeat — NOT producer-signature gated. The reader therefore
 * gates it with `livenessEntryCounts` (the heartbeat's gate), so a forged
 * `producer_signed`-CLAIMING stand-down with a bad signature is dropped, but a
 * forged channel-basis stand-down is accepted on the same forgeable basis the
 * heartbeat already lives with. This is sound because a forged stand-down can
 * only relabel a RED alarm into a non-green `unknown` (off-on-purpose), exactly
 * as a forged channel-basis heartbeat already can — it can NEVER manufacture
 * green. No weaker trust basis than the alarm it suppresses is introduced.
 *
 * Kept DISJOINT from the enforcement, liveness, and not-enforcing sets: a
 * stand-down is neither adjudication, nor a liveness claim, nor a fault (it is
 * the deliberate ABSENCE of enforcement, not a malfunction). Asserted by a
 * disjointness test.
 */
export const CASTLE_WALL_STAND_DOWN_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>(["filter_stopped", CASTLE_WALL_ARM_LEASE_REVOKED_OPERATION]),
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
    | "not_installed"
    // Slice P: a producer key is expected but the reader could not load it, so
    // the wall is reported `degraded` rather than green on a weaker basis.
    | "producer_key_unavailable";
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
  /**
   * Slice P fail-honest signal: a producer key is EXPECTED for this fortress
   * (the daemon published one) but the reader could NOT load it (present but
   * unreadable / malformed). In that state the reader cannot re-verify producer
   * signatures, yet the key-bearing consumer IS enforcing on the signed basis —
   * so falling back to the channel basis here would let the reader render green
   * on a weaker basis than the consumer wrote with. When true, the posture is
   * forced to a non-armed `degraded` state (never armed, never green) regardless
   * of evidence. Set only when `pinnedProducerKeyB64url` is null.
   */
  producerKeyExpectedButUnavailable?: boolean;
  /** Injectable verify fn for tests; defaults to the real Ed25519 verifier. */
  verifyProducerSignature?: VerifyProducerSignatureFn;
}

/**
 * G4 — Castle Wall arm state, enforcement-evidenced.
 *
 * The arm-state determination is intentionally conservative:
 *
 *   armed     ← at least one enforcement-evidence operation
 *               (egress_allowed/blocked, operator_decision; NOT policy_loaded,
 *               which proves only manifest-acceptance, not live adjudication)
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

  // Slice P fail-honest: a producer key is expected (the daemon published one)
  // but the reader could not load it. The consumer is enforcing on the signed
  // basis, so the reader must NOT fall back to the channel basis and render
  // green — it surfaces `degraded` (not-armed) until the key is readable again.
  if (input.producerKeyExpectedButUnavailable === true) {
    return {
      origin_machine: input.originMachine,
      arm_state: "degraded",
      platform,
      evidence_basis: "producer_key_unavailable",
      last_enforcement_evidence_at: null,
      freshness_window_ms: freshnessWindowMs,
      verdict_counts: { allowed: 0, blocked: 0, operator_decisions: 0 },
      audit_integrity_ok: true,
      producer_authenticity: "not_applicable",
    };
  }

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
  // Dedup of re-verified producer-signed tuples so a copied genuine entry counts
  // at most once toward verdict_counts (codex round-4 HIGH: duplicate replay).
  const seenSignedKeys = new Set<string>();

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
    // (including a forged marker-only entry) does NOT count, fail closed (codex
    // HIGH #1/#2). (`policy_loaded` is excluded from arm-eligibility upstream on
    // EVERY basis, so it never reaches this count regardless of the key state.)
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
      // Dedup: a copied genuine signed tuple (same seq + signature) counts once.
      const dedupKey = producerSignedDedupKey(entry.details ?? {});
      const isDuplicate = dedupKey !== null && seenSignedKeys.has(dedupKey);
      if (dedupKey !== null) seenSignedKeys.add(dedupKey);
      if (mapped === null || !inWindow || isDuplicate) countThisEntry = false;
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

/**
 * Map a Node `process.platform` token to the Castle Wall posture's coarse
 * `platform` field (`"macos" | "linux" | "other"`). The posture surfaces this so
 * the operator can see which enforcement story applies (the macOS sysext path vs
 * the Linux path vs an unsupported host) without leaking the exact OS build.
 *
 * Exported (consumed by the dashboard's `buildStatusCastleWall`, which derives
 * the same posture shape for the auth-gated `/v1/status` document) so the two
 * code paths classify the platform identically and can never diverge — the
 * mapping lives in exactly one place. `darwin → macos`, `linux → linux`, and
 * every other token collapses to `other` (the honest "no first-class
 * enforcement story" bucket).
 */
export function mapPlatform(platform: NodeJS.Platform): "macos" | "linux" | "other" {
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
  /**
   * Slice P fail-honest signal: a producer key is EXPECTED (the daemon published
   * one) but the reader could NOT load it. The kernel counts would otherwise
   * rest on the channel basis (a weaker basis than the key-bearing consumer's),
   * so when true the digest reports an unverified chain with zero kernel counts —
   * the same honest shape as a tainted read. Set only when
   * `pinnedProducerKeyB64url` is null.
   */
  producerKeyExpectedButUnavailable?: boolean;
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

  // Slice P fail-honest: a producer key is expected but the reader could not
  // load it. Report an unverified chain with zero kernel counts rather than let
  // channel-basis (possibly forged) entries inflate kernel verdict counts.
  if (input.producerKeyExpectedButUnavailable === true) {
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
      integrity_finding_count: 0,
    };
  }

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
  // Dedup of re-verified producer-signed tuples so a copied genuine entry counts
  // at most once toward kernel_blocks/allows (codex round-4 HIGH).
  const seenSignedKeys = new Set<string>();

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
        const dedupKey = producerSignedDedupKey(entry.details ?? {});
        const isDuplicate = dedupKey !== null && seenSignedKeys.has(dedupKey);
        if (dedupKey !== null) seenSignedKeys.add(dedupKey);
        kernelCounts = kernelCounts && inWindow && opBound && !isDuplicate;
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

// ── Posture agent rows (honest policy-vs-enforcement split, #634) ─────

/**
 * Per-agent enforcement state for the Home agent grid. Mirrors the
 * `EnforcementActive` tri-state from `v1/agents.ts`:
 *
 *   - `"active"`:   protection observed live AND enforcing for THIS agent
 *                   (requires a real per-agent enforcement signal — none exists
 *                   in this read path today, so it is never emitted here).
 *   - `"inactive"`: protection observed NOT enforcing for this agent (likewise
 *                   needs a per-agent signal; never emitted today).
 *   - `"unknown"`:  no per-agent live enforcement signal available (the only
 *                   value emitted today).
 *
 * HONESTY CONTRACT (the #634 fake-green fix): `enforcement_active` is
 * deliberately NOT derived from the machine-level Castle Wall arm-state. The
 * wall posture is machine-scoped; a machine that is `armed` proves the wall
 * adjudicated SOME flow recently, not that it is enforcing THIS agent's policy.
 * Inheriting the machine arm-state per agent would reintroduce exactly the
 * overclaim #634 was merged to eliminate. Until a real per-agent enforcement
 * probe lands we emit `"unknown"` rather than fabricate a green per-agent value.
 */
export type AgentEnforcementActive = "active" | "inactive" | "unknown";

/**
 * A single Home agent-grid row, carrying the honest policy-vs-enforcement split
 * instead of a flat `protected` boolean. The UI renders GREEN only when
 * `enforcement_active === "active"`; a `policy_protected`-only agent renders
 * amber ("protection requested"), never green.
 */
export interface PostureAgentRow {
  origin_machine: string;
  agent_id: string;
  harness: string;
  /** Current lifecycle status as surfaced by the hub registry. */
  status: string;
  /**
   * Policy intent: the operator REQUESTED protection and the agent is present
   * in the wrapped roster (not mid-teardown). Computable now from the stored
   * status. NOT a liveness or enforcement claim.
   */
  policy_protected: boolean;
  /**
   * Whether protection is observed live + enforcing for this agent. `"unknown"`
   * for every agent today (no per-agent enforcement signal exists). Never the
   * machine-level wall arm-state.
   */
  enforcement_active: AgentEnforcementActive;
}

export interface BuildPostureAgentRowsInput {
  originMachine: string;
  /** Wrapped agents from the hub registry. */
  records: LocalAgentRecord[];
}

/**
 * Derive the Home agent-grid rows with the honest #634 split.
 *
 * `policy_protected` mirrors the canonical mapping in `v1/agents.ts`
 * (`toAgentSummary`): an agent is policy-protected when its status is not
 * `unwrapping` (the operator's protection request stands until an explicit
 * unwrap completes). `enforcement_active` is `"unknown"` for every agent
 * because no per-agent live enforcement signal exists in this read path; it is
 * NOT inherited from the machine-level Castle Wall arm-state (that inheritance
 * is the fake-green this fix removes).
 *
 * Pure over its inputs (no I/O, no machine-arm bleed-through) so it unit-tests
 * without a live server. Takes only the roster: deliberately accepts no wall
 * posture, so there is no path by which a machine-level signal could leak into
 * a per-agent enforcement claim.
 */
export function buildPostureAgentRows(
  input: BuildPostureAgentRowsInput,
): PostureAgentRow[] {
  return input.records.map((record) => ({
    origin_machine: input.originMachine,
    agent_id: record.agent_id,
    harness: record.harness,
    status: record.status,
    // Mirror v1/agents.ts:toAgentSummary — policy intent, not liveness.
    policy_protected: record.status !== "unwrapping",
    // No per-agent live enforcement signal exists yet; never fabricate one and
    // never inherit the machine-level wall arm-state (the #634 fake-green).
    enforcement_active: "unknown",
  }));
}

// ── Custody & Exit panel (Slice 3 — the Custody + Exit principles) ────

/**
 * Audit operations that constitute negative CUSTODY evidence — they prove the
 * fortress's key-custody chain is damaged or under suspected attack, so the
 * custody tile must render RED/amber, never green. These are written to the
 * encrypted audit log at boot / by the anti-rollback + master-rotation paths:
 *
 *  - `castle_pin_custody_mismatch` (core/index.ts): the Castle Wall pinned
 *    private key does NOT decrypt under the established master — the dual-path
 *    damage signature from the 2026-06-12 incident.
 *  - `custody_rollback_suspected` (core/anti-rollback.ts): a suspected custody
 *    rollback has FROZEN trust-bearing writes (on-disk epoch older than a
 *    surviving witness). The fortress is in the freeze state until an audited
 *    `restore-attest`.
 *
 * A FRESH instance of either inside the freshness window forces the custody
 * tile out of green. Anything else (no negative evidence) is NOT proof of
 * health — custody establishment is a boot-time fact the dashboard cannot
 * re-derive without the transient master — so the tile renders amber
 * "unconfirmed", never a fabricated green (#617 honesty contract).
 */
export const CUSTODY_DAMAGE_OPERATIONS: ReadonlySet<string> = Object.freeze(
  new Set<string>(["castle_pin_custody_mismatch", "custody_rollback_suspected"]),
);

/**
 * Audit operations that prove a custody establishment / continuity event
 * happened — they are POSITIVE provenance the dashboard can honestly surface
 * (install mode, verified-factor count) but they are NOT a freshness or
 * health proof on their own. They let the panel show "custody established"
 * provenance without claiming the chain is currently healthy.
 */
export const CUSTODY_ESTABLISHMENT_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>([
      "custody_envelope_created",
      "custody_legacy_migrated",
      "custody_master_rotated",
      "custody_restore_attested",
    ]),
  );

/**
 * The custody-posture verdict. `unconfirmed` is the honest default and renders
 * amber — the dashboard cannot prove custody HEALTH from in-process state (the
 * master that would re-derive the envelope MAC / two-factor floor / pin custody
 * is transient and not held at request time), so it never renders green.
 * `damaged` (RED) is the ONLY non-amber state and is earned solely by fresh
 * negative evidence (pin-custody mismatch or a suspected rollback freeze).
 */
export type CustodyState = "damaged" | "unconfirmed";

/**
 * Exit / portability posture. Honestly labeled per the 2026-06-18 delta review:
 * the exit machinery exists as a Tier-1-gated CLI command (`sanctuary exit`),
 * but the FULL clean-exit guarantee is NOT yet earned (Slice 1 of exit shipped
 * memory-class minting + consent only). So the panel reports `export_available`
 * — a true capability statement — and never claims `clean_exit_guaranteed`.
 */
export type ExitState = "export_available";

export interface CustodyExitPanel {
  origin_machine: string;
  /** Custody chain posture (never green; amber unconfirmed or red damaged). */
  custody_state: CustodyState;
  /** Stable basis enum the UI renders human copy from; never leaks internals. */
  custody_basis:
    | "fresh_custody_damage_evidence"
    | "rollback_freeze_active"
    | "integrity_tainted"
    | "no_negative_evidence_unconfirmed";
  /** True when a suspected-rollback freeze is fresh in the window. */
  rollback_freeze_suspected: boolean;
  /** True when a fresh Castle Wall pin-custody mismatch was observed. */
  pin_custody_mismatch: boolean;
  /**
   * Custody establishment provenance, when a fresh-enough establishment event
   * is on the audit chain. Null when none is in the window — the dashboard does
   * NOT claim "established" from absence. Provenance only; never a health claim.
   */
  establishment: {
    operation: string;
    install_mode: string | null;
    verified_wraps: number | null;
    observed_at: string;
  } | null;
  /** ISO8601 of the most recent custody-damage event, if any. */
  last_damage_evidence_at: string | null;
  /** Freshness window (ms) used to judge "recent" custody evidence. */
  freshness_window_ms: number;
  /** True when an integrity finding tainted the audit read backing this. */
  audit_integrity_ok: boolean;
  /**
   * Exit / portability posture. Always `export_available` today (the CLI export
   * exists, Tier-1 gated); the panel surfaces the honest disclaimer that the
   * full clean-exit guarantee is not yet earned.
   */
  exit_state: ExitState;
  /** The operator-facing command that performs the gated export. */
  exit_command: string;
  /**
   * HONEST: true when the full clean-exit claim is earned. Always false today —
   * exit Slice 1 shipped memory-class minting + consent, not the full guarantee.
   */
  clean_exit_guaranteed: boolean;
}

export interface BuildCustodyExitPanelInput {
  auditLog: AuditLog;
  originMachine: string;
  now?: number;
  /** Window over which custody evidence is read (defaults to the digest window). */
  windowMs?: number;
  /**
   * Freshness window for custody-damage evidence (defaults to the enforcement
   * freshness window). A pin mismatch / rollback freeze older than this is not
   * treated as a fresh "damaged" signal (the operator may have already
   * remediated), but it is never silently upgraded to green either.
   */
  freshnessWindowMs?: number;
}

/**
 * Build the Custody & Exit panel — the Slice-3 surface for the Custody and Exit
 * principles of sovereignty.
 *
 * HONESTY CONTRACT (the #617 lesson, identical to the wall + feature-health
 * shapers): the custody tile is GREEN never. The facts that would PROVE custody
 * health — the two-factor floor being met, the envelope MAC verifying, the
 * anti-rollback epoch matching its witnesses, the pinned key being non-
 * extractable — are all derived inside `establishMaster` at boot, under the
 * TRANSIENT master that the dashboard does not hold at request time. So this
 * read-only shaper does NOT re-derive them and does NOT fabricate a green from
 * their absence. What it CAN honestly surface, from the audit chain it already
 * reads:
 *
 *  - DAMAGE (red): a fresh `castle_pin_custody_mismatch` or
 *    `custody_rollback_suspected` proves the custody chain is broken / frozen.
 *  - PROVENANCE (neutral): a custody establishment event carries the honest
 *    install mode + verified-factor count, shown as provenance, NOT as health.
 *  - everything else: amber `unconfirmed` — the honest default.
 *
 * A tainted/unreadable audit read fails closed to `unconfirmed` with integrity
 * flagged (never "no damage, therefore healthy").
 *
 * Exit posture is a true capability statement: the Tier-1-gated `sanctuary exit`
 * export exists, so `export_available` is honest; `clean_exit_guaranteed` is
 * `false` because the full clean-exit claim is not yet earned (delta review).
 */
export async function buildCustodyExitPanel(
  input: BuildCustodyExitPanelInput,
): Promise<CustodyExitPanel> {
  const now = input.now ?? Date.now();
  const windowMs = input.windowMs ?? DEFAULT_DIGEST_WINDOW_MS;
  const freshnessWindowMs =
    input.freshnessWindowMs ?? DEFAULT_ENFORCEMENT_FRESHNESS_MS;
  const since = new Date(now - windowMs).toISOString();

  // The honest exit half is constant today; compute once.
  const exitFields = {
    exit_state: "export_available" as const,
    exit_command: "sanctuary exit",
    clean_exit_guaranteed: false,
  };

  let entries;
  let integrityOk: boolean;
  try {
    const result = await input.auditLog.query({ since, limit: 50_000 });
    entries = result.entries;
    integrityOk = result.integrity_findings.length === 0;
  } catch {
    // A failed/tainted read must NOT read as "no damage, therefore fine".
    // Fail closed to unconfirmed with integrity flagged.
    return {
      origin_machine: input.originMachine,
      custody_state: "unconfirmed",
      custody_basis: "integrity_tainted",
      rollback_freeze_suspected: false,
      pin_custody_mismatch: false,
      establishment: null,
      last_damage_evidence_at: null,
      freshness_window_ms: freshnessWindowMs,
      audit_integrity_ok: false,
      ...exitFields,
    };
  }

  const freshnessFloor = now - freshnessWindowMs;
  let latestDamageMs: number | null = null;
  let rollbackSuspected = false;
  let pinMismatch = false;
  let latestEstablishmentMs: number | null = null;
  let establishment: CustodyExitPanel["establishment"] = null;

  for (const entry of entries) {
    const ts = Date.parse(entry.timestamp);
    // Reject future-dated evidence beyond the small skew, exactly like the wall:
    // a future timestamp must not keep a damage signal "fresh" forever, nor
    // promote a stale establishment event.
    const tsValid =
      !Number.isNaN(ts) && ts <= now + ENFORCEMENT_FUTURE_SKEW_MS;
    if (!tsValid) continue;

    if (CUSTODY_DAMAGE_OPERATIONS.has(entry.operation)) {
      if (latestDamageMs === null || ts > latestDamageMs) latestDamageMs = ts;
      if (ts >= freshnessFloor) {
        if (entry.operation === "custody_rollback_suspected") {
          rollbackSuspected = true;
        } else if (entry.operation === "castle_pin_custody_mismatch") {
          pinMismatch = true;
        }
      }
      continue;
    }

    if (CUSTODY_ESTABLISHMENT_OPERATIONS.has(entry.operation)) {
      if (latestEstablishmentMs === null || ts > latestEstablishmentMs) {
        latestEstablishmentMs = ts;
        const details = isRecord(entry.details) ? entry.details : {};
        const installMode =
          typeof details.install_mode === "string" ? details.install_mode : null;
        const verifiedWraps =
          typeof details.verified_wraps === "number"
            ? details.verified_wraps
            : null;
        establishment = {
          operation: entry.operation,
          install_mode: installMode,
          verified_wraps: verifiedWraps,
          observed_at: new Date(ts).toISOString(),
        };
      }
    }
  }

  let custodyState: CustodyState;
  let custodyBasis: CustodyExitPanel["custody_basis"];
  if (!integrityOk) {
    // A tainted audit read can NEVER read as clean custody.
    custodyState = "unconfirmed";
    custodyBasis = "integrity_tainted";
  } else if (rollbackSuspected) {
    custodyState = "damaged";
    custodyBasis = "rollback_freeze_active";
  } else if (pinMismatch) {
    custodyState = "damaged";
    custodyBasis = "fresh_custody_damage_evidence";
  } else {
    // No fresh negative evidence is NOT proof of health: custody health is a
    // boot-time fact under the transient master. Honest amber, never green.
    custodyState = "unconfirmed";
    custodyBasis = "no_negative_evidence_unconfirmed";
  }

  return {
    origin_machine: input.originMachine,
    custody_state: custodyState,
    custody_basis: custodyBasis,
    rollback_freeze_suspected: rollbackSuspected,
    pin_custody_mismatch: pinMismatch,
    establishment,
    last_damage_evidence_at:
      latestDamageMs !== null ? new Date(latestDamageMs).toISOString() : null,
    freshness_window_ms: freshnessWindowMs,
    audit_integrity_ok: integrityOk,
    ...exitFields,
  };
}

// ── P5: Recognition + portability panel ──────────────────────────────

/**
 * Local reputation evidence shape, copied minimally from `ReputationEvidence`
 * (`shr/generator.ts`) so the shaper does not import the SHR generator. This is
 * the EVIDENCE the local attestation store already aggregates; it is NOT a
 * score, and it is NOT a Verascore value. `verascore_linked` is a LOCAL boolean
 * meaning "the operator successfully ran `reputation_publish` at least once" —
 * it carries no externally-fetched reputation and no number.
 */
export interface RecognitionReputationEvidence {
  attestation_count: number;
  tier_distribution: Record<SovereigntyTier, number>;
  most_recent_attestation_at: string | null;
  dispute_count: number;
  /** LOCAL boolean: a publish was performed. NOT a fetched score. */
  verascore_linked: boolean;
}

/**
 * Counterparty-receipt counts derived from the Concordia bridge. These prove how
 * many negotiations were committed / locally re-verified / attested THROUGH the
 * bridge — protocol-agnostic counts that derive with NO Concordia process
 * running. `verified_true` counts only `bridge_verify` audit events whose
 * recorded `valid === true`; verification is LOCAL bridge cryptography
 * (signature + commitment recomputation + terms-hash match), never a claim made
 * "by Concordia" or "by Verascore".
 */
export interface RecognitionReceiptCounts {
  /** Bridge commitments persisted in `_bridge` storage (committed receipts). */
  committed: number;
  /** `bridge_verify` events whose recorded outcome was `valid === true`. */
  verified_true: number;
  /** `bridge_verify` events whose recorded outcome was `valid === false`. */
  verified_false: number;
  /** `bridge_attest` events (committed → reputation attestation linked). */
  attested: number;
  /**
   * HONESTY: counterparty verification is LOCAL bridge cryptography, never a
   * third-party attestation. The UI keys its label off this constant so the
   * "verified locally" wording can never silently drift to "by Concordia /
   * Verascore". Frozen literal — asserted by an impartiality test.
   */
  verification_basis: "local_bridge_crypto";
  /**
   * HONESTY (#651 LOW): the bridge-receipt counts are derived from at most
   * `audit_query_cap` of the MOST RECENT in-window audit entries. On a busy
   * fortress with more bridge events than the cap, older events fall outside the
   * read and the counts UNDERCOUNT. This flag is `true` exactly when the audit
   * read was truncated (its post-filter `total` exceeded the entries returned),
   * so the UI can disclose "counts capped" rather than silently presenting an
   * undercount as a complete tally. `false` means the read covered every
   * in-window entry, so the counts are complete for the window.
   */
  receipts_capped: boolean;
  /** The audit-read cap applied to derive these counts (entries). */
  audit_query_cap: number;
}

/** Tile colour state for the Recognition panel. Green is earned by evidence. */
export type RecognitionTileState = "present" | "amber";

/** Portable-identity export capability — the Slice-3 amber treatment, reused. */
export type RecognitionExportState = "export_available";

export interface RecognitionPanel {
  origin_machine: string;
  /**
   * The composition render gate, echoed onto the payload for symmetry with the
   * `/composition` endpoint and so a client that fetched this directly can still
   * see the gate. ALWAYS `true` on a served panel — the route only builds the
   * panel when composition is enabled (the panel is ABSENT, not greyed, when
   * off). Never implies a Concordia/Verascore dependency.
   */
  composition_enabled: true;
  /** Counterparty-receipt counts from the local bridge audit/storage evidence. */
  receipts: RecognitionReceiptCounts;
  /**
   * Local reputation EVIDENCE (counts only), or `null` when no reputation store
   * is wired / readable. NEVER a score, NEVER a fetched Verascore value. Null
   * renders amber ("no reputation evidence yet"), never green-from-absence.
   */
  reputation_evidence: RecognitionReputationEvidence | null;
  /** Tile state for the local-reputation row. Amber unless evidence is present. */
  reputation_state: RecognitionTileState;
  /**
   * Portable-identity export capability (reuses Slice 3's amber capability
   * treatment): the Tier-1-gated `sanctuary_export_identity_bundle` exists, so
   * `export_available` is honest; it is rendered amber, never green, because the
   * capability is not the same as a completed, verified portable handover.
   */
  export_state: RecognitionExportState;
  /** The operator-facing tool that performs the gated portable-identity export. */
  export_tool: string;
  /** True when an integrity finding tainted the audit read backing the counts. */
  audit_integrity_ok: boolean;
}

export interface BuildRecognitionPanelInput {
  auditLog: AuditLog;
  originMachine: string;
  now?: number;
  /** Window over which bridge receipt evidence is read (defaults to ALL time). */
  windowMs?: number;
  /**
   * Count of persisted bridge commitments (`storage.list("_bridge")`). Injected
   * by the route layer so the shaper stays pure (it never touches raw storage or
   * the master key). When absent, the committed count falls back to the count of
   * `bridge_commit` audit events — an honest lower bound, never fabricated.
   */
  committedReceiptCount?: number;
  /**
   * Pre-gathered LOCAL reputation evidence (counts only). Injected by the route
   * layer, which already holds the identity + master key needed to read the
   * local attestation store. `null`/absent renders the reputation row amber
   * ("no evidence yet"), never green. This is NOT a Verascore score and there is
   * NO score-fetch path: the panel records counts, not a vendor number.
   */
  reputationEvidence?: RecognitionReputationEvidence | null;
}

/**
 * Audit operations that constitute Concordia-bridge receipt evidence, in a
 * deterministic order. We query each operation type SEPARATELY (the audit
 * `query` filters on a single `operation_type`) so the per-op `total` is the
 * true bridge-event population for that op, never the all-operations total. The
 * cap flag below is then derived from bridge-event truncation alone.
 */
const BRIDGE_RECEIPT_OPERATIONS = Object.freeze([
  "bridge_commit",
  "bridge_verify",
  "bridge_attest",
] as const);

/** Set form of the bridge ops, for the O(1) defensive guard in the tally loop. */
const BRIDGE_RECEIPT_OPERATION_SET: ReadonlySet<string> = new Set(
  BRIDGE_RECEIPT_OPERATIONS,
);

/**
 * Cap on the audit-read backing the bridge-receipt counts. The audit `query`
 * returns the most-recent `limit` in-window entries plus a `total` of the
 * post-filter population, so a fortress with more than this many in-window
 * BRIDGE events truncates and the counts undercount. Because we query each
 * bridge `operation_type` on its own (see `BRIDGE_RECEIPT_OPERATIONS`), `total`
 * is the per-op bridge population — NOT the all-operations audit total — so the
 * cap flag fires only on genuine bridge-event truncation, never on a fortress
 * that is merely busy with non-bridge audit traffic (#651 MEDIUM). We surface
 * that truncation honestly via `receipts.receipts_capped` rather than silently
 * undercounting (#651 LOW). Sized to match the sibling posture shapers.
 */
const RECOGNITION_RECEIPT_QUERY_CAP = 50_000;

/**
 * Build the Recognition + portability panel (P5) — the LAST sovereignty
 * principle on the posture dashboard, and the single most impartiality-loaded
 * surface in it.
 *
 * IMPARTIALITY CONTRACT (each clause is encoded as a test):
 *
 *  1. NO SCORE. The panel never fetches or renders a Verascore (or any vendor)
 *     reputation score. There is no score-fetch path in the codebase and this
 *     shaper creates none: it surfaces LOCAL attestation COUNTS only, and the
 *     `verascore_linked` boolean (a local "did publish" flag, not a number).
 *  2. LOCAL VERIFICATION. Counterparty verification is LOCAL bridge cryptography
 *     (`receipts.verification_basis === "local_bridge_crypto"`); the panel never
 *     labels it "by Concordia" or "by Verascore".
 *  3. NEVER FAKE GREEN (#617). Every row is evidence-based. The reputation row is
 *     amber unless real attestation evidence is present; a tainted/unreadable
 *     audit read fails closed (counts zeroed, integrity flagged), never green.
 *
 * The render gate (composition-enabled) lives in the route layer: this shaper is
 * only called when composition is on, so the panel is ABSENT (not greyed) when
 * off, and its mere presence never implies a Concordia/Verascore dependency.
 */
export async function buildRecognitionPanel(
  input: BuildRecognitionPanelInput,
): Promise<RecognitionPanel> {
  const now = input.now ?? Date.now();
  const since =
    input.windowMs !== undefined
      ? new Date(now - input.windowMs).toISOString()
      : undefined;

  const exportFields = {
    export_state: "export_available" as const,
    export_tool: "sanctuary_export_identity_bundle",
  };

  let entries;
  let integrityOk: boolean;
  let receiptsCapped: boolean;
  try {
    // Query each bridge operation type SEPARATELY so each `total` is the true
    // per-op bridge-event population — NOT the all-operations audit total. The
    // earlier all-ops read made `receipts_capped` fire on any fortress holding
    // more than the cap of NON-bridge entries (state reads, wall enforcement,
    // etc.), emitting a false "incomplete tally" warning even when every bridge
    // event sat comfortably inside the most-recent slice (#651 MEDIUM).
    const results = await Promise.all(
      BRIDGE_RECEIPT_OPERATIONS.map((operation_type) =>
        input.auditLog.query({
          ...(since !== undefined ? { since } : {}),
          operation_type,
          limit: RECOGNITION_RECEIPT_QUERY_CAP,
        }),
      ),
    );
    entries = results.flatMap((r) => r.entries);
    // Integrity findings are chain-level state (the same snapshot is returned by
    // every query), so any one result reflects the whole chain; OR across all is
    // belt-and-suspenders.
    integrityOk = results.every((r) => r.integrity_findings.length === 0);
    // Honest cap disclosure (#651 LOW + MEDIUM): for each bridge op, `total` is
    // that op's full in-window population and the returned `entries` are at most
    // the most-recent `cap` of it. When any op's `total` exceeds its returned
    // entries, older events of that op were dropped and the counts below
    // UNDERCOUNT — surface that rather than presenting an undercount as complete.
    receiptsCapped = results.some((r) => r.total > r.entries.length);
  } catch {
    // A failed/tainted read must NOT read as "no receipts, therefore healthy".
    // Fail closed: zeroed counts + integrity flagged + reputation amber.
    return {
      origin_machine: input.originMachine,
      composition_enabled: true,
      receipts: {
        committed: 0,
        verified_true: 0,
        verified_false: 0,
        attested: 0,
        verification_basis: "local_bridge_crypto",
        receipts_capped: false,
        audit_query_cap: RECOGNITION_RECEIPT_QUERY_CAP,
      },
      reputation_evidence: null,
      reputation_state: "amber",
      audit_integrity_ok: false,
      ...exportFields,
    };
  }

  // Fail closed on a readable-but-TAMPERED chain (#651 LOW). A successful read
  // that returned integrity findings means the entries we would tally come from
  // a chain whose integrity is in question — so the counts cannot be trusted.
  // Mirror the siblings (buildCastleWallPosture -> arm_state "unknown";
  // buildCustodyExitPanel -> custody_basis "integrity_tainted"): zero the
  // receipt counts, flag integrity, and hold the reputation row amber. The
  // "never fake green" invariant applies to the readable-but-tainted path, not
  // only the thrown-read path above.
  if (!integrityOk) {
    return {
      origin_machine: input.originMachine,
      composition_enabled: true,
      receipts: {
        committed: 0,
        verified_true: 0,
        verified_false: 0,
        attested: 0,
        verification_basis: "local_bridge_crypto",
        receipts_capped: false,
        audit_query_cap: RECOGNITION_RECEIPT_QUERY_CAP,
      },
      reputation_evidence: null,
      reputation_state: "amber",
      audit_integrity_ok: false,
      ...exportFields,
    };
  }

  let commitEvents = 0;
  let verifiedTrue = 0;
  let verifiedFalse = 0;
  let attested = 0;
  for (const entry of entries) {
    // Entries are already pre-filtered to bridge ops by the per-op queries; this
    // guard is defense-in-depth so a malformed audit row can never be tallied.
    if (!BRIDGE_RECEIPT_OPERATION_SET.has(entry.operation)) continue;
    if (entry.operation === "bridge_commit") {
      commitEvents += 1;
    } else if (entry.operation === "bridge_verify") {
      const details = isRecord(entry.details) ? entry.details : {};
      if (details.valid === true) verifiedTrue += 1;
      else verifiedFalse += 1;
    } else if (entry.operation === "bridge_attest") {
      attested += 1;
    }
  }

  // Prefer the injected storage-list count for "committed"; fall back to the
  // audit-event count (an honest lower bound) when the route could not list
  // `_bridge`. Never fabricate a count from absence.
  const committed =
    input.committedReceiptCount !== undefined
      ? input.committedReceiptCount
      : commitEvents;

  // Reputation row: amber unless real attestation evidence is present. A tainted
  // read already returned above; here a present evidence block with at least one
  // attestation earns "present" (green), zero attestations stays amber, and a
  // missing evidence block (no store wired) is amber — never green-from-absence.
  const ev =
    input.reputationEvidence !== undefined ? input.reputationEvidence : null;
  const reputationState: RecognitionTileState =
    ev !== null && ev.attestation_count > 0 ? "present" : "amber";

  return {
    origin_machine: input.originMachine,
    composition_enabled: true,
    receipts: {
      committed,
      verified_true: verifiedTrue,
      verified_false: verifiedFalse,
      attested,
      verification_basis: "local_bridge_crypto",
      receipts_capped: receiptsCapped,
      audit_query_cap: RECOGNITION_RECEIPT_QUERY_CAP,
    },
    reputation_evidence: ev,
    reputation_state: reputationState,
    audit_integrity_ok: integrityOk,
    ...exportFields,
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
  /**
   * Whether the OS-level Castle Wall is CONFIRMED to be enforcing these rules for
   * this agent: the SAME enforcement evidence the Home/drill-down agent pill
   * keys on (`enforcement_active === "active"`). The #641 honesty gate: when
   * false (today: always, since no per-agent live enforcement signal exists), the
   * reach view must render the Castle Wall layer / deny pills as amber
   * "configured (not confirmed enforcing)" and MUST NOT claim default-deny is in
   * effect. Green OS-enforcement coloring + the default-deny-in-effect claim are
   * reserved for the case where enforcement is actually proven. This separates a
   * CONFIGURED rule from a CONFIRMED-ENFORCING one (the #634/#638 evidence
   * pattern), so curated/never-armed rules can never read as kernel-enforced.
   */
  enforcement_confirmed: boolean;
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
  /**
   * Whether the OS-level Castle Wall is CONFIRMED to be enforcing for this agent
   * (the #641 honesty gate). The impure caller derives this from the SAME signal
   * the agent pill uses (`enforcement_active === "active"`), today always false,
   * because no per-agent live enforcement signal exists. Threaded onto the
   * payload so the reach renderer downgrades all OS-enforcement coloring + the
   * default-deny narrative to "configured" whenever enforcement is not proven.
   * Optional; absent is treated as `false` (honest, never-fake-green default).
   */
  enforcementConfirmed?: boolean;
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
 *
 * `enforcement_confirmed` is threaded through unchanged from the caller (#641):
 * the shaper does NOT infer enforcement from the rules: having a rule on disk
 * is configuration, not proof the OS is enforcing it. The caller supplies the
 * confirmed signal (the same one the agent pill uses); the renderer renders
 * OS-enforcement coloring + the default-deny claim ONLY when it is true.
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
    // #641: never-fake-green default. Enforcement is "confirmed" only when the
    // caller proves it from the same per-agent signal the agent pill uses;
    // absent ⇒ false ⇒ the reach view renders rules as configured, not enforced.
    enforcement_confirmed: input.enforcementConfirmed === true,
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
