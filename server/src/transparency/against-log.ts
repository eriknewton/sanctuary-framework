/**
 * Host-mode transparency verification (`verify-transparency --against-log`).
 *
 * Runs ON the fortress host, with read access to the audit-log storage, and
 * cross-checks a checkpoint against the ACTUAL log:
 *
 *   - recomputes the Merkle root over the checkpoint's covered sequence
 *     window from the surviving on-disk envelopes (no decryption key needed
 *     — the hash chain metadata is plaintext, per the #437 design)
 *   - detects tail truncation: the live log head must never be behind a
 *     signed checkpoint's head
 *   - detects in-window deletion: every covered sequence must survive
 *     (unless legitimately pruned by rotation, which only removes a
 *     contiguous PREFIX — reported honestly as "not recomputable", never as
 *     a silent pass)
 *   - optionally recounts the per-rule enforcement counters when the caller
 *     can decrypt the log (passphrase provided), comparing them to the
 *     signed counts
 *
 * This module intentionally imports server-runtime storage/audit code; the
 * pure offline verifier lives in verify.ts and stays standalone.
 */

import { computeAuditRoot } from "../audit/chain.js";
import { bytesToString } from "../core/encoding.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { StorageBackend } from "../storage/interface.js";
import { transparencyRuleLabel } from "./checkpoint.js";
import type {
  TransparencyFinding,
  VerifierCheckpointRecord,
} from "./verify.js";

const AUDIT_NAMESPACE = "_audit";

export interface AgainstLogResult {
  /** Counter of the checkpoint that was checked against the log. */
  checked_counter: number | null;
  /** True only when the Merkle root was fully recomputed and matched. */
  merkle_root_recomputed: boolean;
  /** True only when counters were fully recounted and matched. */
  counters_recomputed: boolean;
  findings: TransparencyFinding[];
  notes: string[];
}

export interface VerifyAgainstLogInput {
  /** Schema-validated checkpoint records (any order). */
  records: VerifierCheckpointRecord[];
  /** Storage rooted at the fortress `state` directory. */
  storage: StorageBackend;
  /**
   * Optional decrypting audit log. When provided, the per-rule counters of
   * the checked checkpoint are recounted from the decrypted entries.
   */
  auditLog?: AuditLog;
}

interface SurvivingEnvelope {
  sequence: number;
  entry_hash: string;
}

/**
 * Cross-check the LATEST provided checkpoint against the live audit log.
 * Earlier checkpoints cover windows that rotation may have pruned; the
 * latest checkpoint is the live tamper/rollback sentinel.
 */
export async function verifyAgainstLog(
  input: VerifyAgainstLogInput
): Promise<AgainstLogResult> {
  const findings: TransparencyFinding[] = [];
  const notes: string[] = [];
  const records = [...input.records].sort((a, b) => a.counter - b.counter);
  const checkpoint = records.at(-1);
  if (!checkpoint) {
    return {
      checked_counter: null,
      merkle_root_recomputed: false,
      counters_recomputed: false,
      findings: [
        {
          kind: "empty_input",
          message: "no checkpoint records to check against the log",
        },
      ],
      notes,
    };
  }

  // Read the surviving envelope metadata (plaintext chain fields).
  let envelopes: SurvivingEnvelope[];
  try {
    envelopes = await readSurvivingEnvelopes(input.storage);
  } catch (err) {
    return {
      checked_counter: checkpoint.counter,
      merkle_root_recomputed: false,
      counters_recomputed: false,
      findings: [
        {
          kind: "log_unavailable",
          counter: checkpoint.counter,
          message: `audit log storage could not be read: ${err instanceof Error ? err.message : String(err)}`,
        },
      ],
      notes,
    };
  }

  const bySequence = new Map<number, string>();
  let liveHighest = 0;
  let liveLowest = Number.MAX_SAFE_INTEGER;
  for (const envelope of envelopes) {
    bySequence.set(envelope.sequence, envelope.entry_hash);
    if (envelope.sequence > liveHighest) liveHighest = envelope.sequence;
    if (envelope.sequence < liveLowest) liveLowest = envelope.sequence;
  }
  if (envelopes.length === 0) liveLowest = 0;

  // Tail truncation / rollback: the live head must be at or past the signed head.
  if (liveHighest < checkpoint.audit.highest_sequence) {
    findings.push({
      kind: "log_head_behind_checkpoint",
      counter: checkpoint.counter,
      expected: `live audit head >= ${checkpoint.audit.highest_sequence}`,
      actual: liveHighest,
      message: `live audit log head (${liveHighest}) is BEHIND checkpoint ${checkpoint.counter}'s signed head (${checkpoint.audit.highest_sequence}): the log was truncated or rolled back after the checkpoint was signed`,
    });
  }

  // Merkle-root recomputation over the covered window.
  let merkleRecomputed = false;
  if (checkpoint.audit.entry_count === 0) {
    notes.push(
      `checkpoint ${checkpoint.counter} covers an empty chain; nothing to recompute`
    );
  } else {
    const lowest = checkpoint.audit.lowest_sequence;
    const highest = checkpoint.audit.highest_sequence;
    // A prefix below the live floor is only LEGITIMATE if it was pruned by an
    // authenticated rotation. Deleting checkpoint-covered entries (e.g. the
    // first covered entry) raises liveLowest identically; without proving the
    // cut, that truncation would masquerade as rotation and the signed root
    // would silently never be recomputed. Reuse the #437 master-key-MAC'd
    // rotation anchor to tell the two apart, and fail closed when we cannot.
    const recomputeFrom = Math.max(lowest, liveLowest);
    if (recomputeFrom > lowest) {
      const floor = await authenticateRotationFloor(input.auditLog, liveLowest);
      if (floor.authenticated) {
        notes.push(
          `checkpoint ${checkpoint.counter} covers sequences ${lowest}..${highest}, but an AUTHENTICATED rotation anchor proves entries below ${liveLowest} were legitimately pruned; the signed Merkle root over the missing prefix cannot be recomputed from the surviving log (NOT a verification pass for the root, but the cut is authentic)`
        );
      } else {
        findings.push({
          kind: "rotation_floor_unauthenticated",
          counter: checkpoint.counter,
          expected: `audit entries from sequence ${lowest} present, or an authenticated rotation anchor with base_sequence ${liveLowest}`,
          actual: liveLowest,
          message: `checkpoint ${checkpoint.counter} covers sequences ${lowest}..${highest}, but the live log starts at ${liveLowest} and the prefix loss is NOT proven by an authenticated rotation anchor (${floor.reason}); a deleted prefix is indistinguishable from rotation here, so the signed Merkle root cannot be trusted as recomputed`,
        });
      }
    } else {
      const hashes: string[] = [];
      let missing: number | null = null;
      for (let sequence = lowest; sequence <= highest; sequence++) {
        const hash = bySequence.get(sequence);
        if (!hash) {
          missing = sequence;
          break;
        }
        hashes.push(hash);
      }
      if (missing !== null) {
        findings.push({
          kind: "log_entry_missing",
          counter: checkpoint.counter,
          actual: missing,
          message: `audit entry at sequence ${missing} is missing from the live log inside checkpoint ${checkpoint.counter}'s covered window ${lowest}..${highest} (in-window deletion)`,
        });
      } else {
        const recomputedRoot = computeAuditRoot(hashes);
        if (recomputedRoot !== checkpoint.audit.merkle_root) {
          findings.push({
            kind: "merkle_root_mismatch",
            counter: checkpoint.counter,
            expected: checkpoint.audit.merkle_root,
            actual: recomputedRoot,
            message: `recomputed Merkle root over live sequences ${lowest}..${highest} does not match checkpoint ${checkpoint.counter}'s signed root (log content was altered)`,
          });
        } else {
          merkleRecomputed = true;
        }
        const liveHead = bySequence.get(highest);
        if (liveHead && liveHead !== checkpoint.audit.head_hash) {
          findings.push({
            kind: "head_hash_mismatch",
            counter: checkpoint.counter,
            expected: checkpoint.audit.head_hash,
            actual: liveHead,
            message: `live entry hash at sequence ${highest} does not match checkpoint ${checkpoint.counter}'s signed head hash`,
          });
        }
      }
    }
  }

  // Optional counter recount (requires decryption).
  let countersRecomputed = false;
  if (input.auditLog) {
    try {
      const chain = await input.auditLog.verifiedChainView();
      const covered = chain.filter(
        (item) =>
          item.sequence >= checkpoint.audit.lowest_sequence &&
          item.sequence <= checkpoint.audit.highest_sequence
      );
      if (
        covered.length !== checkpoint.audit.entry_count &&
        checkpoint.audit.entry_count > 0
      ) {
        notes.push(
          `only ${covered.length} of ${checkpoint.audit.entry_count} covered entries survive (rotation); counters recounted over the surviving subset would not be comparable, so the recount was skipped`
        );
      } else {
        const recount = recountEnforcement(
          checkpoint.fortress_id,
          covered.map((item) => item.entry)
        );
        const mismatch = diffEnforcement(recount, checkpoint.enforcement);
        if (mismatch) {
          findings.push({
            kind: "counters_mismatch",
            counter: checkpoint.counter,
            message: `recounted enforcement counters do not match checkpoint ${checkpoint.counter}'s signed counters: ${mismatch}`,
          });
        } else {
          countersRecomputed = true;
        }
      }
    } catch (err) {
      findings.push({
        kind: "log_unavailable",
        counter: checkpoint.counter,
        message: `counter recount failed (audit log could not be decrypted/verified): ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  } else {
    notes.push(
      "counters not recounted: no decryption key provided (pass the fortress passphrase to recount per-rule counters)"
    );
  }

  return {
    checked_counter: checkpoint.counter,
    merkle_root_recomputed: merkleRecomputed,
    counters_recomputed: countersRecomputed,
    findings,
    notes,
  };
}

/**
 * Decide whether a pruned prefix (live log starts above the checkpoint's
 * lowest covered sequence) is a LEGITIMATE rotation or an unauthenticated
 * truncation. Authentic only when an `AuditLog` is available (the master key
 * is needed to verify the anchor MAC) AND its authenticated rotation anchor
 * names exactly `liveLowest` as the base of the surviving chain.
 *
 *   - no auditLog (no passphrase) → the anchor MAC cannot be checked at all,
 *     so the cut is unauthenticatable → fail closed.
 *   - anchor "absent" → a never-rotated log has no anchor; the prefix loss is
 *     therefore NOT rotation → fail closed.
 *   - anchor "invalid" → tampered / wrong key → fail closed.
 *   - anchor "valid" but base_sequence != liveLowest → the authenticated cut
 *     does not match the live floor (head truncated or entry reintroduced) →
 *     fail closed.
 */
async function authenticateRotationFloor(
  auditLog: AuditLog | undefined,
  liveLowest: number
): Promise<{ authenticated: true } | { authenticated: false; reason: string }> {
  if (!auditLog) {
    return {
      authenticated: false,
      reason:
        "no decryption key provided, so the master-key-MAC'd rotation anchor cannot be authenticated (pass the fortress passphrase)",
    };
  }
  let floor: Awaited<ReturnType<AuditLog["authenticatedRotationFloor"]>>;
  try {
    floor = await auditLog.authenticatedRotationFloor();
  } catch (err) {
    return {
      authenticated: false,
      reason: `rotation anchor could not be read: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  if (floor.status === "absent") {
    return {
      authenticated: false,
      reason: "no rotation anchor exists (the log was never rotation-pruned)",
    };
  }
  if (floor.status === "invalid") {
    return {
      authenticated: false,
      reason: "the rotation anchor failed authentication (tampered or wrong key)",
    };
  }
  if (floor.base_sequence !== liveLowest) {
    return {
      authenticated: false,
      reason: `the authenticated rotation anchor base_sequence ${floor.base_sequence} does not match the live floor ${liveLowest}`,
    };
  }
  return { authenticated: true };
}

async function readSurvivingEnvelopes(
  storage: StorageBackend
): Promise<SurvivingEnvelope[]> {
  const metas = await storage.list(AUDIT_NAMESPACE, "entry-");
  const envelopes: SurvivingEnvelope[] = [];
  for (const meta of metas) {
    const raw = await storage.read(AUDIT_NAMESPACE, meta.key);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(bytesToString(raw)) as {
        schema_version?: unknown;
        sequence?: unknown;
        entry_hash?: unknown;
      };
      if (
        parsed.schema_version === 2 &&
        typeof parsed.sequence === "number" &&
        Number.isSafeInteger(parsed.sequence) &&
        parsed.sequence > 0 &&
        typeof parsed.entry_hash === "string"
      ) {
        envelopes.push({
          sequence: parsed.sequence,
          entry_hash: parsed.entry_hash,
        });
      }
    } catch {
      // Malformed envelopes are reported by the audit layer's own
      // verification; here they simply do not contribute a surviving hash,
      // which surfaces as log_entry_missing / merkle_root_mismatch above.
    }
  }
  return envelopes;
}

function recountEnforcement(
  fortressId: string,
  entries: ReadonlyArray<{
    operation: string;
    details?: Record<string, unknown>;
  }>
): {
  total_allowed: number;
  total_blocked: number;
  rules: Map<string, { allowed: number; blocked: number }>;
} {
  let totalAllowed = 0;
  let totalBlocked = 0;
  const rules = new Map<string, { allowed: number; blocked: number }>();
  for (const entry of entries) {
    const kind =
      entry.operation === "egress_allowed"
        ? "allowed"
        : entry.operation === "egress_blocked"
          ? "blocked"
          : null;
    if (!kind) continue;
    if (kind === "allowed") totalAllowed++;
    else totalBlocked++;
    const ruleId = entry.details?.rule_id;
    if (typeof ruleId !== "string" || ruleId.length === 0) continue;
    const label = transparencyRuleLabel(fortressId, ruleId);
    const bucket = rules.get(label) ?? { allowed: 0, blocked: 0 };
    bucket[kind]++;
    rules.set(label, bucket);
  }
  return { total_allowed: totalAllowed, total_blocked: totalBlocked, rules };
}

function diffEnforcement(
  recount: {
    total_allowed: number;
    total_blocked: number;
    rules: Map<string, { allowed: number; blocked: number }>;
  },
  signed: {
    total_allowed: number;
    total_blocked: number;
    rules: Array<{ rule_label: string; allowed: number; blocked: number }>;
  }
): string | null {
  if (recount.total_allowed !== signed.total_allowed) {
    return `total_allowed recounted ${recount.total_allowed}, signed ${signed.total_allowed}`;
  }
  if (recount.total_blocked !== signed.total_blocked) {
    return `total_blocked recounted ${recount.total_blocked}, signed ${signed.total_blocked}`;
  }
  if (recount.rules.size !== signed.rules.length) {
    return `rule-label count recounted ${recount.rules.size}, signed ${signed.rules.length}`;
  }
  for (const rule of signed.rules) {
    const counted = recount.rules.get(rule.rule_label);
    if (!counted) {
      return `signed rule label ${rule.rule_label.slice(0, 12)}… not present in recount`;
    }
    if (counted.allowed !== rule.allowed || counted.blocked !== rule.blocked) {
      return `rule label ${rule.rule_label.slice(0, 12)}… recounted allowed=${counted.allowed}/blocked=${counted.blocked}, signed allowed=${rule.allowed}/blocked=${rule.blocked}`;
    }
  }
  return null;
}
