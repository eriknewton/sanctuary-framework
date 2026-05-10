/**
 * Sanctuary Attestation UX v1.0 -- Failure-Mode Catalog
 *
 * 9-row catalog per design brief section 6. Every row maps to:
 * (a) detection rule, (b) badge-state result, (c) degrade-or-halt decision,
 * (d) operator-visible explanation key.
 *
 * Structural invariant: degrade_decision is always "degrade".
 * Per spawn prompt hard rule: if any row maps to "halt" or "throw",
 * it is misclassified.
 *
 * Design brief: Review/Sanctuary/Attestation_UX_Design_Brief_2026-04-21.md section 6
 */

import { FAILURE_MODE_CODES, type FailureModeCode } from "./constants.js";
import type { FailureModeEntry } from "./types.js";

/**
 * Runtime guard error thrown if the catalog's structural invariants are
 * violated at module-init. Hardening wave 6, finding #88: previously the
 * invariants were only checked test-time via verifyDegradeNotDestroy(); a
 * future commit could ship a malformed catalog and only fail in CI. This
 * guard fails fast at import-time, before any consumer reads the catalog.
 */
export class FailureCatalogInvariantError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FailureCatalogInvariantError";
  }
}

/**
 * The 9-row failure-mode catalog. Closed enum at v1.0.
 *
 * Every cell is a non-modal experience. The only ceremony that fully claims
 * operator focus is first-time-per-annex approval, and it is a deliberate
 * user-initiated event, not a system-thrown error.
 */
export const FAILURE_MODE_CATALOG: readonly FailureModeEntry[] = [
  {
    code: "tcb_drift_annex",
    name: "Annex TCB drift",
    severity: "warning",
    detection_rule:
      "Annex hash diverges from pinned hash; firmware or binary changed since last attestation",
    badge_result: "yellow",
    degrade_decision: "degrade",
    explanation_key: "failure.tcb_drift_annex",
    affected_layers: ["per_agent", "global"],
    remediation_actions: ["Diagnose annex", "Close gates around agent", "Re-attest annex"],
  },
  {
    code: "binary_signature_revoked",
    name: "Binary signature revoked",
    severity: "warning",
    detection_rule:
      "Upstream binary registry marks current binary signature as revoked or superseded",
    badge_result: "yellow",
    degrade_decision: "degrade",
    explanation_key: "failure.binary_signature_revoked",
    affected_layers: ["per_agent", "global"],
    remediation_actions: ["Continue at own risk", "Update binary", "Close gates"],
  },
  {
    code: "sovereign_node_attestation_fail",
    name: "Sovereign node attestation failure",
    severity: "critical",
    detection_rule:
      "TEE attestation quote fails verification against manufacturer chain, or quote is absent on a sovereign_tee node",
    badge_result: "red",
    degrade_decision: "degrade",
    explanation_key: "failure.sovereign_node_attestation_fail",
    affected_layers: ["per_agent", "global"],
    remediation_actions: [
      "Fail over agents to healthy node",
      "Close all gates",
      "Contact infrastructure provider",
    ],
  },
  {
    code: "canonical_audit_unreachable",
    name: "Canonical audit node unreachable",
    severity: "warning",
    detection_rule:
      "Heartbeat from canonical audit node missing for threshold interval; audit chain cannot be extended",
    badge_result: "yellow",
    degrade_decision: "degrade",
    explanation_key: "failure.canonical_audit_unreachable",
    affected_layers: ["global"],
    remediation_actions: [
      "Receipts queue locally",
      "Wait for reconnect",
      "Promote replica to canonical",
    ],
  },
  {
    code: "policy_sync_lag",
    name: "Policy version sync lag",
    severity: "warning",
    detection_rule:
      "At least one node reports a policy version lower than the latest signed version for more than the distribution deadline",
    badge_result: "yellow",
    degrade_decision: "degrade",
    explanation_key: "failure.policy_sync_lag",
    affected_layers: ["global"],
    remediation_actions: [
      "Each node enforces highest version seen",
      "Inspect sync state",
      "Force policy re-broadcast",
    ],
  },
  {
    code: "annex_approval_pending",
    name: "First-time annex approval pending",
    severity: "informational",
    detection_rule:
      "Agent requests an annex that has not been approved by the operator; calls to that annex blocked",
    badge_result: "local_only",
    degrade_decision: "degrade",
    explanation_key: "failure.annex_approval_pending",
    affected_layers: ["per_agent"],
    remediation_actions: [
      "Approve and remember",
      "Approve once",
      "Do not approve",
    ],
  },
  {
    code: "verifier_disagreement",
    name: "Verifier disagreement (then vs now)",
    severity: "warning",
    detection_rule:
      "Receipt re-verification today produces a different attestation state than the embedded time-of-action state",
    badge_result: "yellow",
    degrade_decision: "degrade",
    explanation_key: "failure.verifier_disagreement",
    affected_layers: ["per_action"],
    remediation_actions: [
      "Receipt remains valid",
      "Investigate change since action time",
      "Re-verify receipt chain",
    ],
  },
  {
    code: "local_only_mode",
    name: "Local-only mode (no TEE claim)",
    severity: "informational",
    detection_rule:
      "Agent runs in pure local mode; identity, policy, and receipt signatures are valid; no external attestation chain claimed",
    badge_result: "local_only",
    degrade_decision: "degrade",
    explanation_key: "failure.local_only_mode",
    affected_layers: ["per_agent", "per_action"],
    remediation_actions: [],
  },
  {
    code: "unsigned_code_path",
    name: "Unknown or unsigned code path",
    severity: "critical",
    detection_rule:
      "Action executed through a code path that cannot be traced to a signed binary release or known harness adapter",
    badge_result: "red",
    degrade_decision: "degrade",
    explanation_key: "failure.unsigned_code_path",
    affected_layers: ["per_action", "per_agent", "global"],
    remediation_actions: [
      "Agent paused",
      "Investigate code path",
      "Close gates",
    ],
  },
] as const;

/**
 * Lookup a failure mode by code. Returns undefined if not found.
 */
export function getFailureMode(
  code: FailureModeCode
): FailureModeEntry | undefined {
  return FAILURE_MODE_CATALOG.find((entry) => entry.code === code);
}

/**
 * Get all failure modes at or above a severity threshold.
 */
export function getFailureModesBySeverity(
  minSeverity: "critical" | "warning" | "informational"
): FailureModeEntry[] {
  const severityOrder = { critical: 0, warning: 1, informational: 2 };
  const threshold = severityOrder[minSeverity];
  return FAILURE_MODE_CATALOG.filter(
    (entry) => severityOrder[entry.severity] <= threshold
  );
}

/**
 * Get all failure modes that affect a specific layer.
 */
export function getFailureModesByLayer(
  layer: "global" | "per_agent" | "per_action"
): FailureModeEntry[] {
  return FAILURE_MODE_CATALOG.filter((entry) =>
    entry.affected_layers.includes(layer)
  );
}

/**
 * Structural assertion: every row's degrade_decision is "degrade".
 * This function exists for test-time verification of the invariant.
 */
export function verifyDegradeNotDestroy(): {
  valid: boolean;
  violations: string[];
} {
  const violations: string[] = [];
  for (const entry of FAILURE_MODE_CATALOG) {
    if (entry.degrade_decision !== "degrade") {
      violations.push(
        `${entry.code}: degrade_decision is "${entry.degrade_decision}" (must be "degrade")`
      );
    }
  }
  return { valid: violations.length === 0, violations };
}

/**
 * Validate every catalog invariant. Returns the full violation list rather
 * than throwing so callers (tests, runtime guard) can choose how to react.
 * Hardening wave 6 finding #88.
 *
 * Invariants:
 *  1. Catalog has exactly the same row-count as FAILURE_MODE_CODES (closed enum).
 *  2. Every row's `code` appears in FAILURE_MODE_CODES.
 *  3. Every code in FAILURE_MODE_CODES appears in the catalog (no missing rows).
 *  4. No duplicate `code` values within the catalog.
 *  5. Every row's `degrade_decision === "degrade"` (degrade-not-destroy).
 *  6. Every row's `affected_layers` is non-empty.
 */
export function verifyFailureCatalogInvariants(): {
  valid: boolean;
  violations: string[];
} {
  const violations: string[] = [];
  const codes = new Set<string>();
  const expected = new Set<string>(FAILURE_MODE_CODES);

  if (FAILURE_MODE_CATALOG.length !== FAILURE_MODE_CODES.length) {
    violations.push(
      `catalog row-count ${FAILURE_MODE_CATALOG.length} does not match closed enum size ${FAILURE_MODE_CODES.length}`
    );
  }

  for (const entry of FAILURE_MODE_CATALOG) {
    if (!expected.has(entry.code)) {
      violations.push(
        `${entry.code}: not present in FAILURE_MODE_CODES closed enum`
      );
    }
    if (codes.has(entry.code)) {
      violations.push(`${entry.code}: duplicate row in catalog`);
    }
    codes.add(entry.code);
    if (entry.degrade_decision !== "degrade") {
      violations.push(
        `${entry.code}: degrade_decision is "${entry.degrade_decision}" (must be "degrade")`
      );
    }
    if (!Array.isArray(entry.affected_layers) || entry.affected_layers.length === 0) {
      violations.push(`${entry.code}: affected_layers must be a non-empty array`);
    }
  }

  for (const code of FAILURE_MODE_CODES) {
    if (!codes.has(code)) {
      violations.push(`${code}: declared in FAILURE_MODE_CODES but missing from catalog`);
    }
  }

  return { valid: violations.length === 0, violations };
}

/**
 * Module-init runtime guard. Throws FailureCatalogInvariantError when the
 * catalog drifts from its closed enum or fails any structural invariant.
 * Hardening wave 6 finding #88.
 */
function assertCatalogInvariantsAtImport(): void {
  const result = verifyFailureCatalogInvariants();
  if (!result.valid) {
    throw new FailureCatalogInvariantError(
      `Failure-mode catalog invariant violation: ${result.violations.join("; ")}`
    );
  }
}

assertCatalogInvariantsAtImport();
