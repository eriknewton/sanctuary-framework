/**
 * Sanctuary Composition v1.0 -- Verascore Auto-Publish Hook
 *
 * Auto-publish reputation signal on commitment close.
 * Default scope = operator-private. Public publish requires explicit
 * per-commitment opt-in via a distinct API path.
 *
 * A commitment-close event with no opt-in MUST NOT produce a public publish.
 * This is enforced structurally: the hook checks `requestedScope` and throws
 * ScopeViolationError if "public" is attempted without `explicitPublicOptIn: true`.
 *
 * No cross-operator Verascore publish at v1.0.
 *
 * ESCALATION: if the Verascore API endpoint for scoped-private-publish does not
 * exist, this hook logs the intended publish locally (signal stored in-memory)
 * and surfaces the gap as a Verascore repo follow-up ticket.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "../core/random.js";
import { SIDECAR_SIGNATURE_SCHEME } from "./constants.js";
import { ScopeViolationError, VerascorePublishError } from "./errors.js";
import type { ConcordiaReceipt, VerascoreSignal, CompositionConfig } from "./types.js";
import type { VerascoreScope } from "./constants.js";

/**
 * In-memory store for published Verascore signals.
 * v1.0: signals are stored locally; the actual Verascore API integration
 * is a follow-up (see escalation clause in spawn prompt).
 */
const publishedSignals: VerascoreSignal[] = [];

/** Generate a 128-bit hex signal ID. */
function generateSignalId(): string {
  const bytes = randomBytes(16);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

export interface VerascorePublishOptions {
  /** The Concordia receipt triggering the auto-publish. */
  receipt: ConcordiaReceipt;
  /** Fortress ID. */
  fortressId: string;
  /** Requested scope. Defaults to config default (private). */
  requestedScope?: VerascoreScope;
  /** Explicit public opt-in. REQUIRED for public publish. */
  explicitPublicOptIn?: boolean;
  /** Ed25519 private key for signing the signal. */
  signingKey: Uint8Array;
}

/**
 * Publish a Verascore reputation signal for a commitment close event.
 *
 * @deprecated for production use as of WP-MVP-10 Follow-up #2a.
 *
 * Production callers should use `CompositionService.emitForCommitment()`
 * (canonical) or `CompositionService.publishVerascoreSignal()` (which defaults
 * the signingKey to the HKDF-derived sidecar signing key when omitted). This
 * free function still accepts an explicit signing key for test fixtures and
 * migration paths, and remains importable, but new production code should
 * route through the class method so the HKDF-anchoring is preserved by
 * default.
 *
 * @param config Composition config (for default scope)
 * @param options Publish options
 * @returns The published VerascoreSignal
 * @throws ScopeViolationError if public publish attempted without opt-in
 * @throws VerascorePublishError on publish failure
 */
export function publishVerascoreSignal(
  config: CompositionConfig,
  options: VerascorePublishOptions
): VerascoreSignal {
  const { receipt, fortressId, signingKey } = options;
  const requestedScope = options.requestedScope ?? config.verascore_default_scope;

  // Enforce: public publish requires explicit opt-in
  if (requestedScope === "public" && !options.explicitPublicOptIn) {
    throw new ScopeViolationError("public", "private");
  }

  const signal: VerascoreSignal = {
    signal_id: generateSignalId(),
    source_receipt_id: receipt.receipt_id,
    agent_id: receipt.agent_id,
    fortress_id: fortressId,
    signal_type: "commitment_close",
    scope: requestedScope,
    signature: "", // Signed below
    signature_scheme: SIDECAR_SIGNATURE_SCHEME,
    published_at: new Date().toISOString(),
    behavioral_metrics: {
      commitment_class: receipt.commitment_class,
      counterparty_count: 1, // v1.0: 1-to-1 commitments only
      references_count: receipt.references.length,
    },
  };

  // Sign the signal using the node's Ed25519 key.
  // Signature is over the canonical form of the signal (minus signature field).
  try {
    const signableData = { ...signal, signature: undefined };
    const canonical = JSON.stringify(signableData, Object.keys(signableData).sort());
    const signatureBytes = ed25519.sign(
      new TextEncoder().encode(canonical),
      signingKey
    );
    // Convert to base64url
    let base64 = Buffer.from(signatureBytes).toString("base64");
    base64 = base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    signal.signature = base64;
  } catch (err) {
    throw new VerascorePublishError(
      err instanceof Error ? err.message : "Signing failed",
      signal.signal_id
    );
  }

  // v1.0: store locally. Actual Verascore API call is a follow-up.
  // Per escalation clause: ship the hook in a degraded state that logs
  // the intended publish locally.
  publishedSignals.push(signal);

  return signal;
}

/**
 * Get all published signals (for testing and local inspection).
 */
export function getPublishedSignals(): readonly VerascoreSignal[] {
  return publishedSignals;
}

/**
 * Clear published signals. Test-only.
 */
export function clearPublishedSignals(): void {
  publishedSignals.length = 0;
}

/**
 * Get the count of published signals by scope.
 */
export function getPublishedSignalCount(scope?: VerascoreScope): number {
  if (scope) {
    return publishedSignals.filter((s) => s.scope === scope).length;
  }
  return publishedSignals.length;
}
