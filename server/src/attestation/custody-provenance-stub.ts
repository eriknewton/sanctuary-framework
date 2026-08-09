/**
 * Sanctuary Attestation UX v1.0 -- Custody Provenance Stub (Layer 4)
 *
 * v1.0 stub for the v1.x Key 17 external-protocol surface
 * (x402, ERC-8004, AP2). Emits the badge-state-shape but the
 * adapter hook is a no-op.
 *
 * v1.x migration path:
 * - When Key 17 sovereign-signer adapter ships, remove the `v1_0_stub`
 *   field from the return shape.
 * - Populate `state` from real custody chain analysis via the adapter:
 *   - x402: check signing key origin (Coinbase custodial vs operator Ed25519)
 *   - ERC-8004: verify registry pointer resolves to operator-controlled identity
 *   - AP2: trace mandate hash to operator-signed delegation chain
 * - Populate `adapter_result` with signing key fingerprint, custody chain,
 *   mandate hash, and protocol-specific verification details.
 * - Receipt `references[]` slot already reserved; rendering activates with
 *   no schema migration.
 *
 * Design brief: Review/Sanctuary/Attestation_UX_Design_Brief_2026-04-21.md section 3 Layer 4
 * Key 17: Review/Sanctuary/x402_Sovereign_Signer_Note_for_Ideation_Thread_2026-04-21.md
 */

import { SIGNATURE_SCHEME_V1 } from "./constants.js";
import type { CustodyProvenanceStub } from "./types.js";

// -----------------------------------------------------------------------
// Stub store (v1.0: minimal tracking of requested tx_ids)
// -----------------------------------------------------------------------

const stubStore = new Map<string, CustodyProvenanceStub>();

// -----------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------

/**
 * Get custody provenance for a transaction ID.
 *
 * v1.0: returns a stub shape marked `v1_0_stub: true`.
 * The adapter hook is a no-op; state is always "unknown_custody".
 */
export function getCustodyProvenance(tx_id: string): CustodyProvenanceStub {
  const existing = stubStore.get(tx_id);
  if (existing) {
    return existing;
  }

  // Create and store the stub
  const stub: CustodyProvenanceStub = {
    tx_id,
    v1_0_stub: true,
    // The v1 stub always says unknown custody; without the adapter it must never claim sovereign provenance.
    state: "unknown_custody",
    signature_scheme: SIGNATURE_SCHEME_V1,
    checked_at: new Date().toISOString(),
    adapter_result: {} as Record<string, never>,
    receipt_reference_slot: "custody_provenance",
  };
  stubStore.set(tx_id, stub);
  return stub;
}

/**
 * Check if a custody provenance stub exists for a transaction.
 */
export function hasCustodyProvenance(tx_id: string): boolean {
  return stubStore.has(tx_id);
}

/**
 * Clear stub store. Test-only.
 */
export function clearCustodyProvenanceStore(): void {
  stubStore.clear();
}
