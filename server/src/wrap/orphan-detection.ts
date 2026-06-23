/**
 * Sanctuary wrap - custody-factor orphan detection (element 5)
 *
 * Warns the operator BEFORE a lockout, not during one. It compares the factors
 * the live custody envelope expects (read non-secret metadata only) against
 * the factors that actually exist in the OS keyring, and surfaces a warning
 * when they no longer match - e.g. the envelope enrolled an OS-keyring custody
 * key but that keyring item is now gone, so the operator is one missing factor
 * away from being unable to unlock without the recovery key.
 *
 * This is a WARN, never a brick (F3). Boot is never refused on this signal;
 * `doctor` reports it as WARN. The detector reads no key material and unlocks
 * nothing.
 *
 * It deliberately treats "keyring unreachable in this session" (macOS error 36
 * over SSH / no D-Bus on Linux) as inconclusive, NOT as orphaned: we cannot
 * tell whether the item exists when we cannot reach the keyring, and a false
 * "orphaned" alarm on every headless boot would be noise.
 */

import { readEnrolledFactors } from "../core/master-custody.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  probeKeychainCustodyKey,
  probeKeychainRecoveryKey,
  type KeychainCustodyOptions,
} from "./keychain-custody.js";

export type OrphanVerdict = "ok" | "orphaned" | "inconclusive" | "no-factor";

export interface OrphanCheckResult {
  /**
   *  - "ok":           the enrolled keychain factor is present.
   *  - "orphaned":     the envelope enrolled a keychain factor but the keyring
   *                    is reachable and the item is GONE - warn before lockout.
   *  - "inconclusive": a keychain factor is enrolled but the keyring is
   *                    unreachable this session (cannot say; no alarm).
   *  - "no-factor":    no keychain factor is enrolled (nothing to orphan).
   */
  verdict: OrphanVerdict;
  /** Operator-facing message when verdict is "orphaned"; else a short note. */
  message: string;
  /** The keychain custody service name probed (for the operator). */
  custodyService?: string;
  /** Recovery-key escrow status, when probed: present / missing / unreachable. */
  recoveryEscrow?: "found" | "not-found" | "unreachable";
}

/**
 * Detect a custody-factor orphan for a fortress. Pure read-only diagnostic.
 * Never throws on a keyring failure (the probes classify, they do not throw).
 */
export async function detectCustodyFactorOrphan(
  storage: StorageBackend,
  storagePath: string,
  opts: KeychainCustodyOptions = {}
): Promise<OrphanCheckResult> {
  const factors = await readEnrolledFactors(storage);
  if (!factors.hasKeychainFactor) {
    return {
      verdict: "no-factor",
      message: "no OS-keyring custody factor is enrolled on this fortress",
    };
  }

  const custodyProbe = await probeKeychainCustodyKey(storagePath, opts);
  // Probe the recovery escrow too, for the message detail (best-effort).
  let recoveryEscrow: "found" | "not-found" | "unreachable" | undefined;
  try {
    const recoveryProbe = await probeKeychainRecoveryKey(storagePath, opts);
    recoveryEscrow = recoveryProbe.status;
  } catch {
    recoveryEscrow = undefined;
  }

  if (custodyProbe.status === "found") {
    return {
      verdict: "ok",
      message: "enrolled OS-keyring custody factor is present",
      custodyService: custodyProbe.service,
      ...(recoveryEscrow !== undefined ? { recoveryEscrow } : {}),
    };
  }

  if (custodyProbe.status === "unreachable") {
    return {
      verdict: "inconclusive",
      message:
        "OS keyring is locked or unreachable in this session; cannot verify the " +
        "enrolled keychain factor (no alarm raised)",
      custodyService: custodyProbe.service,
      ...(recoveryEscrow !== undefined ? { recoveryEscrow } : {}),
    };
  }

  // status === "not-found": reachable keyring, enrolled item GONE -> orphaned.
  const recoveryHint =
    recoveryEscrow === "not-found"
      ? "\n  Its recovery-key escrow item is ALSO missing from the keyring."
      : recoveryEscrow === "found"
        ? "\n  The recovery-key escrow item is still present in the keyring."
        : "";
  return {
    verdict: "orphaned",
    message:
      "WARNING: this fortress enrolled an OS-keyring custody factor, but that " +
      `keyring item is MISSING (service ${custodyProbe.service}).` +
      recoveryHint +
      "\n  You are one missing factor away from needing the recovery key to unlock." +
      "\n  Confirm your recovery key is saved off-host (password manager), and " +
      "re-enroll the keychain factor by re-running `sanctuary wrap` / `sanctuary init`.",
    custodyService: custodyProbe.service,
    ...(recoveryEscrow !== undefined ? { recoveryEscrow } : {}),
  };
}
