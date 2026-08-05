/**
 * `sanctuary exit inspect` - read-only answer to "what is in this bundle, and
 * which credential opens it?"
 *
 * The question this closes: an operator holding a bundle and a key had no tool
 * that could tell them whether the key was the right KIND of key. The only
 * signal was a failed import, after the source fortress may already be gone.
 *
 * READ-ONLY BY CONSTRUCTION: this module never calls `openExitContext`, never
 * asks for a passphrase, never opens a StateStore or an AuditLog, and never
 * writes. It operates solely on the bundle directory, through
 * `verifyExitBundle`, which is itself write-free.
 */

import {
  verifyExitBundle,
  type ExitBundleCredentialPath,
  type ExitBundleDetailedVerifierResult,
  type ExitEncryptedStateSummary,
} from "./verifier.js";
import type { SourceCustodyState } from "./source-custody.js";

export interface ExitBundleInspectionReport {
  verdict: "PASS" | "FAIL";
  failure_class?: string;
  identity_id: string;
  fortress_id: string;
  exported_at: string;
  artifact_count: number;
  /** Absent when the bundle carries no encrypted_state artifact. */
  state?: ExitEncryptedStateSummary;
  credential_path: ExitBundleCredentialPath | "unknown";
  /** The exact command line that imports this bundle's state, if any can. */
  credential_instruction: string;
  /**
   * How far this answer was actually checked. Inspect holds no credential, so
   * on the paths that need one it can only confirm that the bundle's re-key
   * material is well formed, never that a particular secret opens it. Reported
   * as its own field so the limit travels with the answer instead of living in
   * a doc-comment nobody reads at 2am.
   */
  credential_bound: string;
  legacy_kdf_params: "absent" | "valid" | "malformed" | "unknown";
  /** Which re-key block is present, and whether import would accept it. */
  source_custody: SourceCustodyState | "unknown";
  warnings: string[];
}

/**
 * The import command line for each credential path.
 *
 * CONTRACT PIN (server/src/exit/cli.ts `runExitCommand` import branch): these
 * strings name real flags on that branch (`--activate`, `--import-state`,
 * `--source-recovery-key`, `--source-passphrase`, `--legacy-source-master`).
 * A flag renamed there must be renamed here in the same commit, or the
 * inspector prints a command that does not parse.
 */
function credentialInstruction(state: ExitEncryptedStateSummary): string {
  switch (state.credential_path) {
    case "bundle-rekey-key":
      return (
        "sanctuary exit import <dir> --activate --import-state " +
        "--source-recovery-key <bundle re-key key shown at export>"
      );
    case "source-passphrase-legacy":
      return (
        "sanctuary exit import <dir> --activate --import-state " +
        "--source-passphrase <source fortress passphrase>"
      );
    case "legacy-recovery-key-as-master":
      return (
        "sanctuary exit import <dir> --activate --import-state " +
        "--source-recovery-key <source fortress recovery key> " +
        "--legacy-source-master"
      );
    case "none-required":
      return "no source credential required: this bundle carries zero state entries";
    case "unusable":
      // Two different damaged blocks land here and they have DIFFERENT
      // remedies, so the text must name which one is broken. Custody is
      // checked first: a malformed custody block kills the import before it
      // ever looks at the legacy marker, so it dominates the message.
      return state.source_custody === "malformed"
        ? "no usable credential: this bundle's re-key block (source_custody) " +
            "is malformed, so import refuses it (SOURCE_CUSTODY_MALFORMED) " +
            "and will not fall back to legacy key derivation. No key of any " +
            "kind opens this bundle's state. Re-export from the source " +
            "fortress."
        : "no usable credential: this bundle's only declared re-key material " +
            "(source_key_derivation) is malformed, so the passphrase path " +
            "cannot run. Re-export from the source fortress. If that fortress " +
            "used a recovery key AS its master, --source-recovery-key <key> " +
            "--legacy-source-master may still recover it.";
  }
}

/**
 * What the report's answer is worth, per path.
 *
 * The distinction is not cosmetic. `unusable` and `none-required` are decided
 * entirely from the artifact, so inspect is as certain as the import would be.
 * Every other path ends in a cryptographic check against a secret inspect does
 * not have, and the honest report says which half was verified. This is the
 * bound named in server/src/exit/source-custody.ts: the shared predicate
 * answers "could ANY key open this?", never "will YOUR key open this?".
 *
 * CONTRACT PIN (server/test/exit/exit-credential-path.test.ts, the
 * `credential-dependent` row of the custody differential): that case drives a
 * structurally perfect wrap whose ciphertext does not authenticate through both
 * `exit inspect` and a real `importExitBundle`, and asserts inspect still names
 * the re-key path AND prints this line. Reword the `bundle-rekey-key` string
 * and that test fails, which is the point of writing it here.
 */
function credentialCheckBound(state: ExitEncryptedStateSummary): string {
  switch (state.credential_path) {
    case "bundle-rekey-key":
      return (
        "structure only (no credential held): the wrap type, payload version, " +
        "algorithm, and IV/ciphertext encoding and length are everything the " +
        "import checks before it needs a secret, and they are intact. Whether " +
        "the key you hold actually authenticates against this wrap is decided " +
        "by AES-GCM inside the import, and inspect cannot answer it."
      );
    case "source-passphrase-legacy":
      return (
        "structure only (no credential held): the bundle's legacy derivation " +
        "parameters are within bounds and will run. Whether your passphrase " +
        "derives the source master is decided inside the import."
      );
    case "legacy-recovery-key-as-master":
      return (
        "shape only (no credential held): this bundle declares no re-key " +
        "material at all, so there is nothing here to check a key against. " +
        "The legacy interpretation is a guess the operator must confirm, and " +
        "a wrong key surfaces as SOURCE_KEY_MISMATCH during the import."
      );
    case "none-required":
      return "conclusive: there is no encrypted state to re-key.";
    case "unusable":
      return (
        "conclusive: no credential is needed to know this bundle's state " +
        "cannot be re-keyed, because the material the import requires is " +
        "damaged in the artifact itself."
      );
  }
}

/**
 * Verify a bundle directory and report what it carries plus which credential
 * re-keys it. Throws `InvalidExitBundleError` (from the verifier) when the
 * directory is not an exit bundle at all; a bundle that IS one but fails
 * verification returns a report with `verdict: "FAIL"`.
 */
export async function inspectExitBundle(
  bundleDir: string
): Promise<ExitBundleInspectionReport> {
  const result: ExitBundleDetailedVerifierResult =
    await verifyExitBundle(bundleDir);
  const state = result.state;
  return {
    verdict: result.passed ? "PASS" : "FAIL",
    ...(result.failure_class !== undefined
      ? { failure_class: result.failure_class }
      : {}),
    identity_id: result.manifest_summary.identity_id,
    fortress_id: result.manifest_summary.fortress_id,
    exported_at: result.manifest_summary.exported_at,
    artifact_count: result.manifest_summary.artifact_count,
    ...(state !== undefined ? { state } : {}),
    credential_path: state?.credential_path ?? "unknown",
    credential_instruction:
      state !== undefined
        ? credentialInstruction(state)
        : "unknown: this bundle carries no encrypted_state artifact",
    credential_bound:
      state !== undefined
        ? credentialCheckBound(state)
        : "nothing checked: this bundle carries no encrypted_state artifact",
    legacy_kdf_params: state?.legacy_kdf_params ?? "unknown",
    source_custody: state?.source_custody ?? "unknown",
    warnings: result.warnings,
  };
}

/**
 * Process exit code for a report: 0 when the bundle verified AND its state can
 * actually be re-keyed (or needs no credential), 1 otherwise. A verified bundle
 * whose credential path is `unusable` is a FAILURE for this command's purpose -
 * "the signature is fine" is exactly the answer that stranded the operator.
 */
export function inspectExitCode(report: ExitBundleInspectionReport): number {
  if (report.verdict !== "PASS") return 1;
  if (report.credential_path === "unusable") return 1;
  if (report.credential_path === "unknown") return 1;
  return 0;
}
