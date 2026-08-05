/**
 * `sanctuary exit inspect` - read-only answer to "what is in this bundle, and
 * which credential does it say it needs?"
 *
 * The question this closes: an operator holding a bundle and a key had no tool
 * that could tell them whether the key was the right KIND of key. The only
 * signal was a failed import, after the source fortress may already be gone.
 *
 * WHAT THIS COMMAND CLAIMS, and what it deliberately does not. Three earlier
 * cuts of this module tried to answer "will your import succeed?" - naming a
 * credential path as usable, or declaring a bundle unopenable. Each was wrong
 * for some bundle, because the answer depends on a secret this process does not
 * have and on code paths it does not run. The claim is now weaker and true by
 * construction: this report describes what the ARTIFACT DECLARES - how many
 * state entries it carries, which re-key blocks are present, and whether those
 * blocks have a usable shape. A runbook can act on "this bundle declares a
 * bundle re-key key and carries 41 state entries" without that sentence being
 * able to be wrong about an import, because it says nothing about one.
 *
 * The one thing it does assert about an import is negative and structural: when
 * a declared block is damaged, the import gate that reads the SAME predicate
 * refuses it. That is a shared-code claim, not a prediction, and the custody
 * differential in server/test/exit/exit-inspect-declares.test.ts holds it by
 * running both sides over the same crafted bundles.
 *
 * READ-ONLY BY CONSTRUCTION: this module never calls `openExitContext`, never
 * asks for a passphrase, never opens a StateStore or an AuditLog, and never
 * writes. It operates solely on the bundle directory, through
 * `verifyExitBundle`, which is itself write-free.
 */

import {
  verifyExitBundle,
  type ExitBundleDeclaredRekeyMaterial,
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
  /** What the artifact DECLARES it needs. Never a claim about an import. */
  declared_rekey_material: ExitBundleDeclaredRekeyMaterial | "unknown";
  /**
   * The command line to TRY for the declared material. Phrased as an attempt
   * rather than a remedy: inspect holds no credential, so it cannot know the
   * attempt will work, and wording that implied otherwise is the exact defect
   * this module has now been rewritten around twice.
   */
  suggested_command: string;
  /**
   * What was and was not checked to produce this report. Its own field, and
   * printed unconditionally by the CLI, so the limit travels with the answer
   * instead of living in a doc-comment nobody reads at 2am.
   */
  credential_bound: string;
  legacy_kdf_params: "absent" | "valid" | "malformed" | "unknown";
  /** Which re-key block is present, and whether it has a usable shape. */
  source_custody: SourceCustodyState | "unknown";
  warnings: string[];
}

/**
 * The import command line to try for each declared material.
 *
 * CONTRACT PIN (server/src/exit/cli.ts `runExitCommand` import branch): these
 * strings name real flags on that branch (`--activate`, `--import-state`,
 * `--source-recovery-key`, `--source-passphrase`, `--legacy-source-master`).
 * A flag renamed there must be renamed here in the same commit, or the
 * inspector prints a command that does not parse.
 */
function suggestedCommand(state: ExitEncryptedStateSummary): string {
  switch (state.declared_rekey_material) {
    case "bundle-rekey-key":
      return (
        "sanctuary exit import <dir> --activate --import-state " +
        "--source-recovery-key <bundle re-key key shown at export>"
      );
    case "legacy-passphrase":
      return (
        "sanctuary exit import <dir> --activate --import-state " +
        "--source-passphrase <source fortress passphrase>"
      );
    case "none-declared":
      return (
        "this bundle declares no re-key material. If it predates envelope " +
        "custody, its source fortress used the recovery key AS the master, and " +
        "that reading must be confirmed explicitly: sanctuary exit import " +
        "<dir> --activate --import-state --source-recovery-key <source " +
        "fortress recovery key> --legacy-source-master"
      );
    case "no-state":
      return "no source credential is declared: this bundle carries zero state entries";
    case "damaged":
      // Two different damaged blocks land here and they have DIFFERENT
      // remedies, so the text must name which one is broken. Entry-list damage
      // is reported first because it is damage to the artifact's own contents,
      // not to a re-key block; custody outranks the legacy marker because the
      // import gate reads custody first.
      if (state.entry_count === null) {
        return (
          "this bundle's state artifact has no readable entries list, so what " +
          "it carries cannot be determined at all. This is not an empty " +
          "bundle. Re-export from the source fortress."
        );
      }
      return state.source_custody === "malformed"
        ? "this bundle's re-key block (source_custody) does not have a usable " +
            "shape. The import gate reads the same check and refuses it " +
            "(SOURCE_CUSTODY_MALFORMED) rather than falling back to legacy key " +
            "derivation. Re-export from the source fortress."
        : "this bundle's only declared re-key material " +
            "(source_key_derivation) does not have a usable shape, so the " +
            "passphrase path cannot run. Re-export from the source fortress. " +
            "If that fortress used a recovery key AS its master, " +
            "--source-recovery-key <key> --legacy-source-master may still " +
            "recover it.";
  }
}

/**
 * What this report was actually checked against, per declared material.
 *
 * Every string here is written to be true without knowing anything about the
 * operator's credential or about the import they will run. Where a secret
 * decides the outcome, the text says so and stops.
 *
 * CONTRACT PIN (server/test/exit/exit-inspect-declares.test.ts): the
 * `credential check:` line is asserted by SUBSTANCE, not by prefix, on both the
 * happy path and the credential-dependent differential row - so the sentence
 * that names AES-GCM as the decider cannot be weakened without a test failing.
 */
function credentialCheckBound(state: ExitEncryptedStateSummary): string {
  switch (state.declared_rekey_material) {
    case "bundle-rekey-key":
      return (
        "declaration and shape only; no credential was held and no import was " +
        "attempted. The wrap type, payload version, algorithm, and " +
        "IV/ciphertext encoding and length are intact for at least one wrap. " +
        "Whether the key you hold authenticates against that wrap is decided " +
        "by AES-GCM inside the import, and inspect does not and cannot answer " +
        "it."
      );
    case "legacy-passphrase":
      return (
        "declaration and shape only; no credential was held and no import was " +
        "attempted. The bundle's legacy derivation parameters are within " +
        "bounds and will run. Whether your passphrase derives the source " +
        "master is decided inside the import."
      );
    case "none-declared":
      return (
        "declaration only; no credential was held and no import was attempted. " +
        "This bundle declares no re-key material, so there is nothing here to " +
        "check a key against. The legacy reading is a guess the operator must " +
        "confirm, and a wrong key surfaces as SOURCE_KEY_MISMATCH during the " +
        "import."
      );
    case "no-state":
      return (
        "read from the artifact: its entry list is readable and empty, so it " +
        "declares no re-key material. No credential was held and no import " +
        "was attempted."
      );
    case "damaged":
      return (
        "read from the artifact: the material named above does not have a " +
        "usable shape, and the import gate applies the same check to the same " +
        "field. No credential was held and no import was attempted."
      );
  }
}

/**
 * Verify a bundle directory and report what it carries plus which credential it
 * declares. Throws `InvalidExitBundleError` (from the verifier) when the
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
    declared_rekey_material: state?.declared_rekey_material ?? "unknown",
    suggested_command:
      state !== undefined
        ? suggestedCommand(state)
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
 * Process exit code for a report: 0 when the bundle verified AND its state
 * artifact is intact enough to describe, 1 otherwise.
 *
 * `damaged` exits non-zero because something in the artifact IS broken and the
 * operator needs a non-zero status to branch on in a script - "the signature is
 * fine" is exactly the answer that stranded them. It is not a claim that their
 * import would have failed for any other reason.
 */
export function inspectExitCode(report: ExitBundleInspectionReport): number {
  if (report.verdict !== "PASS") return 1;
  if (report.declared_rekey_material === "damaged") return 1;
  if (report.declared_rekey_material === "unknown") return 1;
  return 0;
}
