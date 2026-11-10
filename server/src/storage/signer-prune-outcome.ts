/** Internal evidence carried across journal, cache, audit and lock boundaries. */
// Must match phase transitions in exit/bundle.ts and sdw/memory-provenance-signer-prune.ts,
// and the projection in
// sdw/memory-provenance-signer-prune-tools.ts; error names are not evidence.
export type SignerPrunePhase = "not-started" | "rolled-back" | "uncertain" | "committed";

export interface SignerPruneOutcome {
  phase: SignerPrunePhase;
  cleanup: "not-started" | "pending" | "finished";
  finalization: "not-started" | "pending" | "finished";
  completionAudit: "not-started" | "pending" | "settled" | "failed";
}

export function initialSignerPruneOutcome(): SignerPruneOutcome {
  return {
    phase: "not-started",
    cleanup: "not-started",
    finalization: "not-started",
    completionAudit: "not-started",
  };
}

/** Carries internal causes without granting permission to expose them to a caller. */
export class SignerPruneError extends Error {
  readonly outcome: Readonly<SignerPruneOutcome>;

  constructor(outcome: SignerPruneOutcome, cause: unknown) {
    // Default error rendering must not reveal storage paths, keys or signer data.
    super("signer prune failed", { cause });
    this.name = "SignerPruneError";
    this.outcome = Object.freeze({ ...outcome });
  }
}
