// Must match the label prepareRoleIdentity writes in provision.ts.
export const ROLE_IDENTITY_LABEL_PREFIX = "k1-role:";
export const ROLE_IDENTITY_REFUSED = "K1_ROLE_IDENTITY_REFUSED";
/**
 * New-admission check for every operator identity path (identity_create, identity_import, sanctuary_bootstrap and the
 * CLI identity create). It is never called from load, so identities already stored load exactly as before. Callers run
 * it before any key generation, storage write or audit append, so a refusal leaves no record asserting success.
 */
export function assertAdmissibleIdentityLabel(label: unknown): void {
  // The prefix is reserved for dedicated role identities, so no operator admission path can mint a look-alike label.
  if (typeof label === "string" && label.startsWith(ROLE_IDENTITY_LABEL_PREFIX)) throw new Error(ROLE_IDENTITY_REFUSED);
}
