/** Shared at-rest custody names for boot, credential resolution and filesystem admission. */
/** `_meta` key holding the envelope. */
export const CUSTODY_ENVELOPE_KEY = "custody-envelope";
/** Plaintext + purpose label for the custody sentinel. */
export const CUSTODY_SENTINEL_KEY = "custody-sentinel";
export const LEGACY_PASSPHRASE_KEY = "key-params";
export const LEGACY_RECOVERY_KEY = "recovery-key-hash";

// Must match initializedFortressExists in ../evidence-pack/existing-fortress.ts and establishMasterUnderBarrier and establishMasterLocked in master-custody.ts; each key alone denotes existing custody.
export const FORTRESS_INITIALIZATION_KEYS = {
  envelope: CUSTODY_ENVELOPE_KEY,
  sentinel: CUSTODY_SENTINEL_KEY,
  legacyPassphrase: LEGACY_PASSPHRASE_KEY,
  legacyRecovery: LEGACY_RECOVERY_KEY,
} as const;
// Must match createSanctuaryServer in ../index.ts; filesystem custody lives under this root.
export const FORTRESS_STATE_DIRECTORY = "state";
