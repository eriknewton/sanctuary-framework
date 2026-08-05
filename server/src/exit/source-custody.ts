/**
 * The ONE shape-check for a bundle's `source_custody` block.
 *
 * Two callers need the identical rule and must never drift:
 *
 *  - the import path (`bundle.ts` `resolveSourceMasterKey`), which REFUSES a
 *    malformed block with `SOURCE_CUSTODY_MALFORMED` rather than demoting the
 *    import to the legacy derivation path (a downgrade);
 *  - the verifier (`verifier.ts` `summarizeEncryptedState`), which CLASSIFIES
 *    the block so `sanctuary exit inspect` can name the credential that opens
 *    the bundle.
 *
 * They lived apart once, and the verifier's copy was "is it object-shaped?".
 * A signed-but-malformed bundle therefore inspected as `bundle-rekey-key`,
 * printed the re-key import command, and exited 0, while the import it named
 * refused the block outright. An affordance that confidently names an unusable
 * credential is worse than no affordance, because the operator trusts it while
 * leaving and the source fortress may already be gone. One predicate, two
 * callers, no second copy of the rules to fall behind.
 *
 * Fix round 2: "is it object-shaped?" became "is the BLOCK shaped right?",
 * which was the same bug one level down. A block whose wrap payload was
 * malformed (`payload: null`, a missing `iv`, a ciphertext of the wrong length)
 * still classified `valid`, still printed `credential: bundle-rekey-key`, still
 * exited 0, and still could not be imported by any key. The predicate now
 * descends into the wrap payload and checks EVERY field the unwrap path reads.
 *
 * THE BOUND, stated rather than papered over: this file holds no credential, so
 * it decides exactly one question - "could ANY key open this?" - and never
 * "will YOUR key open this?". A structurally perfect wrap whose ciphertext does
 * not authenticate is indistinguishable from a good one here; only AES-GCM
 * inside the import can tell them apart. `exit inspect` prints that limit in
 * its own output (`credential check:` line, see `inspect.ts`
 * `credentialCheckBound`) so the operator is never told more than was checked.
 *
 * This file lives outside `bundle.ts` because `bundle.ts` imports
 * `verifier.ts`; putting the predicate in `bundle.ts` would make the verifier's
 * import of it a cycle. Its ONLY import is the base64url decoder, because the
 * decoded byte lengths are the whole content of the encoding checks and reusing
 * the decoder the unwrap path itself uses is the point.
 */

import { fromBase64url } from "../core/encoding.js";

/** The only `source_custody.format` token that has ever been minted. */
export const SOURCE_CUSTODY_FORMAT = "SANCTUARY_EXIT_SOURCE_CUSTODY_V1";

/**
 * The wrap payload constants, each pinned to the code that consumes it.
 *
 * CONTRACT PIN (server/src/core/encryption.ts `decrypt`): `decrypt` rejects any
 * `payload.v !== 1` and any `payload.alg !== "aes-256-gcm"` outright, before it
 * touches the key. These two literals must match the ones it compares against.
 */
const ENCRYPTED_PAYLOAD_VERSION = 1;
const ENCRYPTED_PAYLOAD_ALG = "aes-256-gcm";

/**
 * Smallest nonce the AES-GCM construction in `@noble/ciphers` will accept;
 * anything shorter throws `aes/gcm: invalid nonce length` before authentication
 * is even attempted. Measured against the installed version, not assumed.
 *
 * Deliberately a FLOOR and not `=== 12`: Sanctuary's own `generateIV` always
 * emits 12 bytes, but `@noble/ciphers` accepts any nonce of 8 bytes or more, so
 * a wrap carrying a longer nonce could still authenticate and import. Rejecting
 * it here would make inspect report `unusable` for a bundle that opens, which
 * is the same disagreement as the bug this file exists to close, mirrored.
 */
const AES_GCM_MIN_IV_BYTES = 8;

/**
 * Exact decoded length of a recovery-key wrap's ciphertext.
 *
 * 48 = 32 (the fortress master, the only plaintext a custody wrap ever carries;
 * must match `assertMaster` in server/src/core/master-custody.ts) + 16 (the
 * AES-GCM tag, which `@noble/ciphers` appends to the ciphertext).
 *
 * Any other length is an import failure no credential can rescue: below 16 the
 * GCM construction refuses the ciphertext for being shorter than the tag, and
 * at any other length the best case is a plaintext that is not 32 bytes, which
 * `deriveNamespaceKey` (server/src/core/key-derivation.ts) throws on for every
 * entry, ending in the all-entries-failed `SOURCE_KEY_MISMATCH` refusal.
 */
const MASTER_KEY_BYTES = 32;
const AES_GCM_TAG_BYTES = 16;
const CUSTODY_WRAP_CT_BYTES = MASTER_KEY_BYTES + AES_GCM_TAG_BYTES;

/**
 * Maximum wraps accepted in a bundle's source_custody block. Export emits
 * exactly one; the cap bounds work on crafted bundles (codex round-1 LOW).
 */
export const SOURCE_CUSTODY_MAX_WRAPS = 4;

/**
 * Three-state read of the block, mirroring how import treats it:
 * `absent` (no block: import takes a different path entirely), `valid` (the
 * bundle re-key path is live), `malformed` (import refuses).
 */
export type SourceCustodyState = "absent" | "valid" | "malformed";

/**
 * True when a wrap's `payload` is one that the unwrap path could decrypt if the
 * caller held the right key.
 *
 * CONTRACT PIN (server/src/core/master-custody.ts `unwrapMatchingWrap` ->
 * server/src/core/encryption.ts `decrypt`): this checks EVERY field those two
 * functions read for a recovery-key wrap, and nothing else. Walking the consumer
 * rather than the declared `EncryptedPayload` interface is the whole method:
 * `ts` is on that interface and `decrypt` never reads it, so requiring `ts` here
 * would make inspect condemn a bundle that imports fine. If a future field is
 * added to the unwrap path, it belongs here in the same commit.
 *
 * Every rejection below is a refusal no credential can lift, which is what makes
 * it safe to share this predicate with the import gate: a bundle that fails here
 * could never have completed an import, so tightening the check cannot turn a
 * working import into a failing one, only an opaque failure into a named one.
 */
function isOpenableRecoveryWrapPayload(candidate: unknown): boolean {
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    Array.isArray(candidate)
  ) {
    // `typeof null === "object"`: the round-2 predicate's exact hole. A null
    // payload reached `decrypt`, threw on `payload.v`, and was swallowed by the
    // per-wrap catch, so import reported a credential failure for a shape bug.
    return false;
  }
  const payload = candidate as {
    v?: unknown;
    alg?: unknown;
    iv?: unknown;
    ct?: unknown;
  };
  // Strict equality, matching `decrypt`'s own `!==` comparisons: the string
  // "1" is a different value there, not a coercible one.
  if (payload.v !== ENCRYPTED_PAYLOAD_VERSION) return false;
  if (payload.alg !== ENCRYPTED_PAYLOAD_ALG) return false;
  // A non-string here makes `fromBase64url` throw on `.replace`, which the
  // unwrap loop swallows; the type check is what turns that into a diagnosis.
  if (typeof payload.iv !== "string") return false;
  if (typeof payload.ct !== "string") return false;
  // `fromBase64url` is LENIENT (it drops out-of-alphabet characters instead of
  // throwing), so a garbage string is not detectable as a string - the decoded
  // byte count is the only observable, and it is the one the AES-GCM
  // construction and the master-key width actually constrain.
  if (fromBase64url(payload.iv).length < AES_GCM_MIN_IV_BYTES) return false;
  if (fromBase64url(payload.ct).length !== CUSTODY_WRAP_CT_BYTES) return false;
  return true;
}

/**
 * True when `candidate` is a `source_custody` block the import path will
 * accept. Total over `unknown`: a crafted, truncated, or null block returns
 * false rather than throwing.
 *
 * The `recovery-key`-only wrap restriction is a security rule, not a schema
 * nicety: a passphrase-type wrap here would reintroduce the offline passphrase
 * oracle and feed bundle-controlled Argon2id parameters into the unwrap path
 * (codex round-1 findings 1 and 2). The HKDF unwrap for recovery-key wraps
 * carries no attacker-tunable cost parameters.
 *
 * NOT checked, deliberately: duplicate wrap ids. `unwrapMatchingWrap` tries
 * wraps in order and returns on the first that authenticates, so a duplicate id
 * does not stop an import; refusing it here would make inspect report `unusable`
 * for a bundle that opens. Same for `verified` and `created_at`, which the
 * unwrap path never reads. The rule is that this predicate mirrors the CONSUMER,
 * not the declared type.
 */
export function isValidSourceCustody(candidate: unknown): boolean {
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    Array.isArray(candidate)
  ) {
    return false;
  }
  const custody = candidate as { format?: unknown; wraps?: unknown };
  if (custody.format !== SOURCE_CUSTODY_FORMAT) return false;
  if (!Array.isArray(custody.wraps)) return false;
  if (custody.wraps.length === 0) return false;
  if (custody.wraps.length > SOURCE_CUSTODY_MAX_WRAPS) return false;
  return custody.wraps.every((wrap: unknown) => {
    if (wrap === null || typeof wrap !== "object" || Array.isArray(wrap)) {
      return false;
    }
    const candidateWrap = wrap as {
      id?: unknown;
      type?: unknown;
      payload?: unknown;
    };
    // `id` is bound into the wrap's AEAD AAD by `custodyAad`, so a non-string
    // id cannot round-trip to the AAD the export authenticated under.
    return (
      typeof candidateWrap.id === "string" &&
      candidateWrap.type === "recovery-key" &&
      isOpenableRecoveryWrapPayload(candidateWrap.payload)
    );
  });
}

/**
 * Classify a bundle's `source_custody` field. `undefined` means the artifact
 * carried no block at all; anything else (including `null`) is run through
 * {@link isValidSourceCustody}, exactly as the import path does.
 */
export function readSourceCustodyState(candidate: unknown): SourceCustodyState {
  if (candidate === undefined) return "absent";
  return isValidSourceCustody(candidate) ? "valid" : "malformed";
}
