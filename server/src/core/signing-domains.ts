/**
 * Internal signing-domain prefixes.
 *
 * Every payload Sanctuary signs with a managed identity key for an INTERNAL
 * protocol purpose is domain-separated by one of these prefixes, so a
 * signature over one artifact can never be replayed as another. The list is
 * the single source both sides pin on:
 *
 *   - producers (for example `sdw/export.ts`) import their domain constant
 *     from HERE rather than declaring a local literal;
 *   - the operator-facing raw signing surface (`identity_sign` in
 *     `cognitive/tools.ts`) REFUSES any payload that begins with one of these
 *     prefixes, so an agent cannot use the raw signer to mint an artifact an
 *     internal verifier would accept (the triggering shape: a hand-built
 *     `sdw_export_delete` manifest signed through `identity_sign`).
 *
 * Adding a new internally signed artifact means adding its domain here; a
 * structural test asserts `export.ts` declares no local `sanctuary.*\n`
 * signing domain of its own.
 */

/** Hash domain for one exported SDW record's ciphertext envelope. */
export const SDW_EXPORT_RECORD_HASH_DOMAIN = "sanctuary.sdw-export-record-hash.v1\n";
/** Digest domain for the approval-bound export scope. */
export const SDW_EXPORT_SCOPE_DIGEST_DOMAIN = "sanctuary.sdw-export-scope-digest.v1\n";
/** Signing domain for the SDW export manifest (Ed25519 via core/identity.ts). */
export const SDW_EXPORT_MANIFEST_SIGNING_DOMAIN = "sanctuary.sdw-export-manifest.v1\n";

export const INTERNAL_SIGNING_DOMAIN_PREFIXES: readonly string[] = [
  SDW_EXPORT_RECORD_HASH_DOMAIN,
  SDW_EXPORT_SCOPE_DIGEST_DOMAIN,
  SDW_EXPORT_MANIFEST_SIGNING_DOMAIN,
];

const encoder = new TextEncoder();

/**
 * True when `payload` begins with any internal signing-domain prefix (byte
 * comparison, so a base64url-decoded payload and a plain-text payload are
 * judged the same way).
 */
export function startsWithInternalSigningDomain(payload: Uint8Array): boolean {
  for (const prefix of INTERNAL_SIGNING_DOMAIN_PREFIXES) {
    const bytes = encoder.encode(prefix);
    if (payload.length < bytes.length) continue;
    let match = true;
    for (let i = 0; i < bytes.length; i += 1) {
      if (payload[i] !== bytes[i]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}
