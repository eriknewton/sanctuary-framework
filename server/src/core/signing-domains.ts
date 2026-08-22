/**
 * Internal signing-domain prefixes.
 *
 * Payloads Sanctuary signs with a managed identity key for an INTERNAL
 * protocol purpose are domain-separated by prefixes like these, so a
 * signature over one artifact can never be replayed as another. This file
 * holds the SDW export domains (their only declaration) and mirrors the
 * state-store and audit/receipt domains (declared at their producers, pinned
 * here by must-match comments); see the SCOPE note on
 * INTERNAL_SIGNING_DOMAIN_PREFIXES. Two sides use it:
 *
 *   - producers (for example `sdw/export.ts`) import their domain constant
 *     from HERE rather than declaring a local literal;
 *   - the operator-facing raw signing surface (`identity_sign` in
 *     `cognitive/tools.ts`) REFUSES any payload that begins with one of these
 *     prefixes, so an agent cannot use the raw signer to mint an artifact an
 *     internal verifier would accept (the triggering shape: a hand-built
 *     `sdw_export_delete` manifest signed through `identity_sign`).
 *
 * Adding a new identity-signed artifact means adding its domain here; a
 * structural test asserts `export.ts` declares no local `sanctuary.*\n`
 * signing domain of its own.
 */

/** Hash domain for one exported SDW record's ciphertext envelope. */
export const SDW_EXPORT_RECORD_HASH_DOMAIN = "sanctuary.sdw-export-record-hash.v1\n";
/** Digest domain for the approval-bound export scope. */
export const SDW_EXPORT_SCOPE_DIGEST_DOMAIN = "sanctuary.sdw-export-scope-digest.v1\n";
/** Signing domain for the SDW export manifest (Ed25519 via core/identity.ts). */
export const SDW_EXPORT_MANIFEST_SIGNING_DOMAIN = "sanctuary.sdw-export-manifest.v1\n";

/**
 * State-store artifacts signed or MAC'd under identity-derived or
 * master-derived keys (must match `STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX`,
 * `LEGACY_STATE_ENVELOPE_SIGNING_DOMAIN` and `STATE_EXPORT_BUNDLE_MAC_DOMAIN`
 * in cognitive/state-store.ts). Listed as PREFIXES: every versioned state
 * envelope domain starts with the first entry.
 */
export const STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX = "sanctuary.state-envelope.v";
export const STATE_EXPORT_BUNDLE_MAC_DOMAIN = "sanctuary.state-export-bundle.v1\n";

/**
 * Managed-identity audit-event and internal-receipt signing domains (must
 * match AUDIT_EVENT_SIGNING_DOMAIN / INTERNAL_RECEIPT_SIGNING_DOMAIN in
 * cognitive/tools.ts, which cannot import this file's consumers).
 */
export const AUDIT_EVENT_SIGNING_DOMAIN_PREFIX = "sanctuary.audit.v1";
export const INTERNAL_RECEIPT_SIGNING_DOMAIN_PREFIX = "sanctuary.receipt.v1";

/**
 * Prefixes the raw `identity_sign` surface refuses. EXACT SCOPE, nothing
 * more: the SDW export domains, the state-store envelope and export-bundle
 * domains, and the managed-identity audit-event and receipt domains. This is
 * NOT a registry of every signing domain in the tree: MAC-only domains keyed
 * under master-derived secrets (audit anchors, custody journals, federation
 * records) are not listed because an identity signature cannot satisfy them,
 * and any future identity-signed artifact must add its domain here.
 */
export const INTERNAL_SIGNING_DOMAIN_PREFIXES: readonly string[] = [
  SDW_EXPORT_RECORD_HASH_DOMAIN,
  SDW_EXPORT_SCOPE_DIGEST_DOMAIN,
  SDW_EXPORT_MANIFEST_SIGNING_DOMAIN,
  STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX,
  STATE_EXPORT_BUNDLE_MAC_DOMAIN,
  AUDIT_EVENT_SIGNING_DOMAIN_PREFIX,
  INTERNAL_RECEIPT_SIGNING_DOMAIN_PREFIX,
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
