/**
 * Internal signing-domain prefixes.
 *
 * Payloads Sanctuary signs with a managed identity key for an INTERNAL
 * protocol purpose are domain-separated by prefixes like these, so a
 * signature over one artifact can never be replayed as another. This file
 * holds the SDW export domains (their only declaration) and mirrors the
 * identity-verified domains declared at their producers (pinned by
 * must-match comments); see the scope note on
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
 * State-store envelope signing domain PREFIX (must match
 * `STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX` in cognitive/state-store.ts; every
 * versioned envelope domain starts with it). Envelopes are signed with the
 * writer's managed identity key.
 */
export const STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX = "sanctuary.state-envelope.v";

/**
 * Managed-identity audit-event, internal-receipt and audit-checkpoint signing
 * domains (must match AUDIT_EVENT_SIGNING_DOMAIN / INTERNAL_RECEIPT_SIGNING_DOMAIN
 * in cognitive/tools.ts and AUDIT_CHECKPOINT_DOMAIN_PREFIX in
 * audit/checkpoint-shape.ts, verified at audit/chain.ts checkpointSigningBytes).
 */
export const AUDIT_EVENT_SIGNING_DOMAIN_PREFIX = "sanctuary.audit.v1";
export const INTERNAL_RECEIPT_SIGNING_DOMAIN_PREFIX = "sanctuary.receipt.v1";
export const AUDIT_CHECKPOINT_SIGNING_DOMAIN_PREFIX = "sanctuary.audit-checkpoint.v1\n";

/**
 * Prefixes the raw `identity_sign` surface refuses: the domains enumerated
 * in this change, each one verified somewhere in the tree against a managed
 * identity key (the SDW export manifest, state-store envelopes, audit events,
 * internal receipts and audit checkpoints). Other identity-signed domains
 * exist and are tracked separately (operator-signed v1, sign-challenge,
 * bridge, reputation, memory-attest, exit-lineage); they are not yet on this
 * list. Hash-only domains (the SDW record-hash and scope-digest domains) and
 * master-MAC domains (state export bundle, audit anchors, custody journals,
 * federation records) are not listed: an identity signature cannot satisfy
 * them. Adding a domain here is how a future artifact joins the refusal.
 */
export const INTERNAL_SIGNING_DOMAIN_PREFIXES: readonly string[] = [
  SDW_EXPORT_MANIFEST_SIGNING_DOMAIN,
  STATE_ENVELOPE_SIGNING_DOMAIN_PREFIX,
  AUDIT_EVENT_SIGNING_DOMAIN_PREFIX,
  INTERNAL_RECEIPT_SIGNING_DOMAIN_PREFIX,
  AUDIT_CHECKPOINT_SIGNING_DOMAIN_PREFIX,
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
