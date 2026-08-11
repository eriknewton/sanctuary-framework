/**
 * Sanctuary MCP Server -- Content-Derived, Domain-Separated Record Ids
 *
 * LD6 BP-DEADLINE-03 (Admission_Completion_Design_Brief_2026-08-11.md, V2-3):
 * the bridge (`_bridge`) and reputation (`_reputation`) stores both used a
 * random-per-call id (`bridge-${Date.now()}-${rand}` / `att-${Date.now()}-
 * ${rand}`), so a caller that timed out waiting for admission had no safe key
 * to retry: re-issuing the SAME logical operation minted a SECOND record and
 * doubled quota. This module derives a stable id from the operation's own
 * identifying fields, so a retry of the SAME logical operation always
 * resolves to the SAME key -- turning a timeout into "retry the same key"
 * instead of "produce a duplicate."
 *
 * This id ALONE is not a trust boundary: a match must still pass intent
 * verification (recompute + signature + tuple equality) at the call site
 * before it is honored as `already_committed` -- see bridge/tools.ts's
 * `BridgeStore` existence guard and reputation/reputation-store.ts's
 * `ReputationStore.record()` existence guard, both of which call
 * `deriveContentId` with the same tag/tuple this module documents.
 */

import { hash } from "./hashing.js";
import { toBase64url, concatBytes, stringToBytes } from "./encoding.js";

/**
 * 4-byte big-endian length prefix, then `field`'s UTF-8 bytes. Explicit
 * length-prefix framing (never a delimiter join) is a canonicalization
 * defense: without it, two DIFFERENT tuples could serialize to the SAME
 * byte string by shifting a delimiter across a field boundary (e.g.
 * `["ab", "c"]` joined with "|" collides with `["a", "bc"]`). Binding each
 * field's own byte length ahead of its content makes that repartitioning
 * impossible -- the only tuple that produces a given framed byte string is
 * the one it was built from.
 *
 * 4 bytes (not a variable-length encoding) because every field this module
 * frames (DIDs, hashes, session/interaction ids, context labels) is far
 * short of 2^32 bytes, and a fixed-width prefix keeps the framing simple and
 * trivially reversible for debugging without a variable-length decoder.
 */
function lengthPrefixed(field: string): Uint8Array {
  const fieldBytes = stringToBytes(field);
  const lengthBytes = new Uint8Array(4);
  new DataView(lengthBytes.buffer).setUint32(0, fieldBytes.length, false);
  return concatBytes(lengthBytes, fieldBytes);
}

/**
 * Derive a content-derived, domain-separated id:
 *
 *   `<prefix>-` + base64url_nopad( SHA-256( LP(domainTag) || LP(f1) || ... ) )
 *
 * `domainTag` is a versioned ASCII label and is ALWAYS the first
 * length-prefixed field, ahead of every tuple field -- so the digest spaces
 * of two different stores (or two different tuple shapes within one store)
 * are disjoint even if the REST of their tuples happened to coincide. This
 * is the domain separation the pre-fix random ids never needed (a random id
 * cannot collide across stores by construction) and that a naive
 * `hash(tuple)` without a tag would be missing.
 *
 * The trailing digest is 43 base64url (no padding) characters: SHA-256
 * produces a 32-byte (256-bit) digest, and base64 encodes 6 bits per
 * character, so 256 bits needs ceil(256 / 6) = 43 characters with the final
 * partial group left unpadded (32 * 8 = 256 bits is not a multiple of 24,
 * so no trailing `=` padding survives base64url's no-padding form).
 */
export function deriveContentId(
  prefix: string,
  domainTag: string,
  fields: readonly string[]
): string {
  const framed = concatBytes(
    lengthPrefixed(domainTag),
    ...fields.map(lengthPrefixed)
  );
  const digest = hash(framed);
  return `${prefix}-${toBase64url(digest)}`;
}
