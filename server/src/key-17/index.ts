/**
 * Key 17 -- Cross-protocol sovereign signer surface.
 *
 * Barrel export for all Key 17 signing surfaces. Each surface derives
 * operator-scoped keys from a shared master key via HKDF with protocol-
 * specific tags.
 */

export {
  signX402Request,
  verifyX402Request,
  deriveX402Key,
  type X402Request,
  type SignedX402Request,
} from "./x402-signer.js";
