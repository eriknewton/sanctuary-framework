/**
 * Public surface of the global-pin immutability chokepoint.
 *
 * It has exactly ONE remaining caller, and that caller is NOT a production
 * path: the dev/test local-sign daemon in `runtime/macos-daemon.ts`
 * (`writeSystemPinnedPublicKey`, reached only under
 * SANCTUARY_CASTLE_LOCAL_SIGN=1 / `localSign: true`). Production signing goes
 * through the root signer helper, and the machine-wide anchor has exactly one
 * writer: the helper's `installPin()`, reached only through the confirmed
 * `castle-wall re-pin` verb, which deliberately does NOT route through here.
 *
 * `provision-pin` used to be the other caller. It was removed (2026-09-09): an
 * operator-uid exclusive-create of a FORTRESS-LOCAL key at the machine-wide
 * path contradicts the definition of the trust anchor (machine-wide pin ==
 * signer-helper key), so on a fresh host it wrote a key re-pin then had to
 * overwrite, and on an already-armed host it refused, failing default init on
 * every such machine. Do not add a caller back.
 */

export {
  globalPinAuthenticates,
  writeGlobalPinIfUnestablished,
  type GlobalPinWriteOutcome,
  type WriteGlobalPinOptions,
} from "./write-guard.js";
