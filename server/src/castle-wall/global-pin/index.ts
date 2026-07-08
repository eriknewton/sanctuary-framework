/**
 * Public surface of the global-pin immutability chokepoint: the ONE guard both
 * global-pin writers (provision-pin in `cli/castle-wall.ts` and the local-sign
 * daemon in `runtime/macos-daemon.ts`) route through so no path can reintroduce
 * the root-euid clobber fail-open. The sanctioned re-pin migrator
 * (`helper-signer.ts installPin()`) deliberately does NOT route through here.
 */

export {
  writeGlobalPinIfUnestablished,
  type GlobalPinWriteOutcome,
  type WriteGlobalPinOptions,
} from "./write-guard.js";
