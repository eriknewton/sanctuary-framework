import { lstatSync } from "node:fs";

/**
 * Resolve the create-with-fchown owner for fortress-internal files a ROOT
 * daemon creates (fortress-ownership spec 2026-07-30, open question 5):
 * a root daemon that writes into an operator-owned fortress must create
 * files owned by the FORTRESS OWNER, not root, or operator readability of
 * audit artifacts erodes boot over boot. Only a root process needs this
 * (a non-root daemon already creates operator-owned files); a root-owned or
 * unreadable fortress yields `undefined` (no owner to hand files to -- the
 * loud warnings in macos-daemon's `resolveSocketReownUid` cover those states).
 *
 * Lives in its own dependency-light module (not `macos-daemon.ts`) so CLI
 * entry points (castle-wall boot, safe-mode audit wiring) can thread the
 * owner WITHOUT pulling the full daemon module graph (system-resolvers,
 * subprocess helpers) into their runtime imports. `macos-daemon.ts`
 * re-exports it for its existing consumers.
 */
export function resolveFortressCreateOwner(input: {
  fortressPath: string;
  /** Current process uid; defaults to `process.getuid?.()`. Injected by tests. */
  processUid?: number | undefined;
  /** Stat the fortress dir for its owner; defaults to `fs.statSync`. */
  statFortressOwner?: (fortressPath: string) => { uid: number; gid: number };
}): { uid: number; gid: number } | undefined {
  const processUid =
    input.processUid !== undefined ? input.processUid : process.getuid?.();
  if (processUid !== 0) {
    return undefined;
  }
  let owner: { uid: number; gid: number };
  try {
    if (input.statFortressOwner) {
      owner = input.statFortressOwner(input.fortressPath);
    } else {
      // lstat, NOT stat (2026-07-31 re-gate): a SYMLINKED fortress would
      // otherwise report its target's owner, and every create-with-fchown
      // write would then hand files outside the fortress to that uid. A
      // symlinked fortress yields no owner at all, so no chown happens.
      const stats = lstatSync(input.fortressPath);
      if (stats.isSymbolicLink() || !stats.isDirectory()) {
        return undefined;
      }
      owner = { uid: stats.uid, gid: stats.gid };
    }
  } catch {
    return undefined;
  }
  // 2026-07-31 re-gate MED: gid 0 is refused for the same reason uid 0 is.
  // A `501:0` fortress would otherwise have every root-created file chowned
  // to GROUP wheel, which is not the operator's custody domain.
  if (owner.uid === 0 || owner.gid === 0) {
    return undefined;
  }
  return owner;
}
