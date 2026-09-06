/**
 * Shared shape contract for the persistent custody-lock scaffold. The file is
 * inert (the Unix socket is the ownership primitive), but it is also the
 * advisory-lock target used by the stale-socket reaper. Only the historical
 * 0644 mode may be repaired in place; every other mismatch is ambiguous and
 * must fail closed.
 */

export interface CustodyLockScaffoldStats {
  uid: number;
  mode: number;
  nlink: number;
  size: number;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}

export type CustodyLockScaffoldShape = "secure" | "legacy-0644" | "unsafe";

export function classifyCustodyLockScaffold(
  stats: CustodyLockScaffoldStats,
  ownerUid: number,
): CustodyLockScaffoldShape {
  if (
    stats.isSymbolicLink() ||
    !stats.isFile() ||
    stats.nlink !== 1 ||
    stats.size !== 0 ||
    stats.uid !== ownerUid
  ) {
    return "unsafe";
  }
  const mode = stats.mode & 0o777;
  if (mode === 0o600) return "secure";
  if (mode === 0o644) return "legacy-0644";
  return "unsafe";
}
