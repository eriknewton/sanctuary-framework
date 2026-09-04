import { platform } from "node:os";

/**
 * Directory-fsync capability failures tolerated on supported Darwin/Linux
 * filesystems. These codes mean the opened directory descriptor cannot be
 * synced by that filesystem. Permission, descriptor, path, and I/O failures
 * are NOT benign and must propagate so durability is never falsely reported.
 */
const BENIGN_DIRECTORY_FSYNC_CODES = new Set([
  "EINVAL",
  "ENOTSUP",
  "EOPNOTSUPP",
]);

export function isBenignDirectoryFsyncError(
  error: unknown,
  host: NodeJS.Platform = platform(),
): boolean {
  const code =
    error instanceof Error && "code" in error
      ? String((error as NodeJS.ErrnoException).code)
      : "";
  // Windows commonly rejects opening/syncing a directory descriptor itself
  // with EISDIR/EPERM even though the preceding file fsync + atomic rename
  // succeeded. This is a platform capability limit, not permission to swallow
  // those codes on Darwin/Linux where they indicate a real durability failure.
  return BENIGN_DIRECTORY_FSYNC_CODES.has(code) ||
    (host === "win32" && (code === "EISDIR" || code === "EPERM"));
}
