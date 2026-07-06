/**
 * Distinguish a TRANSIENT storage-read error (a benign IO hiccup worth retrying)
 * from a durable one, for fail-closed enforcement paths that must not launder a
 * one-off EIO/EAGAIN into an authoritative "corrupt -> drop the paid fleet"
 * verdict (a self-inflicted availability DoS).
 *
 * CONTRACT NOTE: {@link StorageBackend.read} returns `null` for a genuinely
 * ABSENT entry (ENOENT is mapped to null by every backend), so a THROW out of
 * `read` is never "not found" - it is an actual IO failure. This helper reads the
 * `code` of such a throw and classifies the well-known kernel-level transient
 * codes as retryable. Anything else (or an error with no code) is treated as
 * NON-transient, i.e. the caller must fall through to its tamper/fail-closed
 * branch - we only ever WIDEN availability for the codes we are confident are
 * transient, never narrow security.
 */

/** Kernel/libuv error codes that denote a transient, retryable IO condition. */
const TRANSIENT_IO_CODES = new Set<string>([
  "EAGAIN", // resource temporarily unavailable
  "EBUSY", // resource busy
  "EMFILE", // too many open files (process fd table full)
  "ENFILE", // too many open files (system-wide)
  "EIO", // low-level input/output error
  "ETIMEDOUT", // operation timed out
  "EINTR", // interrupted system call
  "ENOMEM", // transient memory pressure
]);

/**
 * Return the transient error code when `err` is a recognized transient IO error,
 * or `null` when it is not (in which case the caller keeps its fail-closed
 * behavior). NEVER throws.
 */
export function readTransientError(err: unknown): string | null {
  if (err instanceof Error && "code" in err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (typeof code === "string" && TRANSIENT_IO_CODES.has(code)) return code;
  }
  return null;
}
