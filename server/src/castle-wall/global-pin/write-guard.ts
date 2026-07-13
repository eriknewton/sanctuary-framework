import { readFile } from "node:fs/promises";

/**
 * The single enforced chokepoint for the global-pin immutability invariant:
 *
 *   "Once a global trust-anchor pin exists, only `sanctuary castle-wall re-pin`
 *    may migrate it. No other writer overwrites an existing, differing pin - at
 *    ANY euid."
 *
 * Two writers must route through here (the RE-PIN migrator `helper-signer.ts
 * installPin()` deliberately does NOT - re-pin is the sanctioned migrator):
 *   1. `writeGlobalPinnedPublicKey` in `cli/castle-wall.ts` (provision-pin).
 *   2. the non-helper (local/dev-sign) branch of `writeSystemPinnedPublicKey`
 *      in `castle-wall/runtime/macos-daemon.ts`.
 *
 * Both previously inferred "someone else owns this file" from a write FAILURE
 * (an EACCES/EPERM that only fires for a non-root caller), so a root-euid run
 * sailed straight through and clobbered a differing signer-owned pin. The
 * invariant is instead enforced by READING the existing pin and comparing bytes
 * BEFORE any write, which is euid-independent.
 */

/**
 * Outcome of a guarded global-pin write:
 *   - "written":    no pin existed; the caller's fresh write established it.
 *   - "idempotent": a pin existed and already equals the incoming key; no write.
 *   - "refused":    a DIFFERING pin exists, or it is present-but-unreadable, or
 *                   the fresh write lost a create race (EEXIST). Never clobbered.
 */
export type GlobalPinWriteOutcome = "written" | "idempotent" | "refused";

export interface WriteGlobalPinOptions {
  /** Absolute path to the global pin file. */
  path: string;
  /**
   * Perform the caller-specific fresh write of `publicKey` to `path`. Invoked
   * ONLY when no pin currently exists at `path` (read returned ENOENT). The
   * caller owns its own write mechanism (exclusive-create `writeFile` for the
   * CLI, `writeFileCustody` rename-over for the daemon) and its own error
   * diagnostics for anything other than a lost EEXIST race, which the guard
   * intercepts below.
   */
  freshWrite: (path: string, publicKey: Uint8Array) => Promise<void>;
  /**
   * Emitted once when the write is REFUSED so the caller can print its own
   * operator guidance (e.g. "run 'sanctuary castle-wall re-pin'"). The guard
   * itself prints nothing; refusal messaging is caller-owned.
   */
  onRefuse?: () => void;
  /**
   * Injectable reader (tests). Defaults to `node:fs/promises` readFile. A test
   * passes a reader that throws a non-ENOENT error to exercise the fail-closed
   * "present-but-unreadable" branch deterministically at any euid (a real
   * `chmod 000` file is still readable by root, so it cannot cover that branch
   * on a root CI runner).
   */
  readExisting?: (path: string) => Promise<Buffer>;
}

function errnoCode(error: unknown): string | undefined {
  return error instanceof Error && "code" in error
    ? (error as NodeJS.ErrnoException).code
    : undefined;
}

/**
 * Enforce the global-pin immutability invariant, then perform the caller's
 * fresh write only if no pin is established. See {@link WriteGlobalPinOptions}.
 *
 * Decision order:
 *   1. read the existing pin (injectable):
 *        - success + bytes equal  -> "idempotent" (no write, no onRefuse)
 *        - success + bytes differ -> onRefuse(); "refused"
 *        - read error ENOENT      -> fall through to the fresh write
 *        - read error (non-ENOENT)-> onRefuse(); "refused"  (fail CLOSED)
 *   2. fresh write:
 *        - resolves               -> "written"
 *        - throws EEXIST          -> onRefuse(); "refused"  (lost create race)
 *        - throws anything else   -> rethrow (caller emits its own diagnostic)
 *
 * Never overwrites an existing, differing pin. Never throws on a refusal.
 */
export async function writeGlobalPinIfUnestablished(
  publicKey: Uint8Array,
  options: WriteGlobalPinOptions,
): Promise<GlobalPinWriteOutcome> {
  const { path, freshWrite, onRefuse } = options;
  const readExisting = options.readExisting ?? ((p: string) => readFile(p));

  let existing: Buffer | undefined;
  try {
    existing = await readExisting(path);
  } catch (readError) {
    if (errnoCode(readError) !== "ENOENT") {
      // Present but unreadable for a reason other than absence (e.g. EACCES
      // reading a root-owned file as an operator-UID caller). We cannot prove
      // it is safe to write, so fail CLOSED: never attempt the write.
      onRefuse?.();
      return "refused";
    }
    // ENOENT: no pin established. Fall through to the fresh write.
  }

  if (existing !== undefined) {
    // Public key: a straightforward byte compare is correct; no timing safety
    // is needed.
    if (existing.equals(Buffer.from(publicKey))) {
      return "idempotent";
    }
    onRefuse?.();
    return "refused";
  }

  try {
    await freshWrite(path, publicKey);
    return "written";
  } catch (writeError) {
    if (errnoCode(writeError) === "EEXIST") {
      // Lost the read-then-write race: something (e.g. the signer helper)
      // established the pin between our read and this write. Treat it exactly
      // like a pre-existing pin - refuse, never clobber.
      onRefuse?.();
      return "refused";
    }
    // Any other fresh-write error (dir absent = ENOENT, dir not writable =
    // EACCES/EPERM, etc.) carries caller-specific operator guidance; surface it
    // to the caller's own catch rather than laundering it into a refusal.
    throw writeError;
  }
}
