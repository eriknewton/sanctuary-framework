/**
 * Castle Wall F1 — boot token (the anti-brick half of the split credential)
 *
 * Option C (hybrid split-credential, ratified 2026-06-10) separates the two
 * things F1 used to conflate into one secret:
 *
 *   1. The BOOT TOKEN (this module) — a small, software-protected, random
 *      per-machine value. It is NOT the fortress passphrase and NOT the
 *      master key. Its only job is to let the launchd boot service come up in
 *      SAFE MODE before any user login: enforce the persisted last-valid
 *      signed manifest (the system extension recovers + verifies that against
 *      the pinned PUBLIC key with no secret at all), classify every other flow
 *      `.agent` and deny, keep SSH / operator endpoints reachable, and record
 *      its own bring-up in a boot-token-keyed audit segment. So even a
 *      complete compromise of the boot token cannot decrypt fortress state,
 *      forge a policy (signing stays with the pinned key the token never
 *      holds), or unlock full operation.
 *
 *   2. The OPERATIONAL SECRET (out of this module) — the high-value
 *      fortress/master key. It stays in the login Keychain today and is the
 *      target for Secure-Enclave binding in the host app (see the boot-service
 *      doc). It is NEVER present in the pre-login boot context; full operation
 *      waits for first login, when the operator session unlocks it.
 *
 * Why a software key and not the Secure Enclave: a LaunchDaemon that must run
 * unattended at cold boot, before any login, cannot use the Secure Enclave at
 * all on macOS (SE operations require a user session + the data-protection
 * keychain, neither of which exists pre-login). That is a structural macOS
 * fact, not a missing entitlement. See
 * `Review/Sanctuary/F1_SecureEnclave_Feasibility_2026-06-10.md`. So the boot
 * token is deliberately software-protected; its custody is "root-only on the
 * FileVault-encrypted volume" (not extractable from a powered-off / snapshot
 * disk while FileVault is on; extractable by root or an unlocked-volume
 * snapshot). That is acceptable precisely because the token is low-value — it
 * never holds the secret that matters.
 *
 * Custody: a 32-byte random value, written 0600 and (when provisioned by the
 * root install path) owned by root, in the same root-owned custody directory
 * as the global pinned key. The safe-mode boot daemon runs in the system
 * (root) context, so it can read a root-owned token directly without granting
 * the operator account any new privilege over it.
 */

import { join } from "node:path";

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import { randomBytes } from "../../core/random.js";
import {
  isCustodyFsError,
  readFileCustody,
  writeFileCustody,
} from "../../storage/custody-fs.js";

/** Root-owned custody directory (shared with the global pinned public key). */
export const CASTLE_BOOT_CUSTODY_DIR = "/Library/Application Support/Sanctuary";
export const CASTLE_BOOT_TOKEN_FILENAME = "castle-wall-boot-token.bin";
export const CASTLE_BOOT_TOKEN_PATH = join(
  CASTLE_BOOT_CUSTODY_DIR,
  CASTLE_BOOT_TOKEN_FILENAME,
);

/** A boot token is exactly 32 random bytes. */
export const BOOT_TOKEN_LENGTH = 32;

/**
 * HKDF domain-separation label for the safe-mode audit key. The boot token is
 * never used as a key directly; the audit key is derived from it so the token
 * can be rotated or repurposed without colliding with any other use.
 */
const SAFE_MODE_AUDIT_INFO = "castle-wall-safe-mode-audit-v1";

export interface BootTokenOptions {
  /** Override the token path (tests). Defaults to {@link CASTLE_BOOT_TOKEN_PATH}. */
  path?: string;
  /**
   * Run a binary WITHOUT a shell, for the optional `chown root` step (only the
   * root provision path uses it). Tests inject a fake. When omitted, the chown
   * is skipped and ownership is left to the writing process's uid.
   */
  chownFn?: (cmd: string, args: string[]) => { code: number; stderr: string };
}

/** Generate a fresh 32-byte boot token. */
export function generateBootToken(): Uint8Array {
  return randomBytes(BOOT_TOKEN_LENGTH);
}

/**
 * Persist a boot token to its custody path, 0600. When `chownFn` is supplied
 * (the root provision path), the file is also chowned to root:wheel so it is
 * root-owned regardless of which uid wrote it. Writes atomically (temp +
 * rename) so a concurrent reader never sees a half-written token.
 *
 * Returns the path written.
 */
export async function persistBootToken(
  token: Uint8Array,
  opts: BootTokenOptions = {},
): Promise<string> {
  if (token.length !== BOOT_TOKEN_LENGTH) {
    throw new Error(
      `Boot token must be ${BOOT_TOKEN_LENGTH} bytes (got ${token.length}).`,
    );
  }
  const path = opts.path ?? CASTLE_BOOT_TOKEN_PATH;
  await writeFileCustody(path, Buffer.from(token), {
    mode: 0o600,
    parentMode: 0o755,
    prepareTemp: opts.chownFn
      ? (tempPath) => {
          const result = opts.chownFn!("chown", ["root:wheel", tempPath]);
          if (result.code !== 0) {
            throw new Error(
              `Could not chown the boot token to root:wheel: ${result.stderr.trim()}. ` +
                `Refusing to install a boot token the operator account could rewrite.`,
            );
          }
        }
      : undefined,
  });
  return path;
}

/** Outcome of reading the boot token. */
export type BootTokenReadResult =
  | { status: "ok"; token: Uint8Array }
  | { status: "not-found" }
  | { status: "bad-mode"; mode: number }
  | { status: "bad-length"; length: number };

/**
 * Read the boot token, fail-closed on any custody violation. The token file
 * must exist, be exactly {@link BOOT_TOKEN_LENGTH} bytes, and have no
 * group/other permission bits (mode & 0o077 === 0). A token that is readable
 * by other accounts is treated as compromised and rejected rather than used.
 */
export async function readBootToken(
  opts: BootTokenOptions = {},
): Promise<BootTokenReadResult> {
  const path = opts.path ?? CASTLE_BOOT_TOKEN_PATH;
  let raw: Buffer;
  try {
    raw = await readFileCustody(path, {
      mode: { rejectGroupOrOther: true },
      verifyPathIdentity: true,
    });
  } catch (err) {
    const code =
      err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
    if (code === "ENOENT") return { status: "not-found" };
    if (isCustodyFsError(err) && err.code === "mode_rejected") {
      const mode = typeof err.details.mode === "number" ? err.details.mode : 0;
      return { status: "bad-mode", mode };
    }
    throw err;
  }
  if (raw.length !== BOOT_TOKEN_LENGTH) {
    return { status: "bad-length", length: raw.length };
  }
  return { status: "ok", token: new Uint8Array(raw) };
}

/**
 * Derive the safe-mode audit key from the boot token. This is the ONLY key the
 * safe-mode boot daemon can mint — it lets the daemon record its own boot-time
 * lifecycle (filter_started, agent-deny baseline) in a dedicated audit segment
 * without the fortress master key, which is not present pre-login. The segment
 * is therefore encrypted under a different key than the master-key audit log;
 * the two are read separately by design (see the boot-service doc).
 */
export function deriveSafeModeAuditKey(token: Uint8Array): Uint8Array {
  if (token.length !== BOOT_TOKEN_LENGTH) {
    throw new Error(
      `Boot token must be ${BOOT_TOKEN_LENGTH} bytes (got ${token.length}).`,
    );
  }
  return hkdf(sha256, token, undefined, SAFE_MODE_AUDIT_INFO, 32);
}

/**
 * Storage path for the boot-audit segment, scoped by a fingerprint of the boot
 * token. Each token gets its own segment under `<fortress>/boot-audit/<fp>`, so
 * rotating the boot token starts a fresh segment instead of colliding with
 * entries the previous token's key encrypted (which the new key cannot read).
 * The provision path and the safe-mode daemon both derive the same path from
 * the live token.
 */
export function safeModeAuditStoragePath(
  fortressPath: string,
  token: Uint8Array,
): string {
  if (token.length !== BOOT_TOKEN_LENGTH) {
    throw new Error(
      `Boot token must be ${BOOT_TOKEN_LENGTH} bytes (got ${token.length}).`,
    );
  }
  const fingerprint = Buffer.from(sha256(token)).toString("hex").slice(0, 16);
  return join(fortressPath, "boot-audit", fingerprint);
}
