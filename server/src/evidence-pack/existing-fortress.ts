/** Read-only initialization marker predicate shared by the MCP child and evidence export. */
import type { Stats } from "node:fs";
import { lstat, stat } from "node:fs/promises";
import { join } from "node:path";

/** Marker presence admits an existing fortress; custody authentication still belongs to boot. */
export async function initializedFortressExists(
  fortressPath: string,
  followRootSymlink = true,
): Promise<boolean> {
  const fortressStats = await (followRootSymlink ? statOrMissing(fortressPath) : lstatOrMissing(fortressPath));
  if (!fortressStats?.isDirectory()) return false;

  for (const key of Object.values(FORTRESS_INITIALIZATION_KEYS)) {
    const markerStats = await lstatOrMissing(join(fortressPath, FORTRESS_STATE_DIRECTORY, "_meta", `${key}.enc`));
    if (markerStats?.isFile()) return true;
  }
  return false;
}

/** `_meta` key holding the envelope. */
export const CUSTODY_ENVELOPE_KEY = "custody-envelope";
/** Plaintext + purpose label for the custody sentinel. */
export const CUSTODY_SENTINEL_KEY = "custody-sentinel";
export const LEGACY_PASSPHRASE_KEY = "key-params";
export const LEGACY_RECOVERY_KEY = "recovery-key-hash";

// Must match establishMasterUnderBarrier and establishMasterLocked in ../core/master-custody.ts; each key alone denotes existing custody.
export const FORTRESS_INITIALIZATION_KEYS = {
  envelope: CUSTODY_ENVELOPE_KEY,
  sentinel: CUSTODY_SENTINEL_KEY,
  legacyPassphrase: LEGACY_PASSPHRASE_KEY,
  legacyRecovery: LEGACY_RECOVERY_KEY,
} as const;
// Must match createSanctuaryServer in ../index.ts; filesystem custody lives under this root.
export const FORTRESS_STATE_DIRECTORY = "state";

async function statOrMissing(path: string): Promise<Stats | null> {
  try {
    return await stat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw err;
  }
}

async function lstatOrMissing(path: string): Promise<Stats | null> {
  try {
    return await lstat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "ENOENT" || code === "ENOTDIR") return null;
    throw err;
  }
}

