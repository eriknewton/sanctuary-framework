import { constants } from "node:fs";
import { lstat, open, readdir, rm, unlink } from "node:fs/promises";
import { join } from "node:path";
import { isBenignDirectoryFsyncError } from "./directory-fsync.js";
import { classifyCustodyLockScaffold } from "./custody-lock-scaffold.js";

/**
 * The single filesystem definition of a fresh fortress after a kernel custody
 * lock has materialized its persistent inode. A killed init may additionally
 * leave the empty private policy directory scaffold created before its first
 * durable write; no file other than the zero-byte lock is inert.
 */
export async function isFreshFortressOrExactLockScaffold(
  root: string,
  custodyLockFileName: string,
  ignoredRootEntry?: string | readonly string[],
): Promise<boolean> {
  const ignoredRootEntries = new Set(
    ignoredRootEntry === undefined
      ? []
      : typeof ignoredRootEntry === "string"
        ? [ignoredRootEntry]
        : ignoredRootEntry,
  );
  const allowedDirectories = new Set([
    "state",
    "state/_meta",
    "policy",
    "policy/egress",
    "policy/egress/rules",
  ]);
  const allowedLock = `state/_meta/${custodyLockFileName}`;
  const resetHistoryQuarantine = /^\.reset-history\.log\.quarantine\.\d{13}\.[a-f0-9]{16}$/u;
  const walk = async (dir: string, relative: string): Promise<boolean> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const nextRelative = relative ? `${relative}/${entry.name}` : entry.name;
      if (relative === "" && ignoredRootEntries.has(entry.name)) continue;
      if (nextRelative === ".reset-history.log" && entry.isFile()) {
        const stats = await lstat(join(dir, entry.name));
        if (
          !stats.isFile() ||
          stats.isSymbolicLink() ||
          stats.nlink !== 1 ||
          stats.size > 1024 * 1024 ||
          (stats.mode & 0o077) !== 0
        ) return false;
        continue;
      }
      if (relative === "" && resetHistoryQuarantine.test(entry.name)) {
        const stats = await lstat(join(dir, entry.name));
        const uid = process.getuid?.();
        // A quarantined symlink is forensic inert data: never follow it, but do
        // not let its preserved directory entry wedge the fresh init produced
        // by the reset that quarantined it. Regular quarantines remain tightly
        // bounded and owner-only.
        if (stats.isSymbolicLink()) continue;
        if (
          !stats.isFile() ||
          stats.nlink !== 1 ||
          stats.size > 1024 * 1024 + 1 ||
          (stats.mode & 0o077) !== 0 ||
          (uid !== undefined && stats.uid !== uid)
        ) return false;
        continue;
      }
      if (nextRelative === allowedLock && entry.isFile()) {
        const stats = await lstat(join(dir, entry.name));
        const uid = process.getuid?.();
        if (
          uid === undefined ||
          classifyCustodyLockScaffold(stats, uid) === "unsafe"
        ) return false;
        continue;
      }
      if (entry.isDirectory() && allowedDirectories.has(nextRelative)) {
        if (nextRelative.startsWith("policy")) {
          const stats = await lstat(join(dir, entry.name));
          const uid = process.getuid?.();
          if (
            uid === undefined ||
            stats.isSymbolicLink() ||
            !stats.isDirectory() ||
            stats.uid !== uid ||
            (stats.mode & 0o077) !== 0
          ) return false;
        }
        if (!(await walk(join(dir, entry.name), nextRelative))) return false;
        continue;
      }
      return false;
    }
    return true;
  };
  try {
    return await walk(root, "");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw error;
  }
}

const RECOVERY_RESIDUE_MAX_BYTES = 16 * 1024;
const RECOVERY_FILE_NAME = "recovery-key.txt";
const RECOVERY_STAGE_PREFIX = `.${RECOVERY_FILE_NAME}.sanctuary-recovery-stage-`;

export function isRecoveryKeyStageFileName(name: string): boolean {
  return name.startsWith(RECOVERY_STAGE_PREFIX) &&
    /^\d+-[a-f0-9]{24}$/u.test(name.slice(RECOVERY_STAGE_PREFIX.length));
}

function assertRecoveryResidueContent(raw: Buffer): void {
  const text = raw.toString("utf8");
  const lines = text.split("\n");
  let cursor = 0;
  const header = lines[cursor++];
  const generated = lines[cursor++];
  if (lines[cursor]?.startsWith("Fortress: ")) cursor += 1;
  const blankBeforeKey = lines[cursor++];
  const label = lines[cursor++];
  const key = lines[cursor++];
  const blankAfterKey = lines[cursor++];
  const expectedTail = [
    "This file was created on first init. Sanctuary will NOT regenerate this file on",
    "subsequent runs and will NOT display the key again. After moving this file off",
    "the host (encrypted backup, password manager, paper safe), delete it from the",
    "fortress directory. Do NOT keep it in the fortress; the recovery key bypasses",
    "the fortress passphrase by design.",
    "",
  ];
  if (
    header !== "SANCTUARY RECOVERY KEY, DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY." ||
    !/^Generated: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(generated ?? "") ||
    blankBeforeKey !== "" ||
    label !== "Recovery key:" ||
    !/^[A-Za-z0-9_-]{43}$/u.test(key ?? "") ||
    Buffer.from(key!, "base64url").length !== 32 ||
    Buffer.from(key!, "base64url").toString("base64url") !== key ||
    blankAfterKey !== "" ||
    JSON.stringify(lines.slice(cursor)) !== JSON.stringify(expectedTail)
  ) {
    throw new Error("recovery-key.txt crash residue has unexpected content");
  }
}

/**
 * Remove only the exact plaintext recovery output left by a crashed fresh init.
 * The caller must hold the custody lock and pass an inode-bound `root`.
 */
export async function cleanupFreshInitRecoveryResidue(
  root: string,
  custodyLockFileName: string,
  ownerUid: number,
): Promise<boolean> {
  const rootEntries = await readdir(root);
  const stageNames = rootEntries.filter((name) =>
    isRecoveryKeyStageFileName(name),
  );
  if (stageNames.length > 1) {
    throw new Error("multiple recovery-key staging residues; refusing automatic cleanup");
  }
  const candidateNames = [
    ...(rootEntries.includes(RECOVERY_FILE_NAME) ? [RECOVERY_FILE_NAME] : []),
    ...stageNames,
  ];
  if (candidateNames.length === 0) return false;
  if (!(await isFreshFortressOrExactLockScaffold(root, custodyLockFileName, candidateNames))) {
    throw new Error("recovery-key output is not the sole fresh-init crash residue");
  }

  const candidates: Array<{ name: string; dev: number | bigint; ino: number | bigint }> = [];
  for (const name of candidateNames) {
    const path = join(root, name);
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    let raw: Buffer | undefined;
    try {
      const held = await handle.stat();
      if (
        !held.isFile() ||
        held.uid !== ownerUid ||
        (held.mode & 0o777) !== 0o600 ||
        held.size <= 0 ||
        held.size > RECOVERY_RESIDUE_MAX_BYTES ||
        held.nlink < 1 ||
        held.nlink > 2
      ) {
        throw new Error("unsafe recovery-key output crash residue; refusing automatic cleanup");
      }
      raw = await handle.readFile();
      assertRecoveryResidueContent(raw);
      candidates.push({ name, dev: held.dev, ino: held.ino });
    } finally {
      raw?.fill(0);
      await handle.close();
    }
  }
  if (
    candidates.length === 2 &&
    (candidates[0]!.dev !== candidates[1]!.dev || candidates[0]!.ino !== candidates[1]!.ino)
  ) {
    throw new Error("recovery-key final and staging residues are not the same inode");
  }

  // No rename/quarantine window: immediately before each unlink, prove the
  // pathname still names the authenticated inode. Sync after every removal so
  // a power cut leaves an idempotently recognizable remaining alias or nothing.
  for (const candidate of candidates) {
    const path = join(root, candidate.name);
    const current = await lstat(path);
    if (
      current.isSymbolicLink() ||
      !current.isFile() ||
      current.dev !== candidate.dev ||
      current.ino !== candidate.ino
    ) {
      throw new Error("recovery-key output identity changed during residue cleanup");
    }
    await unlink(path);
    await syncDirectory(root);
  }
  return true;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } catch (error) {
    if (!isBenignDirectoryFsyncError(error)) throw error;
  } finally {
    await handle.close();
  }
}

async function removeEntryWithoutFollowing(path: string): Promise<void> {
  const entry = await lstat(path);
  if (entry.isSymbolicLink() || !entry.isDirectory()) {
    await unlink(path);
    return;
  }
  await rm(path, { recursive: true });
}

/**
 * Roll a failed non-force init back to the only inert state accepted by the
 * fresh-fortress predicate. `root` must itself be an inode-bound capability
 * (`/proc/self/fd/<n>` on Linux or a Darwin worker cwd). Every intermediate
 * component is lstat-checked before traversal, and symlinks are unlinked rather
 * than followed.
 */
export async function restoreFreshFortressLockScaffold(
  root: string,
  custodyLockFileName: string,
): Promise<void> {
  const statePath = join(root, "state");
  const metaPath = join(statePath, "_meta");
  for (const [path, label] of [
    [statePath, "state"],
    [metaPath, "state/_meta"],
  ] as const) {
    const stats = await lstat(path);
    if (stats.isSymbolicLink() || !stats.isDirectory()) {
      throw new Error(`fresh-init rollback refused unsafe ${label} directory`);
    }
  }
  const lockPath = join(metaPath, custodyLockFileName);
  const lock = await lstat(lockPath);
  const uid = process.getuid?.();
  if (
    uid === undefined ||
    classifyCustodyLockScaffold(lock, uid) !== "secure"
  ) {
    throw new Error("fresh-init rollback refused changed custody lock scaffold");
  }

  for (const entry of await readdir(root)) {
    if (
      entry === "state" ||
      entry === ".reset-history.log" ||
      /^\.reset-history\.log\.quarantine\.\d{13}\.[a-f0-9]{16}$/u.test(entry)
    ) continue;
    await removeEntryWithoutFollowing(join(root, entry));
  }
  for (const entry of await readdir(statePath)) {
    if (entry === "_meta") continue;
    await removeEntryWithoutFollowing(join(statePath, entry));
  }
  for (const entry of await readdir(metaPath)) {
    if (entry === custodyLockFileName) continue;
    await removeEntryWithoutFollowing(join(metaPath, entry));
  }
  await syncDirectory(metaPath);
  await syncDirectory(statePath);
  await syncDirectory(root);
}
