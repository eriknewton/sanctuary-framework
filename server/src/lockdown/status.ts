import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

export interface LockdownStatus {
  active: boolean;
  activated_at: string | null;
  reason?: string;
}

const LOCKDOWN_STATUS_PATH = "lockdown/status.json";

export function inactiveLockdownStatus(): LockdownStatus {
  return { active: false, activated_at: null };
}

export function lockdownStatusPath(storagePath: string): string {
  return join(storagePath, LOCKDOWN_STATUS_PATH);
}

export async function readLockdownStatus(
  storagePath: string | undefined,
): Promise<LockdownStatus> {
  if (!storagePath) return inactiveLockdownStatus();
  try {
    const parsed = JSON.parse(
      await readFile(lockdownStatusPath(storagePath), "utf-8"),
    ) as Partial<LockdownStatus>;
    if (parsed.active !== true || typeof parsed.activated_at !== "string") {
      return inactiveLockdownStatus();
    }
    return {
      active: true,
      activated_at: parsed.activated_at,
      ...(typeof parsed.reason === "string" ? { reason: parsed.reason } : {}),
    };
  } catch {
    return inactiveLockdownStatus();
  }
}

export async function writeLockdownStatus(
  storagePath: string,
  status: LockdownStatus,
): Promise<void> {
  const path = lockdownStatusPath(storagePath);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(status, null, 2) + "\n", {
    mode: 0o600,
  });
}

export function lockdownBanner(status: LockdownStatus): string {
  if (!status.active) return "";
  const since = status.activated_at ?? "unknown";
  return `Fortress lockdown status is ACTIVE (since ${since}). CLI status only; writes are not blocked by this flag.\n`;
}
