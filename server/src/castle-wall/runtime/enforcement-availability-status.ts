import { chmod, chown, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const CASTLE_WALL_ENFORCEMENT_STATUS_FILENAME =
  "castle-wall-enforcement-status.json";
export const CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE =
  "enforcement_unavailable";
export const CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON =
  "manifest_present_arm_lease_missing";
export const CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE =
  "macos_extension_provider_unbound";
export const CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_REASON =
  "status_present_unreadable";
export const CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_SOURCE =
  "local_status_file";

export interface EnforcementAvailabilityStatusFile {
  state: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE;
  reason: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON;
  updated_at: string;
  source: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE;
  manifest_received: true;
  arm_lease_received: false;
}

export interface EnforcementAvailabilityStatusReadFailure {
  state: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE;
  reason: typeof CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_REASON;
  updated_at: string;
  source: typeof CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_SOURCE;
  manifest_received: null;
  arm_lease_received: null;
  read_error: {
    kind: "read_error" | "invalid_json" | "invalid_schema";
    path: string;
    message: string;
  };
}

export type EnforcementAvailabilityStatus =
  | EnforcementAvailabilityStatusFile
  | EnforcementAvailabilityStatusReadFailure;

export interface EnforcementAvailabilityStatusWriteOptions {
  ownerUid?: number;
  ownerGid?: number;
  forceChown?: boolean;
  getuid?: () => number | undefined;
  chownFn?: (path: string, uid: number, gid: number) => Promise<void>;
  chmodFn?: (path: string, mode: number) => Promise<void>;
  writeFileFn?: typeof writeFile;
  statFn?: typeof stat;
}

export function enforcementAvailabilityStatusPath(fortressPath: string): string {
  return join(fortressPath, CASTLE_WALL_ENFORCEMENT_STATUS_FILENAME);
}

export function isEnforcementUnavailableProviderUnboundDetails(
  details: unknown,
): details is { manifest_received: true; arm_lease_received: false } {
  return (
    typeof details === "object" &&
    details !== null &&
    !Array.isArray(details) &&
    (details as Record<string, unknown>).manifest_received === true &&
    (details as Record<string, unknown>).arm_lease_received === false
  );
}

export function buildEnforcementUnavailableStatusFile(
  updatedAt: string,
): EnforcementAvailabilityStatusFile {
  return {
    state: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE,
    reason: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON,
    updated_at: updatedAt,
    source: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE,
    manifest_received: true,
    arm_lease_received: false,
  };
}

export async function writeEnforcementAvailabilityStatusBestEffort(
  fortressPath: string,
  status: EnforcementAvailabilityStatusFile,
  options: EnforcementAvailabilityStatusWriteOptions = {},
): Promise<boolean> {
  try {
    const parsed = parseEnforcementAvailabilityStatus(status);
    if (parsed === null) return false;
    const path = enforcementAvailabilityStatusPath(fortressPath);
    const writeFileFn = options.writeFileFn ?? writeFile;
    const chmodFn = options.chmodFn ?? chmod;
    const chownFn = options.chownFn ?? chown;
    const statFn = options.statFn ?? stat;
    await writeFileFn(path, JSON.stringify(parsed, null, 2) + "\n", {
      mode: 0o600,
    });
    const owner =
      options.ownerUid !== undefined
        ? {
            uid: options.ownerUid,
            gid: options.ownerGid ?? -1,
          }
        : await statFn(fortressPath)
            .then((s) => ({ uid: s.uid, gid: s.gid }))
            .catch(() => null);
    const currentUid = (options.getuid ?? (() => process.getuid?.()))();
    if (
      owner !== null &&
      owner.uid >= 0 &&
      (options.forceChown === true || currentUid === 0)
    ) {
      await chownFn(path, owner.uid, owner.gid);
    }
    await chmodFn(path, 0o600);
    return true;
  } catch {
    return false;
  }
}

export async function readEnforcementAvailabilityStatus(
  fortressPath: string,
): Promise<EnforcementAvailabilityStatus | null> {
  const path = enforcementAvailabilityStatusPath(fortressPath);
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (error) {
    if (isNodeErrorCode(error, "ENOENT")) return null;
    return buildEnforcementAvailabilityStatusReadFailure(path, "read_error", error);
  }

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch (error) {
    return buildEnforcementAvailabilityStatusReadFailure(path, "invalid_json", error);
  }

  const parsed = parseEnforcementAvailabilityStatus(parsedJson);
  if (parsed !== null) return parsed;
  return buildEnforcementAvailabilityStatusReadFailure(
    path,
    "invalid_schema",
    "status file did not match the enforcement availability schema",
  );
}

export async function clearEnforcementAvailabilityStatusBestEffort(
  fortressPath: string,
): Promise<boolean> {
  try {
    await unlink(enforcementAvailabilityStatusPath(fortressPath));
    return true;
  } catch (error) {
    return isNodeErrorCode(error, "ENOENT");
  }
}

export function parseEnforcementAvailabilityStatus(
  value: unknown,
): EnforcementAvailabilityStatusFile | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (
    record.state !== CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE ||
    record.reason !== CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON ||
    record.source !== CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE ||
    record.manifest_received !== true ||
    record.arm_lease_received !== false ||
    typeof record.updated_at !== "string" ||
    Number.isNaN(Date.parse(record.updated_at))
  ) {
    return null;
  }
  return {
    state: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE,
    reason: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON,
    updated_at: record.updated_at,
    source: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE,
    manifest_received: true,
    arm_lease_received: false,
  };
}

export function enforcementAvailabilityStatusTimeMs(
  status: EnforcementAvailabilityStatus | null | undefined,
): number | null {
  if (!status) return null;
  const parsed = Date.parse(status.updated_at);
  return Number.isNaN(parsed) ? null : parsed;
}

export function isFreshEnforcementAvailabilityStatus(
  status: EnforcementAvailabilityStatus | null | undefined,
  input: {
    now: number;
    freshnessWindowMs: number;
    futureSkewMs: number;
  },
): boolean {
  const ts = enforcementAvailabilityStatusTimeMs(status);
  return (
    ts !== null &&
    ts >= input.now - input.freshnessWindowMs &&
    ts <= input.now + input.futureSkewMs
  );
}

export function isEnforcementAvailabilityStatusReadFailure(
  status: EnforcementAvailabilityStatus | null | undefined,
): status is EnforcementAvailabilityStatusReadFailure {
  return status?.reason === CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_REASON;
}

export function buildEnforcementAvailabilityStatusReadFailure(
  path: string,
  kind: EnforcementAvailabilityStatusReadFailure["read_error"]["kind"],
  error: unknown,
  updatedAt: string = new Date().toISOString(),
): EnforcementAvailabilityStatusReadFailure {
  return {
    state: CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE,
    reason: CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_REASON,
    updated_at: updatedAt,
    source: CASTLE_WALL_ENFORCEMENT_STATUS_UNREADABLE_SOURCE,
    manifest_received: null,
    arm_lease_received: null,
    read_error: {
      kind,
      path,
      message: error instanceof Error ? error.message : String(error),
    },
  };
}

function isNodeErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === code
  );
}
