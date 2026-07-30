import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export const CASTLE_WALL_ENFORCEMENT_STATUS_FILENAME =
  "castle-wall-enforcement-status.json";
export const CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE =
  "enforcement_unavailable";
export const CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON =
  "manifest_present_arm_lease_missing";
export const CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE =
  "macos_extension_provider_unbound";

export interface EnforcementAvailabilityStatusFile {
  state: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_STATE;
  reason: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_REASON;
  updated_at: string;
  source: typeof CASTLE_WALL_ENFORCEMENT_UNAVAILABLE_SOURCE;
  manifest_received: true;
  arm_lease_received: false;
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
): Promise<boolean> {
  try {
    const path = enforcementAvailabilityStatusPath(fortressPath);
    await writeFile(path, JSON.stringify(status, null, 2) + "\n", {
      mode: 0o600,
    });
    await chmod(path, 0o600);
    return true;
  } catch {
    return false;
  }
}

export async function readEnforcementAvailabilityStatus(
  fortressPath: string,
): Promise<EnforcementAvailabilityStatusFile | null> {
  try {
    return parseEnforcementAvailabilityStatus(
      JSON.parse(
        await readFile(enforcementAvailabilityStatusPath(fortressPath), "utf8"),
      ),
    );
  } catch {
    return null;
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
  status: EnforcementAvailabilityStatusFile | null | undefined,
): number | null {
  if (!status) return null;
  const parsed = Date.parse(status.updated_at);
  return Number.isNaN(parsed) ? null : parsed;
}

export function isFreshEnforcementAvailabilityStatus(
  status: EnforcementAvailabilityStatusFile | null | undefined,
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
