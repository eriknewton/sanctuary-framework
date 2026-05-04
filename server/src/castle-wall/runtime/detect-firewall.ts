/**
 * E7.2 firewall detection: detect ufw / firewalld / existing nftables tables
 * at install time so the Castle Wall installer can namespace its rules into
 * a dedicated `sanctuary-castle` table without colliding.
 *
 * The detector is split into a pure logic core and a thin process-shim
 * surface: PR 2a tests the logic against fixture system states; PR 2b
 * wires the real `nft list tables` / `systemctl is-active ufw` calls.
 */

import { RuntimeFirewallDetectError } from "./errors.js";

/** Snapshot of the host's firewall state at detection time. */
export interface FirewallEnvironment {
  /** Whether `ufw` reports active. */
  ufwActive: boolean;
  /** Whether `firewalld` reports active. */
  firewalldActive: boolean;
  /** Names of nftables tables already installed (other than `sanctuary-castle`). */
  otherNftablesTables: ReadonlyArray<string>;
}

/** Recommendation surfaced to the installer. */
export interface FirewallNamespaceRecommendation {
  /** The nftables table name Castle Wall should install rules under. */
  castleTableName: "sanctuary-castle";
  /** Conflict-class summary the installer logs as part of the audit event. */
  conflictClass:
    | "no_existing_firewall"
    | "ufw_present_namespace_safe"
    | "firewalld_present_namespace_safe"
    | "existing_nftables_present_namespace_safe"
    | "name_collision";
  /** Human-readable note for the installer to print + log. */
  note: string;
}

/** The dedicated table name Castle Wall always uses. */
export const CASTLE_TABLE_NAME = "sanctuary-castle" as const;

/** Pure logic: take a snapshot, return a namespace recommendation. */
export function recommendNamespace(
  env: FirewallEnvironment
): FirewallNamespaceRecommendation {
  if (env.otherNftablesTables.includes(CASTLE_TABLE_NAME)) {
    return {
      castleTableName: CASTLE_TABLE_NAME,
      conflictClass: "name_collision",
      note: `An existing nftables table named "${CASTLE_TABLE_NAME}" was found. The Castle Wall installer will refuse to overwrite it; remove or rename the existing table and re-run.`,
    };
  }
  if (env.firewalldActive) {
    return {
      castleTableName: CASTLE_TABLE_NAME,
      conflictClass: "firewalld_present_namespace_safe",
      note: `firewalld is active. Castle Wall will install its rules in "${CASTLE_TABLE_NAME}" without modifying firewalld's tables.`,
    };
  }
  if (env.ufwActive) {
    return {
      castleTableName: CASTLE_TABLE_NAME,
      conflictClass: "ufw_present_namespace_safe",
      note: `ufw is active. Castle Wall will install its rules in "${CASTLE_TABLE_NAME}" without modifying ufw's tables.`,
    };
  }
  if (env.otherNftablesTables.length > 0) {
    return {
      castleTableName: CASTLE_TABLE_NAME,
      conflictClass: "existing_nftables_present_namespace_safe",
      note: `Existing nftables tables (${env.otherNftablesTables.join(", ")}) detected. Castle Wall will install rules in "${CASTLE_TABLE_NAME}" alongside them.`,
    };
  }
  return {
    castleTableName: CASTLE_TABLE_NAME,
    conflictClass: "no_existing_firewall",
    note: `No existing firewall detected. Castle Wall will install rules in "${CASTLE_TABLE_NAME}".`,
  };
}

/** Process-shim surface; PR 2b wires real subprocess calls under this. */
export interface FirewallProbe {
  isUfwActive(): Promise<boolean>;
  isFirewalldActive(): Promise<boolean>;
  listNftablesTables(): Promise<ReadonlyArray<string>>;
}

/** Run the probe and produce a namespace recommendation. */
export async function detectAndRecommend(
  probe: FirewallProbe
): Promise<{ environment: FirewallEnvironment; recommendation: FirewallNamespaceRecommendation }> {
  let environment: FirewallEnvironment;
  try {
    const [ufwActive, firewalldActive, otherTables] = await Promise.all([
      probe.isUfwActive(),
      probe.isFirewalldActive(),
      probe.listNftablesTables(),
    ]);
    environment = {
      ufwActive,
      firewalldActive,
      otherNftablesTables: otherTables.filter((t) => t !== CASTLE_TABLE_NAME),
    };
  } catch (err) {
    throw new RuntimeFirewallDetectError(
      `firewall probe failed: ${(err as Error).message}`
    );
  }
  return {
    environment,
    recommendation: recommendNamespace(environment),
  };
}
