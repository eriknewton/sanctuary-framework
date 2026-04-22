/**
 * Sanctuary Operator Console v1.0 — Constants
 *
 * Source of truth for navigation items, surface identifiers, and the MSP
 * / Fleet Operator Console v1.x reservation (spawn prompt AC scope item 5 +
 * Federation Protocol §10.5 narrative).
 *
 * No wire-shape surface is defined here. Reserved extension-envelope keys,
 * reserved event-type prefixes, and reserved capability bits live in
 * `server/src/mesh/constants.ts` (the spec's canonical home).
 */

import {
  RESERVED_EVENT_TYPE_PREFIXES,
  RESERVED_EXTENSION_ENVELOPE_KEYS,
  V01_ALLOWED_CAPABILITY_MASK,
} from "../mesh/constants.js";

/** Console product version, independent of server release. */
export const CONSOLE_VERSION = "1.0.0" as const;

/**
 * The six primary surfaces the console exposes at v1.0. `recovery` is a
 * routing stub at v1.0; the live ceremony lands in WP-MVP-8.
 *
 * Order is the order they render in the navigation bar.
 */
export const CONSOLE_SURFACES = [
  "fortress",
  "agents",
  "policy",
  "join-revoke",
  "mesh-health",
  "recovery",
] as const;
export type ConsoleSurface = (typeof CONSOLE_SURFACES)[number];

/** Display labels per surface. Naming-discipline: no competitor product names. */
export const SURFACE_LABELS: Record<ConsoleSurface, string> = {
  fortress: "Fortress overview",
  agents: "Agents",
  policy: "Policy editor",
  "join-revoke": "Join / revoke",
  "mesh-health": "Mesh Health",
  recovery: "Recovery",
};

/**
 * Disabled v1.x surfaces reserved in the navigation so the v1.x MSP / Fleet
 * Operator Console can drop in without a layout rewrite.
 *
 * Federation Protocol §10.5 narrates Drew-style guardian-delegated read-
 * across-fortress; `federation-room` is the navigation slot that surface
 * will inhabit. v1.0 emits the link as a disabled "v1.x" affordance.
 */
export const RESERVED_V1X_SURFACES = [
  "federation-room",
  "breach-feed",
  "rate-table",
] as const;
export type ReservedV1xSurface = (typeof RESERVED_V1X_SURFACES)[number];

export const RESERVED_V1X_SURFACE_LABELS: Record<ReservedV1xSurface, string> = {
  "federation-room": "Federation room (v1.x)",
  "breach-feed": "Breach feed (v1.x)",
  "rate-table": "Rate table (v1.x)",
};

/** The Tier 1 operation name registered in DEFAULT_POLICY for federation joins. */
export const FEDERATION_NODE_JOIN_OPERATION = "federation_node_join" as const;

/**
 * Guard: reject any attempt to expose a reserved mesh surface through the
 * console. Centralized here so the guard and the HTML affordance use the
 * same source of truth.
 */
export function isReservedMeshSurface(candidate: {
  event_type?: string;
  extension_keys?: string[];
  capabilities?: number;
}): { reserved: boolean; reason?: string } {
  if (candidate.event_type !== undefined) {
    for (const prefix of RESERVED_EVENT_TYPE_PREFIXES) {
      if (candidate.event_type.startsWith(prefix)) {
        return {
          reserved: true,
          reason: `event_type prefix "${prefix}" is reserved for v1.x`,
        };
      }
    }
  }
  if (candidate.extension_keys) {
    for (const key of candidate.extension_keys) {
      if ((RESERVED_EXTENSION_ENVELOPE_KEYS as readonly string[]).includes(key)) {
        return {
          reserved: true,
          reason: `extension envelope key "${key}" is reserved for v1.x`,
        };
      }
    }
  }
  if (candidate.capabilities !== undefined) {
    if ((candidate.capabilities & ~V01_ALLOWED_CAPABILITY_MASK) !== 0) {
      return {
        reserved: true,
        reason: "capability bits 3-31 are reserved for v1.x",
      };
    }
  }
  return { reserved: false };
}
