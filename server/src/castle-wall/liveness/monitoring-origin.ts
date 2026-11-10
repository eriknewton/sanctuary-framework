/**
 * The monitoring-origin predicate for the canary tuple. The canary drop is the
 * wall's own heartbeat; it is not agent traffic, so candidate, inventory and
 * count consumers leave it out. Consumers exclude this monitoring-origin tuple.
 *
 * Must match `CANARY_MONITORING_ORIGIN` in server/src/castle-wall/liveness/constants.ts.
 * This module imports only constants.ts so every consumer can share it without
 * a cycle.
 */
import { CANARY_IP, CANARY_PORT, CANARY_PROTOCOL } from "./constants.js";

export interface MonitoringOriginTuple {
  ip: unknown;
  port: unknown;
  protocol: unknown;
  host?: unknown;
}

/**
 * True exactly when the tuple is the canary IP, port and protocol with no host.
 * A hostful row to the canary address is never a canary, so it stays visible as an anomaly.
 */
export function isMonitoringOriginDestination(tuple: MonitoringOriginTuple): boolean {
  return tuple.ip === CANARY_IP && tuple.port === CANARY_PORT && tuple.protocol === CANARY_PROTOCOL &&
    (tuple.host === null || tuple.host === undefined);
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/**
 * Extract the destination tuple of an audit `details` object in either stored
 * shape: nested `destination.{ip, port, protocol, host}` or flat
 * `dest_ip`, `dest_port`, `dest_protocol`, `dest_host`. Null when neither shape is present.
 */
export function monitoringOriginTupleFromDetails(details: unknown): MonitoringOriginTuple | null {
  const d = record(details);
  if (d === null) return null;
  const nested = record(d.destination);
  if (nested !== null) return { ip: nested.ip, port: nested.port, protocol: nested.protocol, host: nested.host };
  if ("dest_ip" in d) return { ip: d.dest_ip, port: d.dest_port, protocol: d.dest_protocol, host: d.dest_host };
  return null;
}

/**
 * True for an `egress_blocked` audit entry whose destination is the canary tuple.
 * Drops only: an allow to the canary tuple is the canary_destination_allowed fault and must stay visible.
 */
export function isMonitoringOriginDrop(operation: unknown, details: unknown): boolean {
  if (operation !== "egress_blocked") return false;
  const tuple = monitoringOriginTupleFromDetails(details);
  return tuple !== null && isMonitoringOriginDestination(tuple);
}
