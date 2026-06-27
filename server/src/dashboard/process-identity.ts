/**
 * Sanctuary Dashboard - per-process identity for restart detection
 *
 * A dashboard server process mints ONE opaque boot id and records its
 * start timestamp at module load. Both values are surfaced on the
 * unauthenticated `/api/health` probe (`instance` + `since`) so the host
 * app can detect a restart honestly: if `instance` changes between two
 * polls, the backing process restarted (likely a launchd KeepAlive
 * relaunch) and the app drives the Reconnecting -> Live transition from a
 * producer-side fact, not a heuristic.
 *
 * SECURITY (HIGH-1, Dashboard Server Lifecycle Hardening brief D3): these
 * two fields are the ONLY additions to the unauthenticated `/api/health`
 * surface. They are opaque identifiers, not state:
 *   - `instance` is a random per-boot id. It reveals nothing about the
 *     fortress, posture, config, agents, tenants, tokens, or counts. It
 *     is per-process, so it CANNOT correlate across tenants (each tenant
 *     dashboard is a distinct process with a distinct id).
 *   - `since` is the process start time. It reveals only how long this
 *     listener has been up, which an unauthenticated caller can already
 *     infer from the listener answering.
 *
 * The readiness/posture signals (`ready`, `supervisor`) deliberately do
 * NOT live here and do NOT go on `/api/health`; they are auth-gated on
 * `/api/readiness` (an unauthenticated `ready: "locked"` field would be a
 * co-resident-agent oracle for whether the fortress is unlocked, which is
 * exactly the regression the brief's HIGH-1 finding forbids).
 *
 * The values are computed once at module load and frozen for the life of
 * the process. Every `/api/health` handler imports the SAME accessors so
 * the id and timestamp are a single shared source, never recomputed
 * per-request or per-handler.
 */

import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";

/** Opaque per-process boot id, minted once at module load. */
const INSTANCE_ID: string = randomBytes(16).toString("hex");

/**
 * Process/time origin (unix-ms), the exact instant the Node process began.
 * `performance.timeOrigin` is the high-resolution process start, so this is a
 * truthful "process start time" rather than a module-load approximation
 * (`Date.now()` at import would drift by however long startup took). Floored to
 * a whole millisecond to keep it a non-secret, opaque value on the wire.
 */
const SINCE_MS: number = Math.floor(performance.timeOrigin);

/**
 * The opaque per-process boot id. Stable for the life of this process;
 * changes on every restart (a new process loads this module fresh).
 */
export function getProcessInstance(): string {
  return INSTANCE_ID;
}

/**
 * The process start timestamp in unix-ms. Lets the host app reason about
 * uptime and corroborate a restart alongside an `instance` change.
 */
export function getProcessSince(): number {
  return SINCE_MS;
}
