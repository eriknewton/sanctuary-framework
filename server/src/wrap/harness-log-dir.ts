import { stripTrailingSlashes } from "../strings.js";

/** Dedicated harness daemon logs must be writable by the agent uid, not the operator-only fortress. */
export function resolveHarnessDaemonLogDir(newAccountHome: string): string {
  return `${stripTrailingSlashes(newAccountHome)}/logs`;
}
