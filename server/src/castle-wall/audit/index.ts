/** Public surface of the audit module. */

export type {
  CastleWallAuditEvent,
  CastleWallEventType,
  CastleWallEventDestination,
  CastleWallEventAgent,
} from "./events.js";

export type { BuildEventInput } from "./builder.js";
export {
  buildAuditEvent,
  canonicalizeAuditEvent,
  canonicalizeAuditEventToBytes,
} from "./builder.js";
