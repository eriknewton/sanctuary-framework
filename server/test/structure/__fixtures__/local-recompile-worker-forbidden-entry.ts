// Positive control for the local job worker import-graph scan: this entry reaches the shared audit log.
import { AuditLog } from "../../../src/operational/audit-log.js";

export const reached = AuditLog;
