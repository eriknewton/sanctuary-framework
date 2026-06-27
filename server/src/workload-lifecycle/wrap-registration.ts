/**
 * Production bootstrap for declared wrapped-agent workloads.
 *
 * `sanctuary wrap` has a real fortress audit log and a persisted
 * LocalAgentRecord, but it does NOT necessarily launch a child process. This
 * helper records the declaration edge only (`workload_registered`). The
 * supervised launch path remains responsible for `workload_instantiated` once
 * the drill-gated transient-key last mile is wired.
 */

import type { AuditLog } from "../operational/audit-log.js";
import {
  WORKLOAD_CLASS_DEFINITION,
  WORKLOAD_LIFECYCLE_OPS,
  WORKLOAD_LIFECYCLE_SCHEMA,
} from "./constants.js";
import { emitWorkloadLifecycle } from "./payload.js";

export interface RecordWrappedHarnessRegistrationParams {
  auditLog: AuditLog;
  fortressId: string;
  agentId: string;
}

export async function recordWrappedHarnessRegistration(
  params: RecordWrappedHarnessRegistrationParams,
): Promise<void> {
  const operatorIdentity = `fortress:${params.fortressId}`;
  await emitWorkloadLifecycle({
    auditLog: params.auditLog,
    operation: WORKLOAD_LIFECYCLE_OPS.REGISTERED,
    identity_id: params.fortressId,
    payload: {
      lifecycle_schema: WORKLOAD_LIFECYCLE_SCHEMA,
      workload_id: params.agentId,
      instance_id: params.agentId,
      workload_class: "wrapped-agent-harness",
      class_definition: WORKLOAD_CLASS_DEFINITION,
      initiator: { kind: "operator", identity_id: operatorIdentity },
      consent_ref: null,
      consent_status: "absent",
      state_disposition: "running",
      manufactured_preference_caveat: true,
    },
  });
}
