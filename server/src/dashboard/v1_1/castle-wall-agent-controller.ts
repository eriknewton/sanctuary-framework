/**
 * Production v1.1 HubAgentController backed by Castle Wall.
 *
 * Pause/resume/restart remain unsupported because Sanctuary does not own the
 * agent process. Lockdown is the network stop: revoke the confined uid's
 * agent-matchable allow rules and ask the daemon to reload.
 */

import type { AuditLog } from "../../operational/audit-log.js";
import type { HubAgentControlAction } from "../../hub/constants.js";
import type {
  HubAgentController,
  HubAgentLockdownControllerResult,
} from "../../hub/types.js";
import { HubCapabilityError, HubNotFoundError } from "../../hub/errors.js";
import type { HubAgentStatus } from "../../contracts/v1.1/constants.js";
import type { LocalAgentRecord } from "../../contracts/v1.1/local-agent-records.js";
import type { ChannelTemplateId } from "../../policy-engine/constants.js";
import {
  AgentEgressStopError,
  stopAgentEgress,
  type StopAgentEgressObservation,
} from "../../castle-wall/provision/agent-stop.js";

export interface CastleWallAgentControllerDeps {
  storagePath: string;
  fortressPath: string;
  fortressId: string;
  auditLog: AuditLog;
  now: () => Date;
  getAgentRecord(agentId: string): LocalAgentRecord | null;
  stopAgentEgress?: typeof stopAgentEgress;
}

function unsupported(action: string): never {
  throw new HubCapabilityError(action);
}

function toLockdownResult(
  observation: StopAgentEgressObservation,
): HubAgentLockdownControllerResult {
  return {
    outcome: observation.outcome,
    ...(observation.outcome === "engaged"
      ? { new_status: "locked_down" as const }
      : {}),
    agent_uid: observation.agent_uid,
    revoked_rule_ids: observation.revoked_rule_ids,
    residual_allow_count: observation.residual_allow_count,
    reload_confirmed: observation.reload_confirmed,
    ...(observation.reason_code ? { reason_code: observation.reason_code } : {}),
  };
}

export class CastleWallAgentController implements HubAgentController {
  constructor(private readonly deps: CastleWallAgentControllerDeps) {}

  supports(action: HubAgentControlAction, agentId: string): boolean {
    const record = this.deps.getAgentRecord(agentId);
    if (!record) return false;
    switch (action) {
      case "pause":
      case "resume":
      case "restart":
      case "unwrap":
        return false;
      case "lockdown":
        return record.capabilities.can_lockdown === true;
    }
  }

  async pause(_agentId: string): Promise<HubAgentStatus> {
    unsupported("agent_control_pause_unsupported_no_process_handle");
  }

  async resume(_agentId: string): Promise<HubAgentStatus> {
    unsupported("agent_control_resume_unsupported_no_process_handle");
  }

  async restart(_agentId: string): Promise<HubAgentStatus> {
    unsupported("agent_control_restart_unsupported_no_process_handle");
  }

  async unwrap(_agentId: string): Promise<HubAgentStatus> {
    unsupported("agent_control_unwrap_unsupported_operator_decision_pending");
  }

  async lockdown(agentId: string): Promise<HubAgentLockdownControllerResult> {
    const record = this.deps.getAgentRecord(agentId);
    if (!record) throw new HubNotFoundError(`agent ${agentId}`);
    try {
      const stop = this.deps.stopAgentEgress ?? stopAgentEgress;
      const observation = await stop({
        agentId,
        protectionSubject: record.protection_subject,
        fortressId: this.deps.fortressId,
        fortressPath: this.deps.fortressPath,
        storagePath: this.deps.storagePath,
        now: this.deps.now,
      });
      return toLockdownResult(observation);
    } catch (err) {
      if (err instanceof AgentEgressStopError) {
        throw new HubCapabilityError(err.reasonCode);
      }
      throw err;
    }
  }

  async bindPolicy(_agentId: string, _policyId: string): Promise<void> {
    unsupported("agent_control_bind_policy_unsupported_no_consumer");
  }

  async bindChannelTemplate(
    _agentId: string,
    _templateId: ChannelTemplateId,
  ): Promise<void> {
    return;
  }
}
