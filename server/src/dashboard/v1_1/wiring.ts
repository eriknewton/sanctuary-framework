/**
 * v1.1 Server Wiring (v1.1.1 hotfix; agent-registry persistence in v1.1.5)
 *
 * v1.1.0 shipped the v1.1 module suite (dashboard / hub API / exit bundle
 * endpoints / coordination) but no entry-point server imported any of it.
 * This module builds the canonical HubService construction the dashboard
 * entry points share so the routes light up at boot without forcing each
 * caller to know the deps shape.
 *
 * The wiring is deliberately minimal at v1.1.1:
 *
 *   - Local agent registry starts empty by default. v1.1.5 (Finding Z)
 *     adds an optional `storagePath` input that rehydrates the registry
 *     from `<storagePath>/state/_hub/local-agents.json`, written by
 *     `sanctuary wrap` for each successfully wrapped harness. Callers
 *     that pass `storagePath` get the wrap-populated set; callers that
 *     omit it (legacy) keep the empty-by-default behavior. Real
 *     harness-discovery via `discoverTenants()` remains v1.2 work.
 *   - Inbox sources return empty arrays. The privacy chokepoint already
 *     emits audit events through PR #69 / PR #71; the inbox aggregator is
 *     the v1.2 work to project those into operator cards.
 *   - Activity feed reads from the real audit log. This is the one source
 *     that's already complete in v1.1.0 and just needs to be plugged in.
 *   - Agent controller errors on every action. v1.1.1 cannot honestly
 *     pause / unwrap / lockdown anything because no agent registry yet
 *     exists; the wiring returns `HubCapabilityError` rather than lying
 *     about what shipped.
 */

import { createHash } from "node:crypto";

import type { AuditLog } from "../../l2-operational/audit-log.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  type HubAgentController,
} from "../../hub/index.js";
import { HubCapabilityError } from "../../hub/errors.js";
import { readPersistedLocalAgents } from "../../hub/agent-registry-persistence.js";
import type { ChannelTemplateId } from "../../policy-engine/constants.js";
import type { HubAgentStatus } from "../../contracts/v1.1/constants.js";

export interface BuildV11BindingsInputs {
  /** Operator identity id this hub is scoped to. */
  identityId: string;
  /** Stable fortress id surfaced through the API + dashboard top bar. */
  fortressId: string;
  /** Underlying audit log; powers the activity feed projection. */
  auditLog: AuditLog;
  /**
   * Fortress storage root. When provided, the agent registry rehydrates
   * from `<storagePath>/state/_hub/local-agents.json` (best-effort; a
   * missing or unparseable file degrades to an empty registry rather
   * than failing construction). Omit for callers that intentionally
   * want an empty registry (e.g. unit tests, future ephemeral modes).
   */
  storagePath?: string;
}

export interface V11Bindings {
  hubService: HubService;
  identityId: string;
  fortressId: string;
}

class CapabilityErrorAgentController implements HubAgentController {
  private fail(action: string): never {
    throw new HubCapabilityError(
      `agent_control_${action}_not_wired_in_v1.1.1`,
    );
  }
  async pause(_agentId: string): Promise<HubAgentStatus> {
    this.fail("pause");
  }
  async resume(_agentId: string): Promise<HubAgentStatus> {
    this.fail("resume");
  }
  async restart(_agentId: string): Promise<HubAgentStatus> {
    this.fail("restart");
  }
  async unwrap(_agentId: string): Promise<HubAgentStatus> {
    this.fail("unwrap");
  }
  async lockdown(_agentId: string): Promise<HubAgentStatus> {
    this.fail("lockdown");
  }
  async bindPolicy(_agentId: string, _policyId: string): Promise<void> {
    this.fail("bindPolicy");
  }
  async bindChannelTemplate(
    _agentId: string,
    _templateId: ChannelTemplateId,
  ): Promise<void> {
    this.fail("bindChannelTemplate");
  }
}

/**
 * Construct the v1.1 hub bindings the dashboard entry points share. Caller
 * keeps ownership of the returned `HubService`; pass it through to the
 * dashboard layer's `setV11Bindings` setter.
 */
export function buildV11Bindings(
  inputs: BuildV11BindingsInputs,
): V11Bindings {
  // v1.1.5 (Finding Z): seed the registry from the persisted hub-layer
  // file when a storage path is supplied. Reads are best-effort; the
  // persistence helper returns [] on missing-file or parse-error, so a
  // first-boot or corrupted-file fortress simply starts with an empty
  // registry instead of failing construction.
  const seed =
    inputs.storagePath !== undefined
      ? readPersistedLocalAgents(inputs.storagePath)
      : [];
  const registry = new InMemoryLocalAgentRegistry(seed);
  const hubService = new HubService({
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
    agentRegistry: registry,
    inboxSources: {
      listPendingApprovals: () => [],
      listRecentBlockedEgress: () => [],
      listRecentPrivacyEvents: () => [],
      listActiveBudgetWarnings: () => [],
      listActiveRecoveryPrompts: () => [],
      listRecentAgentErrors: () => [],
    },
    activitySources: {
      auditLog: inputs.auditLog,
      identityId: inputs.identityId,
    },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: new CapabilityErrorAgentController(),
  });
  return {
    hubService,
    identityId: inputs.identityId,
    fortressId: inputs.fortressId,
  };
}

/**
 * Synthesize a stable fortress id from the storage path. Until v1.2 lands
 * a canonical fortress id source, the storage path hash is stable across
 * boots of the same fortress and unique across distinct fortresses on the
 * same host. Display only; not used for trust decisions.
 */
export function fortressIdFromStoragePath(storagePath: string): string {
  const digest = createHash("sha256").update(storagePath).digest("hex");
  return `fortress-${digest.slice(0, 16)}`;
}
