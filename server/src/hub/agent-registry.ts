/**
 * Sanctuary v1.1. Local Agent Registry (in-memory implementation)
 *
 * Holds the authoritative `LocalAgentRecord` set for the hub API. The hub
 * does not invent records; it accepts an injected source. This module
 * provides the default in-memory implementation that wrap / unwrap /
 * lockdown / policy-bind callers can mutate.
 *
 * Persistence is intentionally out of scope here; v1.1 wraps persist their
 * own fortress-bound state; this registry is the live read-side projection
 * the hub serves to the dashboard. Persistent re-hydration is a v1.x
 * follow-up.
 *
 * Local-only invariant:
 * Every record describes an agent wrapped on this fortress. The registry
 * MUST NOT carry records sourced from other fortresses; the hub layer
 * blocks cross-fortress filters at the API surface.
 *
 * No-secret invariant:
 * Records carry policy ids, model ids, harness ids; not secrets. Adding
 * a record with a secret-shaped field is rejected.
 */

import type { HubAgentStatus } from "../contracts/v1.1/constants.js";
import type {
  LocalAgentRecord,
  LocalAgentRegistryFilter,
  LocalHarnessKind,
} from "../contracts/v1.1/local-agent-records.js";
import type { ChannelTemplateId } from "../policy-engine/constants.js";
import type { HubAgentRegistrySource } from "./types.js";
import { HubNotFoundError, HubValidationError } from "./errors.js";

const FORBIDDEN_RECORD_KEYS = new Set([
  "private_key",
  "passphrase",
  "recovery_seed",
  "secret",
  "api_key",
  "token",
  "auth_token",
  "bearer_token",
]);

/**
 * Reject records whose surface keys collide with the no-secret invariant.
 *
 * The whole-record shape is enforced by the contract type; this is a
 * defense-in-depth check that catches accidental backend authors stuffing
 * a stray field into the record before storing.
 */
function assertNoSecretFields(record: LocalAgentRecord): void {
  for (const key of Object.keys(record)) {
    if (FORBIDDEN_RECORD_KEYS.has(key.toLowerCase())) {
      throw new HubValidationError(
        `local agent record carries forbidden secret-shaped field: ${key}`,
      );
    }
  }
  // Provider block has its own narrow shape; check it too.
  for (const key of Object.keys(record.model_provider)) {
    if (FORBIDDEN_RECORD_KEYS.has(key.toLowerCase())) {
      throw new HubValidationError(
        `local agent record model_provider carries forbidden secret-shaped field: ${key}`,
      );
    }
  }
}

export class InMemoryLocalAgentRegistry implements HubAgentRegistrySource {
  private records: Map<string, LocalAgentRecord> = new Map();

  constructor(seed?: LocalAgentRecord[]) {
    if (seed) {
      for (const r of seed) this.put(r);
    }
  }

  /**
   * Insert or replace a record. Used by `sanctuary wrap`-side code to
   * register a freshly wrapped agent.
   */
  put(record: LocalAgentRecord): void {
    assertNoSecretFields(record);
    this.records.set(record.agent_id, record);
  }

  /**
   * Remove a record entirely. Used after an approved unwrap completes.
   */
  remove(agentId: string): void {
    this.records.delete(agentId);
  }

  list(filter?: LocalAgentRegistryFilter): LocalAgentRecord[] {
    let entries = Array.from(this.records.values());

    if (filter?.identity_id) {
      entries = entries.filter((r) => r.identity_id === filter.identity_id);
    }
    if (filter?.harnesses && filter.harnesses.length > 0) {
      const allowed = new Set<LocalHarnessKind>(filter.harnesses);
      entries = entries.filter((r) => allowed.has(r.harness));
    }
    if (filter?.statuses && filter.statuses.length > 0) {
      const allowed = new Set<HubAgentStatus>(filter.statuses);
      entries = entries.filter((r) => allowed.has(r.status));
    }

    // Stable sort by agent_id so paginated results stay deterministic.
    entries.sort((a, b) => a.agent_id.localeCompare(b.agent_id));

    if (filter?.cursor) {
      const idx = entries.findIndex((r) => r.agent_id === filter.cursor);
      if (idx >= 0) entries = entries.slice(idx + 1);
    }

    if (filter?.limit !== undefined) {
      const limit = Math.max(0, Math.floor(filter.limit));
      entries = entries.slice(0, limit);
    }

    return entries;
  }

  get(agentId: string): LocalAgentRecord | null {
    return this.records.get(agentId) ?? null;
  }

  updateStatus(
    agentId: string,
    status: HubAgentStatus,
    statusReasonClass?: LocalAgentRecord["status_reason_class"],
  ): LocalAgentRecord {
    const prior = this.records.get(agentId);
    if (!prior) throw new HubNotFoundError(`agent ${agentId}`);
    const next: LocalAgentRecord = {
      ...prior,
      status,
      ...(statusReasonClass !== undefined
        ? { status_reason_class: statusReasonClass }
        : { status_reason_class: undefined }),
      last_activity_at: new Date().toISOString(),
    };
    // Strip the optional field if cleared, to keep the JSON tight.
    if (next.status_reason_class === undefined) {
      delete (next as { status_reason_class?: unknown }).status_reason_class;
    }
    this.records.set(agentId, next);
    return next;
  }

  updatePolicyBinding(agentId: string, policyId: string): LocalAgentRecord {
    if (!policyId || typeof policyId !== "string") {
      throw new HubValidationError("policyId required");
    }
    const prior = this.records.get(agentId);
    if (!prior) throw new HubNotFoundError(`agent ${agentId}`);
    const next: LocalAgentRecord = {
      ...prior,
      policy_id: policyId,
      last_activity_at: new Date().toISOString(),
    };
    this.records.set(agentId, next);
    return next;
  }

  updateChannelTemplateBinding(
    agentId: string,
    templateId: ChannelTemplateId,
  ): LocalAgentRecord {
    const prior = this.records.get(agentId);
    if (!prior) throw new HubNotFoundError(`agent ${agentId}`);
    const next: LocalAgentRecord = {
      ...prior,
      channel_template_id: templateId,
      last_activity_at: new Date().toISOString(),
    };
    this.records.set(agentId, next);
    return next;
  }

  /**
   * Test/inspection helper. Not part of the source interface.
   */
  size(): number {
    return this.records.size;
  }
}
