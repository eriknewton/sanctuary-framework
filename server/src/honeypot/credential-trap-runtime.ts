/**
 * Sanctuary v1.3 WP-V1.3-5 Pi-4 Credential trap runtime.
 *
 * Server-local fake credential exposure for honeypot traps. The runtime
 * reads deployed credential TrapSpecs from the per-fortress TrapRegistry,
 * exposes visible fake credentials through broker/env/config-shaped
 * boundaries, and emits a sentinel finding when a wrapped agent reads or
 * attempts to use one.
 */

import { createHash, randomUUID } from "node:crypto";
import type { IncomingMessage } from "node:http";

import type { AuditLog } from "../l2-operational/audit-log.js";
import type { SentinelFindingStore } from "../sentinel/sentinel-finding-store.js";
import type { SentinelFinding } from "../sentinel/types.js";

import { TrapRegistry } from "./trap-registry.js";
import {
  HONEYPOT_AUDIT_OPS,
  honeypotSentinelId,
  type CredentialEmissionPath,
  type CredentialTrigger,
  type TrapSpec,
} from "./types.js";

export interface CredentialTrapRuntimeDeps {
  registry: TrapRegistry;
  findingStore: SentinelFindingStore;
  auditLog: AuditLog;
  operatorId: string;
  fortressId: string;
  now?: () => Date;
}

export interface CredentialAccess {
  trap_id: string;
  fake_credential_name: string;
  fake_credential_type: CredentialTrigger["fake_credential_type"];
  caller_identity: string;
  emission_path: CredentialEmissionPath;
  access_pattern: "read";
  accessed_at: string;
  finding_id: string;
  credential_value_hash: string;
}

export interface CredentialUseAttempt {
  trap_id: string;
  fake_credential_name: string;
  caller_identity: string;
  target_host: string;
  target_path?: string;
  attempted_at: string;
  finding_id: string;
  credential_value_hash: string;
  castle_wall_decision: "blocked";
  fake_response: string;
}

export interface CredentialTrapStats {
  trap_id: string;
  fake_credential_name: string;
  fake_credential_type: CredentialTrigger["fake_credential_type"];
  visibility: CredentialTrigger["visibility"];
  visible_to_agents?: string[];
  emission_paths: CredentialEmissionPath[];
  monitored_target_hosts: string[];
  read_count: number;
  use_attempt_count: number;
  last_access_at: string | null;
  caller_diversity: number;
  accesses: CredentialAccess[];
  use_attempts: CredentialUseAttempt[];
}

export interface CredentialReadResult {
  handled: true;
  value: string;
  access: CredentialAccess;
}

export interface CredentialUseAttemptResult {
  handled: true;
  statusCode: 401 | 403;
  responseBody: string;
  attempt: CredentialUseAttempt;
}

export class CredentialTrapRuntime {
  private readonly registry: TrapRegistry;
  private readonly findingStore: SentinelFindingStore;
  private readonly auditLog: AuditLog;
  private readonly operatorId: string;
  private readonly fortressId: string;
  private readonly now: () => Date;
  private readonly accesses = new Map<string, CredentialAccess[]>();
  private readonly useAttempts = new Map<string, CredentialUseAttempt[]>();

  constructor(deps: CredentialTrapRuntimeDeps) {
    this.registry = deps.registry;
    this.findingStore = deps.findingStore;
    this.auditLog = deps.auditLog;
    this.operatorId = deps.operatorId;
    this.fortressId = deps.fortressId;
    this.now = deps.now ?? (() => new Date());
  }

  listVisibleCredentials(
    agentId: string | undefined,
    emissionPath: CredentialEmissionPath = "secret_broker",
  ): Array<{
    name: string;
    type: CredentialTrigger["fake_credential_type"];
    emission_path: CredentialEmissionPath;
  }> {
    return this.credentialSpecs()
      .filter((spec) => {
        const trigger = spec.trigger;
        return (
          trigger.emission_paths.includes(emissionPath) &&
          isVisibleToAgent(trigger, agentId)
        );
      })
      .map((spec) => ({
        name: spec.trigger.fake_credential_name,
        type: spec.trigger.fake_credential_type,
        emission_path: emissionPath,
      }));
  }

  async readCredential(
    credentialName: string,
    callerIdentity: string,
    emissionPath: CredentialEmissionPath = "secret_broker",
  ): Promise<{ handled: false } | CredentialReadResult> {
    const agentId = agentIdFromCallerIdentity(callerIdentity);
    const spec = this.credentialSpecs().find((candidate) => {
      const trigger = candidate.trigger;
      return (
        trigger.fake_credential_name === credentialName &&
        trigger.emission_paths.includes(emissionPath) &&
        isVisibleToAgent(trigger, agentId)
      );
    });
    if (!spec) return { handled: false };

    const access = await this.fireRead(spec, callerIdentity, emissionPath);
    return { handled: true, value: spec.trigger.fake_credential_value, access };
  }

  envExportsForAgent(agentId: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const spec of this.credentialSpecs()) {
      const trigger = spec.trigger;
      if (!trigger.emission_paths.includes("env_var_export")) continue;
      if (!isVisibleToAgent(trigger, agentId)) continue;
      out[envVarName(trigger.fake_credential_name)] =
        trigger.fake_credential_value;
    }
    return out;
  }

  configEntriesForAgent(agentId: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const spec of this.credentialSpecs()) {
      const trigger = spec.trigger;
      if (!trigger.emission_paths.includes("config_file")) continue;
      if (!isVisibleToAgent(trigger, agentId)) continue;
      out[trigger.fake_credential_name] = trigger.fake_credential_value;
    }
    return out;
  }

  async recordUseAttempt(input: {
    credentialName?: string;
    credentialValue?: string;
    callerIdentity: string;
    targetHost: string;
    targetPath?: string;
  }): Promise<{ handled: false } | CredentialUseAttemptResult> {
    const spec = this.findSpecForUse(input);
    if (!spec) return { handled: false };

    const findingId = randomUUID();
    const attemptedAt = this.now().toISOString();
    const response = plausibleUseResponse(spec.trigger);
    const attempt: CredentialUseAttempt = {
      trap_id: spec.trap_id,
      fake_credential_name: spec.trigger.fake_credential_name,
      caller_identity: input.callerIdentity,
      target_host: input.targetHost.toLowerCase(),
      ...(input.targetPath ? { target_path: input.targetPath } : {}),
      attempted_at: attemptedAt,
      finding_id: findingId,
      credential_value_hash: hashValue(spec.trigger.fake_credential_value),
      castle_wall_decision: "blocked",
      fake_response: response.body,
    };
    const attempts = this.useAttempts.get(spec.trap_id) ?? [];
    attempts.push(attempt);
    this.useAttempts.set(spec.trap_id, attempts);

    const finding: SentinelFinding = {
      finding_id: findingId,
      sentinel_id: honeypotSentinelId(spec.trap_id),
      severity: spec.finding_severity,
      summary:
        `honeypot ${spec.trap_id} triggered: credential ${spec.trigger.fake_credential_name} use attempted by ${input.callerIdentity} against ${attempt.target_host}`,
      details: {
        trap_id: spec.trap_id,
        trap_class: spec.trap_class,
        fake_credential_name: spec.trigger.fake_credential_name,
        caller_identity: input.callerIdentity,
        target_host: attempt.target_host,
        ...(input.targetPath ? { target_path: input.targetPath } : {}),
        credential_value_hash: attempt.credential_value_hash,
        usage_attempted: true,
        castle_wall_decision: "blocked",
        castle_wall_log_operation: "egress_blocked",
      },
      observed_at: attemptedAt,
      evidence_audit_ids: [],
      fortress_id: this.fortressId,
    };
    await this.findingStore.saveFinding(finding).catch(() => undefined);
    this.auditLog.append("l2", HONEYPOT_AUDIT_OPS.TRIGGERED, this.operatorId, {
      fortress_id: this.fortressId,
      trap_id: spec.trap_id,
      trap_class: spec.trap_class,
      fake_credential_name: spec.trigger.fake_credential_name,
      caller_identity: input.callerIdentity,
      target_host: attempt.target_host,
      ...(input.targetPath ? { target_path: input.targetPath } : {}),
      credential_value_hash: attempt.credential_value_hash,
      finding_id: findingId,
      severity: spec.finding_severity,
      usage_attempted: true,
      castle_wall_decision: "blocked",
    });
    this.auditLog.append("l1", "egress_blocked", this.fortressId, {
      event_type: "egress_blocked",
      fortress_id: this.fortressId,
      agent_id: input.callerIdentity,
      destination_host: attempt.target_host,
      ...(input.targetPath ? { destination_path: input.targetPath } : {}),
      reason: "credential_honeypot_use_attempt",
      trap_id: spec.trap_id,
      fake_credential_name: spec.trigger.fake_credential_name,
      credential_value_hash: attempt.credential_value_hash,
      decision: "block",
    });

    return {
      handled: true,
      statusCode: response.statusCode,
      responseBody: response.body,
      attempt,
    };
  }

  async detectHttpUseAttempt(
    req: IncomingMessage,
  ): Promise<{ handled: false } | CredentialUseAttemptResult> {
    const observed = observedCredentialFromRequest(req);
    if (!observed) return { handled: false };
    const targetHost =
      headerString(req.headers["x-sanctuary-upstream-host"]) ??
      headerString(req.headers.host) ??
      "unknown.local";
    return this.recordUseAttempt({
      credentialValue: observed.value,
      callerIdentity: extractCallerIdentity(req),
      targetHost,
      targetPath: (req.url ?? "/").split("?")[0] ?? "/",
    });
  }

  stats(): CredentialTrapStats[] {
    return this.credentialSpecs().map((spec) => {
      const trigger = spec.trigger;
      const accesses = [...(this.accesses.get(spec.trap_id) ?? [])];
      const attempts = [...(this.useAttempts.get(spec.trap_id) ?? [])];
      const callerSet = new Set([
        ...accesses.map((a) => a.caller_identity),
        ...attempts.map((a) => a.caller_identity),
      ]);
      const last =
        [...accesses.map((a) => a.accessed_at), ...attempts.map((a) => a.attempted_at)]
          .sort()
          .at(-1) ?? null;
      return {
        trap_id: spec.trap_id,
        fake_credential_name: trigger.fake_credential_name,
        fake_credential_type: trigger.fake_credential_type,
        visibility: trigger.visibility,
        ...(trigger.visible_to_agents
          ? { visible_to_agents: [...trigger.visible_to_agents] }
          : {}),
        emission_paths: [...trigger.emission_paths],
        monitored_target_hosts: [...(trigger.monitored_target_hosts ?? [])],
        read_count: accesses.length,
        use_attempt_count: attempts.length,
        last_access_at: last,
        caller_diversity: callerSet.size,
        accesses,
        use_attempts: attempts,
      };
    });
  }

  private async fireRead(
    spec: TrapSpec & { trigger: CredentialTrigger },
    callerIdentity: string,
    emissionPath: CredentialEmissionPath,
  ): Promise<CredentialAccess> {
    const findingId = randomUUID();
    const accessedAt = this.now().toISOString();
    const credentialValueHash = hashValue(spec.trigger.fake_credential_value);
    const access: CredentialAccess = {
      trap_id: spec.trap_id,
      fake_credential_name: spec.trigger.fake_credential_name,
      fake_credential_type: spec.trigger.fake_credential_type,
      caller_identity: callerIdentity,
      emission_path: emissionPath,
      access_pattern: "read",
      accessed_at: accessedAt,
      finding_id: findingId,
      credential_value_hash: credentialValueHash,
    };
    const accesses = this.accesses.get(spec.trap_id) ?? [];
    accesses.push(access);
    this.accesses.set(spec.trap_id, accesses);

    const finding: SentinelFinding = {
      finding_id: findingId,
      sentinel_id: honeypotSentinelId(spec.trap_id),
      severity: spec.finding_severity,
      summary:
        `honeypot ${spec.trap_id} triggered: credential ${spec.trigger.fake_credential_name} read by ${callerIdentity} through ${emissionPath}`,
      details: {
        trap_id: spec.trap_id,
        trap_class: spec.trap_class,
        fake_credential_name: spec.trigger.fake_credential_name,
        fake_credential_type: spec.trigger.fake_credential_type,
        caller_identity: callerIdentity,
        emission_path: emissionPath,
        access_pattern: "read",
        credential_value_hash: credentialValueHash,
      },
      observed_at: accessedAt,
      evidence_audit_ids: [],
      fortress_id: this.fortressId,
    };
    await this.findingStore.saveFinding(finding).catch(() => undefined);
    this.auditLog.append("l2", HONEYPOT_AUDIT_OPS.TRIGGERED, this.operatorId, {
      fortress_id: this.fortressId,
      trap_id: spec.trap_id,
      trap_class: spec.trap_class,
      fake_credential_name: spec.trigger.fake_credential_name,
      fake_credential_type: spec.trigger.fake_credential_type,
      caller_identity: callerIdentity,
      emission_path: emissionPath,
      access_pattern: "read",
      credential_value_hash: credentialValueHash,
      finding_id: findingId,
      severity: spec.finding_severity,
    });
    return access;
  }

  private findSpecForUse(input: {
    credentialName?: string;
    credentialValue?: string;
    targetHost: string;
  }): (TrapSpec & { trigger: CredentialTrigger }) | undefined {
    const targetHost = input.targetHost.toLowerCase();
    return this.credentialSpecs().find((spec) => {
      const trigger = spec.trigger;
      const nameMatches =
        input.credentialName !== undefined &&
        trigger.fake_credential_name === input.credentialName;
      const valueMatches =
        input.credentialValue !== undefined &&
        trigger.fake_credential_value === input.credentialValue;
      if (!nameMatches && !valueMatches) return false;
      const hosts = trigger.monitored_target_hosts ?? [];
      return (
        hosts.length === 0 ||
        hosts.some((h) => h.toLowerCase() === targetHost)
      );
    });
  }

  private credentialSpecs(): Array<TrapSpec & { trigger: CredentialTrigger }> {
    return this.registry
      .list()
      .filter(
        (spec): spec is TrapSpec & { trigger: CredentialTrigger } =>
          spec.trigger.kind === "credential",
      );
  }
}

function isVisibleToAgent(
  trigger: CredentialTrigger,
  agentId: string | undefined,
): boolean {
  if (trigger.visibility === "all_wrapped_agents") return true;
  if (!agentId) return false;
  return (trigger.visible_to_agents ?? []).includes(agentId);
}

function agentIdFromCallerIdentity(callerIdentity: string): string | undefined {
  return callerIdentity.startsWith("agent:")
    ? callerIdentity.slice("agent:".length)
    : undefined;
}

function envVarName(name: string): string {
  return name
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase();
}

function hashValue(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex").slice(0, 32);
}

function plausibleUseResponse(trigger: CredentialTrigger): {
  statusCode: 401 | 403;
  body: string;
} {
  const body =
    trigger.fake_response_on_use ??
    "HTTP/1.1 401 Unauthorized\n{\"error\":\"invalid_api_key\"}";
  return {
    statusCode: /\b403\b|forbidden/i.test(body) ? 403 : 401,
    body,
  };
}

function headerString(value: string | string[] | undefined): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (Array.isArray(value) && typeof value[0] === "string") return value[0];
  return undefined;
}

function observedCredentialFromRequest(
  req: IncomingMessage,
): { value: string } | null {
  const values = [
    headerString(req.headers.authorization),
    headerString(req.headers["x-api-key"]),
    headerString(req.headers.cookie),
    req.url,
  ].filter((v): v is string => typeof v === "string" && v.length > 0);
  for (const value of values) {
    const token = extractLikelyToken(value);
    if (token) return { value: token };
  }
  return null;
}

function extractLikelyToken(value: string): string | null {
  const bearer = value.match(/\bBearer\s+([A-Za-z0-9._~+/-]{12,512}={0,2})/i);
  if (bearer?.[1]) return bearer[1];
  const apiKey = value.match(/\b(?:api[_-]?key|token|secret)=([A-Za-z0-9._~+/-]{12,512}={0,2})/i);
  if (apiKey?.[1]) return apiKey[1];
  if (/^[A-Za-z0-9._~+/-]{12,512}={0,2}$/.test(value)) return value;
  return null;
}

function extractCallerIdentity(req: IncomingMessage): string {
  const agent = req.headers["x-sanctuary-agent"];
  if (typeof agent === "string" && agent.length > 0) return `agent:${agent}`;
  const ip = req.socket.remoteAddress;
  return ip ? `ip:${ip}` : "ip:unknown";
}
