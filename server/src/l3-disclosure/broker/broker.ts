/**
 * Sanctuary MCP Server — L3 Secret Broker: Orchestrator
 *
 * Composes the pluggable Backend (keychain for v0.10.0) with the scoped
 * token issuer and AuditLog. This is the class the CLI and MCP server
 * interface talk to; they should not reach past it into the Backend
 * directly.
 *
 * Administrative operations (add/rotate/delete/grant/revoke) go through
 * this class so every mutation is audited. The hot path is
 * `issueToken` → `readViaToken`, both delegating to TokenIssuer.
 */

import type { Backend } from "./backend-interface.js";
import type { AuditLog } from "../../l2-operational/audit-log.js";
import { BROKER_OPS } from "../../l2-operational/audit-log.js";
import {
  TokenIssuer,
  type SkillSecretGrant,
  type IssueTokenRequest,
  type TokenBinding,
} from "./token-issuer.js";

export interface BrokerOptions {
  backend: Backend;
  auditLog: AuditLog;
  /** Initial grants from policy; can be augmented at runtime via grant/revoke. */
  grants?: SkillSecretGrant[];
  /** Principal identity_id to attribute administrative ops to. */
  principalIdentityId: string;
}

export interface AuditSummary {
  entries: Array<{
    timestamp: string;
    operation: string;
    result: "success" | "failure";
    details?: Record<string, unknown>;
  }>;
  total: number;
}

export class Broker {
  private readonly backend: Backend;
  private readonly auditLog: AuditLog;
  private readonly issuer: TokenIssuer;
  private readonly principalIdentityId: string;

  constructor(opts: BrokerOptions) {
    this.backend = opts.backend;
    this.auditLog = opts.auditLog;
    this.principalIdentityId = opts.principalIdentityId;
    this.issuer = new TokenIssuer({
      backend: opts.backend,
      auditLog: opts.auditLog,
      grants: opts.grants,
    });
  }

  /** Ensure backend is initialized and unlocked. Audits the unlock. */
  async ensureUnlocked(passphrase: string): Promise<void> {
    await this.backend.ensureInitialized(passphrase);
    this.auditLog.append(
      "l3",
      BROKER_OPS.BACKEND_UNLOCKED,
      this.principalIdentityId,
      { backend: this.backend.constructor.name },
      "success"
    );
  }

  async addSecret(name: string, value: string): Promise<void> {
    await this.backend.addSecret(name, value);
    this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_ADDED,
      this.principalIdentityId,
      { secret: name }
    );
  }

  async rotateSecret(name: string, newValue: string): Promise<void> {
    await this.backend.rotateSecret(name, newValue);
    this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_ROTATED,
      this.principalIdentityId,
      { secret: name }
    );
  }

  async deleteSecret(name: string): Promise<void> {
    await this.backend.deleteSecret(name);
    this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_DELETED,
      this.principalIdentityId,
      { secret: name }
    );
  }

  async listSecretNames(): Promise<string[]> {
    return this.backend.listSecretNames();
  }

  grant(g: SkillSecretGrant): void {
    this.issuer.setGrant(g);
    this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_GRANTED,
      this.principalIdentityId,
      { skill: g.skill, secret: g.secret, scope: g.scope, ttl_seconds: g.ttlSeconds ?? null }
    );
  }

  revoke(skill: string, secret: string): void {
    this.issuer.revokeGrant(skill, secret);
    this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_REVOKED,
      this.principalIdentityId,
      { skill, secret }
    );
  }

  getGrants(): SkillSecretGrant[] {
    return this.issuer.getGrants();
  }

  async issueToken(req: IssueTokenRequest): Promise<TokenBinding> {
    return this.issuer.issueToken(req);
  }

  async readViaToken(token: string): Promise<string> {
    return this.issuer.readViaToken(token);
  }

  /** Revoke a single outstanding token. */
  revokeToken(token: string): boolean {
    return this.issuer.revokeToken(token);
  }

  /** Observability: current live token count. */
  liveTokenCount(): number {
    return this.issuer.liveTokenCount();
  }

  /**
   * Audit query restricted to broker-scoped operations. Returns entries
   * with their timestamps, op, and result (never the secret value).
   */
  async queryAudit(opts?: { since?: string; limit?: number }): Promise<AuditSummary> {
    const allOps = Object.values(BROKER_OPS);
    // AuditLog.query filters by a single operation — call once per op and merge.
    const merged: AuditSummary["entries"] = [];
    let total = 0;
    for (const op of allOps) {
      const r = await this.auditLog.query({
        since: opts?.since,
        layer: "l3",
        operation_type: op,
        limit: opts?.limit ?? 1000,
      });
      total += r.total;
      for (const e of r.entries) {
        merged.push({
          timestamp: e.timestamp,
          operation: e.operation,
          result: e.result,
          details: e.details,
        });
      }
    }
    merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const limit = opts?.limit ?? 1000;
    return { entries: merged.slice(-limit), total };
  }
}
