/**
 * Sanctuary MCP Server, L3 Secret Broker: Orchestrator
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
import type { AuditLog, AuditEntry } from "../../operational/audit-log.js";
import { BROKER_OPS } from "../../operational/audit-log.js";
import {
  redactAuditEntryForAgent,
  type AgentAuditView,
} from "../../operational/agent-audit-redaction.js";
import {
  TokenIssuer,
  type SkillSecretGrant,
  type IssueTokenRequest,
  type TokenBinding,
  type VerifiedBrokerCallerClaims,
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
  /**
   * Allowlist-redacted entries — the SAME agent-facing view every other
   * agent-facing audit read emits ({ timestamp, operation, result,
   * has_details }). The broker audit `details` carry the credential NAME, the
   * granted/requested scope, ttl, the `scope_exceeds_grant`-style reason, and
   * the tenant/audience claims (token-issuer.ts); none of that may cross to the
   * agent, so the raw `details` object is NEVER returned here (CISO HIGH,
   * 2026-06-16).
   */
  entries: AgentAuditView[];
  total: number;
}

/**
 * Operator-only, FULL-FIDELITY broker audit summary. Carries the raw `details`
 * (credential NAME, scope, reason). Served exclusively to the operator CLI
 * (`sanctuary-secrets audit`) — NEVER to the agent-facing `broker/audit_query`
 * tool, which uses the redacted {@link AuditSummary} above.
 */
export interface OperatorAuditSummary {
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
  /**
   * Per-secret-name mutex. Hardening wave 6 finding #64: two concurrent
   * addSecret() / rotateSecret() / deleteSecret() calls on the same name
   * MUST serialize cleanly. The keychain backend's `find-then-add` and
   * `find-then-delete-then-add` shapes (KeychainBackend.addSecret /
   * .rotateSecret) are not atomic against another caller racing the same
   * service-name; without serialization the second caller can observe a
   * stale "exists" check and either drop the new value or leave a
   * duplicate keychain entry.
   *
   * Implementation: an in-memory promise chain per name. Subsequent
   * callers `await` the chain tail and append their own work; failures
   * propagate to the failing caller without poisoning the chain for
   * later callers.
   */
  private readonly nameLocks = new Map<string, Promise<unknown>>();

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

  /**
   * Serialize `op` against any other in-flight write to the same secret
   * `name`. Per-name fairness only, distinct names run in parallel.
   * The current chain tail is used as the acceptance gate; we then
   * publish a new tail that swallows the operation's outcome so a
   * thrown error does not poison the next caller's wait.
   */
  private async withNameLock<T>(name: string, op: () => Promise<T>): Promise<T> {
    const previous = this.nameLocks.get(name) ?? Promise.resolve();
    let release: () => void = () => {};
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    // Publish the new tail before awaiting the previous tail so any
    // racing caller chains behind us, not behind `previous`.
    this.nameLocks.set(name, next);
    try {
      // Wait for the prior chain holder (ignore its outcome, failures
      // are reported to that caller, not propagated downstream).
      await previous.catch(() => {});
      return await op();
    } finally {
      release();
      // If we are still the chain tail, drop the entry so the map does
      // not grow without bound across the broker's lifetime.
      if (this.nameLocks.get(name) === next) {
        this.nameLocks.delete(name);
      }
    }
  }

  /**
   * Diagnostic-only: visible for tests so they can assert that distinct
   * names do not contend on a shared lock. Not part of the public broker
   * contract; do not consume from production code.
   */
  __nameLockCountForTests(): number {
    return this.nameLocks.size;
  }

  /** Ensure backend is initialized and unlocked. Audits the unlock. */
  async ensureUnlocked(passphrase: string): Promise<void> {
    await this.backend.ensureInitialized(passphrase);
    // Unlock provenance is recorded through the broker audit log; callers do not infer readiness from backend state alone.
    await this.auditLog.appendCritical({
      layer: "l3",
      operation: BROKER_OPS.BACKEND_UNLOCKED,
      identity_id: this.principalIdentityId,
      result: "success",
      details: { backend: this.backend.constructor.name },
    });
  }

  async addSecret(name: string, value: string): Promise<void> {
    await this.withNameLock(name, async () => {
      await this.backend.addSecret(name, value);
      // Audit after backend success only; a failed write cannot leave a false secret_added provenance row.
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_ADDED,
        identity_id: this.principalIdentityId,
        result: "success",
        details: { secret: name },
      });
    });
  }

  async rotateSecret(name: string, newValue: string): Promise<void> {
    await this.withNameLock(name, async () => {
      await this.backend.rotateSecret(name, newValue);
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_ROTATED,
        identity_id: this.principalIdentityId,
        result: "success",
        details: { secret: name },
      });
    });
  }

  async deleteSecret(name: string): Promise<void> {
    await this.withNameLock(name, async () => {
      await this.backend.deleteSecret(name);
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_DELETED,
        identity_id: this.principalIdentityId,
        result: "success",
        details: { secret: name },
      });
    });
  }

  async listSecretNames(): Promise<string[]> {
    return this.backend.listSecretNames();
  }

  grant(g: SkillSecretGrant): void {
    this.issuer.setGrant(g);
    void this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_GRANTED,
      this.principalIdentityId,
      { skill: g.skill, secret: g.secret, scope: g.scope, ttl_seconds: g.ttlSeconds ?? null }
    );
  }

  revoke(skill: string, secret: string): void {
    this.issuer.revokeGrant(skill, secret);
    void this.auditLog.append(
      "l3",
      BROKER_OPS.SECRET_REVOKED,
      this.principalIdentityId,
      { skill, secret }
    );
  }

  /**
   * OPERATOR-ONLY full grant inventory (every principal's grants). Used by
   * the `sanctuary secrets` CLI. An agent-facing surface must use
   * {@link getGrantsForCaller} instead — see BROKER-GRANT-INVENTORY-CROSS-CALLER.
   */
  getGrants(): SkillSecretGrant[] {
    return this.issuer.getGrants();
  }

  /**
   * Grant inventory scoped to one verified caller — the ONLY grant listing
   * an agent-facing surface (`broker/list_grants`) may return. `caller`
   * must be the server-verified claims for the request (skill/agent/
   * tenant/fortress/audience), never anything read from MCP call
   * arguments, matching the same verified-claims contract `issueToken`
   * enforces.
   */
  getGrantsForCaller(caller: VerifiedBrokerCallerClaims): SkillSecretGrant[] {
    return this.issuer.getGrantsForCaller(caller);
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
   * Drop expired tokens from the in-memory issuer map. Hardening wave 6
   * finding #86: previously expiry pruning depended on opportunistic
   * `pruneExpired()` calls; now the fortress-unlock initialization path
   * (openBroker -> after backend.ensureInitialized -> after Broker
   * construction) fires this once so each fortress-unlock cycle drops
   * stale bindings before any operator interaction.
   *
   * Returns the number of tokens removed. Safe to call repeatedly; idempotent.
   */
  pruneExpiredTokens(): number {
    return this.issuer.pruneExpired();
  }

  /**
   * Audit query restricted to broker-scoped operations, for the agent-facing
   * `broker/audit_query` MCP tool.
   *
   * Returns ONLY the allowlist-redacted agent view of each entry ({ timestamp,
   * operation, result, has_details }) — the SAME view every other agent-facing
   * audit read uses (redactAuditEntryForAgent). The raw broker `details` (the
   * credential NAME, granted/requested scope, ttl, the `scope_exceeds_grant`
   * reason, the tenant/audience/fortress claims) are NEVER returned (CISO HIGH,
   * 2026-06-16). When `identity_id` is supplied the result is scoped to that
   * caller's OWN broker entries, filtered BEFORE the limit so the limit bounds
   * the caller's own entries (CISO LOW, 2026-06-16).
   *
   * The full-fidelity broker audit (secret name, scope, reason) is an OPERATOR
   * need and is served off the operator CLI / `auditLog.query` directly — not
   * through this agent-facing tool.
   */
  async queryAudit(opts?: {
    since?: string;
    limit?: number;
    identity_id?: string;
  }): Promise<AuditSummary> {
    const { entries, total } = await this.mergeBrokerAuditEntries(opts);
    const limit = opts?.limit ?? 1000;
    // Allowlist redaction at the boundary means token scopes, secret names, and denial reasons never reach agent audit reads.
    const redacted = entries.map((e) => redactAuditEntryForAgent(e));
    return { entries: redacted.slice(-limit), total };
  }

  /**
   * OPERATOR-ONLY full-fidelity broker audit. Returns the raw `details` (secret
   * NAME, scope, reason) for the operator CLI (`sanctuary-secrets audit`). NEVER
   * call this from an agent-facing surface — that is what {@link queryAudit}
   * (the redacted view) is for.
   */
  async queryAuditOperator(opts?: {
    since?: string;
    limit?: number;
  }): Promise<OperatorAuditSummary> {
    const { entries, total } = await this.mergeBrokerAuditEntries(opts);
    const limit = opts?.limit ?? 1000;
    const full = entries.map((e) => ({
      timestamp: e.timestamp,
      operation: e.operation,
      result: e.result,
      details: e.details,
    }));
    return { entries: full.slice(-limit), total };
  }

  /**
   * Shared scan: BROKER_OPS filtered, merged, and time-sorted. Returns the RAW
   * AuditEntry rows; each public query method then projects to its own
   * fidelity (redacted agent view vs full operator view). AuditLog.query filters
   * by a single operation, so we call once per broker op and merge.
   */
  private async mergeBrokerAuditEntries(opts?: {
    since?: string;
    limit?: number;
    identity_id?: string;
  }): Promise<{ entries: AuditEntry[]; total: number }> {
    const allOps = Object.values(BROKER_OPS);
    const merged: AuditEntry[] = [];
    let total = 0;
    for (const op of allOps) {
      const r = await this.auditLog.query({
        since: opts?.since,
        layer: "l3",
        operation_type: op,
        identity_id: opts?.identity_id,
        limit: opts?.limit ?? 1000,
      });
      total += r.total;
      merged.push(...r.entries);
    }
    merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return { entries: merged, total };
  }
}
