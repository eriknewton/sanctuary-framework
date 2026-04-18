/**
 * Sanctuary MCP Server — L3 Secret Broker: Scoped Ephemeral Token Issuer
 *
 * Issues short-lived tokens bound to a (skill, secret, scope) triple. A
 * token is the only way a skill can exchange its declared policy scope
 * for a concrete credential read. Tokens are random 32-byte base64url
 * strings — unguessable. State is in-memory only: tokens survive the
 * broker process; a restart invalidates all tokens and skills re-request.
 *
 * This module is intentionally independent of the storage backend — it
 * calls into `Backend.readSecret` only at the moment of read, so the
 * same token issuer composes with every future backend (Linux libsecret,
 * Windows Credential Manager, Vault, etc.).
 *
 * Audit integration: every issuance, denial, and read generates an
 * AuditEntry at layer "l3". See BROKER_OPS in l2-operational/audit-log
 * for the operation-name catalog.
 */

import { randomBytes } from "node:crypto";
import type { Backend, SecretScope } from "./backend-interface.js";
import type { AuditLog } from "../../l2-operational/audit-log.js";
import { BROKER_OPS } from "../../l2-operational/audit-log.js";

export const DEFAULT_TOKEN_TTL_SECONDS = 15 * 60;
export const MAX_TOKEN_TTL_SECONDS = 60 * 60; // 1 hour cap

export interface SkillSecretGrant {
  /** Name of the skill this grant applies to. */
  skill: string;
  /** Name of the secret as stored in the broker backend. */
  secret: string;
  /** Maximum scope this skill can request for this secret. */
  scope: SecretScope;
  /** Default TTL (seconds) when the skill does not specify one. */
  ttlSeconds?: number;
}

export interface TokenBinding {
  token: string;
  skill: string;
  secret: string;
  scope: SecretScope;
  agent: string;
  /** Sanctuary identity id of the principal that approved issuance. */
  identity_id: string;
  issued_at: string;
  expires_at: string;
}

export interface IssueTokenRequest {
  skill: string;
  secret: string;
  /** Requested scope; must be <= grant.scope. */
  requestedScope?: SecretScope;
  /** Requested TTL (seconds); capped at MAX_TOKEN_TTL_SECONDS. */
  ttlSeconds?: number;
  /** Caller agent id (opaque; for audit). */
  agent: string;
  /** Identity id of the principal authorizing this issuance (for audit). */
  identity_id: string;
}

export class BrokerDeniedError extends Error {
  constructor(message = "Broker denied") {
    super(message);
    this.name = "BrokerDeniedError";
  }
}

export class BrokerTokenExpiredError extends Error {
  constructor() {
    super("Broker token expired");
    this.name = "BrokerTokenExpiredError";
  }
}

export class BrokerTokenUnknownError extends Error {
  constructor() {
    super("Broker token not recognized");
    this.name = "BrokerTokenUnknownError";
  }
}

export interface TokenIssuerOptions {
  /** Default TTL applied when neither grant nor request specifies one. */
  defaultTtlSeconds?: number;
  /** Max TTL regardless of caller request. */
  maxTtlSeconds?: number;
  /** Initial grants (typically loaded from policy). */
  grants?: SkillSecretGrant[];
  /** Required: Backend instance. */
  backend: Backend;
  /** Required: AuditLog for attestation. */
  auditLog: AuditLog;
  /** Clock, injectable for testing. Defaults to Date.now. */
  now?: () => number;
}

const SCOPE_RANK: Record<SecretScope, number> = { read: 1, rotate: 2 };

function scopeSatisfies(requested: SecretScope, grant: SecretScope): boolean {
  return SCOPE_RANK[requested] <= SCOPE_RANK[grant];
}

export class TokenIssuer {
  private readonly grants = new Map<string, SkillSecretGrant>();
  private readonly tokens = new Map<string, TokenBinding>();
  private readonly backend: Backend;
  private readonly auditLog: AuditLog;
  private readonly defaultTtlSeconds: number;
  private readonly maxTtlSeconds: number;
  private readonly now: () => number;

  constructor(opts: TokenIssuerOptions) {
    this.backend = opts.backend;
    this.auditLog = opts.auditLog;
    this.defaultTtlSeconds = opts.defaultTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    this.maxTtlSeconds = opts.maxTtlSeconds ?? MAX_TOKEN_TTL_SECONDS;
    this.now = opts.now ?? (() => Date.now());
    for (const g of opts.grants ?? []) this.setGrant(g);
  }

  /** Register or update a grant. Replaces any existing grant for (skill, secret). */
  setGrant(grant: SkillSecretGrant): void {
    this.grants.set(grantKey(grant.skill, grant.secret), { ...grant });
  }

  /**
   * Revoke a grant. Outstanding tokens for it remain in the map but the
   * per-read grant recheck in `readViaToken` will deny them with a
   * `grant_revoked` audit entry. We keep the token entries so the audit
   * trail records *why* the denial happened (denied vs. unknown).
   */
  revokeGrant(skill: string, secret: string): void {
    this.grants.delete(grantKey(skill, secret));
  }

  getGrants(): SkillSecretGrant[] {
    return Array.from(this.grants.values());
  }

  /**
   * Request a token. Returns the opaque token string on success; throws
   * BrokerDeniedError with a generic message on failure. The reason for
   * denial is recorded in the audit log but not returned to the caller.
   */
  async issueToken(req: IssueTokenRequest): Promise<TokenBinding> {
    const grant = this.grants.get(grantKey(req.skill, req.secret));
    const requestedScope: SecretScope = req.requestedScope ?? "read";

    if (!grant) {
      this.auditLog.append(
        "l3",
        BROKER_OPS.TOKEN_DENIED,
        req.identity_id,
        {
          skill: req.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          reason: "no_grant",
          agent: req.agent,
        },
        "failure"
      );
      throw new BrokerDeniedError();
    }
    if (!scopeSatisfies(requestedScope, grant.scope)) {
      this.auditLog.append(
        "l3",
        BROKER_OPS.TOKEN_DENIED,
        req.identity_id,
        {
          skill: req.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          granted_scope: grant.scope,
          reason: "scope_exceeds_grant",
          agent: req.agent,
        },
        "failure"
      );
      throw new BrokerDeniedError();
    }

    const ttl = clampTtl(
      req.ttlSeconds ?? grant.ttlSeconds ?? this.defaultTtlSeconds,
      this.maxTtlSeconds
    );
    const nowMs = this.now();
    const token = randomBytes(32).toString("base64url");
    const binding: TokenBinding = {
      token,
      skill: req.skill,
      secret: req.secret,
      scope: requestedScope,
      agent: req.agent,
      identity_id: req.identity_id,
      issued_at: new Date(nowMs).toISOString(),
      expires_at: new Date(nowMs + ttl * 1000).toISOString(),
    };
    this.tokens.set(token, binding);
    this.auditLog.append(
      "l3",
      BROKER_OPS.TOKEN_ISSUED,
      req.identity_id,
      {
        skill: req.skill,
        secret: req.secret,
        scope: requestedScope,
        agent: req.agent,
        expires_at: binding.expires_at,
        ttl_seconds: ttl,
      },
      "success"
    );
    return binding;
  }

  /**
   * Exchange a token for a secret value. Single-use semantics are NOT
   * enforced — the token may be used multiple times within its TTL, but
   * every use is audited. Throws on unknown, expired, or revoked tokens.
   * NEVER returns the secret value in an error; NEVER logs the value.
   */
  async readViaToken(token: string): Promise<string> {
    const binding = this.tokens.get(token);
    if (!binding) {
      // No principal known, so log against "unknown" identity.
      this.auditLog.append(
        "l3",
        BROKER_OPS.SECRET_READ,
        "unknown",
        { reason: "token_unknown" },
        "failure"
      );
      throw new BrokerTokenUnknownError();
    }
    const nowMs = this.now();
    if (nowMs >= Date.parse(binding.expires_at)) {
      this.tokens.delete(token);
      this.auditLog.append(
        "l3",
        BROKER_OPS.SECRET_READ,
        binding.identity_id,
        {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          reason: "token_expired",
        },
        "failure"
      );
      throw new BrokerTokenExpiredError();
    }

    // Re-check grant — it may have been revoked since issuance.
    const grant = this.grants.get(grantKey(binding.skill, binding.secret));
    if (!grant || !scopeSatisfies(binding.scope, grant.scope)) {
      this.tokens.delete(token);
      this.auditLog.append(
        "l3",
        BROKER_OPS.SECRET_READ,
        binding.identity_id,
        {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          reason: grant ? "scope_exceeds_current_grant" : "grant_revoked",
        },
        "failure"
      );
      throw new BrokerDeniedError();
    }

    // Read from backend. Errors propagate; we audit but do not leak the value.
    try {
      const value = await this.backend.readSecret(binding.secret);
      this.auditLog.append(
        "l3",
        BROKER_OPS.SECRET_READ,
        binding.identity_id,
        {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
        },
        "success"
      );
      return value;
    } catch (err) {
      this.auditLog.append(
        "l3",
        BROKER_OPS.SECRET_READ,
        binding.identity_id,
        {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          reason: "backend_error",
          error: errorName(err),
        },
        "failure"
      );
      throw err;
    }
  }

  /** Manually revoke a specific token. */
  revokeToken(token: string): boolean {
    return this.tokens.delete(token);
  }

  /** Count of currently-live tokens (for observability). */
  liveTokenCount(): number {
    return this.tokens.size;
  }

  /**
   * Drop expired tokens from the in-memory map. Called opportunistically;
   * not required for correctness (readViaToken also validates expiry).
   */
  pruneExpired(): number {
    const nowMs = this.now();
    let removed = 0;
    for (const [token, binding] of this.tokens) {
      if (nowMs >= Date.parse(binding.expires_at)) {
        this.tokens.delete(token);
        removed++;
      }
    }
    return removed;
  }
}

function grantKey(skill: string, secret: string): string {
  return `${skill}\u0000${secret}`;
}

function clampTtl(requested: number, max: number): number {
  if (!Number.isFinite(requested) || requested <= 0) return DEFAULT_TOKEN_TTL_SECONDS;
  return Math.min(Math.floor(requested), max);
}

function errorName(err: unknown): string {
  if (err instanceof Error) return err.name;
  return "UnknownError";
}
