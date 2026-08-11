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
 * AuditEntry at layer "l3". See BROKER_OPS in operational/audit-log
 * for the operation-name catalog.
 */

import { randomBytes } from "node:crypto";
import type { Backend, SecretScope } from "./backend-interface.js";
import type { AuditLog } from "../../operational/audit-log.js";
import { BROKER_OPS } from "../../operational/audit-log.js";

export const DEFAULT_TOKEN_TTL_SECONDS = 15 * 60;
export const MAX_TOKEN_TTL_SECONDS = 60 * 60; // 1 hour cap

/**
 * Global ceiling on live (unexpired) tokens across every skill and caller.
 * Derivation: a generous fleet-scale headroom of ~40 concurrently-granted
 * skills times ~50 live tokens each (a skill re-requesting well inside its
 * own default TTL window) rounds up to 2000. This bounds the issuer's
 * memory to a small, fixed footprint regardless of how many tokens have
 * ever been requested (BROKER-TOKEN-STORE-UNBOUNDED) — issuance fails
 * closed once the live map hits this size, it never grows past it.
 */
export const MAX_LIVE_TOKENS_GLOBAL = 2000;

/**
 * Per-caller (skill+agent) ceiling on live tokens. Derivation: a legitimate
 * caller holds at most a handful of concurrent scoped tokens (read/rotate,
 * a few distinct secrets, occasional retries) — realistic use stays in the
 * single digits. 100 is far above that while still turning a runaway or
 * malicious request_token loop from one caller into a small, fixed
 * per-caller footprint instead of unbounded growth.
 */
export const MAX_LIVE_TOKENS_PER_CALLER = 100;

export interface SkillSecretGrant {
  /** Name of the skill this grant applies to. */
  skill: string;
  /** Name of the secret as stored in the broker backend. */
  secret: string;
  /** Maximum scope this skill can request for this secret. */
  scope: SecretScope;
  /** Optional caller agent constraint. */
  agent?: string;
  /** Optional tenant constraint. */
  tenant_id?: string;
  /** Optional fortress constraint. */
  fortress_id?: string;
  /** Optional token audience constraint. */
  audience?: string;
  /** Default TTL (seconds) when the skill does not specify one. */
  ttlSeconds?: number;
}

export interface VerifiedBrokerCallerClaims {
  /** Verified harness/session skill name. Never sourced from MCP args. */
  skill: string;
  /** Verified caller agent id. */
  agent: string;
  /** Sanctuary identity id of the principal that approved issuance. */
  identity_id: string;
  /** Tenant scope this caller is bound to. */
  tenant_id: string;
  /** Fortress scope this caller is bound to. */
  fortress_id: string;
  /** Intended token audience. */
  audience: string;
}

export interface TokenBinding {
  token: string;
  skill: string;
  secret: string;
  scope: SecretScope;
  agent: string;
  /** Sanctuary identity id of the principal that approved issuance. */
  identity_id: string;
  tenant_id: string;
  fortress_id: string;
  audience: string;
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
  /** Verified harness/session claims authorizing this issuance. */
  caller: VerifiedBrokerCallerClaims;
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
  /** Global live-token cap override. See MAX_LIVE_TOKENS_GLOBAL for the default and its derivation. */
  maxLiveTokensGlobal?: number;
  /** Per-caller live-token cap override. See MAX_LIVE_TOKENS_PER_CALLER for the default and its derivation. */
  maxLiveTokensPerCaller?: number;
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
  private readonly maxLiveTokensGlobal: number;
  private readonly maxLiveTokensPerCaller: number;
  private readonly now: () => number;

  constructor(opts: TokenIssuerOptions) {
    this.backend = opts.backend;
    this.auditLog = opts.auditLog;
    this.defaultTtlSeconds = opts.defaultTtlSeconds ?? DEFAULT_TOKEN_TTL_SECONDS;
    this.maxTtlSeconds = opts.maxTtlSeconds ?? MAX_TOKEN_TTL_SECONDS;
    this.maxLiveTokensGlobal = opts.maxLiveTokensGlobal ?? MAX_LIVE_TOKENS_GLOBAL;
    this.maxLiveTokensPerCaller = opts.maxLiveTokensPerCaller ?? MAX_LIVE_TOKENS_PER_CALLER;
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

  /**
   * OPERATOR-ONLY full inventory. Every grant regardless of principal — this
   * is what the operator CLI (`sanctuary secrets list`) shows. An
   * agent-facing surface MUST use {@link getGrantsForCaller} instead
   * (BROKER-GRANT-INVENTORY-CROSS-CALLER): this method does not filter by
   * caller identity at all.
   */
  getGrants(): SkillSecretGrant[] {
    return Array.from(this.grants.values());
  }

  /**
   * Grants visible to one verified caller: exactly the grants whose skill
   * matches the caller's verified skill and whose optional
   * agent/tenant/fortress/audience constraints (when present on the grant)
   * match the caller's verified claims. Reuses `grantClaimMismatch`, the
   * same check `issueToken` enforces, so "visible in list_grants" and
   * "issuable via request_token" never diverge. `caller` must be the
   * server-verified claims for this request, never anything sourced from
   * MCP call arguments.
   */
  getGrantsForCaller(caller: VerifiedBrokerCallerClaims): SkillSecretGrant[] {
    return this.getGrants().filter(
      (g) => g.skill === caller.skill && grantClaimMismatch(g, caller) === null
    );
  }

  /**
   * Request a token. Returns the opaque token string on success; throws
   * BrokerDeniedError with a generic message on failure. The reason for
   * denial is recorded in the audit log but not returned to the caller.
   */
  async issueToken(req: IssueTokenRequest): Promise<TokenBinding> {
    // Prune BEFORE every issuance attempt (not just once at broker open, see
    // openBroker) — a caller that requests tokens in a loop must not be able
    // to outrun opportunistic pruning and accumulate unbounded expired
    // entries in the live map (BROKER-TOKEN-STORE-UNBOUNDED).
    this.pruneExpired();

    const requestedScope: SecretScope = req.requestedScope ?? "read";
    if (req.skill !== req.caller.skill) {
      // Skill identity is taken from verified caller claims; an MCP argument cannot mint a token for another skill.
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.TOKEN_DENIED,
        identity_id: req.caller.identity_id,
        result: "failure",
        details: {
          skill: req.skill,
          verified_skill: req.caller.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          reason: "caller_skill_mismatch",
          agent: req.caller.agent,
          tenant_id: req.caller.tenant_id,
          fortress_id: req.caller.fortress_id,
          audience: req.caller.audience,
        },
      });
      throw new BrokerDeniedError();
    }

    const grant = this.grants.get(grantKey(req.caller.skill, req.secret));

    if (!grant) {
      // No grant means deny with an audit reason; absence of policy never widens broker access.
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.TOKEN_DENIED,
        identity_id: req.caller.identity_id,
        result: "failure",
        details: {
          skill: req.caller.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          reason: "no_grant",
          agent: req.caller.agent,
          tenant_id: req.caller.tenant_id,
          fortress_id: req.caller.fortress_id,
          audience: req.caller.audience,
        },
      });
      throw new BrokerDeniedError();
    }
    const claimMismatch = grantClaimMismatch(grant, req.caller);
    if (claimMismatch) {
      // Tenant, fortress, audience, and agent constraints are rechecked against verified claims before token issuance.
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.TOKEN_DENIED,
        identity_id: req.caller.identity_id,
        result: "failure",
        details: {
          skill: req.caller.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          reason: "caller_claim_mismatch",
          claim: claimMismatch,
          agent: req.caller.agent,
          tenant_id: req.caller.tenant_id,
          fortress_id: req.caller.fortress_id,
          audience: req.caller.audience,
        },
      });
      throw new BrokerDeniedError();
    }
    if (!scopeSatisfies(requestedScope, grant.scope)) {
      // Requested scope must be no stronger than the grant, so callers cannot self-upgrade read into rotate.
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.TOKEN_DENIED,
        identity_id: req.caller.identity_id,
        result: "failure",
        details: {
          skill: req.caller.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          granted_scope: grant.scope,
          reason: "scope_exceeds_grant",
          agent: req.caller.agent,
          tenant_id: req.caller.tenant_id,
          fortress_id: req.caller.fortress_id,
          audience: req.caller.audience,
        },
      });
      throw new BrokerDeniedError();
    }

    // Fail-closed caps, checked only once the request is otherwise
    // authorized so an unauthorized probe cannot use capacity denials as a
    // side channel. Both caps are rechecked on every issuance (post-prune
    // above), so an attacker cannot get ahead of them by issuing faster
    // than any background sweep.
    if (this.tokens.size >= this.maxLiveTokensGlobal) {
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.TOKEN_DENIED,
        identity_id: req.caller.identity_id,
        result: "failure",
        details: {
          skill: req.caller.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          reason: "token_store_at_capacity",
          live_tokens: this.tokens.size,
          cap: this.maxLiveTokensGlobal,
          agent: req.caller.agent,
          tenant_id: req.caller.tenant_id,
          fortress_id: req.caller.fortress_id,
          audience: req.caller.audience,
        },
      });
      throw new BrokerDeniedError();
    }
    const callerLiveCount = this.countLiveTokensForCaller(req.caller.skill, req.caller.agent);
    if (callerLiveCount >= this.maxLiveTokensPerCaller) {
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.TOKEN_DENIED,
        identity_id: req.caller.identity_id,
        result: "failure",
        details: {
          skill: req.caller.skill,
          secret: req.secret,
          requested_scope: requestedScope,
          reason: "caller_token_quota_exceeded",
          live_tokens_for_caller: callerLiveCount,
          cap: this.maxLiveTokensPerCaller,
          agent: req.caller.agent,
          tenant_id: req.caller.tenant_id,
          fortress_id: req.caller.fortress_id,
          audience: req.caller.audience,
        },
      });
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
      skill: req.caller.skill,
      secret: req.secret,
      scope: requestedScope,
      agent: req.caller.agent,
      identity_id: req.caller.identity_id,
      tenant_id: req.caller.tenant_id,
      fortress_id: req.caller.fortress_id,
      audience: req.caller.audience,
      issued_at: new Date(nowMs).toISOString(),
      expires_at: new Date(nowMs + ttl * 1000).toISOString(),
    };
    await this.auditLog.appendCritical({
      layer: "l3",
      operation: BROKER_OPS.TOKEN_ISSUED,
      identity_id: req.caller.identity_id,
      result: "success",
      details: {
        skill: req.caller.skill,
        secret: req.secret,
        scope: requestedScope,
        agent: req.caller.agent,
        tenant_id: req.caller.tenant_id,
        fortress_id: req.caller.fortress_id,
        audience: req.caller.audience,
        expires_at: binding.expires_at,
        ttl_seconds: ttl,
      },
    });
    // The success audit is durable before the token enters the live map, so issued tokens have provenance.
    this.tokens.set(token, binding);
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
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_READ,
        identity_id: "unknown",
        result: "failure",
        details: { reason: "token_unknown" },
      });
      throw new BrokerTokenUnknownError();
    }
    const nowMs = this.now();
    if (nowMs >= Date.parse(binding.expires_at)) {
      // Expiry is enforced again at read time, so pruning is only hygiene and never the security boundary.
      this.tokens.delete(token);
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_READ,
        identity_id: binding.identity_id,
        result: "failure",
        details: {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          tenant_id: binding.tenant_id,
          fortress_id: binding.fortress_id,
          audience: binding.audience,
          reason: "token_expired",
        },
      });
      throw new BrokerTokenExpiredError();
    }

    // Re-check the live grant on every read; a token cannot outlive a revoked or narrowed policy.
    const grant = this.grants.get(grantKey(binding.skill, binding.secret));
    if (!grant || !scopeSatisfies(binding.scope, grant.scope)) {
      this.tokens.delete(token);
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_READ,
        identity_id: binding.identity_id,
        result: "failure",
        details: {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          tenant_id: binding.tenant_id,
          fortress_id: binding.fortress_id,
          audience: binding.audience,
          reason: grant ? "scope_exceeds_current_grant" : "grant_revoked",
        },
      });
      throw new BrokerDeniedError();
    }

    // Backend errors propagate after a redacted audit entry; the secret value is never logged or embedded in the error path.
    try {
      const value = await this.backend.readSecret(binding.secret);
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_READ,
        identity_id: binding.identity_id,
        result: "success",
        details: {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          tenant_id: binding.tenant_id,
          fortress_id: binding.fortress_id,
          audience: binding.audience,
        },
      });
      return value;
    } catch (err) {
      await this.auditLog.appendCritical({
        layer: "l3",
        operation: BROKER_OPS.SECRET_READ,
        identity_id: binding.identity_id,
        result: "failure",
        details: {
          skill: binding.skill,
          secret: binding.secret,
          scope: binding.scope,
          agent: binding.agent,
          tenant_id: binding.tenant_id,
          fortress_id: binding.fortress_id,
          audience: binding.audience,
          reason: "backend_error",
          // Full name AND message land ONLY in the operator-only audit
          // trail (OperatorAuditSummary / queryAuditOperator); the agent-facing
          // `broker/audit_query` tool redacts `details` away entirely
          // (redactAuditEntryForAgent), and the MCP surface in
          // broker-server.ts must never echo `err.message` into its response
          // — it can carry the secret NAME, an absolute keychain path, or raw
          // `security(1)` diagnostics (BROKER-BACKEND-DIAGNOSTIC-LEAK).
          error: errorName(err),
          error_message: errorMessage(err),
        },
      });
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
   * Count of currently-live tokens issued to one (skill, agent) caller.
   * Used to enforce {@link MAX_LIVE_TOKENS_PER_CALLER} at issuance time.
   */
  private countLiveTokensForCaller(skill: string, agent: string): number {
    let count = 0;
    for (const binding of this.tokens.values()) {
      if (binding.skill === skill && binding.agent === agent) count++;
    }
    return count;
  }

  /**
   * Drop expired tokens from the in-memory map. Called opportunistically —
   * at broker open (see openBroker) and now at the top of every issueToken
   * call — plus it is not required for correctness (readViaToken also
   * validates expiry on every use).
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

function grantClaimMismatch(
  grant: SkillSecretGrant,
  caller: VerifiedBrokerCallerClaims
): "agent" | "tenant_id" | "fortress_id" | "audience" | null {
  if (grant.agent !== undefined && grant.agent !== caller.agent) return "agent";
  if (grant.tenant_id !== undefined && grant.tenant_id !== caller.tenant_id) return "tenant_id";
  if (grant.fortress_id !== undefined && grant.fortress_id !== caller.fortress_id) {
    return "fortress_id";
  }
  if (grant.audience !== undefined && grant.audience !== caller.audience) return "audience";
  return null;
}

function clampTtl(requested: number, max: number): number {
  if (!Number.isFinite(requested) || requested <= 0) return DEFAULT_TOKEN_TTL_SECONDS;
  return Math.min(Math.floor(requested), max);
}

function errorName(err: unknown): string {
  if (err instanceof Error) return err.name;
  return "UnknownError";
}

/**
 * Operator-audit-only. Never route this into an agent-facing response —
 * see the invariant comment at the `backend_error` audit call site.
 */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
