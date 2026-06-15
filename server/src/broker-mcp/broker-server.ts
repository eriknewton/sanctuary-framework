/**
 * Sanctuary MCP Server — Standalone Broker MCP Interface
 *
 * Exposes the Secret Broker as an MCP server so ANY harness speaking MCP
 * — OpenClaw, Cline, Claude Code, Cursor, LangGraph, Mastra, CrewAI, etc.
 * — can consume it. This is the GTM wedge for v0.10.0: the broker is not
 * coupled to Sanctuary-wrapped agents; it is a drop-in sovereignty
 * primitive for every MCP ecosystem.
 *
 * Four tools are exposed:
 *   broker/request_token    — skill asks for a scoped ephemeral token.
 *   broker/read_secret      — skill exchanges token for credential value.
 *   broker/list_grants      — self-introspection: what grants exist.
 *   broker/audit_query      — read-only audit trail (no values).
 *
 * Denials return generic error messages; the reason is in the audit log,
 * never in the response. This matches the Sanctuary denial-opacity rule.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { Broker } from "../l3-disclosure/broker/broker.js";
import { SANCTUARY_VERSION } from "../config.js";
import {
  BrokerDeniedError,
  BrokerTokenExpiredError,
  BrokerTokenUnknownError,
  type VerifiedBrokerCallerClaims,
} from "../l3-disclosure/broker/token-issuer.js";

// Re-export the shared package version. v0.10.0-rc.2 had an inlined local
// require of package.json at this file's source depth — correct from src/
// but one level too high from the bundled server/dist/cli.js, so the
// broker-server subcommand died at module-load with "Cannot find module".
// Routing the version through config.SANCTUARY_VERSION keeps the require
// concern in exactly one file (config.ts), where source-depth and
// bundle-depth happen to match. See Wiki/status/nsa-soak-report-v010-rc2-2026-04-18.md
// Finding 1 for the full postmortem.
const PKG_VERSION = SANCTUARY_VERSION;

export interface BrokerServerOptions {
  /** Verified harness/session skill identity. Never read from MCP args. */
  skill: string;
  /** Caller agent id surfaced in every audit entry. */
  agentId: string;
  /** Sanctuary identity_id — the principal authorizing issuance. */
  identityId: string;
  /** Tenant claim verified by the wrapping harness/session. */
  tenantId: string;
  /** Fortress claim verified by the wrapping harness/session. */
  fortressId: string;
  /** Intended token audience verified by the wrapping harness/session. */
  audience: string;
}

function ok(payload: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(payload) }],
  };
}

function genericError(message = "Broker denied") {
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true,
  };
}

export function createBrokerMcpServer(
  broker: Broker,
  opts: BrokerServerOptions
): Server {
  const server = new Server(
    {
      name: "sanctuary-broker",
      version: PKG_VERSION,
    },
    {
      capabilities: { tools: {} },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "broker/request_token",
        description:
          "Request a scoped ephemeral token for a named secret. The requested skill must match the verified caller skill and have a broker-policy.json grant. Returns {token, expires_at} on success; generic error on denial.",
        inputSchema: {
          type: "object",
          properties: {
            skill: { type: "string", description: "Requesting skill name (must match the granted skill)." },
            secret: { type: "string", description: "Name of the secret to read." },
            scope: {
              type: "string",
              enum: ["read", "rotate"],
              description: "Requested scope. Must be <= the granted scope.",
            },
            ttl_seconds: {
              type: "number",
              description: "TTL override (seconds). Clamped at broker max.",
            },
          },
          required: ["skill", "secret"],
        },
      },
      {
        name: "broker/read_secret",
        description:
          "Exchange a previously-issued token for the raw credential value. Returns {value} on success; generic error on denial, expiry, or unknown token. Token may be used multiple times within its TTL.",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string", description: "Token previously returned by broker/request_token." },
          },
          required: ["token"],
        },
      },
      {
        name: "broker/list_grants",
        description:
          "List the currently-active grants visible to this broker. Names only — no secret values.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "broker/audit_query",
        description:
          "Query your own broker-scoped audit trail (token request/issue/deny/read for your identity). Each entry is reduced to a fixed safe view ({ timestamp, operation, result, has_details }) — never the secret name, the granted/requested scope, the ttl, the denial reason, or any tenant/audience claim; those are operator-only.",
        inputSchema: {
          type: "object",
          properties: {
            since: {
              type: "string",
              description: "ISO 8601 timestamp; only entries at or after this time are returned.",
            },
            limit: {
              type: "number",
              description: "Max entries to return (default 200).",
            },
          },
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: rawArgs } = request.params;
    const args = (rawArgs ?? {}) as Record<string, unknown>;

    try {
      switch (name) {
        case "broker/request_token": {
          const claimedSkill = requireString(args, "skill");
          const secret = requireString(args, "secret");
          const scopeRaw = optionalString(args, "scope");
          const scope = scopeRaw === "rotate" ? "rotate" : scopeRaw === "read" ? "read" : undefined;
          const ttl = optionalNumber(args, "ttl_seconds");
          const caller = verifiedCallerClaims(opts);
          const binding = await broker.issueToken({
            skill: claimedSkill,
            secret,
            caller,
            requestedScope: scope,
            ttlSeconds: ttl,
          });
          return ok({
            token: binding.token,
            expires_at: binding.expires_at,
            scope: binding.scope,
          });
        }

        case "broker/read_secret": {
          const token = requireString(args, "token");
          const value = await broker.readViaToken(token);
          return ok({ value });
        }

        case "broker/list_grants": {
          const grants = broker.getGrants().map((g) => ({
            skill: g.skill,
            secret: g.secret,
            scope: g.scope,
            agent: g.agent ?? null,
            tenant_id: g.tenant_id ?? null,
            fortress_id: g.fortress_id ?? null,
            audience: g.audience ?? null,
            ttl_seconds: g.ttlSeconds ?? null,
          }));
          return ok({ grants });
        }

        case "broker/audit_query": {
          const since = optionalString(args, "since");
          const limit = optionalNumber(args, "limit");
          // Scope to the verified caller's OWN broker entries and return the
          // allowlist-redacted view only (no secret name / scope / ttl / reason
          // / tenant). The identity is the harness-verified principal, never
          // read from MCP args.
          const summary = await broker.queryAudit({
            since,
            limit,
            identity_id: opts.identityId,
          });
          return ok(summary);
        }

        default:
          return genericError(`Unknown tool: ${name}`);
      }
    } catch (e) {
      if (
        e instanceof BrokerDeniedError ||
        e instanceof BrokerTokenExpiredError ||
        e instanceof BrokerTokenUnknownError
      ) {
        // Generic denial message; specific reason is in the audit trail.
        return genericError("Broker denied");
      }
      // Unexpected errors surface their name but NEVER the secret value.
      const errMsg = e instanceof Error ? `${e.name}: ${e.message}` : String(e);
      return genericError(`Broker error: ${errMsg}`);
    }
  });

  return server;
}

function requireString(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new BrokerDeniedError(`Missing or empty: ${key}`);
  }
  return v;
}

function optionalString(args: Record<string, unknown>, key: string): string | undefined {
  const v = args[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function optionalNumber(args: Record<string, unknown>, key: string): number | undefined {
  const v = args[key];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

function verifiedCallerClaims(opts: BrokerServerOptions): VerifiedBrokerCallerClaims {
  return {
    skill: opts.skill,
    agent: opts.agentId,
    identity_id: opts.identityId,
    tenant_id: opts.tenantId,
    fortress_id: opts.fortressId,
    audience: opts.audience,
  };
}
