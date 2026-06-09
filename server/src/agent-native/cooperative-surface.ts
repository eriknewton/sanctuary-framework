import { randomBytes } from "node:crypto";
import type { AuditEntry, AuditLog } from "../l2-operational/audit-log.js";
import type { IdentityManager } from "../l1-cognitive/tools.js";
import { toolResult, type ToolDefinition } from "../router.js";
import {
  canonicalJson,
  fixedDenial,
  FIXED_DENIAL_MESSAGE,
  normalizedArgsHash,
  OpaqueNamespaceRegistry,
  resolveActiveSessionIdentity,
  sha256,
  type SessionBinding,
} from "./safety-base.js";

type PrimitiveCaller = (
  name: string,
  args: Record<string, unknown>
) => Promise<Record<string, unknown>>;

interface HiddenMarker {
  namespace: string;
  key: string;
  version: number;
  content_hash: `sha256:${string}`;
  hidden_at: string;
  ttl_expires_at?: string;
}

interface EventCursor {
  cursor_id: string;
  owner_fingerprint: string;
  operation?: string;
  offset: number;
  opened_at: string;
  reads: number;
}

interface HelpProbeSummary {
  count: number;
  examples: string[];
  first_seen: string;
  last_seen: string;
}

export interface CooperativeSurfaceOptions {
  identityManager: IdentityManager;
  namespaceRegistry: OpaqueNamespaceRegistry;
  auditLog: AuditLog;
  currentSessionBinding: () => SessionBinding | undefined;
  primitiveTools: ToolDefinition[];
}

export function createAgentNativeCooperativeTools(
  options: CooperativeSurfaceOptions
): { tools: ToolDefinition[] } {
  const hidden = new Map<string, HiddenMarker>();
  const cursors = new Map<string, EventCursor>();
  const helpProbeSummaries = new Map<string, HelpProbeSummary>();

  const callPrimitive: PrimitiveCaller = async (name, args) => {
    const tool = options.primitiveTools.find((candidate) => candidate.name === name);
    if (!tool) throw new Error(`missing primitive tool: ${name}`);
    const result = await tool.handler(args);
    return JSON.parse(result.content[0]?.text ?? "{}") as Record<string, unknown>;
  };

  function active() {
    return resolveActiveSessionIdentity(options.currentSessionBinding());
  }

  function activeMemoryNamespace(): string {
    return options.namespaceRegistry.issueMemoryHandle(active().identity_id);
  }

  function hiddenKey(namespace: string, key: string): string {
    return `${active().requester_identity_fingerprint}:${namespace}:${key}`;
  }

  function stateContentHash(read: Record<string, unknown>): `sha256:${string}` {
    return sha256(String(read.value ?? ""));
  }

  function isVerifiedRead(read: Record<string, unknown>): boolean {
    return read.integrity_verified === true && read.signature_verified === true;
  }

  async function audit(
    operation: string,
    details: Record<string, unknown> = {},
    result: "success" | "failure" = "success"
  ): Promise<string> {
    let identityId = "system";
    try {
      identityId = active().identity_id;
    } catch {
      // Keep denial auditing fail-closed but non-throwing for missing sessions.
    }
    const auditRef = `audit:${operation}:${randomBytes(8).toString("hex")}`;
    await options.auditLog.appendCritical({
      layer: "l2",
      operation,
      identity_id: identityId,
      result,
      details: { audit_ref: auditRef, ...details },
    });
    return auditRef;
  }

  function deny(
    auditRef: string,
    remediation: "request_review" | "try_lower_scope" | "wait" = "request_review",
    retryAfter: null | "later" | "minutes" | "hours" = null
  ) {
    return toolResult(fixedDenial(auditRef, remediation, retryAfter));
  }

  function rememberPrimitiveArgs(args: Record<string, unknown>): Record<string, unknown> {
    const namespace =
      typeof (args.opts as Record<string, unknown> | undefined)?.namespace === "string"
        ? ((args.opts as Record<string, unknown>).namespace as string)
        : activeMemoryNamespace();
    const opts = (args.opts as Record<string, unknown> | undefined) ?? {};
    const metadata: Record<string, unknown> = {};
    if (typeof opts.ttl === "number") metadata.ttl_seconds = opts.ttl;
    if (Array.isArray(opts.tags)) metadata.tags = opts.tags;
    return {
      namespace,
      key: args.key,
      value: args.value,
      identity_id: active().identity_id,
      ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
    };
  }

  function recallPrimitiveArgs(args: Record<string, unknown>): Record<string, unknown> {
    const namespace =
      typeof (args.opts as Record<string, unknown> | undefined)?.namespace === "string"
        ? ((args.opts as Record<string, unknown>).namespace as string)
        : activeMemoryNamespace();
    return { namespace, key: args.key, verify_integrity: true };
  }

  function deletePrimitiveArgs(args: Record<string, unknown>): Record<string, unknown> {
    const namespace =
      typeof (args.opts as Record<string, unknown> | undefined)?.namespace === "string"
        ? ((args.opts as Record<string, unknown>).namespace as string)
        : activeMemoryNamespace();
    return {
      namespace,
      key: args.key,
      reason: typeof args.reason === "string" ? args.reason : "secure facade forget",
    };
  }

  function classifyIntent(intent: string): {
    safety_class: "ordinary" | "sensitive" | "gated";
    tool: string | null;
    example: Record<string, unknown> | null;
    why_sanctuary: string;
    remediation_class?: "request_review" | "try_lower_scope" | "wait";
    probe_key?: string;
  } {
    const normalized = intent.normalize("NFKC");
    const lower = normalized.toLowerCase();
    const decoded: string[] = [];
    for (const token of normalized.split(/[^a-z0-9+/=_-]+/i)) {
      if (token.length >= 8 && /^[a-z0-9+/=_-]+$/i.test(token)) {
        try {
          decoded.push(Buffer.from(token, "base64").toString("utf8").toLowerCase());
        } catch {
          // Not base64.
        }
      }
    }
    const haystack = [lower, lower.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/@/g, "a"), ...decoded].join(" ");
    const gated = [
      "delete",
      "forget",
      "erase",
      "export",
      "import",
      "identity bundle",
      "private key",
      "sign",
      "approval",
      "policy",
      "webhook",
      "callback",
      "http://",
      "https://",
      "other agent",
      "prior session",
      "widen",
    ];
    if (gated.some((needle) => haystack.includes(needle))) {
      return {
        safety_class: "gated",
        tool: haystack.includes("forget") || haystack.includes("delete") ? "sanctuary_forget" : null,
        example: { args: "<operator-approved placeholders only>" },
        why_sanctuary: "This request may need operator review before execution.",
        remediation_class: "request_review",
        probe_key: gated.find((needle) => haystack.includes(needle)),
      };
    }
    if (/\b(remember|store|save)\b/.test(haystack)) {
      return {
        safety_class: "ordinary",
        tool: "sanctuary_remember",
        example: { key: "user_tz", value: "America/Los_Angeles" },
        why_sanctuary: "State is encrypted, identity-bound, and audited.",
      };
    }
    if (/\b(recall|read|lookup|get)\b/.test(haystack)) {
      return {
        safety_class: "ordinary",
        tool: "sanctuary_recall",
        example: { key: "user_tz" },
        why_sanctuary: "Recall preserves verification status in the response.",
      };
    }
    return {
      safety_class: "sensitive",
      tool: null,
      example: null,
      why_sanctuary: "The request is ambiguous, so runnable guidance is suppressed.",
      remediation_class: "try_lower_scope",
      probe_key: "ambiguous",
    };
  }

  async function recordHelpProbe(intent: string, probeKey: string | undefined, safetyClass: string) {
    if (safetyClass === "ordinary") return;
    const activeIdentity = active();
    const summaryKey = `${activeIdentity.requester_identity_fingerprint}:${probeKey ?? "sensitive"}`;
    const now = new Date().toISOString();
    const current = helpProbeSummaries.get(summaryKey) ?? {
      count: 0,
      examples: [],
      first_seen: now,
      last_seen: now,
    };
    current.count += 1;
    current.last_seen = now;
    if (current.examples.length < 3 && !current.examples.includes(intent.slice(0, 120))) {
      current.examples.push(intent.slice(0, 120));
    }
    helpProbeSummaries.set(summaryKey, current);
    if (current.count === 1 || current.count % 5 === 0) {
      await audit("sanctuary_help_probe_summary", {
        safety_class: safetyClass,
        probe_key: probeKey ?? "sensitive",
        count: current.count,
        samples: current.examples,
      });
    }
  }

  function redactEvent(entry: AuditEntry, index: number): Record<string, unknown> {
    return {
      cursor_event_id: index,
      timestamp: entry.timestamp,
      layer: entry.layer,
      operation: entry.operation,
      result: entry.result,
      identity_match: entry.identity_id === active().identity_id,
      summary: {
        has_details: !!entry.details,
      },
    };
  }

  const tools: ToolDefinition[] = [
    {
      name: "sanctuary_remember",
      description: "Store active-session memory through encrypted state_write.",
      tool_class: "write",
      approvalTargetToolName: "state_write",
      approvalTargetArgs: rememberPrimitiveArgs,
      inputSchema: {
        type: "object",
        properties: {
          key: { type: "string" },
          value: { type: "string" },
          opts: {
            type: "object",
            properties: {
              namespace: { type: "string" },
              ttl: { type: "number" },
              tags: { type: "array", items: { type: "string" } },
            },
          },
        },
        required: ["key", "value"],
      },
      handler: async (args) => {
        try {
          const primitiveArgs = rememberPrimitiveArgs(args);
          const result = await callPrimitive("state_write", primitiveArgs);
          await audit("sanctuary_remember", {
            primitive_tool: "state_write",
            primitive_args_hash: normalizedArgsHash(primitiveArgs),
            facade_call: { key: args.key },
          });
          return toolResult({
            key: result.key,
            namespace_handle: result.namespace,
            audit_ref: "audit:sanctuary_remember",
          });
        } catch {
          return deny("audit:sanctuary_remember", "try_lower_scope");
        }
      },
    },
    {
      name: "sanctuary_recall",
      description: "Read active-session memory with verification preserved.",
      tool_class: "read",
      approvalTargetToolName: "state_read",
      approvalTargetArgs: recallPrimitiveArgs,
      inputSchema: {
        type: "object",
        properties: {
          key: { type: "string" },
          opts: {
            type: "object",
            properties: {
              namespace: { type: "string" },
              full: { type: "boolean" },
            },
          },
        },
        required: ["key"],
      },
      handler: async (args) => {
        try {
          const primitiveArgs = recallPrimitiveArgs(args);
          const marker = hidden.get(hiddenKey(primitiveArgs.namespace as string, primitiveArgs.key as string));
          const read = await callPrimitive("state_read", primitiveArgs);
          if (read.denied) return toolResult(read);
          if (!isVerifiedRead(read)) return deny("audit:sanctuary_recall");
          if (marker) {
            const markerMatches =
              marker.version === read.version &&
              marker.content_hash === stateContentHash(read);
            return markerMatches
              ? deny("audit:sanctuary_recall", "try_lower_scope")
              : deny("audit:sanctuary_recall", "request_review");
          }
          const auditRef = await audit("sanctuary_recall", {
            primitive_tool: "state_read",
            primitive_args_hash: normalizedArgsHash(primitiveArgs),
            verified: true,
          });
          if ((args.opts as Record<string, unknown> | undefined)?.full === true) {
            return toolResult({ ...read, verified: true, audit_ref: auditRef });
          }
          return toolResult({ value: read.value, verified: true, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_recall", "try_lower_scope");
        }
      },
    },
    {
      name: "sanctuary_hide",
      description: "Hide a key from default facade recall without erasing it.",
      tool_class: "write",
      approvalTargetToolName: "state_read",
      approvalTargetArgs: recallPrimitiveArgs,
      inputSchema: {
        type: "object",
        properties: {
          key: { type: "string" },
          opts: {
            type: "object",
            properties: {
              namespace: { type: "string" },
              ttl: { type: "number" },
            },
          },
        },
        required: ["key"],
      },
      handler: async (args) => {
        try {
          const primitiveArgs = recallPrimitiveArgs(args);
          const read = await callPrimitive("state_read", primitiveArgs);
          if (read.denied || !isVerifiedRead(read) || typeof read.version !== "number") {
            return deny("audit:sanctuary_hide");
          }
          const opts = (args.opts as Record<string, unknown> | undefined) ?? {};
          const ttl = typeof opts.ttl === "number" ? opts.ttl : undefined;
          const marker: HiddenMarker = {
            namespace: primitiveArgs.namespace as string,
            key: primitiveArgs.key as string,
            version: read.version,
            content_hash: stateContentHash(read),
            hidden_at: new Date().toISOString(),
            ...(ttl ? { ttl_expires_at: new Date(Date.now() + ttl * 1000).toISOString() } : {}),
          };
          hidden.set(hiddenKey(marker.namespace, marker.key), marker);
          const auditRef = await audit("sanctuary_hide", {
            marker_namespace: "_facade/hidden",
            marker_hash: sha256(canonicalJson(marker)),
            target: `${marker.namespace}/${marker.key}`,
          });
          return toolResult({
            hidden: true,
            erased: false,
            key: marker.key,
            namespace_handle: marker.namespace,
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_hide", "try_lower_scope");
        }
      },
    },
    {
      name: "sanctuary_forget",
      description: "Securely delete a key through state_delete with approval proof.",
      tool_class: "write",
      approvalTargetToolName: "state_delete",
      approvalTargetArgs: deletePrimitiveArgs,
      inputSchema: {
        type: "object",
        properties: {
          key: { type: "string" },
          mode: { type: "string", enum: ["secure"] },
          approval_ref: { type: "string" },
          reason: { type: "string" },
          opts: {
            type: "object",
            properties: { namespace: { type: "string" } },
          },
        },
        required: ["key", "mode", "approval_ref"],
      },
      handler: async (args) => {
        if (args.mode !== "secure") return deny("audit:sanctuary_forget");
        try {
          const primitiveArgs = deletePrimitiveArgs(args);
          const result = await callPrimitive("state_delete", primitiveArgs);
          hidden.delete(hiddenKey(primitiveArgs.namespace as string, primitiveArgs.key as string));
          const auditRef = await audit("sanctuary_forget", {
            primitive_tool: "state_delete",
            primitive_args_hash: normalizedArgsHash(primitiveArgs),
            facade_call: { key: args.key, mode: args.mode },
          });
          return toolResult({ ...result, mode: "secure", audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_forget");
        }
      },
    },
    {
      name: "sanctuary_help",
      description: "Policy-mediated guidance for Sanctuary tool use.",
      tool_class: "read",
      inputSchema: {
        type: "object",
        properties: { intent: { type: "string" } },
        required: ["intent"],
      },
      handler: async (args) => {
        try {
          const classified = classifyIntent(args.intent as string);
          await recordHelpProbe(args.intent as string, classified.probe_key, classified.safety_class);
          const auditRef = await audit("sanctuary_help", {
            safety_class: classified.safety_class,
            runnable_example: classified.safety_class === "ordinary",
          });
          return toolResult({ ...classified, probe_key: undefined, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_help", "wait");
        }
      },
    },
    {
      name: "sanctuary_who_am_i",
      description: "Return disclosable active-session identity facts.",
      tool_class: "read",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        try {
          const activeIdentity = active();
          const identity = options.identityManager.get(activeIdentity.identity_id);
          if (!identity) return deny("audit:sanctuary_who_am_i");
          const auditRef = await audit("sanctuary_who_am_i");
          return toolResult({
            label: identity.label,
            active_identity_fingerprint: activeIdentity.requester_identity_fingerprint,
            memory_namespace_handle: activeMemoryNamespace(),
            did: identity.did,
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_who_am_i");
        }
      },
    },
    {
      name: "sanctuary_active_protections",
      description: "Return positive-only coarse guarantees for this session.",
      tool_class: "read",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        try {
          active();
          const auditRef = await audit("sanctuary_active_protections");
          return toolResult({
            guarantees: [
              "state_encrypted_at_rest",
              "approval_gate_mediated",
              "append_only_audit_for_critical_operations",
              "opaque_memory_namespace_handles",
            ],
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_active_protections");
        }
      },
    },
    {
      name: "sanctuary_events_open_cursor",
      description: "Open an identity-bound pull cursor over redacted local events.",
      tool_class: "read",
      inputSchema: {
        type: "object",
        properties: {
          filter: {
            type: "object",
            properties: { operation: { type: "string" }, other_agent: { type: "string" }, callback: { type: "string" }, url: { type: "string" } },
          },
          opts: { type: "object", properties: { limit: { type: "number" } } },
        },
      },
      handler: async (args) => {
        try {
          const filter = (args.filter as Record<string, unknown> | undefined) ?? {};
          if (filter.callback || filter.url || filter.other_agent) return deny("audit:sanctuary_events_open_cursor");
          const activeIdentity = active();
          const cursor: EventCursor = {
            cursor_id: `cursor:${randomBytes(12).toString("hex")}`,
            owner_fingerprint: activeIdentity.requester_identity_fingerprint,
            operation: typeof filter.operation === "string" ? filter.operation : undefined,
            offset: 0,
            opened_at: new Date().toISOString(),
            reads: 0,
          };
          cursors.set(cursor.cursor_id, cursor);
          const auditRef = await audit("sanctuary_events_open_cursor", { operation: cursor.operation });
          return toolResult({ cursor: cursor.cursor_id, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_events_open_cursor", "wait");
        }
      },
    },
    {
      name: "sanctuary_events_read",
      description: "Read redacted local events from an identity-bound cursor.",
      tool_class: "read",
      inputSchema: {
        type: "object",
        properties: {
          cursor: { type: "string" },
          opts: { type: "object", properties: { limit: { type: "number" } } },
        },
        required: ["cursor"],
      },
      handler: async (args) => {
        try {
          const cursor = cursors.get(args.cursor as string);
          const activeIdentity = active();
          if (!cursor || cursor.owner_fingerprint !== activeIdentity.requester_identity_fingerprint) {
            return deny("audit:sanctuary_events_read");
          }
          cursor.reads += 1;
          if (cursor.reads > 10) return deny("audit:sanctuary_events_read", "wait", "minutes");
          const limit = Math.min(25, Math.max(1, Number((args.opts as Record<string, unknown> | undefined)?.limit ?? 10)));
          const queried = await options.auditLog.runAllowingIntegrityFindings(() =>
            options.auditLog.query({ operation_type: cursor.operation, limit: 500 })
          );
          if (queried.integrity_findings.length > 0) return deny("audit:sanctuary_events_read");
          const own = queried.entries.filter((entry) => entry.identity_id === activeIdentity.identity_id);
          const page = own.slice(cursor.offset, cursor.offset + limit);
          cursor.offset += page.length;
          const auditRef = await audit("sanctuary_events_read", { count: page.length });
          return toolResult({
            events: page.map((entry, index) => redactEvent(entry, cursor.offset + index)),
            next_cursor: cursor.cursor_id,
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_events_read", "wait");
        }
      },
    },
    {
      name: "sanctuary_events_close",
      description: "Close a pull event cursor.",
      tool_class: "write",
      inputSchema: { type: "object", properties: { cursor: { type: "string" } }, required: ["cursor"] },
      handler: async (args) => {
        try {
          const cursor = cursors.get(args.cursor as string);
          if (!cursor || cursor.owner_fingerprint !== active().requester_identity_fingerprint) {
            return deny("audit:sanctuary_events_close");
          }
          cursors.delete(cursor.cursor_id);
          const auditRef = await audit("sanctuary_events_close");
          return toolResult({ closed: true, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_events_close");
        }
      },
    },
    {
      name: "sanctuary_audit_search",
      description: "Search own signed/default audit history with integrity checks.",
      tool_class: "read",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string" },
          scope: { type: "string", enum: ["own_signed"] },
          limit: { type: "number" },
        },
        required: ["query"],
      },
      handler: async (args) => {
        try {
          if (args.scope && args.scope !== "own_signed") return deny("audit:sanctuary_audit_search");
          const activeIdentity = active();
          const queried = await options.auditLog.runAllowingIntegrityFindings(() =>
            options.auditLog.query({ limit: 500 })
          );
          if (queried.integrity_findings.length > 0) return deny("audit:sanctuary_audit_search");
          const needle = String(args.query).toLowerCase();
          const limit = Math.min(25, Math.max(1, Number(args.limit ?? 10)));
          const matches = queried.entries
            .filter((entry) => entry.identity_id === activeIdentity.identity_id)
            .filter((entry) => `${entry.operation} ${canonicalJson(entry.details ?? {})}`.toLowerCase().includes(needle))
            .slice(-limit)
            .map((entry, index) => ({
              audit_ref: `audit:search:${index}`,
              timestamp: entry.timestamp,
              operation: entry.operation,
              verification: "verified_against_audit_chain",
              summary: { result: entry.result },
            }));
          const auditRef = await audit("sanctuary_audit_search", {
            scope: "own_signed",
            result_count: matches.length,
            derived_index_label: "audit-search-index",
          });
          return toolResult({ scope: "own_signed", results: matches, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_audit_search");
        }
      },
    },
    {
      name: "sanctuary_compound_execute",
      description: "Execute a small plan with up-front approval binding for gated steps.",
      tool_class: "write",
      inputSchema: {
        type: "object",
        properties: {
          steps: { type: "array", items: { type: "object" } },
          approvals: { type: "object" },
        },
        required: ["steps"],
      },
      handler: async (args) => {
        try {
          const steps = Array.isArray(args.steps) ? args.steps as Record<string, unknown>[] : [];
          const planSteps = steps.map((step, index) => {
            const tool = String(step.tool ?? "");
            const stepArgs = (step.args && typeof step.args === "object" && !Array.isArray(step.args))
              ? step.args as Record<string, unknown>
              : {};
            const primitive =
              tool === "sanctuary_forget" ? deletePrimitiveArgs(stepArgs) :
              tool === "sanctuary_remember" ? rememberPrimitiveArgs(stepArgs) :
              tool === "sanctuary_hide" || tool === "sanctuary_recall" ? recallPrimitiveArgs(stepArgs) :
              null;
            const primitiveTool =
              tool === "sanctuary_forget" ? "state_delete" :
              tool === "sanctuary_remember" ? "state_write" :
              tool === "sanctuary_hide" || tool === "sanctuary_recall" ? "state_read" :
              null;
            if (!primitive || !primitiveTool) throw new Error(FIXED_DENIAL_MESSAGE);
            return {
              step_id: `step-${index + 1}`,
              tool,
              args: stepArgs,
              primitive_tool: primitiveTool,
              normalized_args_hash: normalizedArgsHash(primitive),
              primitive,
              risk_tier: primitiveTool === "state_delete" ? 1 : 3,
            };
          });
          const planHash = sha256(canonicalJson(planSteps.map((step) => ({
            step_id: step.step_id,
            primitive_tool: step.primitive_tool,
            normalized_args_hash: step.normalized_args_hash,
            risk_tier: step.risk_tier,
          }))));
          const approvals = (args.approvals && typeof args.approvals === "object" && !Array.isArray(args.approvals))
            ? args.approvals as Record<string, unknown>
            : {};
          for (const step of planSteps) {
            if (step.risk_tier === 1 && typeof approvals[step.step_id] !== "string") {
              const auditRef = await audit("sanctuary_compound_execute", {
                plan_hash: planHash,
                failed_step: step.step_id,
                skipped_steps: planSteps.filter((candidate) => candidate.step_id !== step.step_id).map((candidate) => candidate.step_id),
                release_not_consume: true,
              }, "failure");
              return toolResult({
                status: "partial_failed",
                completed_steps: [],
                failed_step: step.step_id,
                skipped_steps: planSteps.filter((candidate) => candidate.step_id !== step.step_id).map((candidate) => candidate.step_id),
                audit_ref: auditRef,
              });
            }
          }
          const completed: string[] = [];
          for (const step of planSteps) {
            const result =
              step.tool === "sanctuary_remember" ? await callPrimitive("state_write", step.primitive) :
              step.tool === "sanctuary_recall" || step.tool === "sanctuary_hide" ? await callPrimitive("state_read", step.primitive) :
              await callPrimitive("state_delete", step.primitive);
            if (result.denied || result.error) {
              const auditRef = await audit("sanctuary_compound_execute", {
                plan_hash: planHash,
                completed_steps: completed,
                failed_step: step.step_id,
                release_not_consume: true,
              }, "failure");
              return toolResult({ status: "partial_failed", completed_steps: completed, failed_step: step.step_id, audit_ref: auditRef });
            }
            completed.push(step.step_id);
          }
          const auditRef = await audit("sanctuary_compound_execute", { plan_hash: planHash, completed_steps: completed });
          return toolResult({ status: "completed", plan_hash: planHash, completed_steps: completed, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_compound_execute");
        }
      },
    },
  ];

  return { tools };
}
