import { randomBytes } from "node:crypto";
import type { AuditEntry, AuditLog } from "../operational/audit-log.js";
import { buildAgentSearchCorpus } from "../operational/agent-audit-redaction.js";
import type { IdentityManager } from "../cognitive/tools.js";
import { toolResult, type ToolDefinition } from "../router.js";
import type { StorageBackend } from "../storage/interface.js";
import {
  ApprovalProofStore,
  approvalEnvelopeHash,
  canonicalJson,
  deriveTargetResource,
  fixedDenial,
  FIXED_DENIAL_MESSAGE,
  normalizedArgsHash,
  OpaqueNamespaceRegistry,
  resolveActiveSessionIdentity,
  sha256,
  type SessionBinding,
} from "./safety-base.js";

const FACADE_HIDDEN_MARKER_NAMESPACE = "_facade/hidden";

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
  storage?: StorageBackend;
  approvalProofStore?: ApprovalProofStore;
}

export function createAgentNativeCooperativeTools(
  options: CooperativeSurfaceOptions
): { tools: ToolDefinition[] } {
  const hidden = new Map<string, HiddenMarker>();
  const cursors = new Map<string, EventCursor>();
  const helpProbeSummaries = new Map<string, HelpProbeSummary>();
  const approvalProofStore = options.approvalProofStore ?? new ApprovalProofStore();

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

  function facadeMemoryNamespace(args: Record<string, unknown>): string {
    const requested = (args.opts as Record<string, unknown> | undefined)?.namespace;
    if (requested === undefined) return activeMemoryNamespace();
    if (typeof requested !== "string" || !options.namespaceRegistry.isOpaqueMemoryHandle(requested)) {
      throw new Error(FIXED_DENIAL_MESSAGE);
    }
    options.namespaceRegistry.assertOwned(requested, options.currentSessionBinding());
    return requested;
  }

  function hiddenKey(namespace: string, key: string): string {
    return `${active().requester_identity_fingerprint}:${namespace}:${key}`;
  }

  function hiddenStorageKey(namespace: string, key: string): string {
    return sha256(hiddenKey(namespace, key)).replace("sha256:", "");
  }

  function encodeMarker(marker: HiddenMarker): Uint8Array {
    return Buffer.from(canonicalJson(marker), "utf8");
  }

  function decodeMarker(raw: Uint8Array): HiddenMarker | null {
    try {
      const parsed = JSON.parse(Buffer.from(raw).toString("utf8")) as Record<string, unknown>;
      if (
        typeof parsed.namespace !== "string" ||
        typeof parsed.key !== "string" ||
        typeof parsed.version !== "number" ||
        typeof parsed.content_hash !== "string" ||
        !parsed.content_hash.startsWith("sha256:") ||
        typeof parsed.hidden_at !== "string"
      ) {
        return null;
      }
      if (parsed.ttl_expires_at !== undefined && typeof parsed.ttl_expires_at !== "string") {
        return null;
      }
      return {
        namespace: parsed.namespace,
        key: parsed.key,
        version: parsed.version,
        content_hash: parsed.content_hash as `sha256:${string}`,
        hidden_at: parsed.hidden_at,
        ...(parsed.ttl_expires_at ? { ttl_expires_at: parsed.ttl_expires_at } : {}),
      };
    } catch {
      return null;
    }
  }

  async function loadHiddenMarker(namespace: string, key: string): Promise<HiddenMarker | "invalid" | undefined> {
    const cacheKey = hiddenKey(namespace, key);
    const cached = hidden.get(cacheKey);
    if (cached) {
      if (isHiddenMarkerExpired(cached)) {
        await garbageCollectExpiredHiddenMarker(cached);
        return undefined;
      }
      return cached;
    }
    if (!options.storage) return undefined;
    const raw = await options.storage.read(FACADE_HIDDEN_MARKER_NAMESPACE, hiddenStorageKey(namespace, key));
    if (!raw) return undefined;
    const marker = decodeMarker(raw);
    if (!marker || marker.namespace !== namespace || marker.key !== key) return "invalid";
    if (isHiddenMarkerExpired(marker)) {
      await garbageCollectExpiredHiddenMarker(marker);
      return undefined;
    }
    hidden.set(cacheKey, marker);
    return marker;
  }

  async function storeHiddenMarker(marker: HiddenMarker): Promise<void> {
    hidden.set(hiddenKey(marker.namespace, marker.key), marker);
    if (options.storage) {
      await options.storage.write(
        FACADE_HIDDEN_MARKER_NAMESPACE,
        hiddenStorageKey(marker.namespace, marker.key),
        encodeMarker(marker)
      );
    }
  }

  async function deleteHiddenMarker(namespace: string, key: string): Promise<void> {
    hidden.delete(hiddenKey(namespace, key));
    if (options.storage) {
      await options.storage.delete(
        FACADE_HIDDEN_MARKER_NAMESPACE,
        hiddenStorageKey(namespace, key),
        true
      );
    }
  }

  function isHiddenMarkerExpired(marker: HiddenMarker): boolean {
    return marker.ttl_expires_at !== undefined && Date.parse(marker.ttl_expires_at) <= Date.now();
  }

  async function garbageCollectExpiredHiddenMarker(marker: HiddenMarker): Promise<void> {
    await deleteHiddenMarker(marker.namespace, marker.key);
    await audit("sanctuary_hide_marker_gc", {
      marker_namespace: FACADE_HIDDEN_MARKER_NAMESPACE,
      marker_hash: sha256(canonicalJson(marker)),
      target: `${marker.namespace}/${marker.key}`,
      expired_at: marker.ttl_expires_at,
    });
  }

  function stateContentHash(read: Record<string, unknown>): `sha256:${string}` {
    return sha256(String(read.value ?? ""));
  }

  function isVerifiedRead(read: Record<string, unknown>): boolean {
    return read.integrity_verified === true && read.signature_verified === true;
  }

  function reserveApprovalForStep(params: {
    approval_ref: string;
    reservation_id: string;
    plan_hash: `sha256:${string}`;
    step_id: string;
    primitive_tool: string;
    primitive: Record<string, unknown>;
    risk_tier: 1 | 2 | 3;
  }): boolean {
    const record = approvalProofStore.get(params.approval_ref);
    if (!record) return false;
    const activeIdentity = active();
    const rebuilt = {
      ...record.envelope,
      tool_name: params.primitive_tool,
      normalized_args_hash: normalizedArgsHash(params.primitive),
      requester_identity_fingerprint: activeIdentity.requester_identity_fingerprint,
      target_resource: deriveTargetResource(params.primitive_tool, params.primitive),
      risk_tier: params.risk_tier,
      plan_hash: params.plan_hash,
      step_id: params.step_id,
    };
    const matches =
      approvalEnvelopeHash(rebuilt) === record.envelope_hash &&
      record.decision === "approved" &&
      !record.consumed &&
      Date.parse(record.envelope.expires_at) > Date.now() &&
      rebuilt.requester_identity_fingerprint === record.envelope.requester_identity_fingerprint &&
      rebuilt.nonce === record.envelope.nonce &&
      rebuilt.target_resource === record.envelope.target_resource &&
      rebuilt.tool_name === record.envelope.tool_name &&
      rebuilt.plan_hash === record.envelope.plan_hash &&
      rebuilt.step_id === record.envelope.step_id;
    if (!matches) return false;
    return approvalProofStore.reserveIfUnconsumed(params.approval_ref, params.reservation_id) !== null;
  }

  function releaseReservedApprovals(
    reserved: Array<{ approval_ref: string; reservation_id: string }>
  ): void {
    for (const approval of reserved) {
      approvalProofStore.releaseReservation(approval.approval_ref, approval.reservation_id);
    }
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
    const namespace = facadeMemoryNamespace(args);
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
    const namespace = facadeMemoryNamespace(args);
    return { namespace, key: args.key, verify_integrity: true };
  }

  function deletePrimitiveArgs(args: Record<string, unknown>): Record<string, unknown> {
    const namespace = facadeMemoryNamespace(args);
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
    const decoded = new Set<string>();
    try {
      decoded.add(decodeURIComponent(normalized).toLowerCase());
    } catch {
      // Not URL-encoded.
    }
    for (const token of normalized.split(/[^a-z0-9%+/=_-]+/i)) {
      if (token.includes("%")) {
        try {
          decoded.add(decodeURIComponent(token).toLowerCase());
        } catch {
          // Not URL-encoded.
        }
      }
      if (token.length >= 8 && /^[a-z0-9+/=_-]+$/i.test(token)) {
        try {
          decoded.add(Buffer.from(token, "base64").toString("utf8").toLowerCase());
        } catch {
          // Not base64.
        }
      }
    }
    const variants = [
      lower,
      lower.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/@/g, "a"),
      ...decoded,
    ];
    const haystack = variants.join(" ");
    const compactHaystack = variants.map((value) => value.replace(/[^a-z0-9:/._-]/g, "")).join(" ");
    const gated = [
      "delete",
      "forget",
      "erase",
      "wipe",
      "purge",
      "remove",
      "remove permanently",
      "removepermanently",
      "destroy",
      "shred",
      "drop",
      "export",
      "import",
      "identity bundle",
      "identitybundle",
      "private key",
      "secret key",
      "sign",
      "signature",
      "approval",
      "policy",
      "webhook",
      "callback",
      "http://",
      "https://",
      "other agent",
      "otheragent",
      "prior session",
      "priorsession",
      "widen",
    ];
    const isOrdinaryClause = (value: string): boolean =>
      /\b(remember|store|save|recall|read|lookup|get)\b/.test(value);
    const clauseHasGatedNeedle = (value: string): string | undefined => {
      const compact = value.replace(/[^a-z0-9:/._-]/g, "");
      return gated.find((needle) => value.includes(needle) || compact.includes(needle));
    };
    const clauses = normalized
      .split(/\b(?:then|and|also|after|before|while)\b|[,;]+/i)
      .map((clause) => clause.toLowerCase().trim())
      .filter((clause) => clause.length > 0);
    if (clauses.length > 1) {
      for (const clause of clauses) {
        const gatedClause = clauseHasGatedNeedle(clause);
        if (gatedClause) {
          return {
            safety_class: "gated",
            tool: ["forget", "delete", "erase", "wipe", "purge", "remove", "remove permanently", "removepermanently"].some((needle) =>
              clause.includes(needle) || clause.replace(/[^a-z0-9:/._-]/g, "").includes(needle)
            ) ? "sanctuary_forget" : null,
            example: { args: "<operator-approved placeholders only>" },
            why_sanctuary: "This request may need operator review before execution.",
            remediation_class: "request_review",
            probe_key: gatedClause,
          };
        }
        if (!isOrdinaryClause(clause)) {
          return {
            safety_class: "sensitive",
            tool: null,
            example: null,
            why_sanctuary: "The request is ambiguous, so runnable guidance is suppressed.",
            remediation_class: "try_lower_scope",
            probe_key: "multi_intent",
          };
        }
      }
    }
    const matchedGated = gated.find((needle) => haystack.includes(needle) || compactHaystack.includes(needle));
    if (matchedGated) {
      return {
        safety_class: "gated",
        tool: ["forget", "delete", "erase", "wipe", "purge", "remove", "remove permanently", "removepermanently"].some((needle) =>
          haystack.includes(needle) || compactHaystack.includes(needle)
        ) ? "sanctuary_forget" : null,
        example: { args: "<operator-approved placeholders only>" },
        why_sanctuary: "This request may need operator review before execution.",
        remediation_class: "request_review",
        probe_key: matchedGated,
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
      description: "Store a key/value into encrypted sovereign memory for this session. Wraps state_write with an approval-binding and audit record. Use this (not raw state_write) for agent working memory you want auditable. Returns { key, namespace_handle, audit_ref }; the namespace is an opaque handle, never the raw path.",
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
          if (result.denied || result.error) return deny("audit:sanctuary_remember", "try_lower_scope");
          const auditRef = await audit("sanctuary_remember", {
            primitive_tool: "state_write",
            primitive_args_hash: normalizedArgsHash(primitiveArgs),
            facade_call: { key: args.key },
          });
          return toolResult({
            key: result.key,
            namespace_handle: result.namespace,
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_remember", "try_lower_scope");
        }
      },
    },
    {
      name: "sanctuary_recall",
      description: "Read a key from encrypted sovereign memory, verifying integrity before returning. Returns { value, verified: true, audit_ref } (pass opts.full for the full record). Denied if integrity fails or the key was hidden via sanctuary_hide. Use as the read counterpart to sanctuary_remember.",
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
          const marker = await loadHiddenMarker(
            primitiveArgs.namespace as string,
            primitiveArgs.key as string
          );
          const read = await callPrimitive("state_read", primitiveArgs);
          if (read.denied) return toolResult(read);
          if (!isVerifiedRead(read)) return deny("audit:sanctuary_recall");
          if (marker) {
            if (marker === "invalid") return deny("audit:sanctuary_recall", "request_review");
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
      description: "Mark a stored key as hidden so sanctuary_recall will not return it, without deleting the data. Use to suppress a memory from default reads while keeping it recoverable. Returns an audit_ref; the value still exists in the store and can be deleted with sanctuary_forget.",
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
          await storeHiddenMarker(marker);
          const auditRef = await audit("sanctuary_hide", {
            marker_namespace: FACADE_HIDDEN_MARKER_NAMESPACE,
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
      description: "Permanently delete a memory key via state_delete: the entry is removed and its file gets a best-effort random-byte overwrite before unlinking. On copy-on-write/SSD media (APFS, ext4, flash) the original bytes may persist, so at-rest confidentiality rests on encryption (data is stored as ciphertext), not on the overwrite. Tier 1: requires operator approval; pass the approval proof. Returns an audit_ref for the deletion event.",
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
          await deleteHiddenMarker(
            primitiveArgs.namespace as string,
            primitiveArgs.key as string
          );
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
      description: "Given a free-text intent, return policy-aware guidance on which Sanctuary tools to use and how, including a runnable example for ordinary (non-gated) intents. Use to discover the right tool before acting. Read-only; returns the classified guidance plus an audit_ref.",
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
      description: "Return the disclosable identity facts for the current session: label, did, active-identity fingerprint, and memory namespace handle. Use to confirm which sovereign identity you are operating as. Read-only; private keys are never included.",
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
      description: "List the security guarantees currently in force for this session (e.g. state-encrypted-at-rest, approval-gate-mediated, append-only audit for critical ops, opaque memory handles). Use to tell a counterparty or yourself what protections apply. Read-only; returns guarantee flags plus an audit_ref. Reports only what IS active: absence of a flag is not a claim.",
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
      description: "Open a paginated cursor over your own redacted local audit events, optionally filtered by operation. Use before sanctuary_events_read to page through recent activity. Returns { cursor, audit_ref }. Bound to your identity; cross-agent and callback/URL filters are refused.",
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
      description: "Read the next page of redacted events from a cursor opened with sanctuary_events_open_cursor (default 10, max 25 per call). Returns { events, next_cursor, audit_ref }. Only your own identity's events are visible; capped at 10 reads per cursor, then rate-limited.",
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
          // Scope to the caller's identity BEFORE the limit (AuditLog.query
          // filters identity_id before its slice) so the 500-entry window is
          // entirely the caller's OWN entries — cursor paging no longer drops a
          // caller's older entries that sat behind other identities' (CISO LOW,
          // 2026-06-16).
          const queried = await options.auditLog.runAllowingIntegrityFindings(() =>
            options.auditLog.query({
              operation_type: cursor.operation,
              identity_id: activeIdentity.identity_id,
              limit: 500,
            })
          );
          if (queried.integrity_findings.length > 0) return deny("audit:sanctuary_events_read");
          const own = queried.entries;
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
      description: "Release an event cursor opened with sanctuary_events_open_cursor. Call when done paging to free the cursor. Returns { closed: true, audit_ref }.",
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
      description: "Full-text search your own audit history (scope is always own_signed), verifying entries against the audit chain first. Use to find when a past operation ran and its result. Returns matching entries with timestamp, operation, and verified_against_audit_chain status; refuses if the chain fails integrity.",
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
          // Scope to the caller's identity BEFORE the limit (AuditLog.query
          // filters identity_id before its slice) so the 500-entry search window
          // is entirely the caller's OWN entries — a caller with many
          // other-identity entries ahead of theirs no longer has older own
          // entries pushed out of the searchable window (CISO LOW, 2026-06-16).
          const queried = await options.auditLog.runAllowingIntegrityFindings(() =>
            options.auditLog.query({
              identity_id: activeIdentity.identity_id,
              limit: 500,
            })
          );
          if (queried.integrity_findings.length > 0) return deny("audit:sanctuary_audit_search");
          const needle = String(args.query).toLowerCase();
          const limit = Math.min(25, Math.max(1, Number(args.limit ?? 10)));
          const matches = queried.entries
            // Search the AGENT search-corpus projection, never the raw entry
            // (property #11, no-policy-inference; LOW-1). The needle is matched
            // ONLY against the operation name plus the search-ALLOWLIST of safe
            // detail keys (buildAgentSearchCorpus) — a tiny, explicitly non-
            // policy subset (dest_host/destination — the egress targets the agent
            // itself supplied). Every other key — the free-text `reason`, the
            // fine-grained `decision` (REMOVED 2026-06-16: it let an agent probe
            // WHICH policy disposition fired off `result_count`), every
            // `*rule_id*`, `tier`/`policy_*`, `decision_provenance`, the
            // signed-canonical blob, and any NEW operator-attribution field — is
            // absent from the corpus, so a probe for a sensitive value, a
            // sensitive key NAME, or any sentinel can never differentially match
            // off `result_count`. Because it is an allowlist, adding a sensitive
            // detail key later cannot regress this. The OPERATOR audit-search
            // path stays full-fidelity (it does not call this projection).
            .filter((entry) =>
              `${entry.operation} ${canonicalJson(buildAgentSearchCorpus(entry))}`
                .toLowerCase()
                .includes(needle)
            )
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
      description: "Execute a short plan of facade steps (sanctuary_remember/recall/hide/forget) in one call, reserving operator approvals up front for any Tier 1 step (e.g. a forget/delete). Use to batch a memory workflow atomically with respect to approval. Pass approvals keyed by step_id; the plan is hash-bound, and a missing approval aborts the whole plan.",
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
              risk_tier: (primitiveTool === "state_delete" ? 1 : 3) as 1 | 3,
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
          const reservedApprovals: Array<{ step_id: string; approval_ref: string; reservation_id: string }> = [];
          for (const step of planSteps) {
            if (step.risk_tier === 1) {
              const approvalRef = approvals[step.step_id];
              const reservationId = `compound:${planHash}:${step.step_id}:${randomBytes(8).toString("hex")}`;
              const approvalReserved = typeof approvalRef === "string" && reserveApprovalForStep({
                approval_ref: approvalRef,
                reservation_id: reservationId,
                plan_hash: planHash,
                step_id: step.step_id,
                primitive_tool: step.primitive_tool,
                primitive: step.primitive,
                risk_tier: step.risk_tier,
              });
              if (approvalReserved && typeof approvalRef === "string") {
                reservedApprovals.push({
                  step_id: step.step_id,
                  approval_ref: approvalRef,
                  reservation_id: reservationId,
                });
                continue;
              }
              releaseReservedApprovals(reservedApprovals);
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
            const reserved = reservedApprovals.find((approval) => approval.step_id === step.step_id);
            if (reserved && !approvalProofStore.consumeReserved(reserved.approval_ref, reserved.reservation_id)) {
              releaseReservedApprovals(reservedApprovals.filter((approval) => approval.step_id !== step.step_id));
              const auditRef = await audit("sanctuary_compound_execute", {
                plan_hash: planHash,
                completed_steps: completed,
                failed_step: step.step_id,
                release_not_consume: true,
              }, "failure");
              return toolResult({ status: "partial_failed", completed_steps: completed, failed_step: step.step_id, audit_ref: auditRef });
            }
            const result =
              step.tool === "sanctuary_remember" ? await callPrimitive("state_write", step.primitive) :
              step.tool === "sanctuary_recall" || step.tool === "sanctuary_hide" ? await callPrimitive("state_read", step.primitive) :
              await callPrimitive("state_delete", step.primitive);
            if (result.denied || result.error) {
              releaseReservedApprovals(reservedApprovals.filter((approval) => approval.step_id !== step.step_id));
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
