import { enforceDeclaredStringLengths } from "../tool-args.js";
import { classifyIntent, HELP_INTENT_SCHEMA_MAX_CHARS } from "./intent-classifier.js";
import { randomBytes } from "node:crypto";
import type { AuditEntry, AuditLog } from "../operational/audit-log.js";
import {
  buildAgentSearchCorpus,
  redactAuditEntryForAgent,
} from "../operational/agent-audit-redaction.js";
import type { IdentityManager } from "../cognitive/tools.js";
import type { StoredIdentity } from "../core/identity.js";
import { toolResult, type ToolDefinition } from "../router.js";
import type { StorageBackend } from "../storage/interface.js";
import type { StateStore } from "../cognitive/state-store.js";
import type { ResponseScreen } from "../proxy/response-screen.js";
import { buildFeatureHealthPanel, SLICE1_FEATURE_REGISTRY } from "../principal-policy/feature-health.js";
import type { ProducerKeyObservation } from "../principal-policy/panel-producer.js";
import { buildCustodyExitPanel } from "../principal-policy/posture.js";
import { observeProtections } from "./protection-observations.js";
import { composeProtectionLayers, summarizeProtectionLayers } from "./protection-layers.js";
import {
  COOPERATIVE_CAPABILITIES,
  UNBOUND_OPERATOR_ACTION,
  UNCONFIRMED_OPERATOR_ACTION,
} from "./capabilities-catalog.js";
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
  SessionIdentityError,
  SessionNotBoundError,
  sha256,
  UNBOUND_SESSION,
  type ActiveSessionIdentity,
  type SessionBinding,
} from "./safety-base.js";
import {
  COOPERATIVE_TOOL_NAMES,
  isCompoundExecutableToolName,
  type CompoundExecutableToolName,
} from "./tool-names.js";

// The catalog half must match UNBOUND_CATALOG_TOOLS in capabilities-catalog.ts.
const UNBOUND_COOPERATIVE_TOOLS = new Set<string>([
  COOPERATIVE_TOOL_NAMES.help, COOPERATIVE_TOOL_NAMES.capabilities,
  COOPERATIVE_TOOL_NAMES.whoAmI, COOPERATIVE_TOOL_NAMES.activeProtections,
]);
const BOUND_ONLY_COOPERATIVE_TOOLS = new Set<string>(
  Object.values(COOPERATIVE_TOOL_NAMES).filter(tool => !UNBOUND_COOPERATIVE_TOOLS.has(tool))
);

const FACADE_HIDDEN_MARKER_NAMESPACE = "_facade/hidden";

/** One read of the session, named by what it establishes. */
type SessionView =
  | { state: "session_BOUND"; identity: ActiveSessionIdentity; record: StoredIdentity; binding: SessionBinding; binding_source: SessionBinding["binding_source"] }
  | { state: "session_NOT_BOUND"; error: SessionIdentityError }
  | { state: "session_UNCONFIRMED"; error: SessionIdentityError };

/** What the operator should do for a session with no confirmed identity; the sentences must match capabilities-catalog.ts. */
function operatorActionFor(view: Exclude<SessionView, { state: "session_BOUND" }>): string {
  return view.state === "session_NOT_BOUND" ? UNBOUND_OPERATOR_ACTION : UNCONFIRMED_OPERATOR_ACTION;
}

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

// Thirty-two needles plus seven named keys fit within sixty-four, the next power of two.
export const HELP_PROBE_MAX_KEYS = 64;
// One minute, matching the window of other rate-bounded audit summaries.
export const HELP_PROBE_ROW_INTERVAL_MS = 60_000;
// Three samples of one hundred twenty characters keep each key's retained examples bounded.
const HELP_PROBE_MAX_SAMPLES = 3;
const HELP_PROBE_SAMPLE_CHARS = 120;
interface HelpProbeSummary {
  count: number;
  examples: string[];
  first_seen_ms: number;
  last_seen_ms: number;
  last_row_ms?: number;
  append_pending: boolean;
}

export interface CooperativeSurfaceOptions {
  now?: () => number;
  identityManager: IdentityManager;
  namespaceRegistry: OpaqueNamespaceRegistry;
  auditLog: AuditLog;
  currentSessionBinding: () => SessionBinding | undefined;
  primitiveTools: ToolDefinition[];
  storage?: StorageBackend;
  /** The constructed encrypted state consumer, when supplied by the server boot path. */
  stateStore?: StateStore;
  /** Existing screening readiness observation; separate from inbound protection. */
  responseScreen?: Pick<ResponseScreen, "assertReady">;
  /** Resolve the dashboard's broker key per request; an unavailable source reports unknown. */
  resolveBrokerProducerKey?: () => Promise<{ keyB64url: string | null; observation: ProducerKeyObservation }>;
  approvalProofStore?: ApprovalProofStore;
}

export function createAgentNativeCooperativeTools(
  options: CooperativeSurfaceOptions
): { tools: ToolDefinition[] } {
  const hidden = new Map<string, HiddenMarker>();
  const cursors = new Map<string, EventCursor>();
  const helpProbeSummaries = new Map<string, HelpProbeSummary>();
  let helpProbeOverflow = 0;
  let helpProbeOverflowUnconfirmed = 0;
  let helpProbeAppendTail: Promise<void> = Promise.resolve();
  // The real clock keeps the row bound live when the caller supplies no clock.
  const helpProbeNow = options.now ?? Date.now;
  const approvalProofStore = options.approvalProofStore ?? new ApprovalProofStore();

  const callPrimitive: PrimitiveCaller = async (name, args) => {
    const tool = options.primitiveTools.find((candidate) => candidate.name === name);
    if (!tool) throw new Error(`missing primitive tool: ${name}`);
    const result = await tool.handler(args);
    return JSON.parse(result.content[0]?.text ?? "{}") as Record<string, unknown>;
  };

  function sessionView(): SessionView {
    // The three session-reporting tools read one predicate, so none claims an identity the others deny.
    try {
      // The binding read sits inside the classification, so an identity error it raises names the same state as one from resolution.
      const binding = options.currentSessionBinding();
      const identity = resolveActiveSessionIdentity(binding);
      // A binding whose identity has left the manager is not an identity. No production path removes one today
      // (IdentityManager in cognitive/tools.ts has no remove method), so this arm is defence in depth.
      const record = options.identityManager.get(identity.identity_id);
      if (!record) return { state: "session_UNCONFIRMED", error: new SessionIdentityError() };
      return { state: "session_BOUND", identity, record, binding: binding!, binding_source: binding!.binding_source };
    } catch (error) {
      if (error instanceof SessionNotBoundError) return { state: "session_NOT_BOUND", error };
      if (error instanceof SessionIdentityError) return { state: "session_UNCONFIRMED", error };
      throw error;
    }
  }

  function active(): ActiveSessionIdentity {
    const view = sessionView();
    if (view.state === "session_BOUND") return view.identity;
    // The original error is rethrown, so argumentStageCause in tool-outcome.ts keeps its cause.
    throw view.error;
  }

  async function activeMemoryNamespace(): Promise<string> {
    return options.namespaceRegistry.issuePersistedMemoryHandle(active().identity_id);
  }

  async function facadeMemoryNamespace(args: Record<string, unknown>): Promise<string> {
    const requested = (args.opts as Record<string, unknown> | undefined)?.namespace;
    if (requested === undefined) return activeMemoryNamespace();
    if (typeof requested !== "string" || !options.namespaceRegistry.isOpaqueMemoryHandle(requested)) {
      throw new Error(FIXED_DENIAL_MESSAGE);
    }
    await options.namespaceRegistry.assertOwnedPersisted(requested, options.currentSessionBinding());
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
    result: "success" | "failure" = "success",
    identityIdSnapshot?: string
  ): Promise<string> {
    // Queued summaries retain their admission identity; other audit calls resolve the current binding.
    let identityId = identityIdSnapshot ?? "system";
    if (identityIdSnapshot === undefined) {
      try {
        identityId = active().identity_id;
      } catch {
        // Keep denial auditing fail-closed but non-throwing for missing sessions.
      }
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

  function requireBoundSessionArgs(args: Record<string, unknown>): Record<string, unknown> {
    // A bound-only tool refuses before the gate when the session has no identity, so no approval request reaches the operator.
    active();
    // The gate evaluates the handler's own arguments, unchanged.
    return args;
  }

  async function rememberPrimitiveArgs(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const namespace = await facadeMemoryNamespace(args);
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

  async function recallPrimitiveArgs(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const namespace = await facadeMemoryNamespace(args);
    return { namespace, key: args.key, verify_integrity: true };
  }

  async function deletePrimitiveArgs(args: Record<string, unknown>): Promise<Record<string, unknown>> {
    const namespace = await facadeMemoryNamespace(args);
    return {
      namespace,
      key: args.key,
      reason: typeof args.reason === "string" ? args.reason : "secure facade forget",
    };
  }

  function forgetModeIsSecure(args: Record<string, unknown>): boolean {
    return args.mode === "secure";
  }

  async function applyHideSideEffects(
    args: Record<string, unknown>,
    primitiveArgs: Record<string, unknown>,
    read: Record<string, unknown>
  ): Promise<{ marker: HiddenMarker; auditRef: string } | null> {
    if (!isVerifiedRead(read) || typeof read.version !== "number") {
      return null;
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
    return { marker, auditRef };
  }

  async function applyForgetSideEffects(
    args: Record<string, unknown>,
    primitiveArgs: Record<string, unknown>
  ): Promise<string> {
    await deleteHiddenMarker(
      primitiveArgs.namespace as string,
      primitiveArgs.key as string
    );
    return await audit("sanctuary_forget", {
      primitive_tool: "state_delete",
      primitive_args_hash: normalizedArgsHash(primitiveArgs),
      facade_call: { key: args.key, mode: args.mode },
    });
  }

  async function compoundStepPrimitive(tool: CompoundExecutableToolName, stepArgs: Record<string, unknown>): Promise<{
    primitiveTool: "state_delete" | "state_write" | "state_read";
    primitive: Record<string, unknown>;
    riskTier: 1 | 3;
  }> {
    switch (tool) {
      case COOPERATIVE_TOOL_NAMES.forget:
        return {
          primitiveTool: "state_delete",
          primitive: await deletePrimitiveArgs(stepArgs),
          riskTier: 1,
        };
      case COOPERATIVE_TOOL_NAMES.remember:
        return {
          primitiveTool: "state_write",
          primitive: await rememberPrimitiveArgs(stepArgs),
          riskTier: 3,
        };
      case COOPERATIVE_TOOL_NAMES.hide:
      case COOPERATIVE_TOOL_NAMES.recall:
        return {
          primitiveTool: "state_read",
          primitive: await recallPrimitiveArgs(stepArgs),
          riskTier: 3,
        };
    }
    const exhaustive: never = tool;
    return exhaustive;
  }

  async function callCompoundStepPrimitive(step: {
    tool: CompoundExecutableToolName;
    primitive: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    switch (step.tool) {
      case COOPERATIVE_TOOL_NAMES.remember:
        return await callPrimitive("state_write", step.primitive);
      case COOPERATIVE_TOOL_NAMES.recall:
      case COOPERATIVE_TOOL_NAMES.hide:
        return await callPrimitive("state_read", step.primitive);
      case COOPERATIVE_TOOL_NAMES.forget:
        return await callPrimitive("state_delete", step.primitive);
    }
    const exhaustive: never = step.tool;
    return exhaustive;
  }

  async function applyCompoundStepSideEffects(
    step: {
      tool: CompoundExecutableToolName;
      args: Record<string, unknown>;
      primitive: Record<string, unknown>;
    },
    result: Record<string, unknown>
  ): Promise<boolean> {
    switch (step.tool) {
      case COOPERATIVE_TOOL_NAMES.hide:
        return (await applyHideSideEffects(step.args, step.primitive, result)) !== null;
      case COOPERATIVE_TOOL_NAMES.forget:
        await applyForgetSideEffects(step.args, step.primitive);
        return true;
      case COOPERATIVE_TOOL_NAMES.remember:
      case COOPERATIVE_TOOL_NAMES.recall:
        return true;
    }
    const exhaustive: never = step.tool;
    return exhaustive;
  }

  async function recordHelpProbe(intent: string, probeKey: string | undefined, safetyClass: string) {
    if (safetyClass === "ordinary") return;
    let origin = "unbound";
    let identityId = "system";
    try {
      // The queue key and audit subject come from the same binding before any append can wait.
      const binding = active();
      origin = binding.requester_identity_fingerprint;
      identityId = binding.identity_id;
    } catch (error) {
      if (!(error instanceof SessionIdentityError)) throw error;
    }
    const summaryKey = `${origin}:${probeKey ?? "sensitive"}`;
    const now = helpProbeNow();
    let current = helpProbeSummaries.get(summaryKey);
    if (!current) {
      // Only expired, settled reservations can be evicted without admitting another row inside their interval.
      if (helpProbeSummaries.size >= HELP_PROBE_MAX_KEYS) {
        let oldestKey: string | undefined;
        let oldestSeen = Infinity;
        for (const [key, summary] of helpProbeSummaries) {
          if (!summary.append_pending && summary.last_row_ms !== undefined &&
              now - summary.last_row_ms >= HELP_PROBE_ROW_INTERVAL_MS && summary.last_seen_ms < oldestSeen) {
            oldestKey = key;
            oldestSeen = summary.last_seen_ms;
          }
        }
        if (oldestKey === undefined) {
          // A full table retains every live reservation; saturating at the exact-integer limit bounds overflow accounting.
          helpProbeOverflow = Math.min(Number.MAX_SAFE_INTEGER, helpProbeOverflow + 1);
          return;
        }
        helpProbeSummaries.delete(oldestKey);
      }
      current = { count: 0, examples: [], first_seen_ms: now, last_seen_ms: now, append_pending: false };
      helpProbeSummaries.set(summaryKey, current);
    }
    current.count += 1;
    current.last_seen_ms = now;
    const sample = intent.slice(0, HELP_PROBE_SAMPLE_CHARS);
    if (current.examples.length < HELP_PROBE_MAX_SAMPLES && !current.examples.includes(sample)) current.examples.push(sample);
    if (!current.append_pending && (current.last_row_ms === undefined || now - current.last_row_ms >= HELP_PROBE_ROW_INTERVAL_MS)) {
      // Reserving before the await keeps pending appends and interval slots exclusive across admission waves.
      current.last_row_ms = now;
      current.append_pending = true;
      const previousAppend = helpProbeAppendTail;
      let releaseAppend!: () => void;
      // Each queued append owns one non-evictable table entry, so the queue shares the table cap.
      helpProbeAppendTail = new Promise<void>(resolve => { releaseAppend = resolve; });
      let reservedOverflow = 0;
      let reservedUnconfirmed = 0;
      try {
        // Serial append admission carries overflow into the next row after a pending reservation settles.
        await previousAppend;
        reservedOverflow = helpProbeOverflow;
        reservedUnconfirmed = helpProbeOverflowUnconfirmed;
        // A successful append carries each reservation; unconfirmed amounts stay distinct from confirmed overflow.
        helpProbeOverflow = 0;
        helpProbeOverflowUnconfirmed = 0;
        await audit("sanctuary_help_probe_summary", {
          safety_class: safetyClass,
          probe_key: probeKey ?? "sensitive",
          count: current.count,
          samples: [...current.examples],
          overflow_count: reservedOverflow,
          overflow_unconfirmed_count: reservedUnconfirmed,
        }, "success", identityId);
      } catch (error) {
        // Unconfirmed is an upper bound on overflow that may be on no stored row; re-reporting is honest, losing it is not.
        helpProbeOverflowUnconfirmed = Math.min(Number.MAX_SAFE_INTEGER, helpProbeOverflowUnconfirmed + reservedOverflow + reservedUnconfirmed);
        throw error;
      } finally {
        // The interval starts again at settlement so late completion cannot place two rows together.
        current.last_row_ms = helpProbeNow();
        current.append_pending = false;
        releaseAppend();
      }
    }
  }

  function redactEvent(entry: AuditEntry, index: number): Record<string, unknown> {
    return {
      cursor_event_id: index,
      ...redactAuditEntryForAgent(entry),
    };
  }

  const tools: ToolDefinition[] = [
    {
      name: COOPERATIVE_TOOL_NAMES.remember,
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
      handler: async (args, callerIdentity) => {
        // Rule 13: intent failed -> deny, no write; committed -> success linked to intent;
        // refused -> linked failure; primitive threw -> propagate, intent only, commit unknown;
        // outcome append fails after commit -> generic denial; completion unacknowledged: the value and intent exist,
        //   whether the outcome row exists depends on where the append failed;
        // crash before commit -> intent only, no value;
        // crash after commit before outcome -> value plus intent only, never evidence of a completed save.
        let intentRef: string | undefined;
        let primitiveRunning = false;
        try {
          const primitiveArgs = await rememberPrimitiveArgs(args);
          intentRef = await audit("sanctuary_remember_intent", {
            // The server-set agent: form must match callerIdentity in router.ts; preserve the session identity for own-scope search.
            agent_id: callerIdentity,
            primitive_tool: "state_write",
            primitive_args_hash: normalizedArgsHash(primitiveArgs),
            facade_call: { key: args.key },
          });
          // Attribution must be durable before state_write can commit; intent success proves only that the attempt was recorded.
          primitiveRunning = true;
          const result = await callPrimitive("state_write", primitiveArgs);
          primitiveRunning = false;
          if (result.denied || result.error) {
            await audit("sanctuary_remember", { agent_id: callerIdentity, intent_audit_ref: intentRef }, "failure");
            return deny(intentRef, "try_lower_scope");
          }
          // intent_audit_ref must match sdw/memory-tools.ts and the intent correlation in dashboard/v1_1/client.ts and principal-policy/posture-evidence-html.ts.
          const auditRef = await audit("sanctuary_remember", { agent_id: callerIdentity, intent_audit_ref: intentRef });
          return toolResult({
            key: result.key,
            namespace_handle: result.namespace,
            audit_ref: auditRef,
          });
        } catch (error) {
          // A primitive throw cannot establish non-commit: the value may precede a failed anchor write.
          if (primitiveRunning) throw error;
          // Intent or outcome append failure leaves no invented outcome; an acknowledged intent still names the attempt.
          return deny(intentRef ?? "audit:sanctuary_remember", "try_lower_scope");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.recall,
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
          const primitiveArgs = await recallPrimitiveArgs(args);
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
      name: COOPERATIVE_TOOL_NAMES.hide,
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
          const primitiveArgs = await recallPrimitiveArgs(args);
          const read = await callPrimitive("state_read", primitiveArgs);
          if (read.denied) {
            return deny("audit:sanctuary_hide");
          }
          const hiddenResult = await applyHideSideEffects(args, primitiveArgs, read);
          if (!hiddenResult) return deny("audit:sanctuary_hide");
          const { marker, auditRef } = hiddenResult;
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
      name: COOPERATIVE_TOOL_NAMES.forget,
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
        if (!forgetModeIsSecure(args)) return deny("audit:sanctuary_forget");
        try {
          const primitiveArgs = await deletePrimitiveArgs(args);
          const result = await callPrimitive("state_delete", primitiveArgs);
          if (result.denied || result.error) return deny("audit:sanctuary_forget");
          const auditRef = await applyForgetSideEffects(args, primitiveArgs);
          return toolResult({ ...result, mode: "secure", audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_forget");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.help,
      description: "Given a free-text intent (for example \"save my timezone\", \"delete a stored secret\", \"should I install this\"), return which Sanctuary tool to use and how, with an argument template for ordinary requests. Evaluation questions (what this protects, the bounds, which platforms, how to verify, how to uninstall) return intent_class \"evaluate\" with a guidance string and the related read-only tools. Guidance for sensitive or gated requests is deliberately coarse and never reveals policy internals. Intents longer than 4,096 characters are rejected; past 1,024 characters only a risk screen runs. Returns the guidance plus an audit_ref. For the start-here catalog of cooperative tools call sanctuary_capabilities; the complete advertised tool list is MCP tools/list.",
      tool_class: "read",
      // The cap must match HELP_INTENT_SCHEMA_MAX_CHARS in intent-classifier.ts.
      // It must match sanctuary_help in test/fixtures/tools-list-wire-golden.json and test/structure/__fixtures__/public-surface/mcp-tool-surface.json.
      // Registration must match enforceDeclaredStringLengths in tool-args.ts, preserving the schema object's identity.
      inputSchema: enforceDeclaredStringLengths({
        type: "object",
        properties: { intent: { type: "string", maxLength: HELP_INTENT_SCHEMA_MAX_CHARS } },
        required: ["intent"],
      }),
      handler: async (args) => {
        try {
          const classified = classifyIntent(args.intent as string);
          let sessionBound: false | undefined;
          // Bound-only guidance exposes its binding requirement when the session has no identity.
          if (classified.tool && BOUND_ONLY_COOPERATIVE_TOOLS.has(classified.tool)) {
            try {
              active();
            } catch (error) {
              if (!(error instanceof SessionIdentityError)) throw error;
              sessionBound = false;
            }
          }
          await recordHelpProbe(args.intent as string, classified.probe_key, classified.safety_class);
          const auditRef = await audit("sanctuary_help", {
            safety_class: classified.safety_class,
            // An evaluate route with no example (uninstall; the Tier 1 tiers
            // route) is audited as not runnable;
            // every pre-existing ordinary route carries one, so this is
            // unchanged for them.
            runnable_example: classified.safety_class === "ordinary" && classified.example !== null,
          });
          return toolResult({ ...classified, probe_key: undefined, session_bound: sessionBound, audit_ref: auditRef });
        } catch {
          return deny("audit:sanctuary_help", "wait");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.capabilities,
      description: "Return the start-here catalog of Sanctuary's cooperative tools: for each tool, what it does and when to reach for it. Read-only, takes no arguments. Call this to discover what cooperative memory/identity/audit tools are available and route your work through them instead of ad-hoc state. The same catalog is also delivered in the MCP server instructions at connect time; this tool re-serves it on demand. Returns { session: { bound, binding_source } when bound or { bound, operator_action } when not, capabilities: [{ tool, does, when, available }], audit_ref }.",
      tool_class: "read",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        try {
          const view = sessionView();
          const bound = view.state === "session_BOUND";
          const auditRef = await audit("sanctuary_capabilities", {
            tool_count: COOPERATIVE_CAPABILITIES.length,
          });
          return toolResult({
            session: view.state === "session_BOUND"
              ? { bound: true, binding_source: view.binding_source }
              : { bound: false, operator_action: operatorActionFor(view) },
            capabilities: COOPERATIVE_CAPABILITIES.map((entry) => ({
              tool: entry.tool,
              does: entry.does,
              when: entry.when,
              // Availability is computed from the same session read as the session field.
              available: bound || UNBOUND_COOPERATIVE_TOOLS.has(entry.tool),
            })),
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_capabilities", "wait");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.whoAmI,
      description: "Return whether this session has a Sanctuary identity and how it was bound, with the disclosable identity facts when it does: label, did, active-identity fingerprint and memory namespace handle. With no identity it answers bound false and says what to tell your operator. A default binding lasts until this server process exits. Read-only; private keys are never included.",
      tool_class: "read",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        try {
          const view = sessionView();
          if (view.state !== "session_BOUND") {
            // arm_UNBOUND: an unbound answer carries no identity fact and no refusal marker, so the router passes it as a success.
            const auditRef = await audit("sanctuary_who_am_i");
            return toolResult({ bound: false, operator_action: operatorActionFor(view), audit_ref: auditRef });
          }
          // arm_BOUND: every fact comes from the one session read above, including its manager record.
          const activeIdentity = view.identity;
          const identity = view.record;
          const auditRef = await audit("sanctuary_who_am_i");
          return toolResult({
            bound: true,
            binding_source: view.binding_source,
            label: identity.label,
            active_identity_fingerprint: activeIdentity.requester_identity_fingerprint,
            memory_namespace_handle:
              await options.namespaceRegistry.lookupPersistedMemoryHandle(identity.identity_id) ?? null,
            did: identity.did,
            audit_ref: auditRef,
          });
        } catch {
          // arm_FAULT: a session read that fails for a reason other than identity gives the fixed denial.
          return deny("audit:sanctuary_who_am_i");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.activeProtections,
      description: "List every layer of Sanctuary with its evidence-based status, including layers that are off, not built, or unknown. Use to ask what is protecting this session right now. Read-only; returns { guarantees, layers, summary, audit_ref }. The guarantees field preserves legacy flags; layers and the one-line-per-layer summary report observed status. Answers in a session with no identity; the identity layer then reads unknown.",
      tool_class: "read",
      inputSchema: { type: "object", properties: {} },
      handler: async () => {
        try {
          const view = sessionView();
          // A session with no confirmed identity is observed as unbound, so the identity layer reads unknown.
          const observedBinding = view.state === "session_BOUND" ? view.binding : UNBOUND_SESSION;
          const boundRecord = view.state === "session_BOUND" ? view.record : undefined;
          // The identity layer is decided by the session read above, so protections never reports a layer that
          // who-am-I and capabilities, reading the same view, would deny; must match observeProtections in
          // protection-observations.ts, which reads only get from the manager.
          const readOnceIdentityManager: Pick<IdentityManager, "get"> = {
            get: (identityId: string) => (boundRecord !== undefined && identityId === boundRecord.identity_id ? boundRecord : undefined),
          };
          // The audit row names the identity from the same read, so the manager is consulted once per call.
          const auditRef = await audit("sanctuary_active_protections", {}, "success",
            view.state === "session_BOUND" ? view.identity.identity_id : "system");
          // Must match the dashboard accessor: this key pins broker heartbeat signatures, not agent identity.
          const brokerKey = await Promise.resolve().then(() => options.resolveBrokerProducerKey?.()).catch(() => null);
          // Must match withDerivedKeyRestriction in posture-routes.ts: only observed presence or absence is conclusive.
          const brokerKeyUnavailable = brokerKey?.observation !== "present" && brokerKey?.observation !== "absent";
          // Must match custodyObservation in protectionEvidenceSchema (protection-layers.ts): age starts before the audit read.
          const custodyObservation = { state: "fresh" as const, completed_at: new Date(Date.now()).toISOString() };
          const [health, custody, chain] = await Promise.allSettled([
            buildFeatureHealthPanel({
              auditLog: options.auditLog,
              originMachine: "local",
              // Include daemon observations so a reported stop overrides recent token activity on both surfaces.
              registry: SLICE1_FEATURE_REGISTRY.filter(feature => feature.liveness === "event_driven" || feature.id === "secret_broker_daemon"),
              protectionClaimSubject: null,
              brokerPinnedProducerKeyB64url: brokerKey?.keyB64url ?? null,
              brokerProducerKeyExpectedButUnavailable: brokerKeyUnavailable,
            }),
            buildCustodyExitPanel({ auditLog: options.auditLog, originMachine: "local" }),
            options.auditLog.getAuditChainVerdict(),
          ]);
          // Must match observeProtections in protection-observations.ts: supply raw consumers (the identity manager
          // being the read-once view above) and qualified reads.
          const layers = composeProtectionLayers(observeProtections({
            identityManager: readOnceIdentityManager as IdentityManager,
            currentSessionBinding: () => observedBinding,
            get stateStore() { return options.stateStore; },
            get responseScreen() { return options.responseScreen; },
          }, {
            custodyObservation: custody.status === "fulfilled" ? custodyObservation : { state: "unavailable", completed_at: null },
            featureHealth: health.status === "fulfilled" ? health.value : undefined,
            custodyExit: custody.status === "fulfilled" ? custody.value : undefined,
            auditChain: chain.status === "fulfilled" ? chain.value.status : undefined,
            now: Date.now(),
          }));
          return toolResult({
            guarantees: [
              "state_encrypted_at_rest",
              "approval_gate_mediated",
              "append_only_audit_for_critical_operations",
              "opaque_memory_namespace_handles",
            ],
            layers,
            summary: summarizeProtectionLayers(layers),
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_active_protections");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.eventsOpenCursor,
      description: "Open a paginated cursor over your own redacted local audit events, optionally filtered by operation. Use before sanctuary_events_read to page through recent activity. Returns { cursor, audit_ref }. Bound to your identity; cross-agent and callback/URL filters are refused.",
      tool_class: "read",
      approvalTargetArgs: requireBoundSessionArgs,
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
      name: COOPERATIVE_TOOL_NAMES.eventsRead,
      description: "Read the next page of redacted events from a cursor opened with sanctuary_events_open_cursor (default 10, max 25 per call). Returns { events, next_cursor, audit_ref }. Only your own identity's events are visible; capped at 10 reads per cursor, then rate-limited.",
      tool_class: "read",
      approvalTargetArgs: requireBoundSessionArgs,
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
          // audit-chokepoint-exempt: fail-closed DENY on any integrity finding,
          // not a clean-CLAIM. `sanctuary_events_read` returns redacted events; a
          // finding makes it refuse, it never stamps a verified-clean label, so it
          // does not derive an audit-chain cleanliness verdict (F2 round-4 HIGH-2).
          if (queried.integrity_findings.length > 0) return deny("audit:sanctuary_events_read");
          const own = queried.entries;
          const startOffset = cursor.offset;
          const page = own.slice(startOffset, startOffset + limit);
          cursor.offset = startOffset + page.length;
          const auditRef = await audit("sanctuary_events_read", { count: page.length });
          return toolResult({
            events: page.map((entry, index) => redactEvent(entry, startOffset + index)),
            next_cursor: cursor.cursor_id,
            audit_ref: auditRef,
          });
        } catch {
          return deny("audit:sanctuary_events_read", "wait");
        }
      },
    },
    {
      name: COOPERATIVE_TOOL_NAMES.eventsClose,
      description: "Release an event cursor opened with sanctuary_events_open_cursor. Call when done paging to free the cursor. Returns { closed: true, audit_ref }.",
      tool_class: "write",
      approvalTargetArgs: requireBoundSessionArgs,
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
      name: COOPERATIVE_TOOL_NAMES.auditSearch,
      description: "Search your own recent audit entries for a text match. Scope is always own_signed and a bound session identity is required. Only the operation name and a small allowlist of detail fields are searched, over a bounded window of your most recent entries, and the number of matches is capped, so this is not a complete history search. Each match gives timestamp, operation, result, and a verification label saying whether the full chain or only its post-split part was verified. Refuses when the audit chain reports integrity findings. Use to find when a recent operation ran and how it ended.",
      tool_class: "read",
      approvalTargetArgs: requireBoundSessionArgs,
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
          // BLOCKER-1 (round 3): route the "verified against the audit chain"
          // claim through the shared verdict, which folds the sealed-region
          // crypto verdict the routine query skips. Deny on any `findings`
          // (routine tamper OR a sealed hash_mismatch/incomplete). The old gate
          // only saw routine findings and stamped "verified_against_audit_chain"
          // over a tampered sealed entry. On `verified_suffix_only` (the sealed
          // history is unreadable at the agent's privilege, the common armed-box
          // case) the agent verified only the post-split chain, so it claims the
          // honest weaker label rather than full-chain verification.
          const chainVerdict = await options.auditLog.getAuditChainVerdict();
          if (chainVerdict.status === "findings") return deny("audit:sanctuary_audit_search");
          const verificationLabel =
            chainVerdict.status === "verified"
              ? "verified_against_audit_chain"
              : "verified_against_post_split_chain";
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
              verification: verificationLabel,
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
      name: COOPERATIVE_TOOL_NAMES.compoundExecute,
      description: "Execute a short plan of sanctuary_remember, sanctuary_recall, sanctuary_hide and sanctuary_forget steps in order, in one call. Tier 1 under the default policy: requires operator approval for the call itself. Each step is { tool, args } and gets a step_id by position (step-1, step-2, and so on). Every sanctuary_forget step also needs its own operator approval, passed in approvals keyed by step_id and bound to this exact plan and step. Step approvals are reserved before any step runs, and if one is missing or does not match, no step runs. Completed steps are not rolled back: if a step fails, the call returns the standard refusal, and the steps before it may have taken effect; use sanctuary_recall to check your current memory state.",
      tool_class: "write",
      approvalTargetArgs: requireBoundSessionArgs,
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
          const planSteps = await Promise.all(steps.map(async (step, index) => {
            const tool = String(step.tool ?? "");
            const stepArgs = (step.args && typeof step.args === "object" && !Array.isArray(step.args))
              ? step.args as Record<string, unknown>
              : {};
            if (!isCompoundExecutableToolName(tool)) {
              throw new Error(FIXED_DENIAL_MESSAGE);
            }
            if (tool === COOPERATIVE_TOOL_NAMES.forget && !forgetModeIsSecure(stepArgs)) {
              throw new Error(FIXED_DENIAL_MESSAGE);
            }
            const { primitiveTool, primitive, riskTier } = await compoundStepPrimitive(tool, stepArgs);
            return {
              step_id: `step-${index + 1}`,
              tool,
              args: stepArgs,
              primitive_tool: primitiveTool,
              normalized_args_hash: normalizedArgsHash(primitive),
              primitive,
              risk_tier: riskTier,
            };
          }));
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
            const result = await callCompoundStepPrimitive(step);
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
            let sideEffectsApplied = true;
            try {
              sideEffectsApplied = await applyCompoundStepSideEffects(step, result);
            } catch {
              sideEffectsApplied = false;
            }
            if (!sideEffectsApplied) {
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
