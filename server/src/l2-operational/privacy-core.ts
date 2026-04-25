/**
 * Sanctuary v1.1 — local query privacy core.
 *
 * This module is intentionally independent of dashboard UI and transport
 * enforcement. Enforcement paths call it with a payload, destination category,
 * identity-bound policy, and encrypted placeholder vault; the module returns a
 * filtered payload or a fail-closed denial plus a shared privacy audit payload.
 */

import type { StorageBackend } from "../storage/interface.js";
import { encrypt, decrypt, type EncryptedPayload } from "../core/encryption.js";
import { derivePurposeKey } from "../core/key-derivation.js";
import { bytesToString, stringToBytes, toBase64url } from "../core/encoding.js";
import { hmacSha256 } from "../core/hashing.js";
import { randomBytes } from "../core/random.js";
import type { AuditLog } from "./audit-log.js";
import {
  detectSensitiveSpans,
  detectorClassForSpan,
  type PrivacyPlaceholderVault,
  type PrivacySpanClass,
  PrivacyVaultError,
  type SensitiveSpan,
} from "./privacy-filter.js";
import type {
  PrivacyAction,
  PrivacyAuditPayload,
  PrivacyDeniedPayload,
  PrivacyDestinationCategory,
  PrivacyDetectorClass,
  PrivacyFieldDecision,
  PrivacyHashAlg,
} from "../contracts/v1.1/index.js";

export const PRIVACY_AUDIT_OPERATION = "privacy_event";
export const PRIVACY_POLICY_NAMESPACE = "_privacy_policies";
const HASH_ALG: PrivacyHashAlg = "hmac-sha256-fortress-keyed-v1";

export type PrivacyPolicyAction =
  | "placeholder"
  | Extract<PrivacyAction, "allow" | "redact" | "hash" | "deny">;

export interface PrivacyPolicy {
  version: 1;
  policy_id: string;
  policy_name?: string;
  identity_id: string;
  detector_actions?: Partial<Record<PrivacyDetectorClass, PrivacyPolicyAction>>;
  destination_detector_actions?: Partial<
    Record<PrivacyDestinationCategory, Partial<Record<PrivacyDetectorClass, PrivacyPolicyAction>>>
  >;
  client_names?: string[];
  project_names?: string[];
  domain_terms?: string[];
  person_names?: string[];
  placeholder_scope?: "identity" | "policy";
  rehydration?: {
    default_action?: "allow" | "deny";
    allowed_destinations?: PrivacyDestinationCategory[];
    denied_destinations?: PrivacyDestinationCategory[];
  };
  max_depth?: number;
  max_payload_bytes?: number;
  max_string_bytes?: number;
  operator_override?: {
    allow_on_policy_error?: boolean;
    allow_on_filter_error?: boolean;
    allow_on_vault_error?: boolean;
    allow_on_detector_error?: boolean;
  };
  created_at: string;
  updated_at: string;
}

export type CreatePrivacyPolicyInput = Omit<
  PrivacyPolicy,
  "version" | "policy_id" | "created_at" | "updated_at"
> & {
  version?: 1;
  policy_id?: string;
  created_at?: string;
  updated_at?: string;
};

export interface PrivacyCoreFinding {
  raw_path: string;
  detector_class: PrivacyDetectorClass;
  span_class: PrivacySpanClass;
  action: PrivacyAction;
  content_hash: string;
  placeholder_label?: string;
}

export interface PrivacyFilterRequest {
  payload: unknown;
  policy: PrivacyPolicy | null;
  identity_id?: string;
  agent_id: string;
  destination_category: PrivacyDestinationCategory;
  audit_log?: AuditLog;
  event_id?: string;
}

export type PrivacyFilterDecision =
  | {
      status: "allowed";
      payload: unknown;
      findings: [];
      audit_payload: PrivacyAuditPayload;
    }
  | {
      status: "filtered";
      payload: unknown;
      findings: PrivacyCoreFinding[];
      audit_payload: PrivacyAuditPayload;
    }
  | {
      status: "denied";
      payload: undefined;
      findings: PrivacyCoreFinding[];
      audit_payload: PrivacyDeniedPayload;
    };

export interface PrivacyRehydrationRequest {
  response: unknown;
  policy: PrivacyPolicy | null;
  identity_id?: string;
  agent_id: string;
  destination_category: PrivacyDestinationCategory;
  audit_log?: AuditLog;
  event_id?: string;
}

export type PrivacyRehydrationDecision =
  | {
      status: "rehydrated";
      response: unknown;
      rehydrated_count: number;
      unresolvable_count: number;
      audit_payload: PrivacyAuditPayload;
    }
  | {
      status: "denied";
      response: unknown;
      rehydrated_count: 0;
      unresolvable_count: 0;
      audit_payload: PrivacyDeniedPayload;
    };

export class PrivacyPolicyStore {
  private storage: StorageBackend;
  private encryptionKey: Uint8Array;
  private policies = new Map<string, PrivacyPolicy>();

  constructor(storage: StorageBackend, masterKey: Uint8Array) {
    this.storage = storage;
    this.encryptionKey = derivePurposeKey(masterKey, "l2-privacy-policies-v1");
  }

  async create(input: CreatePrivacyPolicyInput): Promise<PrivacyPolicy> {
    const now = new Date().toISOString();
    const policy: PrivacyPolicy = {
      ...input,
      version: 1,
      policy_id: input.policy_id || `pp-${Date.now()}-${toBase64url(randomBytes(8))}`,
      created_at: input.created_at ?? now,
      updated_at: input.updated_at ?? now,
    };
    validatePrivacyPolicy(policy, input.identity_id);
    await this.persist(policy);
    this.policies.set(policy.policy_id, policy);
    return policy;
  }

  async get(policyId: string, identityId?: string): Promise<PrivacyPolicy | null> {
    const cached = this.policies.get(policyId);
    if (cached) {
      return !identityId || cached.identity_id === identityId ? cached : null;
    }

    const raw = await this.storage.read(PRIVACY_POLICY_NAMESPACE, policyId);
    if (!raw) return null;
    try {
      const encrypted: EncryptedPayload = JSON.parse(bytesToString(raw));
      const decrypted = decrypt(encrypted, this.encryptionKey);
      const policy = JSON.parse(bytesToString(decrypted)) as PrivacyPolicy;
      validatePrivacyPolicy(policy, identityId ?? policy.identity_id);
      this.policies.set(policy.policy_id, policy);
      return !identityId || policy.identity_id === identityId ? policy : null;
    } catch {
      return null;
    }
  }

  async list(identityId?: string): Promise<PrivacyPolicy[]> {
    const entries = await this.storage.list(PRIVACY_POLICY_NAMESPACE);
    for (const meta of entries) {
      if (this.policies.has(meta.key)) continue;
      await this.get(meta.key);
    }
    const policies = Array.from(this.policies.values());
    return identityId
      ? policies.filter((policy) => policy.identity_id === identityId)
      : policies;
  }

  private async persist(policy: PrivacyPolicy): Promise<void> {
    const encrypted = encrypt(stringToBytes(JSON.stringify(policy)), this.encryptionKey);
    await this.storage.write(
      PRIVACY_POLICY_NAMESPACE,
      policy.policy_id,
      stringToBytes(JSON.stringify(encrypted))
    );
  }
}

export class LocalPrivacyEngine {
  private vault: PrivacyPlaceholderVault;
  private hmacKey: Uint8Array;

  constructor(vault: PrivacyPlaceholderVault, masterKey: Uint8Array) {
    this.vault = vault;
    this.hmacKey = derivePurposeKey(
      masterKey,
      "sanctuary-v1.1-privacy-content-hmac"
    );
  }

  async filterOutbound(
    request: PrivacyFilterRequest
  ): Promise<PrivacyFilterDecision> {
    const eventId = request.event_id ?? newPrivacyEventId();
    const emittedAt = new Date().toISOString();

    if (!request.policy) {
      const denied = this.deniedPayload(
        request,
        eventId,
        emittedAt,
        "missing-policy",
        "fail_closed_no_policy"
      );
      emitPrivacyAuditEvent(request.audit_log, denied, "failure");
      return { status: "denied", payload: undefined, findings: [], audit_payload: denied };
    }

    const policy = request.policy;
    try {
      validatePrivacyPolicy(policy, request.identity_id);
      this.assertPayloadWithinBounds(request.payload, policy);

      const scope = vaultScopeForPolicy(policy);
      const findings: PrivacyCoreFinding[] = [];
      const filtered = await this.filterNode(
        request.payload,
        "$",
        0,
        policy,
        request.destination_category,
        scope,
        findings,
        new WeakSet<object>()
      );
      const fieldDecisions = await this.fieldDecisionsForFindings(
        findings,
        `${scope}:event:${eventId}`
      );
      const payloadHash = this.keyedHash(filtered);

      const auditPayload: PrivacyAuditPayload = findings.length === 0
        ? {
            version: "1.1",
            kind: "allowed",
            event_id: eventId,
            emitted_at: emittedAt,
            policy_id: policy.policy_id,
            identity_id: policy.identity_id,
            agent_id: request.agent_id,
            destination_category: request.destination_category,
            outbound_payload_hash: payloadHash,
            payload_hash_alg: HASH_ALG,
          }
        : {
            version: "1.1",
            kind: "filtered",
            event_id: eventId,
            emitted_at: emittedAt,
            policy_id: policy.policy_id,
            identity_id: policy.identity_id,
            agent_id: request.agent_id,
            destination_category: request.destination_category,
            field_decisions: fieldDecisions,
            outbound_payload_hash: payloadHash,
            payload_hash_alg: HASH_ALG,
          };

      emitPrivacyAuditEvent(request.audit_log, auditPayload);
      return findings.length === 0
        ? { status: "allowed", payload: filtered, findings: [], audit_payload: auditPayload }
        : { status: "filtered", payload: filtered, findings, audit_payload: auditPayload };
    } catch (err) {
      const reason = err instanceof PrivacyPolicyDenyError
        ? "policy_deny_rule"
        : err instanceof PrivacyPolicyError
          ? "fail_closed_no_policy"
        : isPrivacyVaultError(err)
          ? "fail_closed_vault_error"
          : "fail_closed_filter_error";

      if (shouldAllowOnError(policy, reason)) {
        const auditPayload: PrivacyAuditPayload = {
          version: "1.1",
          kind: "allowed",
          event_id: eventId,
          emitted_at: emittedAt,
          policy_id: policy.policy_id,
          identity_id: policy.identity_id,
          agent_id: request.agent_id,
          destination_category: request.destination_category,
          outbound_payload_hash: this.keyedHash(request.payload),
          payload_hash_alg: HASH_ALG,
        };
        emitPrivacyAuditEvent(request.audit_log, auditPayload);
        return { status: "allowed", payload: request.payload, findings: [], audit_payload: auditPayload };
      }

      const denied = this.deniedPayload(
        request,
        eventId,
        emittedAt,
        policy.policy_id,
        reason
      );
      emitPrivacyAuditEvent(request.audit_log, denied, "failure");
      return { status: "denied", payload: undefined, findings: [], audit_payload: denied };
    }
  }

  async rehydrateResponse(
    request: PrivacyRehydrationRequest
  ): Promise<PrivacyRehydrationDecision> {
    const eventId = request.event_id ?? newPrivacyEventId();
    const emittedAt = new Date().toISOString();

    if (!request.policy) {
      const denied = this.deniedPayload(
        request,
        eventId,
        emittedAt,
        "missing-policy",
        "fail_closed_no_policy"
      );
      emitPrivacyAuditEvent(request.audit_log, denied, "failure");
      return {
        status: "denied",
        response: request.response,
        rehydrated_count: 0,
        unresolvable_count: 0,
        audit_payload: denied,
      };
    }

    const policy = request.policy;
    try {
      validatePrivacyPolicy(policy, request.identity_id);
      if (!policyAllowsRehydration(policy, request.destination_category)) {
        const denied = this.deniedPayload(
          request,
          eventId,
          emittedAt,
          policy.policy_id,
          "policy_deny_rule"
        );
        emitPrivacyAuditEvent(request.audit_log, denied, "failure");
        return {
          status: "denied",
          response: request.response,
          rehydrated_count: 0,
          unresolvable_count: 0,
          audit_payload: denied,
        };
      }

      this.assertPayloadWithinBounds(request.response, policy);
      const counts = { rehydrated: 0, unresolvable: 0 };
      const response = await this.rehydrateNode(
        request.response,
        vaultScopeForPolicy(policy),
        0,
        policy,
        counts,
        new WeakSet<object>()
      );
      const auditPayload: PrivacyAuditPayload = {
        version: "1.1",
        kind: "rehydrated",
        event_id: eventId,
        emitted_at: emittedAt,
        policy_id: policy.policy_id,
        identity_id: policy.identity_id,
        agent_id: request.agent_id,
        destination_category: request.destination_category,
        rehydrated_count: counts.rehydrated,
        unresolvable_count: counts.unresolvable,
        response_hash: this.keyedHash(response),
        response_hash_alg: HASH_ALG,
      };
      emitPrivacyAuditEvent(request.audit_log, auditPayload);
      return {
        status: "rehydrated",
        response,
        rehydrated_count: counts.rehydrated,
        unresolvable_count: counts.unresolvable,
        audit_payload: auditPayload,
      };
    } catch (err) {
      const reason = err instanceof PrivacyPolicyError
        ? "fail_closed_no_policy"
        : isPrivacyVaultError(err)
        ? "fail_closed_vault_error"
        : "fail_closed_filter_error";
      const denied = this.deniedPayload(
        request,
        eventId,
        emittedAt,
        policy.policy_id,
        reason
      );
      emitPrivacyAuditEvent(request.audit_log, denied, "failure");
      return {
        status: "denied",
        response: request.response,
        rehydrated_count: 0,
        unresolvable_count: 0,
        audit_payload: denied,
      };
    }
  }

  private async filterNode(
    value: unknown,
    path: string,
    depth: number,
    policy: PrivacyPolicy,
    destination: PrivacyDestinationCategory,
    scope: string,
    findings: PrivacyCoreFinding[],
    seen: WeakSet<object>
  ): Promise<unknown> {
    const maxDepth = policy.max_depth ?? 16;
    if (depth > maxDepth) {
      throw new PrivacyFilterError("payload_depth_limit");
    }

    if (typeof value === "string") {
      return this.filterString(value, path, policy, destination, scope, findings);
    }

    if (Array.isArray(value)) {
      if (seen.has(value)) throw new PrivacyFilterError("payload_cycle");
      seen.add(value);
      const out: unknown[] = [];
      for (let i = 0; i < value.length; i++) {
        out.push(await this.filterNode(
          value[i],
          `${path}[${i}]`,
          depth + 1,
          policy,
          destination,
          scope,
          findings,
          seen
        ));
      }
      seen.delete(value);
      return out;
    }

    if (value && typeof value === "object") {
      if (seen.has(value)) throw new PrivacyFilterError("payload_cycle");
      seen.add(value);
      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        const filteredKey = await this.filterString(
          key,
          `${path}.$key`,
          policy,
          destination,
          scope,
          findings
        );
        const safeKey = typeof filteredKey === "string" ? filteredKey : key;
        const uniqueKey = Object.prototype.hasOwnProperty.call(out, safeKey)
          ? `${safeKey}_${Object.keys(out).length}`
          : safeKey;
        out[uniqueKey] = await this.filterNode(
          child,
          `${path}.${key}`,
          depth + 1,
          policy,
          destination,
          scope,
          findings,
          seen
        );
      }
      seen.delete(value);
      return out;
    }

    return value;
  }

  private async filterString(
    input: string,
    path: string,
    policy: PrivacyPolicy,
    destination: PrivacyDestinationCategory,
    scope: string,
    findings: PrivacyCoreFinding[]
  ): Promise<string> {
    const maxStringBytes = policy.max_string_bytes ?? 128 * 1024;
    if (stringToBytes(input).length > maxStringBytes) {
      throw new PrivacyFilterError("string_size_limit");
    }

    let spans: SensitiveSpan[];
    try {
      spans = detectSensitiveSpans(input, {
        clientNames: policy.client_names,
        projectNames: policy.project_names,
        domainTerms: policy.domain_terms,
        personNames: policy.person_names,
        pathHint: path,
      });
    } catch (err) {
      throw new PrivacyDetectorError("detector_error", err);
    }
    if (spans.length === 0) return input;

    let cursor = 0;
    const pieces: string[] = [];
    for (const span of spans) {
      const detector = span.detectorClass ?? detectorClassForSpan(span.class);
      const action = actionForDetector(policy, destination, detector);
      pieces.push(input.slice(cursor, span.start));

      if (action === "allow") {
        pieces.push(span.text);
      } else if (action === "deny") {
        throw new PrivacyPolicyDenyError(detector);
      } else if (action === "hash") {
        const contentHash = this.keyedHash(span.text);
        pieces.push(`[HASH:${contentHash}]`);
        findings.push({
          raw_path: path,
          detector_class: detector,
          span_class: span.class,
          action: "hash",
          content_hash: contentHash,
        });
      } else if (action === "redact") {
        findings.push({
          raw_path: path,
          detector_class: detector,
          span_class: span.class,
          action: "redact",
          content_hash: this.keyedHash(span.text),
        });
        pieces.push(`[${detector.toUpperCase()}_REDACTED]`);
      } else {
        const placeholder = await this.vault.placeholderFor(span.class, span.text, scope);
        findings.push({
          raw_path: path,
          detector_class: detector,
          span_class: span.class,
          action: "redact",
          content_hash: this.keyedHash(span.text),
          placeholder_label: placeholder,
        });
        pieces.push(placeholder);
      }
      cursor = span.end;
    }
    pieces.push(input.slice(cursor));
    return pieces.join("");
  }

  private async fieldDecisionsForFindings(
    findings: PrivacyCoreFinding[],
    pathScope: string
  ): Promise<PrivacyFieldDecision[]> {
    const decisions: PrivacyFieldDecision[] = [];
    for (const finding of findings) {
      const fieldPath = await this.vault.aliasForFieldPath(finding.raw_path, pathScope);
      decisions.push({
        field_path: fieldPath,
        detector_class: finding.detector_class,
        action: finding.action,
        content_hash: finding.content_hash,
        hash_alg: HASH_ALG,
        placeholder_label: finding.placeholder_label,
      });
    }
    return decisions;
  }

  private async rehydrateNode(
    value: unknown,
    scope: string,
    depth: number,
    policy: PrivacyPolicy,
    counts: { rehydrated: number; unresolvable: number },
    seen: WeakSet<object>
  ): Promise<unknown> {
    const maxDepth = policy.max_depth ?? 16;
    if (depth > maxDepth) {
      throw new PrivacyFilterError("payload_depth_limit");
    }

    if (typeof value === "string") {
      return this.rehydrateString(value, scope, counts);
    }

    if (Array.isArray(value)) {
      if (seen.has(value)) throw new PrivacyFilterError("payload_cycle");
      seen.add(value);
      const out: unknown[] = [];
      for (let i = 0; i < value.length; i++) {
        out.push(await this.rehydrateNode(value[i], scope, depth + 1, policy, counts, seen));
      }
      seen.delete(value);
      return out;
    }

    if (value && typeof value === "object") {
      if (seen.has(value)) throw new PrivacyFilterError("payload_cycle");
      seen.add(value);
      const out: Record<string, unknown> = {};
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        out[key] = await this.rehydrateNode(child, scope, depth + 1, policy, counts, seen);
      }
      seen.delete(value);
      return out;
    }

    return value;
  }

  private async rehydrateString(
    input: string,
    scope: string,
    counts: { rehydrated: number; unresolvable: number }
  ): Promise<string> {
    const pattern = /\b(?:EMAIL|PHONE|SSN|CARD|PERSON|CLIENT|PROJECT|SECRET|CREDENTIAL|ACCOUNT|FILE_PATH|TERM|ADDRESS|URL|DATE|PRIVATE)_\d+\b/g;
    let cursor = 0;
    const pieces: string[] = [];
    for (const match of input.matchAll(pattern)) {
      if (match.index === undefined) continue;
      const placeholder = match[0];
      pieces.push(input.slice(cursor, match.index));
      const raw = await this.vault.resolvePlaceholder(placeholder, scope);
      if (raw === null) {
        counts.unresolvable++;
        pieces.push(placeholder);
      } else {
        counts.rehydrated++;
        pieces.push(raw);
      }
      cursor = match.index + placeholder.length;
    }
    pieces.push(input.slice(cursor));
    return pieces.join("");
  }

  private assertPayloadWithinBounds(value: unknown, policy: PrivacyPolicy): void {
    const maxBytes = policy.max_payload_bytes ?? 1024 * 1024;
    const bytes = stringToBytes(canonicalJson(value)).length;
    if (bytes > maxBytes) {
      throw new PrivacyFilterError("payload_size_limit");
    }
  }

  private deniedPayload(
    request: Pick<PrivacyFilterRequest, "policy" | "identity_id" | "agent_id" | "destination_category">,
    eventId: string,
    emittedAt: string,
    policyId: string,
    reason: PrivacyDeniedPayload["denial_reason_class"]
  ): PrivacyDeniedPayload {
    return {
      version: "1.1",
      kind: "denied",
      event_id: eventId,
      emitted_at: emittedAt,
      policy_id: policyId,
      identity_id: request.policy?.identity_id ?? request.identity_id ?? "unknown",
      agent_id: request.agent_id,
      destination_category: request.destination_category,
      denial_reason_class: reason,
    };
  }

  private keyedHash(value: unknown): string {
    const input = typeof value === "string" ? value : canonicalJson(value);
    return bytesToHex(hmacSha256(this.hmacKey, stringToBytes(input)));
  }
}

export function emitPrivacyAuditEvent(
  auditLog: AuditLog | undefined,
  payload: PrivacyAuditPayload,
  result: "success" | "failure" = "success"
): void {
  auditLog?.append(
    "l2",
    PRIVACY_AUDIT_OPERATION,
    payload.identity_id,
    payload as unknown as Record<string, unknown>,
    result
  );
}

export function validatePrivacyPolicy(
  policy: PrivacyPolicy,
  expectedIdentityId?: string
): void {
  if (policy.version !== 1) {
    throw new PrivacyPolicyError("privacy_policy_version_invalid");
  }
  if (!policy.policy_id || !policy.identity_id) {
    throw new PrivacyPolicyError("privacy_policy_unbound");
  }
  if (expectedIdentityId && policy.identity_id !== expectedIdentityId) {
    throw new PrivacyPolicyError("privacy_policy_identity_mismatch");
  }
  if (policy.max_depth !== undefined && policy.max_depth < 0) {
    throw new PrivacyPolicyError("privacy_policy_depth_invalid");
  }
  if (policy.max_payload_bytes !== undefined && policy.max_payload_bytes < 1) {
    throw new PrivacyPolicyError("privacy_policy_size_invalid");
  }
}

export function vaultScopeForPolicy(policy: PrivacyPolicy): string {
  return policy.placeholder_scope === "policy"
    ? `${policy.identity_id}:${policy.policy_id}`
    : policy.identity_id;
}

function actionForDetector(
  policy: PrivacyPolicy,
  destination: PrivacyDestinationCategory,
  detector: PrivacyDetectorClass
): PrivacyPolicyAction {
  return policy.destination_detector_actions?.[destination]?.[detector]
    ?? policy.detector_actions?.[detector]
    ?? "placeholder";
}

function policyAllowsRehydration(
  policy: PrivacyPolicy,
  destination: PrivacyDestinationCategory
): boolean {
  const rehydration = policy.rehydration;
  if (!rehydration) return false;
  if (rehydration.denied_destinations?.includes(destination)) return false;
  if (rehydration.allowed_destinations?.includes(destination)) return true;
  return rehydration.default_action === "allow";
}

function shouldAllowOnError(
  policy: PrivacyPolicy,
  reason: PrivacyDeniedPayload["denial_reason_class"]
): boolean {
  if (reason === "fail_closed_vault_error") {
    return policy.operator_override?.allow_on_vault_error === true;
  }
  if (reason === "fail_closed_filter_error") {
    return policy.operator_override?.allow_on_filter_error === true
      || policy.operator_override?.allow_on_detector_error === true;
  }
  if (reason === "fail_closed_no_policy") {
    return policy.operator_override?.allow_on_policy_error === true;
  }
  return false;
}

function canonicalJson(value: unknown): string {
  if (
    value === undefined ||
    typeof value === "function" ||
    typeof value === "symbol"
  ) {
    return "null";
  }
  if (typeof value === "bigint") {
    return JSON.stringify(value.toString());
  }
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([key, child]) => (
    `${JSON.stringify(key)}:${canonicalJson(child)}`
  )).join(",")}}`;
}

function newPrivacyEventId(): string {
  return `privacy-${Date.now()}-${toBase64url(randomBytes(8))}`;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

class PrivacyPolicyError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "PrivacyPolicyError";
  }
}

class PrivacyFilterError extends Error {
  constructor(code: string) {
    super(code);
    this.name = "PrivacyFilterError";
  }
}

class PrivacyDetectorError extends Error {
  readonly cause?: unknown;

  constructor(code: string, cause?: unknown) {
    super(code);
    this.name = "PrivacyDetectorError";
    this.cause = cause;
  }
}

class PrivacyPolicyDenyError extends Error {
  constructor(readonly detectorClass: PrivacyDetectorClass) {
    super("privacy_policy_deny_rule");
    this.name = "PrivacyPolicyDenyError";
  }
}

function isPrivacyVaultError(err: unknown): boolean {
  return err instanceof PrivacyVaultError ||
    (err instanceof Error && err.name === "PrivacyVaultError");
}
