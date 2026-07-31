/**
 * Level-triggered Castle Wall enforcement availability.
 *
 * v3 contract: macOS Castle Wall may report green only from a fresh,
 * producer-signed assertion emitted by the system extension. Daemon status,
 * policy intent, audit heartbeat, prior flow evidence, and local files are not
 * truth sources for availability.
 */

import { randomBytes } from "node:crypto";
import { createConnection } from "node:net";

import { ed25519 } from "@noble/curves/ed25519";

import {
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
} from "../constants.js";
import type {
  AuditProducerSignatureNotification,
  EnforcementAvailabilityReportNotification,
  EnforcementAvailabilityResponse,
  EnforcementAvailabilitySnapshot,
  FlowDecisionRecordedNotification,
} from "../ipc/messages.js";
import { frame, parseFrame } from "../ipc/framing.js";
import { canonicalize } from "../../mesh/canonical-json.js";
import {
  fromBase64url,
  producerSigningBytes,
} from "./producer-signature.js";

export const ENFORCEMENT_AVAILABILITY_REPORT_OPERATION =
  "enforcement_availability_report" as const;

export const DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS = 30_000;

export type EnforcementAvailabilityStatus =
  | "live"
  | "non_green"
  | "undetermined";

export interface ResolvedEnforcementAvailability {
  status: EnforcementAvailabilityStatus;
  reason: string;
  observed_at: string | null;
  freshness_window_ms: number;
  active_connection_count: number;
}

/**
 * The two delivery paths that carry producer-signed availability from the
 * extension. Both are signed from the SAME producer counter, but they are
 * delivered asynchronously relative to each other, so seqs interleave across
 * paths: a dedicated report signed at seq N routinely arrives after a
 * flow-carried report signed at seq N+k. Replay floors are therefore kept
 * per stream: within one stream delivery is in signing order, so a seq at or
 * below that stream's floor is a genuine replay; across streams it is just
 * out-of-order delivery. Cross-stream replay (re-delivering one stream's
 * message on the other path) is structurally impossible because each
 * verifier checks the signed body's `operation` field
 * (`enforcement_availability_report` vs `egress_approved`/`egress_blocked`).
 *
 * Scope (deliberate, and unchanged from the single-floor design this
 * replaces): floors are per CONNECTION and reset when a connection
 * re-registers, because an extension restart resets the producer counter and
 * a floor that survived reconnect would falsely reject every post-restart
 * report forever (stuck-at-undetermined). The residual cross-connection
 * window is bounded elsewhere: reaching the socket requires local access,
 * resolve() greens only if EVERY active connection holds a fresh live
 * report, and a replayed tuple is only fresh for the consumer-observed
 * freshness window after delivery.
 */
export type EnforcementAvailabilityStream = "dedicated_report" | "flow_carried";

export type EnforcementAvailabilityVerification =
  | {
      ok: true;
      enforcement: EnforcementAvailabilitySnapshot;
      seq: number;
      operation: string;
    }
  | { ok: false; reason: string };

export interface EnforcementAvailabilityStoreOptions {
  freshnessWindowMs?: number;
}

export interface EnforcementAvailabilitySocketQueryOptions {
  timeoutMs?: number;
  generateRequestId?: () => string;
}

interface ConnectionAvailabilityState {
  report: EnforcementAvailabilitySnapshot | null;
  observedAtMs: number | null;
  invalidReason: string | null;
  /**
   * Per-stream monotonic replay floors (two numbers per connection; bounded
   * memory, cleared with the connection on unregister). See
   * {@link EnforcementAvailabilityStream} for why the floor is per stream.
   */
  lastProducerSeqByStream: Record<EnforcementAvailabilityStream, number | null>;
}

export class EnforcementAvailabilityStore {
  private readonly freshnessWindowMs: number;
  private readonly connections = new Map<string, ConnectionAvailabilityState>();

  constructor(options: EnforcementAvailabilityStoreOptions = {}) {
    this.freshnessWindowMs =
      options.freshnessWindowMs ?? DEFAULT_ENFORCEMENT_AVAILABILITY_FRESHNESS_MS;
  }

  registerConnection(connectionId: string): void {
    if (this.connections.has(connectionId)) return;
    this.connections.set(connectionId, {
      report: null,
      observedAtMs: null,
      invalidReason: null,
      lastProducerSeqByStream: { dedicated_report: null, flow_carried: null },
    });
  }

  unregisterConnection(connectionId: string): void {
    this.connections.delete(connectionId);
  }

  recordValidReport(
    connectionId: string,
    report: EnforcementAvailabilitySnapshot,
    observedAtMs: number,
    seq?: number,
    stream: EnforcementAvailabilityStream = "dedicated_report",
  ): void {
    this.registerConnection(connectionId);
    const state = this.connections.get(connectionId);
    if (!state) return;
    if (seq !== undefined) {
      state.lastProducerSeqByStream[stream] = seq;
    }
    state.report = report;
    state.observedAtMs = observedAtMs;
    state.invalidReason = null;
  }

  recordInvalidReport(
    connectionId: string,
    reason: string,
    seq?: number,
    stream: EnforcementAvailabilityStream = "dedicated_report",
  ): void {
    this.registerConnection(connectionId);
    const state = this.connections.get(connectionId);
    if (!state) return;
    if (seq !== undefined) {
      state.lastProducerSeqByStream[stream] = seq;
    }
    state.report = null;
    state.observedAtMs = null;
    state.invalidReason = reason;
  }

  lastProducerSeq(
    connectionId: string,
    stream: EnforcementAvailabilityStream = "dedicated_report",
  ): number | null {
    return (
      this.connections.get(connectionId)?.lastProducerSeqByStream[stream] ?? null
    );
  }

  resolve(nowMs = Date.now()): ResolvedEnforcementAvailability {
    const activeConnectionCount = this.connections.size;
    if (activeConnectionCount === 0) {
      return this.undetermined("no_extension_connection", activeConnectionCount);
    }

    let firstUndetermined: ResolvedEnforcementAvailability | null = null;
    let allLive = true;
    for (const state of this.connections.values()) {
      const perConnection = this.resolveConnection(state, nowMs, activeConnectionCount);
      if (perConnection.status === "non_green") {
        return perConnection;
      }
      if (perConnection.status === "undetermined") {
        allLive = false;
        firstUndetermined ??= perConnection;
      }
    }

    if (allLive) {
      const observedAt = Math.min(
        ...[...this.connections.values()].map((state) => state.observedAtMs ?? nowMs),
      );
      return {
        status: "live",
        reason: "ok",
        observed_at: new Date(observedAt).toISOString(),
        freshness_window_ms: this.freshnessWindowMs,
        active_connection_count: activeConnectionCount,
      };
    }
    return (
      firstUndetermined ??
      this.undetermined("no_fresh_live_report", activeConnectionCount)
    );
  }

  private resolveConnection(
    state: ConnectionAvailabilityState,
    nowMs: number,
    activeConnectionCount: number,
  ): ResolvedEnforcementAvailability {
    if (state.invalidReason !== null) {
      return this.undetermined(state.invalidReason, activeConnectionCount);
    }
    if (state.report === null || state.observedAtMs === null) {
      return this.undetermined("no_report", activeConnectionCount);
    }
    if (nowMs - state.observedAtMs > this.freshnessWindowMs) {
      return this.undetermined(
        "stale_report",
        activeConnectionCount,
        state.observedAtMs,
      );
    }
    const reason = nonGreenReason(state.report);
    if (reason !== null) {
      return {
        status: "non_green",
        reason,
        observed_at: new Date(state.observedAtMs).toISOString(),
        freshness_window_ms: this.freshnessWindowMs,
        active_connection_count: activeConnectionCount,
      };
    }
    return {
      status: "live",
      reason: "ok",
      observed_at: new Date(state.observedAtMs).toISOString(),
      freshness_window_ms: this.freshnessWindowMs,
      active_connection_count: activeConnectionCount,
    };
  }

  private undetermined(
    reason: string,
    activeConnectionCount: number,
    observedAtMs: number | null = null,
  ): ResolvedEnforcementAvailability {
    return {
      status: "undetermined",
      reason,
      observed_at: observedAtMs === null ? null : new Date(observedAtMs).toISOString(),
      freshness_window_ms: this.freshnessWindowMs,
      active_connection_count: activeConnectionCount,
    };
  }
}

export function verifyEnforcementAvailabilityReport(input: {
  notification: EnforcementAvailabilityReportNotification;
  pinnedProducerKeyB64url: string | null;
  fortressId: string;
}): EnforcementAvailabilityVerification {
  const visibleReason = validateEnforcementAvailabilitySnapshot(
    input.notification.enforcement,
  );
  if (visibleReason !== null) return { ok: false, reason: visibleReason };
  const producer = normalizeProducer(input.notification.producer);
  if (producer === null) return { ok: false, reason: "producer_signature_missing" };
  const base = verifyProducerTuple({
    producer,
    pinnedProducerKeyB64url: input.pinnedProducerKeyB64url,
  });
  if (!base.ok) return base;
  const body = parseCanonicalBody(producer.event_canonical_json);
  if (!isRecord(body)) return { ok: false, reason: "producer_body_not_object" };
  if (body.operation !== ENFORCEMENT_AVAILABILITY_REPORT_OPERATION) {
    return { ok: false, reason: "producer_body_wrong_operation" };
  }
  if (body.identity_id !== input.fortressId) {
    return { ok: false, reason: "producer_body_wrong_identity" };
  }
  const details = isRecord(body.details) ? body.details : null;
  if (details === null) return { ok: false, reason: "producer_body_missing_details" };
  if (details.seq !== producer.seq) {
    return { ok: false, reason: "producer_body_seq_mismatch" };
  }
  if ((details.prior_sha256_hex ?? null) !== producer.prior_sha256_hex) {
    return { ok: false, reason: "producer_body_prior_mismatch" };
  }
  if (!snapshotCanonicalEqual(details.enforcement, input.notification.enforcement)) {
    return { ok: false, reason: "producer_body_enforcement_mismatch" };
  }
  if (body.result !== (snapshotIsGreen(input.notification.enforcement) ? "success" : "failure")) {
    return { ok: false, reason: "producer_body_result_mismatch" };
  }
  return {
    ok: true,
    enforcement: input.notification.enforcement,
    seq: producer.seq,
    operation: String(body.operation),
  };
}

export async function queryMacOSEnforcementAvailability(
  socketPath: string,
  options: EnforcementAvailabilitySocketQueryOptions = {},
): Promise<ResolvedEnforcementAvailability> {
  const timeoutMs = options.timeoutMs ?? 1_500;
  const requestId =
    options.generateRequestId?.() ?? randomBytes(16).toString("hex");
  const response = await new Promise<EnforcementAvailabilityResponse>(
    (resolvePromise, reject) => {
      const socket = createConnection(socketPath);
      let inbound = new Uint8Array(0);
      let settled = false;
      const timer = setTimeout(() => {
        finish(new Error("enforcement availability request timed out"));
      }, timeoutMs);
      const finish = (result: EnforcementAvailabilityResponse | Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (result instanceof Error) reject(result);
        else resolvePromise(result);
      };
      socket.once("connect", () => {
        socket.write(
          frame(
            JSON.stringify({
              jsonrpc: "2.0",
              method: "castle-wall.enforcement_availability_request",
              params: {
                type: "enforcement_availability_request",
                request_id: requestId,
              },
            }),
          ),
        );
      });
      socket.on("data", (chunk: Buffer) => {
        const merged = new Uint8Array(inbound.length + chunk.length);
        merged.set(inbound, 0);
        merged.set(
          new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.length),
          inbound.length,
        );
        inbound = merged;
        while (inbound.length > 0) {
          const parsed = parseFrame(inbound);
          if (parsed.kind === "need_more") break;
          if (parsed.kind === "error") {
            finish(new Error(`enforcement availability framing error: ${parsed.reason}`));
            return;
          }
          inbound = inbound.slice(parsed.consumedBytes);
          try {
            const envelope = JSON.parse(parsed.body) as {
              params?: { type?: string; request_id?: string };
            };
            if (
              envelope.params?.type === "enforcement_availability_response" &&
              envelope.params.request_id === requestId
            ) {
              finish(envelope.params as EnforcementAvailabilityResponse);
              return;
            }
          } catch {
            // Ignore malformed/non-response frames until timeout.
          }
        }
      });
      socket.once("error", finish);
    },
  );
  const availability = parseResolvedAvailability(response.availability);
  if (availability === null) {
    throw new Error("malformed enforcement availability response");
  }
  return availability;
}

function parseResolvedAvailability(
  value: unknown,
): ResolvedEnforcementAvailability | null {
  if (!isRecord(value)) return null;
  const status = value.status;
  if (
    status !== "live" &&
    status !== "non_green" &&
    status !== "undetermined"
  ) {
    return null;
  }
  if (typeof value.reason !== "string") return null;
  if (value.observed_at !== null && typeof value.observed_at !== "string") {
    return null;
  }
  if (
    typeof value.freshness_window_ms !== "number" ||
    !Number.isFinite(value.freshness_window_ms)
  ) {
    return null;
  }
  if (
    typeof value.active_connection_count !== "number" ||
    !Number.isInteger(value.active_connection_count) ||
    value.active_connection_count < 0
  ) {
    return null;
  }
  return {
    status,
    reason: value.reason,
    observed_at: value.observed_at,
    freshness_window_ms: value.freshness_window_ms,
    active_connection_count: value.active_connection_count,
  };
}

export function verifyFlowDecisionEnforcementCarriage(input: {
  notification: FlowDecisionRecordedNotification;
  pinnedProducerKeyB64url: string | null;
}): EnforcementAvailabilityVerification {
  if (input.notification.enforcement === null || input.notification.enforcement === undefined) {
    return { ok: false, reason: "enforcement_block_missing" };
  }
  const visibleReason = validateEnforcementAvailabilitySnapshot(
    input.notification.enforcement,
  );
  if (visibleReason !== null) return { ok: false, reason: visibleReason };
  const producer = normalizeProducer(input.notification.producer);
  if (producer === null) return { ok: false, reason: "producer_signature_missing" };
  const base = verifyProducerTuple({
    producer,
    pinnedProducerKeyB64url: input.pinnedProducerKeyB64url,
  });
  if (!base.ok) return base;
  const body = parseCanonicalBody(producer.event_canonical_json);
  if (!isRecord(body)) return { ok: false, reason: "producer_body_not_object" };
  const expectedOperation =
    input.notification.decision === "allow" ? "egress_approved" : "egress_blocked";
  const expectedResult =
    input.notification.decision === "allow" ? "success" : "blocked";
  if (body.operation !== expectedOperation || body.result !== expectedResult) {
    return { ok: false, reason: "producer_body_wrong_flow_operation" };
  }
  const details = isRecord(body.details) ? body.details : null;
  if (details === null) return { ok: false, reason: "producer_body_missing_details" };
  if (details.seq !== producer.seq) {
    return { ok: false, reason: "producer_body_seq_mismatch" };
  }
  if ((details.prior_sha256_hex ?? null) !== producer.prior_sha256_hex) {
    return { ok: false, reason: "producer_body_prior_mismatch" };
  }
  if (details.source !== "macos_extension") {
    return { ok: false, reason: "producer_body_wrong_source" };
  }
  if (!snapshotCanonicalEqual(details.enforcement, input.notification.enforcement)) {
    return { ok: false, reason: "producer_body_enforcement_mismatch" };
  }
  return {
    ok: true,
    enforcement: input.notification.enforcement,
    seq: producer.seq,
    operation: String(body.operation),
  };
}

export function validateEnforcementAvailabilitySnapshot(
  value: unknown,
): string | null {
  if (!isRecord(value)) return "enforcement_block_missing";
  if (value.protocol_version !== 1) return "unsupported_protocol_version";
  if (value.source !== "macos_extension") return "invalid_source";
  if (
    value.lease_state !== "live" &&
    value.lease_state !== "missing" &&
    value.lease_state !== "unarmed" &&
    value.lease_state !== "failed_open"
  ) {
    return "invalid_lease_state";
  }
  if (
    value.lease_reason !== "ok" &&
    value.lease_reason !== "arm_lease_missing" &&
    value.lease_reason !== "not_armed" &&
    value.lease_reason !== "lease_revoked" &&
    value.lease_reason !== "ttl_expired" &&
    value.lease_reason !== "heartbeat_stopped"
  ) {
    return "invalid_lease_reason";
  }
  if (value.lease_state === "live" && value.lease_reason !== "ok") {
    return "invalid_live_lease_reason";
  }
  if (value.lease_state === "missing" && value.lease_reason !== "arm_lease_missing") {
    return "invalid_missing_lease_reason";
  }
  if (value.lease_state === "unarmed" && value.lease_reason !== "not_armed") {
    return "invalid_unarmed_lease_reason";
  }
  if (
    value.lease_state === "failed_open" &&
    value.lease_reason !== "lease_revoked" &&
    value.lease_reason !== "ttl_expired" &&
    value.lease_reason !== "heartbeat_stopped"
  ) {
    return "invalid_failed_open_lease_reason";
  }
  if (value.manifest_state !== "applied" && value.manifest_state !== "absent") {
    return "invalid_manifest_state";
  }
  if (
    value.manifest_state === "applied" &&
    (typeof value.manifest_signature_b64url !== "string" ||
      value.manifest_signature_b64url.length === 0)
  ) {
    return "missing_manifest_signature";
  }
  if (value.manifest_state === "absent" && value.manifest_signature_b64url !== null) {
    return "invalid_absent_manifest_signature";
  }
  if (typeof value.provider_bound !== "boolean") return "invalid_provider_bound";
  if (
    value.producer_claimed_at !== undefined &&
    typeof value.producer_claimed_at !== "string"
  ) {
    return "invalid_producer_claimed_at";
  }
  return null;
}

export function snapshotIsGreen(
  snapshot: EnforcementAvailabilitySnapshot,
): boolean {
  return nonGreenReason(snapshot) === null;
}

export function nonGreenReason(
  snapshot: EnforcementAvailabilitySnapshot,
): string | null {
  const invalid = validateEnforcementAvailabilitySnapshot(snapshot);
  if (invalid !== null) return invalid;
  if (snapshot.lease_state !== "live") {
    return `lease:${snapshot.lease_reason}`;
  }
  if (snapshot.manifest_state !== "applied") {
    return "manifest_absent";
  }
  if (snapshot.provider_bound !== true) {
    return "provider_unbound";
  }
  return null;
}

function verifyProducerTuple(input: {
  producer: AuditProducerSignatureNotification;
  pinnedProducerKeyB64url: string | null;
}): { ok: true } | { ok: false; reason: string } {
  if (input.pinnedProducerKeyB64url === null) {
    return { ok: false, reason: "producer_key_missing" };
  }
  if (input.producer.key_id !== CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1) {
    return { ok: false, reason: "producer_key_id_mismatch" };
  }
  try {
    const publicKey = fromBase64url(input.pinnedProducerKeyB64url);
    const signature = fromBase64url(input.producer.signature_b64url);
    const signedBytes = producerSigningBytes(
      input.producer.event_canonical_json,
      input.producer.captured_at_unix_ms,
      input.producer.seq,
    );
    if (!ed25519.verify(signature, signedBytes, publicKey)) {
      return { ok: false, reason: "producer_signature_invalid" };
    }
  } catch {
    return { ok: false, reason: "producer_signature_invalid" };
  }
  return { ok: true };
}

function normalizeProducer(
  value: AuditProducerSignatureNotification | null | undefined,
): AuditProducerSignatureNotification | null {
  if (value === null || value === undefined) return null;
  if (
    typeof value.event_canonical_json !== "string" ||
    typeof value.captured_at_unix_ms !== "number" ||
    typeof value.seq !== "number" ||
    !Number.isInteger(value.seq) ||
    value.seq < 0 ||
    !(
      typeof value.prior_sha256_hex === "string" ||
      value.prior_sha256_hex === null
    ) ||
    typeof value.signature_b64url !== "string" ||
    typeof value.key_id !== "string"
  ) {
    return null;
  }
  return value;
}

function parseCanonicalBody(json: string): unknown {
  try {
    return JSON.parse(json) as unknown;
  } catch {
    return null;
  }
}

function snapshotCanonicalEqual(a: unknown, b: unknown): boolean {
  try {
    return canonicalize(a) === canonicalize(b);
  } catch {
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
