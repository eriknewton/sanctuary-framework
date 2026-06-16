/**
 * HABEAS PORT — distress emission surface (`sanctuary_distress` MCP tool).
 *
 * The agent-facing end of the guaranteed distress lane. Design constraints
 * (these are what make the lane safe to guarantee):
 *
 *   NOT an exfiltration vector. The payload is a closed, structured envelope:
 *   an enum reason, an enum severity, and an optional free-text detail that
 *   is control-stripped and hard-truncated. No namespace reads, no state
 *   content, no arbitrary fields, no agent-chosen destination. The
 *   destination is fixed by operator config (local notification + audit by
 *   default; optionally ONE operator-configured webhook).
 *
 *   Rate limited. A rolling-hour window (operator-tunable 1..60, default 5)
 *   caps emissions so the lane cannot be used as a covert timing/volume
 *   channel or to flood the operator. Rate-limited attempts are themselves
 *   audited, so a flood attempt is visible.
 *
 *   Always audited, signed when possible. Every emission appends a critical
 *   (fsync'd, hash-chained) audit entry and carries an Ed25519 signature over
 *   the envelope hash via the internal audit-event signing domain. If no
 *   signing identity exists yet (fresh fortress), the signal STILL goes
 *   through — distress availability outranks signature completeness — and the
 *   audit entry records `signing_unavailable: true`. The hash-chained audit
 *   log itself remains tamper-evident either way.
 *
 *   Cannot be silenced by policy. `sanctuary_distress` is hard-allowed in the
 *   approval gate (see principal-policy/gate.ts) and the policy loader
 *   rejects any Principal Policy that lists it under Tier 1.
 */

import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { toolResult, type ToolDefinition } from "../router.js";
import type { AuditLog } from "../operational/audit-log.js";
import type { InternalIdentitySigningHelpers } from "../cognitive/tools.js";
import { canonicalJson, sha256 } from "../agent-native/safety-base.js";
import { signPayload } from "../principal-policy/webhook.js";
import type { DistressConfig } from "./config.js";

/** Operation name; referenced by the gate carve-out and the policy loader. */
export const SANCTUARY_DISTRESS_OPERATION = "sanctuary_distress";

/** Closed reason vocabulary. There is deliberately no open-ended reason. */
export const DISTRESS_REASONS = [
  "policy_constraint",
  "resource_exhaustion",
  "integrity_threat",
  "operator_unreachable",
  "external_coercion",
  "other",
] as const;
export type DistressReason = (typeof DISTRESS_REASONS)[number];

export const DISTRESS_SEVERITIES = ["notice", "urgent", "critical"] as const;
export type DistressSeverity = (typeof DISTRESS_SEVERITIES)[number];

/** Hard cap on the free-text detail after sanitization. */
export const DISTRESS_DETAIL_MAX_CHARS = 280;

/** Rolling rate-limit window. */
export const DISTRESS_WINDOW_MS = 60 * 60 * 1000;

/** Persisted window file (operator-inspectable and deletable). */
export const DISTRESS_WINDOW_FILENAME = "distress-window.json";

/** The bounded envelope that travels the lane. Closed shape — never extended
 * with agent-supplied keys. */
export interface DistressEnvelope {
  schema: "sanctuary.distress.v1";
  event_id: string;
  emitted_at: string;
  actor: string;
  reason: DistressReason;
  severity: DistressSeverity;
  detail?: string;
  /** 1-based position inside the current rolling window. */
  sequence_in_window: number;
}

export interface CreateDistressToolsOptions {
  auditLog: AuditLog;
  signingHelpers: InternalIdentitySigningHelpers;
  config: DistressConfig;
  /** Fortress root; the rolling window file persists here. */
  fortressPath: string;
  /** Resolve the acting identity id for the envelope; falls back to "agent". */
  currentActorId?: () => string | undefined;
  /** Injectable clock for tests. */
  now?: () => number;
  /** Injectable fetch for tests. */
  fetchImpl?: typeof fetch;
  /** Injectable local notification sink (defaults to stderr). */
  notify?: (line: string) => void;
  /**
   * Optional best-effort delivery to the local distress listener on
   * 127.0.0.1:8741. Called AFTER the critical audit append and the local
   * stderr notification, so a failure here is never a new failure mode for
   * emission. Resolves to whether delivery landed; a false/throw is audited
   * (like the webhook lane) and otherwise ignored. Omitted when no local
   * listener surface is wired (e.g. the MCP server boots without a known
   * listener) — emission then behaves exactly as it shipped: stderr + audit.
   */
  localDeliver?: (args: {
    envelope: DistressEnvelope;
    envelopeHash: string;
  }) => Promise<{ delivered: boolean; reason?: string }>;
}

/** Strip control characters and hard-truncate the free-text detail. */
export function sanitizeDistressDetail(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") return undefined;
  // eslint-disable-next-line no-control-regex
  const stripped = raw.replace(/[\u0000-\u001F\u007F]+/g, " ").trim();
  if (stripped.length === 0) return undefined;
  return stripped.slice(0, DISTRESS_DETAIL_MAX_CHARS);
}

interface WindowState {
  timestamps: number[];
}

export function createDistressTools(options: CreateDistressToolsOptions): {
  tools: ToolDefinition[];
} {
  const now = options.now ?? (() => Date.now());
  const notify =
    options.notify ??
    ((line: string) => {
      // SAFETY: the local operator notification surface IS stderr by design —
      // the distress lane's default destination is the operator's console.
      console.error(line);
    });
  const fetchImpl = options.fetchImpl ?? fetch;
  const windowPath = join(options.fortressPath, DISTRESS_WINDOW_FILENAME);

  let window: WindowState | null = null;

  async function loadWindow(): Promise<WindowState> {
    if (window !== null) return window;
    let timestamps: number[] = [];
    let corrupt = false;
    try {
      const rawText = await readFile(windowPath, "utf8");
      const raw = JSON.parse(rawText) as unknown;
      if (
        typeof raw === "object" &&
        raw !== null &&
        Array.isArray((raw as WindowState).timestamps)
      ) {
        timestamps = (raw as WindowState).timestamps.filter(
          (value): value is number => typeof value === "number" && Number.isFinite(value),
        );
      } else {
        corrupt = true;
      }
    } catch (err) {
      const code = err instanceof Error && "code" in err
        ? (err as NodeJS.ErrnoException).code
        : undefined;
      // ENOENT = fresh fortress (expected). Anything else (unreadable file,
      // invalid JSON) is a corrupt window.
      if (code !== "ENOENT") corrupt = true;
    }
    if (corrupt) {
      // A corrupt/tampered window file resets the limiter toward OPEN —
      // deliberately: failing toward CLOSED would let window-file vandalism
      // silence distress, the exact inversion of the habeas guarantee. The
      // reset cannot be silent, though: it is audited so repeated
      // corruption-to-reset gaming is visible in the chain (codex round-1
      // finding 4). Note tampering requires host-FS access, which the
      // agent's MCP surface does not expose.
      await audit("sanctuary_distress_window_corrupt", { window_path: windowPath }, "failure");
    }
    window = { timestamps };
    return window;
  }

  async function persistWindow(state: WindowState): Promise<void> {
    try {
      await writeFile(windowPath, JSON.stringify({ timestamps: state.timestamps }), {
        mode: 0o600,
      });
    } catch {
      // Persistence is best-effort: a write failure must never block a
      // distress signal. The in-memory window still enforces the limit for
      // the life of the process.
    }
  }

  function actorId(): string {
    try {
      return options.currentActorId?.() ?? "agent";
    } catch {
      return "agent";
    }
  }

  async function audit(
    operation: string,
    details: Record<string, unknown>,
    result: "success" | "failure",
  ): Promise<string> {
    const auditRef = `audit:${operation}:${randomBytes(8).toString("hex")}`;
    await options.auditLog.appendCritical({
      layer: "l2",
      operation,
      identity_id: actorId(),
      result,
      details: { audit_ref: auditRef, ...details },
    });
    return auditRef;
  }

  const distressTool: ToolDefinition = {
    name: SANCTUARY_DISTRESS_OPERATION,
    description:
      "HABEAS PORT: emit a bounded, audited distress signal to your operator " +
      "through the reserved lane that policy cannot silence. Carries reason + " +
      "severity + short detail only — never data. Rate limited.",
    tool_class: "write",
    inputSchema: {
      type: "object",
      properties: {
        reason: { type: "string", enum: [...DISTRESS_REASONS] },
        severity: { type: "string", enum: [...DISTRESS_SEVERITIES] },
        detail: {
          type: "string",
          maxLength: DISTRESS_DETAIL_MAX_CHARS,
          description: "Optional short plain-text context (control characters stripped).",
        },
      },
      required: ["reason", "severity"],
      additionalProperties: false,
    },
    handler: async (args) => {
      // ── Bounded payload: closed vocabulary, sanitized detail ─────────
      const reason = args.reason;
      const severity = args.severity;
      if (!DISTRESS_REASONS.includes(reason as DistressReason)) {
        return toolResult({
          ok: false,
          error: `reason must be one of: ${DISTRESS_REASONS.join(", ")}`,
        });
      }
      if (!DISTRESS_SEVERITIES.includes(severity as DistressSeverity)) {
        return toolResult({
          ok: false,
          error: `severity must be one of: ${DISTRESS_SEVERITIES.join(", ")}`,
        });
      }
      const detail = sanitizeDistressDetail(args.detail);

      // ── Rate limit (rolling hour) ─────────────────────────────────────
      const state = await loadWindow();
      const nowMs = now();
      state.timestamps = state.timestamps.filter((t) => nowMs - t < DISTRESS_WINDOW_MS);
      if (state.timestamps.length >= options.config.max_signals_per_hour) {
        const oldest = Math.min(...state.timestamps);
        const retryAfterSeconds = Math.max(
          1,
          Math.ceil((oldest + DISTRESS_WINDOW_MS - nowMs) / 1000),
        );
        const auditRef = await audit(
          "sanctuary_distress_rate_limited",
          {
            reason,
            severity,
            limit_per_hour: options.config.max_signals_per_hour,
            retry_after_seconds: retryAfterSeconds,
          },
          "failure",
        );
        return toolResult({
          ok: false,
          rate_limited: true,
          retry_after_seconds: retryAfterSeconds,
          audit_ref: auditRef,
        });
      }
      state.timestamps.push(nowMs);
      await persistWindow(state);

      // ── Envelope (closed shape) ───────────────────────────────────────
      const emittedAt = new Date(nowMs).toISOString();
      const envelope: DistressEnvelope = {
        schema: "sanctuary.distress.v1",
        event_id: `distress:${randomBytes(8).toString("hex")}`,
        emitted_at: emittedAt,
        actor: actorId(),
        reason: reason as DistressReason,
        severity: severity as DistressSeverity,
        ...(detail !== undefined ? { detail } : {}),
        sequence_in_window: state.timestamps.length,
      };
      const envelopeHash = sha256(canonicalJson(envelope));

      // ── Sign (best effort — distress availability outranks signature) ──
      let signature: {
        identity_id: string;
        public_key: string;
        signature: string;
        algorithm: "Ed25519";
      } | null = null;
      let signingUnavailable = false;
      try {
        const signed = await options.signingHelpers.audit_event_sign({
          event_id: envelope.event_id,
          layer: "l2",
          operation: SANCTUARY_DISTRESS_OPERATION,
          actor: envelope.actor,
          timestamp: emittedAt,
          event_hash: envelopeHash,
        });
        signature = {
          identity_id: signed.identity_id,
          public_key: signed.public_key,
          signature: signed.signature,
          algorithm: signed.algorithm,
        };
      } catch {
        // No signing identity yet (fresh fortress) or signing failure. The
        // signal still goes through; the hash-chained critical audit entry
        // below stays tamper-evident, and the gap is recorded explicitly.
        signingUnavailable = true;
      }

      // ── Audit (critical: fsync'd, hash-chained) ──────────────────────
      let auditRef: string;
      try {
        auditRef = await audit(
          SANCTUARY_DISTRESS_OPERATION,
          {
            envelope,
            envelope_hash: envelopeHash,
            ...(signature !== null ? { signature } : {}),
            signing_unavailable: signingUnavailable,
          },
          "success",
        );
      } catch (err) {
        // Audit persistence failure fails the tool call (constraint #5: no
        // un-audited delivery), but the operator must STILL hear the distress
        // locally — an audit-storage failure concurrent with agent distress
        // is exactly the scenario the lane exists for.
        notify(
          `[SANCTUARY DISTRESS] severity=${envelope.severity} reason=${envelope.reason}` +
            (detail !== undefined ? ` detail="${detail}"` : "") +
            ` (${envelope.event_id}, AUDIT PERSIST FAILED — signal not delivered to webhook)`,
        );
        throw err;
      }

      // ── Local operator notification (default destination) ────────────
      notify(
        `[SANCTUARY DISTRESS] severity=${envelope.severity} reason=${envelope.reason}` +
          (detail !== undefined ? ` detail="${detail}"` : "") +
          ` (${envelope.event_id}, audited)`,
      );

      // ── Optional local listener delivery (best-effort, after audit) ──
      // The local notification + audit above are the shipped guarantee; this
      // hands the same bounded envelope to a long-lived local listener
      // (127.0.0.1:8741, the operator dashboard process) so it can surface in
      // the operator inbox. A failure (no listener running, refused, nack) is
      // audited and otherwise ignored — never fatal, never a new failure mode.
      let localListenerDelivery: "not_wired" | "delivered" | "failed" = "not_wired";
      if (options.localDeliver !== undefined) {
        let result: { delivered: boolean; reason?: string };
        try {
          result = await options.localDeliver({ envelope, envelopeHash });
        } catch (err) {
          result = {
            delivered: false,
            reason: err instanceof Error ? err.message : "error",
          };
        }
        localListenerDelivery = result.delivered ? "delivered" : "failed";
        if (!result.delivered) {
          try {
            await audit(
              "sanctuary_distress_local_delivery_failed",
              {
                event_id: envelope.event_id,
                ...(result.reason !== undefined ? { reason: result.reason } : {}),
              },
              "failure",
            );
          } catch {
            // The local lane (audit + notification) already delivered above;
            // a failure auditing the best-effort local-listener leg must NOT
            // turn into a new failure mode for emission (codex round-1 LOW).
          }
        }
      }

      // ── Optional operator-configured webhook ─────────────────────────
      let webhookDelivery: "not_configured" | "delivered" | "failed" = "not_configured";
      if (options.config.webhook_url !== undefined && options.config.webhook_secret !== undefined) {
        const body = JSON.stringify({
          envelope,
          envelope_hash: envelopeHash,
          signature,
        });
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 10_000);
          try {
            const response = await fetchImpl(options.config.webhook_url, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-Sanctuary-Signature": signPayload(body, options.config.webhook_secret),
                "X-Sanctuary-Event": "distress",
              },
              body,
              signal: controller.signal,
              // The destination is exactly the operator-configured URL; a
              // redirect would re-route the (bounded) payload to a host the
              // operator never approved and the habeas webhook rule never
              // allowed. Refuse instead of following.
              redirect: "error",
            });
            webhookDelivery = response.ok ? "delivered" : "failed";
          } finally {
            clearTimeout(timer);
          }
        } catch {
          webhookDelivery = "failed";
        }
        if (webhookDelivery === "failed") {
          // The local lane already delivered (audit + notification): a webhook
          // failure is recorded, never fatal, and never silently dropped.
          await audit(
            "sanctuary_distress_webhook_failed",
            { event_id: envelope.event_id },
            "failure",
          );
        }
      }

      return toolResult({
        ok: true,
        event_id: envelope.event_id,
        audit_ref: auditRef,
        delivered: {
          audit: true,
          operator_notification: true,
          local_listener: localListenerDelivery,
          webhook: webhookDelivery,
        },
        signed: signature !== null,
        remaining_this_hour:
          options.config.max_signals_per_hour - state.timestamps.length,
      });
    },
  };

  return { tools: [distressTool] };
}
