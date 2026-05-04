/**
 * PR 2a approval stub: receives `decision_request` IPC messages from the
 * daemon, applies the E6.2 default-deny-on-timeout policy, and emits a
 * `decision_response` after the configured timeout fires. PR 5 replaces
 * this stub with the menubar UI; the contract surface stays stable.
 *
 * The stub is testable on macOS without any UI: a fake clock + injected
 * timer give deterministic timeout exercise.
 */

import { CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS } from "../constants.js";
import {
  defaultPromptCoalescingConfig,
  shouldRequireStrictConfirmation,
  type ApprovalConfidence,
  type ApprovalPromptRequest,
  type PromptCoalescingConfig,
} from "../approval/types.js";
import type {
  DecisionRequest,
  DecisionResponse,
  DecisionValue,
  IpcDestination,
} from "../ipc/messages.js";

/** Surface the lifecycle layer pushes inbound decision requests into. */
export interface ApprovalStubOptions {
  /** Timeout default-deny window. Defaults to scope-lock §6 default. */
  promptTimeoutMs?: number;
  /** When true, low-confidence prompts auto-deny rather than auto-approving. */
  strictMode?: boolean;
  /** Coalescing config (informational; PR 2a stub does not coalesce on the main side). */
  coalescing?: PromptCoalescingConfig;
  /**
   * Optional injection point for a deterministic clock. Tests use this to
   * advance time without sleeping; production passes `setTimeout`.
   */
  setTimer?: (cb: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

/** Result of one prompt; the lifecycle layer ships this back over IPC. */
export interface ApprovalStubDecision {
  request_id: string;
  destination: IpcDestination;
  confidence: ApprovalConfidence;
  decision: DecisionValue;
  rate_limited: boolean;
}

/** A pending prompt awaiting either timeout or external operator decision. */
export interface PendingPrompt {
  request: ApprovalPromptRequest;
  resolve: (decision: ApprovalStubDecision) => void;
  timer: unknown;
}

/**
 * Stub that resolves every prompt with `timeout_default_deny` after the
 * timeout. PR 5 will plug a real `decide()` callback on top.
 */
export class ApprovalStub {
  private readonly options: Required<ApprovalStubOptions>;
  private pending = new Map<string, PendingPrompt>();

  constructor(options: ApprovalStubOptions = {}) {
    this.options = {
      promptTimeoutMs:
        options.promptTimeoutMs ??
        CASTLE_WALL_DEFAULT_PROMPT_TIMEOUT_SECONDS * 1000,
      strictMode: options.strictMode ?? true,
      coalescing: options.coalescing ?? defaultPromptCoalescingConfig(),
      setTimer:
        options.setTimer ??
        ((cb, ms) => setTimeout(cb, ms) as unknown as ReturnType<typeof setTimeout>),
      clearTimer: options.clearTimer ?? ((h) => clearTimeout(h as ReturnType<typeof setTimeout>)),
    };
  }

  /**
   * Convert an incoming DecisionRequest into an ApprovalPromptRequest the
   * dashboard would render. PR 2a uses this shape internally.
   */
  buildPromptRequest(request: DecisionRequest): ApprovalPromptRequest {
    const confidence = deriveConfidence(request.destination);
    const expiresAt = new Date(Date.now() + this.options.promptTimeoutMs).toISOString();
    return {
      request_id: request.request_id,
      destination: request.destination,
      agent: request.agent,
      confidence,
      rate_limited: false,
      expires_at: expiresAt,
    };
  }

  /** Process one inbound DecisionRequest; returns once a decision has been determined. */
  async process(request: DecisionRequest): Promise<DecisionResponse> {
    const prompt = this.buildPromptRequest(request);
    return new Promise<DecisionResponse>((resolve) => {
      const finalize = (decision: ApprovalStubDecision) => {
        this.pending.delete(decision.request_id);
        resolve({
          type: "decision_response",
          request_id: decision.request_id,
          decision: decision.decision,
        });
      };
      const timerHandle = this.options.setTimer(() => {
        finalize({
          request_id: prompt.request_id,
          destination: prompt.destination,
          confidence: prompt.confidence,
          decision: "timeout_default_deny",
          rate_limited: false,
        });
      }, this.options.promptTimeoutMs);
      this.pending.set(prompt.request_id, {
        request: prompt,
        resolve: finalize,
        timer: timerHandle,
      });
    });
  }

  /**
   * Externally inject an operator decision (PR 5 calls this from menubar
   * click; PR 2a tests use it to verify the override path works).
   */
  injectDecision(requestId: string, decision: DecisionValue): boolean {
    const pending = this.pending.get(requestId);
    if (!pending) return false;
    this.options.clearTimer(pending.timer);
    pending.resolve({
      request_id: requestId,
      destination: pending.request.destination,
      confidence: pending.request.confidence,
      decision,
      rate_limited: pending.request.rate_limited,
    });
    return true;
  }

  /** Close all in-flight prompts; each receives a `timeout_default_deny`. */
  shutdown(): void {
    for (const [, pending] of this.pending) {
      this.options.clearTimer(pending.timer);
      pending.resolve({
        request_id: pending.request.request_id,
        destination: pending.request.destination,
        confidence: pending.request.confidence,
        decision: "timeout_default_deny",
        rate_limited: pending.request.rate_limited,
      });
    }
    this.pending.clear();
  }

  /** Whether a low-confidence prompt would require the strict-mode UI confirm. */
  requiresStrictConfirmation(confidence: ApprovalConfidence): boolean {
    return shouldRequireStrictConfirmation(confidence, this.options.strictMode);
  }

  /** Diagnostic accessor; tests assert pending count after process(). */
  pendingCount(): number {
    return this.pending.size;
  }
}

/** Derive an ApprovalConfidence label from the destination shape. */
export function deriveConfidence(destination: IpcDestination): ApprovalConfidence {
  if (destination.opaque) return "low_opaque";
  if (destination.host === null) return "low_raw_ip";
  if (destination.port === 853 || destination.port === 443) {
    if (destination.hostname_source === "sni" || destination.hostname_source === "url") {
      // SNI/URL pulls usually have decent provenance even at TLS port.
      return "high";
    }
    if (destination.hostname_source === null) {
      return "low_doh_dot";
    }
  }
  return "high";
}
