/**
 * Sanctuary MCP Server — Approval Channel
 *
 * Out-of-band communication with the human principal for operation approval.
 * The default channel uses stderr (outside MCP's stdin/stdout protocol),
 * ensuring the agent cannot intercept or forge approval responses.
 *
 * Security invariant:
 * - Approval prompts go through a channel the agent cannot access.
 * - Timeouts result in denial by default (fail closed).
 */

import type {
  ApprovalRequest,
  ApprovalResponse,
  ApprovalChannelConfig,
} from "./types.js";

/** Abstract approval channel interface */
export interface ApprovalChannel {
  requestApproval(request: ApprovalRequest): Promise<ApprovalResponse>;
}

/**
 * Stderr approval channel — writes prompts to stderr, waits for response.
 *
 * In the MCP stdio model:
 * - stdin/stdout carry the MCP protocol (JSON-RPC)
 * - stderr is available for out-of-band human communication
 *
 * Since many harnesses do not support interactive stdin during tool calls,
 * this channel uses a timeout-based model: the prompt is displayed, and
 * if no response is received within the timeout, the default action applies.
 *
 * For MVS, the channel auto-resolves based on the auto_deny setting.
 * Interactive stdin reading is deferred to a future version with harness support.
 */
export class StderrApprovalChannel implements ApprovalChannel {
  private config: ApprovalChannelConfig;

  constructor(config: ApprovalChannelConfig) {
    this.config = config;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    // Format and emit the approval prompt
    const prompt = this.formatPrompt(request);
    process.stderr.write(prompt + "\n");

    // For MVS: auto-resolve after a brief pause to ensure stderr is flushed.
    // Full interactive approval (reading stdin) requires harness support
    // that most MCP hosts don't yet provide.
    //
    // The prompt is still displayed — the human sees what's happening.
    // Auto-deny means unapproved operations fail safely.
    // Auto-allow means the prompt is informational (log mode).
    await new Promise((resolve) => setTimeout(resolve, 100));

    if (this.config.auto_deny) {
      return {
        decision: "deny",
        decided_at: new Date().toISOString(),
        decided_by: "timeout",
      };
    } else {
      return {
        decision: "approve",
        decided_at: new Date().toISOString(),
        decided_by: "auto",
      };
    }
  }

  private formatPrompt(request: ApprovalRequest): string {
    const tierLabel =
      request.tier === 1
        ? "Tier 1 — always requires approval"
        : "Tier 2 — behavioral anomaly detected";

    const contextLines = Object.entries(request.context)
      .map(([k, v]) => `  ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`)
      .join("\n");

    return [
      "",
      "╔══════════════════════════════════════════════════════════════════╗",
      "║  SANCTUARY: Approval Required                                    ║",
      "╠══════════════════════════════════════════════════════════════════╣",
      `║  Operation:  ${request.operation.padEnd(50)}║`,
      `║  ${tierLabel.padEnd(62)}║`,
      `║  Reason:     ${request.reason.slice(0, 50).padEnd(50)}║`,
      "║                                                                  ║",
      `║  Details:                                                        ║`,
      ...contextLines.split("\n").map(
        (line) => `║    ${line.padEnd(60)}║`
      ),
      "║                                                                  ║",
      this.config.auto_deny
        ? "║  Auto-denying (configure approval_channel.auto_deny to change)  ║"
        : "║  Auto-approving (informational mode)                            ║",
      "╚══════════════════════════════════════════════════════════════════╝",
      "",
    ].join("\n");
  }
}

/**
 * Programmatic approval channel — for testing and API integration.
 */
export class CallbackApprovalChannel implements ApprovalChannel {
  private callback: (request: ApprovalRequest) => Promise<ApprovalResponse>;

  constructor(
    callback: (request: ApprovalRequest) => Promise<ApprovalResponse>
  ) {
    this.callback = callback;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    return this.callback(request);
  }
}

/**
 * Auto-approve channel — for testing. Approves everything.
 */
export class AutoApproveChannel implements ApprovalChannel {
  async requestApproval(_request: ApprovalRequest): Promise<ApprovalResponse> {
    return {
      decision: "approve",
      decided_at: new Date().toISOString(),
      decided_by: "auto",
    };
  }
}
