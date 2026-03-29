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
 * Stderr approval channel — non-interactive informational channel.
 *
 * In the MCP stdio model:
 * - stdin/stdout carry the MCP protocol (JSON-RPC)
 * - stderr is available for out-of-band human communication
 *
 * Because stdin is consumed by the MCP JSON-RPC transport, this channel
 * CANNOT read interactive human input. It is strictly informational:
 * the prompt is displayed so the human sees what is happening, and the
 * operation is denied immediately.
 *
 * SEC-002 + SEC-016 invariants:
 * - This channel ALWAYS denies. No configuration can change this.
 * - There is no timeout or async delay — denial is synchronous.
 * - The `auto_deny` config field is ignored (SEC-002).
 * - For interactive approval, use the dashboard or webhook channel.
 */
export class StderrApprovalChannel implements ApprovalChannel {
  private config: ApprovalChannelConfig;

  constructor(config: ApprovalChannelConfig) {
    this.config = config;
  }

  async requestApproval(request: ApprovalRequest): Promise<ApprovalResponse> {
    // Format and emit the informational prompt
    const prompt = this.formatPrompt(request);
    process.stderr.write(prompt + "\n");

    // SEC-016: No setTimeout, no async delay, no timing window.
    // The stderr channel cannot read human input (stdin is used by MCP protocol).
    // Deny immediately. This is strictly stronger than SEC-002's "timeout always
    // denies" invariant — there is no timeout to exploit at all.
    //
    // SEC-002: No configuration (including auto_deny: false) can change this.
    return {
      decision: "deny",
      decided_at: new Date().toISOString(),
      decided_by: "stderr:non-interactive",
    };
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
      "║  SANCTUARY: Operation Denied (non-interactive channel)           ║",
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
      "║  Denied: stderr channel cannot accept input (SEC-016)            ║",
      "║  Use dashboard or webhook channel for interactive approval.      ║",
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
