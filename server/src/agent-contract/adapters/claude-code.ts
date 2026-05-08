/**
 * Sanctuary Agent Contract v0.1 — Claude Code Reference Adapter (§5).
 *
 * Claude Code is Anthropic's CLI coding agent. It runs as a subprocess that
 * accepts a single-prompt or interactive session and streams MCP-shaped
 * tool calls over stdio. This adapter wraps it:
 *
 *   Claude Code (child) ──stdio──► Tier B adapter ──Sanctuary─► broker
 *
 * Claude Code's model_provider is pinned to "anthropic" on the card.
 *
 * Lifecycle translation:
 *   - launch:     spawn child with HTTP_PROXY env + prompt on argv or stdin;
 *                 issue Agent Card; emit `launched` event.
 *   - pause:      send SIGSTOP; hold stdin/stdout buffers.
 *   - checkpoint: capture current conversation transcript hash as
 *                 checkpoint_hash; emit `checkpointed` event.
 *   - resume:     send SIGCONT; emit `resumed` with the recorded hash.
 *   - retire:     close stdin cleanly, wait for exit; emit `retired`.
 *   - revoke:     SIGKILL, emit `revoked` with guardian_quorum.
 *
 * The adapter is responsible for enforcing the §2.4 capability check on
 * every tool call the child attempts. An undeclared capability triggers a
 * broker-level deny; the adapter translates that into a Claude-Code-shaped
 * MCP error response so the child handles it cleanly.
 */

import {
  TierBAdapter,
  registerTierBAdapter,
  type LifecycleCommand,
  type TierBAdapterParams,
} from "./tier-b-sdk.js";
import { CapabilityUndeclaredError } from "../errors.js";
import {
  requiredModelProviderFor,
  type CapabilityKind,
} from "../constants.js";

/**
 * Abstract transport for the Claude Code subprocess. The integration test
 * stubs this with an in-memory implementation; the CLI synthesizes one
 * backed by `child_process.spawn`.
 */
export interface ClaudeCodeTransport {
  /** Send a message to the child's stdin. */
  send(message: string): Promise<void>;
  /** Receive next message from the child's stdout. Null = EOF. */
  receive(): Promise<string | null>;
  /** Signal the child. */
  signal(sig: "SIGSTOP" | "SIGCONT" | "SIGTERM" | "SIGKILL"): Promise<void>;
  /** Close stdin and wait for exit. */
  close(): Promise<void>;
}

export interface ClaudeCodeAdapterParams extends TierBAdapterParams {
  transport: ClaudeCodeTransport;
}

/**
 * ClaudeCodeAdapter — second reference Tier B adapter.
 *
 * Spec requirement: model_provider MUST be "anthropic" (the broker does
 * not enforce this, but the reference adapter pins it by construction and
 * the integration test verifies).
 */
export class ClaudeCodeAdapter extends TierBAdapter {
  readonly harnessId = "claude-code";

  constructor(private ccParams: ClaudeCodeAdapterParams) {
    super(ccParams);
    // Defense in depth: the structural enforcement lives at `issueAgentCard`
    // (constants.ts ADAPTER_PROVIDER_PINS). Construction-time check stays so a
    // misconfiguration surfaces at adapter instantiation rather than later
    // during launch.
    const required = requiredModelProviderFor("claude-code");
    if (required !== null && ccParams.model_provider !== required) {
      throw new Error(
        `claude-code adapter requires model_provider="${required}"; got ${ccParams.model_provider}`
      );
    }
  }

  protected override harnessEnv(): Record<string, string> {
    return {
      CLAUDE_CODE_NON_INTERACTIVE: "true",
      // Claude Code respects ANTHROPIC_API_KEY; we deliberately do NOT
      // read it from the parent env — the operator injects it through the
      // broker's secret-broker channel and the adapter forwards a
      // reference, not the key itself.
      ANTHROPIC_API_KEY_REFERENCE: "sanctuary-broker",
    };
  }

  protected translateLifecycle(cmd: LifecycleCommand): string {
    switch (cmd) {
      case "launch":
        return "/start";
      case "pause":
        return "/pause"; // handled via SIGSTOP separately
      case "checkpoint":
        return "/checkpoint";
      case "resume":
        return "/resume";
      case "retire":
        return "/exit";
      case "revoke":
        return "/revoke";
    }
  }

  /**
   * Validate that a tool call the child wants to make is declared on the
   * Agent Card. On allow, calls the superclass `observeHarnessAction` to
   * wrap + emit usage. On deny, translate to an MCP error response the
   * child can render.
   */
  async attemptToolCall(args: {
    tool_name: string;
    input: unknown;
    output: unknown;
    capability_kind?: CapabilityKind;
  }): Promise<
    | { ok: true; usage_event_id: string }
    | { ok: false; mcp_error: { code: number; message: string } }
  > {
    const kind = args.capability_kind ?? "tool-call";
    try {
      const emitted = this.observeHarnessAction({
        capability_kind: kind,
        capability_target: args.tool_name,
        input: args.input,
        output: args.output,
      });
      return { ok: true, usage_event_id: emitted.usage.body.usage_event_id };
    } catch (e) {
      if (e instanceof CapabilityUndeclaredError) {
        return {
          ok: false,
          mcp_error: {
            // JSON-RPC 2.0 Invalid Params — the child reads this as a tool
            // error and can either surface to the user or attempt a
            // capability extension (separate flow).
            code: -32602,
            message: `sanctuary: ${args.tool_name} not declared on Agent Card (attempted kind=${kind})`,
          },
        };
      }
      throw e;
    }
  }

  async sendLifecycle(
    cmd: Exclude<LifecycleCommand, "launch">,
    args: {
      from_state: Parameters<TierBAdapter["emitLifecycle"]>[0]["from_state"];
      reason?: string;
      checkpoint_hash?: string;
      guardian_quorum?: Parameters<
        TierBAdapter["emitLifecycle"]
      >[0]["guardian_quorum"];
    }
  ) {
    if (cmd === "pause") {
      await this.ccParams.transport.signal("SIGSTOP");
    } else if (cmd === "resume") {
      await this.ccParams.transport.signal("SIGCONT");
    } else if (cmd === "revoke") {
      await this.ccParams.transport.signal("SIGKILL");
    } else {
      await this.ccParams.transport.send(this.translateLifecycle(cmd));
    }
    const to_state = (() => {
      switch (cmd) {
        case "pause":
          return "paused" as const;
        case "checkpoint":
          return "checkpointed" as const;
        case "resume":
          return "resumed" as const;
        case "retire":
          return "retired" as const;
        case "revoke":
          return "revoked" as const;
      }
    })();
    return this.emitLifecycle({
      from_state: args.from_state,
      to_state,
      reason: args.reason ?? `claude-code-${cmd}`,
      checkpoint_hash: args.checkpoint_hash,
      guardian_quorum: args.guardian_quorum,
    });
  }

  async retire(
    from_state: Parameters<TierBAdapter["emitLifecycle"]>[0]["from_state"],
    reason: string
  ) {
    await this.ccParams.transport.send(this.translateLifecycle("retire"));
    await this.ccParams.transport.close();
    return this.emitLifecycle({
      from_state,
      to_state: "retired",
      reason,
    });
  }
}

registerTierBAdapter({
  id: "claude-code",
  label: "Claude Code — Anthropic CLI coding agent",
  factory: (params) => {
    const cp = params as ClaudeCodeAdapterParams;
    if (!cp.transport) {
      throw new Error(
        `claude-code adapter requires a ClaudeCodeTransport in params`
      );
    }
    return new ClaudeCodeAdapter(cp);
  },
});
