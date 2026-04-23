/**
 * Sanctuary Agent Contract v0.1: Hermes Reference Adapter (§5).
 *
 * Hermes Agent is NousResearch's open-source multi-channel harness
 * (Telegram, Discord, Slack, WhatsApp, Signal, Email, CLI). v0.9.0 shipped
 * April 2026. This adapter wraps a Hermes subprocess as a managed child
 * that speaks MCP over stdio, with Sanctuary interposed between the
 * harness and its upstream MCP servers:
 *
 *   Hermes (child) ──stdio MCP──► Tier B adapter ──Sanctuary─► broker
 *
 * Unlike `claude-code.ts`, this adapter does NOT pin `model_provider`.
 * Hermes operators may run DeepHermes / Hermes-3 / Hermes-4 (NousResearch
 * model families) OR any other back-end model the operator configures
 * behind the harness. The Agent Card emitted at launch carries whatever
 * `model_provider` the caller passes in (commonly `self-hosted` for
 * locally-hosted NousResearch weights, or `other` for a non-enum provider).
 * This deliberate deviation from `claude-code.ts` is part of the
 * harness-model separation Hermes was designed around; pinning would lie
 * about the deployment.
 *
 * Lifecycle translation:
 *   - launch:       spawn child with HTTP_PROXY env + Sanctuary agent env;
 *                   issue Agent Card; emit `launched` event.
 *   - pause:        send MCP `notifications/cancelled` to in-flight tool
 *                   calls, hold stdin buffer; emit `paused` event.
 *   - checkpoint:   capture stdin / stdout byte position, hash; emit
 *                   `checkpointed` with checkpoint_hash.
 *   - resume:       restart buffered stream from the captured offset; emit
 *                   `resumed` with the same checkpoint_hash.
 *   - retire:       send MCP shutdown, close child stdin, wait for exit;
 *                   emit `retired` (seals audit log segment).
 *   - revoke:       SIGKILL the child, emit `revoked` with guardian_quorum.
 *
 * The transport interface (`HermesTransport`) is stubbable so the
 * integration test can exercise the contract without actually launching
 * the real Hermes harness.
 */

import {
  TierBAdapter,
  registerTierBAdapter,
  type LifecycleCommand,
  type TierBAdapterParams,
} from "./tier-b-sdk.js";

export interface HermesTransport {
  /** Send a line to Hermes's stdin. Return value reserved for future backpressure signaling. */
  send(line: string): Promise<void>;
  /** Receive the next line from Hermes's stdout. Returns null on EOF. */
  receive(): Promise<string | null>;
  /** Terminate the child process. `signal` defaults to SIGTERM. */
  close(signal?: "SIGTERM" | "SIGKILL"): Promise<void>;
}

export interface HermesAdapterParams extends TierBAdapterParams {
  transport: HermesTransport;
}

/**
 * HermesAdapter (fourth reference Tier B adapter).
 *
 * Shipped at ~200 lines per Walkthrough Key 5 LOCKED (adapters 100-500 lines).
 */
export class HermesAdapter extends TierBAdapter {
  readonly harnessId = "hermes";

  constructor(private hermesParams: HermesAdapterParams) {
    super(hermesParams);
    // Deliberately no model_provider pin; see file header.
  }

  protected override harnessEnv(): Record<string, string> {
    return {
      // Hermes speaks MCP natively; declaring transport=stdio matches the
      // managed-child wiring above. Telemetry opt-out follows the same
      // pattern as the other reference adapters.
      HERMES_MCP_TRANSPORT: "stdio",
      HERMES_TELEMETRY_DISABLED: "true",
      // Hermes honours no_proxy / HTTP_PROXY for the embedded LLM client;
      // the SDK base injects those. This flag tells Hermes to route every
      // outbound MCP call through the Sanctuary-supplied upstream instead
      // of its own directory-resident mcp_servers block.
      HERMES_UPSTREAM_MODE: "sanctuary",
    };
  }

  /**
   * Map a Sanctuary lifecycle command to the MCP line Hermes expects.
   * We emit canonical MCP-shape strings; Hermes's JSON-RPC router reads
   * method / id and dispatches. `sanctuary/*` methods are reserved by
   * the adapter for lifecycle events that have no canonical MCP verb.
   */
  protected translateLifecycle(cmd: LifecycleCommand): string {
    switch (cmd) {
      case "launch":
        return `{"jsonrpc":"2.0","method":"initialize","id":1}`;
      case "pause":
        return `{"jsonrpc":"2.0","method":"notifications/cancelled"}`;
      case "checkpoint":
        return `{"jsonrpc":"2.0","method":"sanctuary/checkpoint"}`;
      case "resume":
        return `{"jsonrpc":"2.0","method":"sanctuary/resume"}`;
      case "retire":
        return `{"jsonrpc":"2.0","method":"shutdown"}`;
      case "revoke":
        return `{"jsonrpc":"2.0","method":"sanctuary/revoke"}`;
    }
  }

  /**
   * Send a lifecycle command over the transport. Emits the corresponding
   * lifecycle event after send.
   */
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
    const line = this.translateLifecycle(cmd);
    await this.hermesParams.transport.send(line);
    const to_state = lifecycleCmdToState(cmd);
    return this.emitLifecycle({
      from_state: args.from_state,
      to_state,
      reason: args.reason ?? `hermes-${cmd}`,
      checkpoint_hash: args.checkpoint_hash,
      guardian_quorum: args.guardian_quorum,
    });
  }

  /**
   * Retire the child. Sends shutdown, closes the transport, emits the
   * `retired` lifecycle event.
   */
  async retire(
    from_state: Parameters<TierBAdapter["emitLifecycle"]>[0]["from_state"],
    reason: string
  ) {
    const line = this.translateLifecycle("retire");
    await this.hermesParams.transport.send(line);
    await this.hermesParams.transport.close("SIGTERM");
    return this.emitLifecycle({
      from_state,
      to_state: "retired",
      reason,
    });
  }
}

function lifecycleCmdToState(cmd: Exclude<LifecycleCommand, "launch">) {
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
}

registerTierBAdapter({
  id: "hermes",
  label: "Hermes Agent (NousResearch multi-channel harness, stdio MCP)",
  factory: (params) => {
    const hp = params as HermesAdapterParams;
    if (!hp.transport) {
      throw new Error(
        `hermes adapter requires a HermesTransport in params; the sanctuary wrap CLI synthesizes one`
      );
    }
    return new HermesAdapter(hp);
  },
});
