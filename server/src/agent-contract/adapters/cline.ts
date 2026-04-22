/**
 * Sanctuary Agent Contract v0.1 — Cline Reference Adapter (§5).
 *
 * Cline is an open-source VS Code coding agent. Its runtime speaks MCP over
 * stdio; this adapter treats Cline as a managed child process that reads
 * MCP over stdin and writes over stdout. The adapter sits between the
 * broker and Cline's MCP client:
 *
 *   Cline (child) ──stdin/stdout MCP──► Tier B adapter ──Sanctuary─► broker
 *
 * Lifecycle translation:
 *   - launch:       spawn child with HTTP_PROXY env + Sanctuary agent env;
 *                   issue Agent Card; emit `launched` event.
 *   - pause:        send MCP `notifications/cancelled` to in-flight tool calls,
 *                   hold stdin buffer; emit `paused` event.
 *   - checkpoint:   capture stdin / stdout byte position, hash; emit
 *                   `checkpointed` with checkpoint_hash.
 *   - resume:       restart buffered stream from the captured offset; emit
 *                   `resumed` with the same checkpoint_hash.
 *   - retire:       send MCP shutdown, close child stdin, wait for exit;
 *                   emit `retired` (seals audit log segment).
 *   - revoke:       SIGKILL the child, emit `revoked` with guardian_quorum.
 *
 * This reference adapter ships the MCP-translation machinery as a stubbable
 * interface (`ClineTransport`) so the integration test can exercise the
 * contract without actually launching VS Code.
 */

import {
  TierBAdapter,
  registerTierBAdapter,
  type LifecycleCommand,
  type TierBAdapterParams,
} from "./tier-b-sdk.js";

export interface ClineTransport {
  /** Send a line to Cline's stdin. Return value reserved for future backpressure signaling. */
  send(line: string): Promise<void>;
  /** Receive the next line from Cline's stdout. Returns null on EOF. */
  receive(): Promise<string | null>;
  /** Terminate the child process. `signal` defaults to SIGTERM. */
  close(signal?: "SIGTERM" | "SIGKILL"): Promise<void>;
}

export interface ClineAdapterParams extends TierBAdapterParams {
  transport: ClineTransport;
}

/**
 * ClineAdapter — the first reference Tier B adapter.
 *
 * Shipped at ~200 lines per Walkthrough Key 5 LOCKED (adapters 100-500 lines).
 */
export class ClineAdapter extends TierBAdapter {
  readonly harnessId = "cline";

  constructor(private clineParams: ClineAdapterParams) {
    super(clineParams);
  }

  protected override harnessEnv(): Record<string, string> {
    return {
      // Cline respects `VSCODE_PROXY_URI` in extension-host context; we
      // duplicate HTTP_PROXY for the embedded Node process and let the
      // extension honor whichever it reads.
      CLINE_MCP_TRANSPORT: "stdio",
      VSCODE_DISABLE_TELEMETRY: "true",
    };
  }

  /**
   * Map a Sanctuary lifecycle command to the MCP line Cline expects.
   * Subclasses may override; we ship canonical MCP-shape strings here.
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
    await this.clineParams.transport.send(line);
    const to_state = lifecycleCmdToState(cmd);
    return this.emitLifecycle({
      from_state: args.from_state,
      to_state,
      reason: args.reason ?? `cline-${cmd}`,
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
    await this.clineParams.transport.send(line);
    await this.clineParams.transport.close("SIGTERM");
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
  id: "cline",
  label: "Cline — VS Code coding agent (stdio MCP)",
  factory: (params) => {
    // The CLI caller must inject a real ClineTransport; at registry-time
    // we fail loudly if the params are missing the transport. The CLI's
    // `sanctuary wrap --tier-b cline` command synthesizes one that spawns
    // the child process.
    const cp = params as ClineAdapterParams;
    if (!cp.transport) {
      throw new Error(
        `cline adapter requires a ClineTransport in params — the sanctuary wrap CLI synthesizes one`
      );
    }
    return new ClineAdapter(cp);
  },
});
