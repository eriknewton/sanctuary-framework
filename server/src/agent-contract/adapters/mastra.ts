/**
 * Sanctuary Agent Contract v0.1 — Mastra Reference Adapter (§5).
 *
 * Mastra is a TypeScript agent framework that runs agents in-process as
 * library code rather than subprocesses. The adapter wraps a Mastra agent
 * runtime through a callback interface: the Mastra app calls into the
 * adapter before each action, the adapter enforces §2.4 capability + emits
 * usage events, and returns allow/deny.
 *
 * Because Mastra runs in-process, there is no HTTP_PROXY injection — the
 * adapter expects the operator's `fetch` wrapper to be installed into the
 * Mastra runtime before launch. The broker provides `withMastraFetch` as a
 * separate helper (not part of this PR; flagged for WP-MVP-4 follow-up).
 *
 * Lifecycle translation is cooperative — Mastra has no OS signals; the
 * adapter exposes canonical command methods (pause / checkpoint / resume
 * / retire / revoke) that the embedding app calls.
 *
 * Sub-agent handling: Mastra's common pattern is for one agent to spawn
 * workers. The adapter's `labelSubAgent` returns a `sub_of:` string; the
 * embedding app MUST pass that label through its sub-agent metadata so the
 * audit log sees the hierarchy. The adapter refuses to mint a new Agent
 * Card for a sub-agent (§5 invariant).
 */

import {
  TierBAdapter,
  registerTierBAdapter,
  type LifecycleCommand,
  type TierBAdapterParams,
} from "./tier-b-sdk.js";
import { CapabilityUndeclaredError, TierBInvariantError } from "../errors.js";
import type { CapabilityKind } from "../constants.js";

/**
 * Mastra pre-action hook shape. The embedding app wires this onto its
 * Mastra agent's `before` middleware slot.
 */
export type MastraPreActionHook = (action: {
  tool_name: string;
  capability_kind: CapabilityKind;
  input: unknown;
}) => Promise<{ proceed: true } | { proceed: false; reason: string }>;

/**
 * Mastra post-action hook shape. Called after the tool call completes with
 * its output, for usage-event emission.
 */
export type MastraPostActionHook = (action: {
  tool_name: string;
  capability_kind: CapabilityKind;
  input: unknown;
  output: unknown;
}) => Promise<{ usage_event_id: string }>;

export interface MastraAdapterParams extends TierBAdapterParams {
  /**
   * Optional embedding-app identity — if the app runs in a sandbox different
   * from the broker process, the app reports its process id here for audit
   * linkage.
   */
  embedding_app_pid?: number;
}

/**
 * MastraAdapter — third reference Tier B adapter. In-process variant.
 */
export class MastraAdapter extends TierBAdapter {
  readonly harnessId = "mastra";

  constructor(mastraParams: MastraAdapterParams) {
    super(mastraParams);
  }

  protected override harnessEnv(): Record<string, string> {
    // In-process harness — minimal env. The embedding app is responsible
    // for wiring HTTP_PROXY into its own `fetch` calls.
    return {
      MASTRA_SANCTUARY_EMBEDDED: "true",
    };
  }

  protected translateLifecycle(cmd: LifecycleCommand): string {
    // Mastra is in-process; the "string" we return is the method name the
    // embedding app should call on its Mastra runtime. The adapter exposes
    // matching methods below.
    switch (cmd) {
      case "launch":
        return "mastra.runtime.start";
      case "pause":
        return "mastra.runtime.pause";
      case "checkpoint":
        return "mastra.runtime.checkpoint";
      case "resume":
        return "mastra.runtime.resume";
      case "retire":
        return "mastra.runtime.stop";
      case "revoke":
        return "mastra.runtime.terminate";
    }
  }

  /**
   * Build the pre-action hook the embedding app wires into its Mastra
   * middleware. Denies when a tool call's capability is undeclared on the
   * Agent Card.
   */
  buildPreActionHook(): MastraPreActionHook {
    return async (action) => {
      if (!this.getCard()) {
        return {
          proceed: false,
          reason:
            "mastra adapter pre-action hook invoked before adapter.launch()",
        };
      }
      try {
        this.observeHarnessAction({
          capability_kind: action.capability_kind,
          capability_target: action.tool_name,
          input: action.input,
          // Output not yet available at pre-hook time — use sentinel + let
          // the post-hook emit the real usage event.
          output: { pending: true },
          attestation_state: "degraded",
        });
        // The observe call above emits a "pending" usage event — a real
        // implementation would defer emission until post-hook. For a
        // reference adapter we emit twice (pending + complete) so audit
        // trails show the gate check AND the result. Flagged for WP-MVP-4
        // follow-up: collapse to single event emission.
        return { proceed: true };
      } catch (e) {
        if (e instanceof CapabilityUndeclaredError) {
          return {
            proceed: false,
            reason: e.message,
          };
        }
        throw e;
      }
    };
  }

  /** Build the post-action hook — emits the final usage event with real output. */
  buildPostActionHook(): MastraPostActionHook {
    return async (action) => {
      const emitted = this.observeHarnessAction({
        capability_kind: action.capability_kind,
        capability_target: action.tool_name,
        input: action.input,
        output: action.output,
      });
      return { usage_event_id: emitted.usage.body.usage_event_id };
    };
  }

  /**
   * Reject any attempt by the embedding app to promote a sub-agent worker
   * to a first-class Sanctuary identity. Returns the stable sub-agent label
   * string; the embedding app MUST include this in its Mastra sub-agent
   * metadata.
   */
  registerSubAgent(label: string): string {
    if (!label || label.includes(":") || label.includes("|")) {
      throw new TierBInvariantError(
        `mastra sub-agent label must be non-empty and free of ':' '|'`
      );
    }
    return this.labelSubAgent(label);
  }
}

registerTierBAdapter({
  id: "mastra",
  label: "Mastra — TypeScript agent framework (in-process)",
  factory: (params) => {
    return new MastraAdapter(params as MastraAdapterParams);
  },
});
