/**
 * Castle Wall IPC readiness classifier: contradictory-frame handling.
 *
 * `castleWallRuntimeReadiness` is the single place a `status_response` becomes a
 * readiness claim, and every armed/ACTIVE/enforcement-complete surface is
 * derived from its return value. These cases pin the rule that a frame CLAIMING
 * a kernel runtime must carry kernel-runtime proof on that same frame, so a
 * peer cannot assert a live runtime while its own health token denies holding
 * one.
 */

import { describe, it, expect } from "vitest";
import {
  castleWallRuntimeReadiness,
  type StatusResponse,
} from "../../../src/castle-wall/ipc/messages.js";

type ReadinessInput = Parameters<typeof castleWallRuntimeReadiness>[0];

/** A frame whose non-runtime fields are all in the healthy, uncontested shape. */
function readyFrame(overrides: Partial<ReadinessInput>): ReadinessInput {
  return {
    no_wall_engaged: false,
    manifest_state: "ready",
    lifecycle_state: "running",
    runtime_state: "kernel_runtime_ready",
    kernel_runtime_ready: true,
    enforcing: false,
    runtime_health: "ready",
    ...overrides,
  } satisfies Pick<
    StatusResponse,
    | "lifecycle_state"
    | "manifest_state"
    | "runtime_state"
    | "kernel_runtime_ready"
    | "enforcing"
    | "no_wall_engaged"
    | "runtime_health"
  >;
}

describe("castle-wall/ipc : runtime readiness from contradictory frames", () => {
  it("classifies the fully-proven frame as kernel_runtime_ready", () => {
    // The converse case, so the rules below are not vacuously always-unavailable.
    expect(castleWallRuntimeReadiness(readyFrame({}))).toBe("kernel_runtime_ready");
    expect(
      castleWallRuntimeReadiness(
        readyFrame({ runtime_state: "enforcing", enforcing: true })
      )
    ).toBe("enforcing");
  });

  it("withholds the claim when a kernel-runtime frame carries no health token", () => {
    // A daemon that advertises the runtime block but not the health capability
    // sends ready-state fields with no current proof behind them. Absent
    // evidence is indeterminate, never proven.
    expect(
      castleWallRuntimeReadiness(readyFrame({ runtime_health: undefined }))
    ).toBe("unavailable");
    expect(
      castleWallRuntimeReadiness(
        readyFrame({
          runtime_state: "enforcing",
          enforcing: true,
          runtime_health: undefined,
        })
      )
    ).toBe("unavailable");
  });

  it("withholds the claim when the frame denies holding a kernel runtime", () => {
    // `no_runtime` means "this daemon holds no kernel runtime at all"; paired
    // with a `kernel_runtime_ready` state field it is self-contradictory.
    expect(
      castleWallRuntimeReadiness(readyFrame({ runtime_health: "no_runtime" }))
    ).toBe("unavailable");
  });

  it("still reports control_plane_only, which claims no kernel runtime", () => {
    // The rule must not swallow the honest no-kernel-runtime answer: a
    // control-plane daemon legitimately reports `no_runtime` health.
    expect(
      castleWallRuntimeReadiness(
        readyFrame({
          runtime_state: "control_plane_only",
          kernel_runtime_ready: false,
          runtime_health: "no_runtime",
        })
      )
    ).toBe("control_plane_only");
  });

  it("keeps the proven-loss and bypass branches ahead of the new rule", () => {
    // `lost` is PROVEN loss, not indeterminacy, and the operator's explicit
    // bypass outranks every observation. Returning `unavailable` for either
    // would let them slip through a caller's fail-closed branch.
    expect(castleWallRuntimeReadiness(readyFrame({ runtime_health: "lost" }))).toBe(
      "degraded"
    );
    expect(
      castleWallRuntimeReadiness(
        readyFrame({ no_wall_engaged: true, runtime_health: "no_runtime" })
      )
    ).toBe("degraded");
  });
});
