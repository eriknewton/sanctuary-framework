/**
 * Bug B (the one-flow gap): pure decision-table tests for
 * `resolvePolicyDaemonAction`. The security-critical branch is "refuse, not
 * swap" -- a boot service that targets a DIFFERENT fortress must NEVER be
 * silently replaced (one machine runs one wall). The side-effecting composition
 * (real probe / install-boot / uninstall-boot) is tested at the orchestrator
 * (injected-op) level; this file pins the decision itself.
 */

import { describe, it, expect } from "vitest";

import {
  resolvePolicyDaemonAction,
  type PolicyDaemonState,
} from "../../../src/castle-wall/provision/policy-daemon.js";

function state(overrides: Partial<PolicyDaemonState> = {}): PolicyDaemonState {
  return {
    socketReachable: false,
    bootServiceForThisFortress: false,
    bootServiceReadyForThisFortress: false,
    bootServiceForAnyFortress: false,
    ...overrides,
  };
}

describe("castle-wall/provision/policy-daemon: resolvePolicyDaemonAction", () => {
  it("install-fresh when the socket answers but NO persistent boot service exists (Bug D transient daemon)", () => {
    expect(resolvePolicyDaemonAction(state({ socketReachable: true }))).toBe("install-fresh");
  });

  it("noop only when the socket answers AND a matching boot service is ready", () => {
    expect(
      resolvePolicyDaemonAction(
        state({
          socketReachable: true,
          bootServiceForThisFortress: true,
          bootServiceReadyForThisFortress: true,
          bootServiceForAnyFortress: true,
        }),
      ),
    ).toBe("noop");
  });

  it("restart-existing when the socket answers but the matching boot service is not ready (Bug D)", () => {
    expect(
      resolvePolicyDaemonAction(
        state({
          socketReachable: true,
          bootServiceForThisFortress: true,
          bootServiceReadyForThisFortress: false,
          bootServiceForAnyFortress: true,
        }),
      ),
    ).toBe("restart-existing");
  });

  it("refuses when the socket answers but the singleton boot service targets a different fortress", () => {
    expect(
      resolvePolicyDaemonAction(
        state({ socketReachable: true, bootServiceForThisFortress: false, bootServiceForAnyFortress: true }),
      ),
    ).toBe("refuse-conflict");
  });

  it("install-fresh when the socket is down and NO boot service exists for any fortress (fresh box)", () => {
    expect(resolvePolicyDaemonAction(state({ bootServiceForAnyFortress: false }))).toBe("install-fresh");
  });

  it("restart-existing when a boot service for THIS fortress exists but its socket is not reachable", () => {
    expect(
      resolvePolicyDaemonAction(state({ bootServiceForThisFortress: true, bootServiceForAnyFortress: true })),
    ).toBe("restart-existing");
  });

  it("refuse-conflict when a boot service exists for a DIFFERENT fortress (refuse, do NOT swap the machine's wall)", () => {
    expect(
      resolvePolicyDaemonAction(state({ bootServiceForThisFortress: false, bootServiceForAnyFortress: true })),
    ).toBe("refuse-conflict");
  });
});
