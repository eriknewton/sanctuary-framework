/**
 * Castle Wall failure-mode tests.
 *
 * Asserts the v1.0 default disposition table covers every FailureMode value
 * (no missing entries) and that the no-wall mode helper produces a sane
 * disengaged baseline.
 */

import { describe, it, expect } from "vitest";
import {
  DEFAULT_FAILURE_DISPOSITIONS,
  makeNoWallModeDisengaged,
  type FailureMode,
} from "../../../src/castle-wall/failure/modes.js";

const ALL_FAILURE_MODES: FailureMode[] = [
  "startup_filter_install_failed",
  "startup_policy_parse_failed",
  "startup_ipc_bind_failed",
  "runtime_daemon_crash",
  "runtime_kernel_module_unloaded",
  "runtime_ipc_drop_kernel_up",
  "runtime_external_firewall_clobber",
  "runtime_queue_saturated",
];

describe("castle-wall/failure/modes : DEFAULT_FAILURE_DISPOSITIONS", () => {
  it("has a disposition for every named FailureMode", () => {
    for (const mode of ALL_FAILURE_MODES) {
      const disposition = DEFAULT_FAILURE_DISPOSITIONS[mode];
      expect(disposition).toBeDefined();
    }
  });

  it("startup failures map to refuse_to_start", () => {
    expect(DEFAULT_FAILURE_DISPOSITIONS.startup_filter_install_failed.kind).toBe("refuse_to_start");
    expect(DEFAULT_FAILURE_DISPOSITIONS.startup_policy_parse_failed.kind).toBe("refuse_to_start");
    expect(DEFAULT_FAILURE_DISPOSITIONS.startup_ipc_bind_failed.kind).toBe("refuse_to_start");
  });

  it("runtime daemon crash and kernel module unload map to fail_closed", () => {
    expect(DEFAULT_FAILURE_DISPOSITIONS.runtime_daemon_crash.kind).toBe("fail_closed");
    expect(DEFAULT_FAILURE_DISPOSITIONS.runtime_kernel_module_unloaded.kind).toBe("fail_closed");
  });

  it("IPC drop with kernel up maps to fail_degraded", () => {
    expect(DEFAULT_FAILURE_DISPOSITIONS.runtime_ipc_drop_kernel_up.kind).toBe("fail_degraded");
  });

  it("external firewall clobber maps to restore_and_audit", () => {
    expect(DEFAULT_FAILURE_DISPOSITIONS.runtime_external_firewall_clobber.kind).toBe("restore_and_audit");
  });

  it("queue saturated maps to fail_closed (per Codex amendment 7)", () => {
    expect(DEFAULT_FAILURE_DISPOSITIONS.runtime_queue_saturated.kind).toBe("fail_closed");
  });

  it("freezes the disposition table so subsequent PRs do not silently mutate defaults", () => {
    expect(Object.isFrozen(DEFAULT_FAILURE_DISPOSITIONS)).toBe(true);
  });
});

describe("castle-wall/failure/modes : NoWallMode", () => {
  it("disengaged baseline reports engaged=false and null timestamps", () => {
    const m = makeNoWallModeDisengaged();
    expect(m.engaged).toBe(false);
    expect(m.engaged_at).toBe(null);
    expect(m.expires_at).toBe(null);
    expect(m.audit_event_id).toBe(null);
  });

  it("baseline always requires re-authentication to extend (literal type guarantee)", () => {
    const m = makeNoWallModeDisengaged();
    expect(m.re_authenticate_to_extend).toBe(true);
  });
});
