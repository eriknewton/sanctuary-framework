/**
 * Tests for the agent-origin descriptor validator (2026-05-29
 * origin-classifier foundation).
 *
 * The single invariant under test: `validateAgentOrigin` returns a
 * fully-formed descriptor or `null`. A malformed candidate must degrade to
 * `null` (omit the field => fail-closed classify-all-agent on the sysext),
 * never to a half-built descriptor that could mis-resolve a flow as operator.
 */

import { describe, it, expect } from "vitest";

import { validateAgentOrigin } from "../../../src/castle-wall/allowlist/agent-origin.js";

describe("castle-wall/allowlist/agent-origin : validateAgentOrigin", () => {
  it("accepts a well-formed uid descriptor", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 600,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 600,
      system_uid_allow_ceiling: 500,
    });
  });

  it("accepts a well-formed nat descriptor (signing id)", () => {
    const out = validateAgentOrigin({
      mode: "nat",
      egress_helper_signing_id: "ai.sanctuaryprotocol.egress-helper",
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "nat",
      egress_helper_signing_id: "ai.sanctuaryprotocol.egress-helper",
      system_uid_allow_ceiling: 500,
    });
  });

  it("accepts a nat descriptor with team id + port range", () => {
    const out = validateAgentOrigin({
      mode: "nat",
      egress_helper_team_id: "YFQSWQ9BJN",
      agent_runtime_port_range: [49152, 65535],
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "nat",
      egress_helper_team_id: "YFQSWQ9BJN",
      agent_runtime_port_range: [49152, 65535],
      system_uid_allow_ceiling: 500,
    });
  });

  it("strips stray fields not valid for the mode (uid drops nat fields)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 600,
      egress_helper_signing_id: "should-not-survive",
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 600,
      system_uid_allow_ceiling: 500,
    });
    expect(out).not.toHaveProperty("egress_helper_signing_id");
  });

  // --- Fail-closed: malformed => null ---

  it("rejects non-objects", () => {
    expect(validateAgentOrigin(null)).toBeNull();
    expect(validateAgentOrigin(undefined)).toBeNull();
    expect(validateAgentOrigin("uid")).toBeNull();
    expect(validateAgentOrigin(42)).toBeNull();
  });

  it("rejects an unknown mode", () => {
    expect(
      validateAgentOrigin({ mode: "sandbox", system_uid_allow_ceiling: 500 })
    ).toBeNull();
  });

  it("rejects a missing system_uid_allow_ceiling", () => {
    expect(
      validateAgentOrigin({ mode: "uid", agent_uid: 600 })
    ).toBeNull();
  });

  it("rejects a uid descriptor with no agent_uid (would fail-open to operator)", () => {
    expect(
      validateAgentOrigin({ mode: "uid", system_uid_allow_ceiling: 500 })
    ).toBeNull();
  });

  it("rejects a uid descriptor with a non-integer agent_uid", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 6.5,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  // --- Floor invariant (uid mode): agent_uid must be >= 1 AND >= ceiling ---

  it("rejects agent_uid 0 (root can never be the confined agent)", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 0,
        system_uid_allow_ceiling: 0,
      })
    ).toBeNull();
  });

  it("rejects an agent_uid strictly below the system-uid ceiling", () => {
    // uid inside the system-daemon allow band is nonsensical/dangerous.
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 100,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("accepts agent_uid EQUAL to the ceiling (boundary is allowed, not strictly-below)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 500,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 500,
      system_uid_allow_ceiling: 500,
    });
  });

  it("accepts the real Mini2 shape (agent_uid 502 >= ceiling 500)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 502,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 502,
      system_uid_allow_ceiling: 500,
    });
  });

  it("rejects a nat descriptor with neither signing id nor team id", () => {
    expect(
      validateAgentOrigin({ mode: "nat", system_uid_allow_ceiling: 500 })
    ).toBeNull();
  });

  it("rejects empty-string identities (treated as absent)", () => {
    expect(
      validateAgentOrigin({
        mode: "nat",
        egress_helper_signing_id: "",
        egress_helper_team_id: "",
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("drops a malformed port range but KEEPS the descriptor", () => {
    const out = validateAgentOrigin({
      mode: "nat",
      egress_helper_signing_id: "id",
      agent_runtime_port_range: [70000, 80000], // out of range
      system_uid_allow_ceiling: 500,
    });
    expect(out).not.toBeNull();
    expect(out).not.toHaveProperty("agent_runtime_port_range");
  });

  it("drops a reversed port range (lo > hi) but keeps the descriptor", () => {
    const out = validateAgentOrigin({
      mode: "nat",
      egress_helper_signing_id: "id",
      agent_runtime_port_range: [65535, 49152],
      system_uid_allow_ceiling: 500,
    });
    expect(out).not.toBeNull();
    expect(out).not.toHaveProperty("agent_runtime_port_range");
  });

  it("drops a 1-element port range but keeps the descriptor", () => {
    const out = validateAgentOrigin({
      mode: "nat",
      egress_helper_signing_id: "id",
      agent_runtime_port_range: [49152],
      system_uid_allow_ceiling: 500,
    });
    expect(out).not.toBeNull();
    expect(out).not.toHaveProperty("agent_runtime_port_range");
  });

  // --- S5-0 (2026-07-14): gate_uid, the second confined principal ---

  it("accepts a well-formed twin-uid descriptor (agent_uid + gate_uid)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 600,
      gate_uid: 601,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 600,
      gate_uid: 601,
      system_uid_allow_ceiling: 500,
    });
  });

  it("still accepts a uid descriptor with no gate_uid (byte-identical to today)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 600,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 600,
      system_uid_allow_ceiling: 500,
    });
    expect(out).not.toHaveProperty("gate_uid");
  });

  it("rejects the WHOLE descriptor when gate_uid collides with agent_uid (the scope-leak the field must prevent)", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        gate_uid: 600,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("rejects the WHOLE descriptor when gate_uid is 0 (root can never be confined)", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        gate_uid: 0,
        system_uid_allow_ceiling: 0,
      })
    ).toBeNull();
  });

  it("rejects the WHOLE descriptor when gate_uid is strictly below the system-uid ceiling", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        gate_uid: 100,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("rejects the WHOLE descriptor when gate_uid is a non-integer", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        gate_uid: 601.5,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("rejects the WHOLE descriptor when gate_uid is negative", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        gate_uid: -1,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("accepts gate_uid EQUAL to the ceiling (boundary allowed, same as agent_uid)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: 600,
      gate_uid: 500,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: 600,
      gate_uid: 500,
      system_uid_allow_ceiling: 500,
    });
  });

  it("rejects a NAT descriptor carrying gate_uid (UID-mode-only concept, no half-built cross-mode descriptor)", () => {
    expect(
      validateAgentOrigin({
        mode: "nat",
        egress_helper_signing_id: "ai.sanctuaryprotocol.egress-helper",
        gate_uid: 601,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  // --- LOW-1 (2026-07-14): uid-family fields capped at UInt32.max (wire type) ---

  const UINT32_MAX = 0xffffffff;

  it("accepts agent_uid + gate_uid at exactly UInt32.max (boundary)", () => {
    const out = validateAgentOrigin({
      mode: "uid",
      agent_uid: UINT32_MAX,
      gate_uid: UINT32_MAX - 1,
      system_uid_allow_ceiling: 500,
    });
    expect(out).toEqual({
      mode: "uid",
      agent_uid: UINT32_MAX,
      gate_uid: UINT32_MAX - 1,
      system_uid_allow_ceiling: 500,
    });
  });

  it("rejects agent_uid above UInt32.max (would fail the sysext UInt32 decode)", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: UINT32_MAX + 1,
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("rejects gate_uid above UInt32.max", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        gate_uid: 9007199254740991, // Number.MAX_SAFE_INTEGER, far above UInt32.max
        system_uid_allow_ceiling: 500,
      })
    ).toBeNull();
  });

  it("rejects system_uid_allow_ceiling above UInt32.max (also decodes as UInt32)", () => {
    expect(
      validateAgentOrigin({
        mode: "uid",
        agent_uid: 600,
        system_uid_allow_ceiling: UINT32_MAX + 1,
      })
    ).toBeNull();
  });
});
