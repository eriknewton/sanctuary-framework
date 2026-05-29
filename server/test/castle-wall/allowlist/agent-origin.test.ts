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
});
