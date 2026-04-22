/**
 * Agent Contract v0.1 — Lifecycle event tests (§2.8).
 */

import { describe, it, expect } from "vitest";
import {
  allowedTransitions,
  emitLifecycleEvent,
  TERMINAL_LIFECYCLE_STATES,
  verifyLifecycleEvent,
} from "../../src/agent-contract/lifecycle.js";
import { LifecycleTransitionError } from "../../src/agent-contract/errors.js";
import { LIFECYCLE_STATES } from "../../src/agent-contract/constants.js";
import { buildTestFortress } from "./fixture.js";
import type { SignedEvent } from "../../src/mesh/types.js";

describe("Lifecycle event emission (§2.8)", () => {
  it("emits launched from uninstantiated", () => {
    const f = buildTestFortress();
    const { event, signed_event } = emitLifecycleEvent({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      from_state: "uninstantiated",
      to_state: "launched",
      reason: "boot",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(event.to_state).toBe("launched");
    const verified = verifyLifecycleEvent(signed_event, f.verifyContext);
    expect(verified.event.from_state).toBe("uninstantiated");
  });

  it("rejects launched from any state other than uninstantiated", () => {
    const f = buildTestFortress();
    expect(() =>
      emitLifecycleEvent({
        agent_id: "agent-a",
        fortress_id: f.master.public.fortress_id,
        from_state: "paused",
        to_state: "launched",
        reason: "invalid",
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(LifecycleTransitionError);
  });

  it("rejects resumed without checkpoint_hash", () => {
    const f = buildTestFortress();
    expect(() =>
      emitLifecycleEvent({
        agent_id: "agent-a",
        fortress_id: f.master.public.fortress_id,
        from_state: "checkpointed",
        to_state: "resumed",
        reason: "no hash",
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(/checkpoint_hash/);
  });

  it("rejects revoked without guardian_quorum", () => {
    const f = buildTestFortress();
    expect(() =>
      emitLifecycleEvent({
        agent_id: "agent-a",
        fortress_id: f.master.public.fortress_id,
        from_state: "launched",
        to_state: "revoked",
        reason: "missing quorum",
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(/guardian_quorum/);
  });

  it("accepts revoked with guardian_quorum", () => {
    const f = buildTestFortress();
    const { event } = emitLifecycleEvent({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      from_state: "launched",
      to_state: "revoked",
      reason: "guardian revoke",
      guardian_quorum: [
        {
          guardian_pubkey: "gpk",
          signature: "sig",
        },
        {
          guardian_pubkey: "gpk2",
          signature: "sig2",
        },
      ],
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(event.guardian_quorum).toHaveLength(2);
  });

  it("terminal states have no outbound transitions", () => {
    for (const s of TERMINAL_LIFECYCLE_STATES) {
      expect(allowedTransitions(s)).toEqual([]);
    }
  });

  it("rejects verify when wrong event_type", () => {
    const f = buildTestFortress();
    const { signed_event } = emitLifecycleEvent({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      from_state: "uninstantiated",
      to_state: "launched",
      reason: "r",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    const wrong = { ...signed_event, event_type: "heartbeat" };
    expect(() =>
      verifyLifecycleEvent(wrong as SignedEvent, f.verifyContext)
    ).toThrow(LifecycleTransitionError);
  });

  it("enumerates every state in LIFECYCLE_STATES", () => {
    expect(LIFECYCLE_STATES).toEqual([
      "launched",
      "paused",
      "checkpointed",
      "resumed",
      "retired",
      "revoked",
    ]);
  });
});
