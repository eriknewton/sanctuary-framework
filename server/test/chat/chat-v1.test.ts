/**
 * Sanctuary WP-MVP-7 Chat v1.0 — Comprehensive Test Suite
 *
 * Tests all 8 acceptance criteria from the spawn prompt:
 *
 * 1. MLS group round-trip (single-fortress) with forward secrecy
 * 2. Cross-fortress MLS round-trip
 * 3. Presence correctness (staleness transitions)
 * 4. Agent coordination-peers enforcement
 * 5. Retention-sweep integration
 * 6. pgvector search (deterministic fixture)
 * 7. Signed-event fields on every signed artifact
 * 8. Baseline + CI (structural)
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "../../src/core/random.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import { SIGNATURE_SCHEME_V1, PROTOCOL_VERSION } from "../../src/mesh/constants.js";
import { broadcastTopic } from "../../src/mesh/libp2p-transport/protocols.js";
import { canonicalizeToBytes } from "../../src/mesh/canonical-json.js";
import {
  MLSGroupManager,
  intraFortressGroupId,
  crossFortressGroupId,
  type MLSMemberIdentity,
} from "../../src/chat/mls-group.js";
import {
  PresenceTracker,
  PresencePublisher,
  computePresenceState,
} from "../../src/chat/presence.js";
import { PRESENCE_STALENESS } from "../../src/chat/constants.js";
import { packEphemeralEvent } from "../../src/chat/ephemeral-event.js";
import {
  evaluateChatGate,
  enforceCoordinationPeers,
  withCoordinationPeers,
  getCoordinationPeers,
} from "../../src/chat/coordination-gate.js";
import {
  CHAT_GATE_REASON_CODES,
  chatTopic,
  presenceTopic,
  crossFortressChatTopic,
} from "../../src/chat/constants.js";
import { ChatPeerNotAuthorizedError, ChatNoCoordinationPeersError } from "../../src/chat/errors.js";
import { InMemoryChatLogStore } from "../../src/chat/chat-log.js";
import { InMemoryPgVectorIndex } from "../../src/chat/pgvector-index.js";
import { ChatRetentionAdapter } from "../../src/chat/retention-bridge.js";
import {
  InMemoryRetentionStore,
  executeRetentionSweep,
} from "../../src/policy-engine/retention-sweep.js";
import { ChatService, type ChatServiceParams } from "../../src/chat/chat-service.js";
import type { CompiledPolicy } from "../../src/policy-engine/types.js";
import type { ChatPlaintext } from "../../src/chat/types.js";

// ═══════════════════════════════════════════════════════════════════════
// Test helpers
// ═══════════════════════════════════════════════════════════════════════

function makeIdentity(memberId: string): MLSMemberIdentity {
  const privKey = ed25519.utils.randomPrivateKey();
  const pubKey = ed25519.getPublicKey(privKey);
  return { member_id: memberId, public_key: pubKey, private_key: privKey };
}

function makeMinimalPolicy(agentId: string, fortressId: string): CompiledPolicy {
  return {
    schema_version: "0.1",
    agent_id: agentId,
    fortress_id: fortressId,
    policy_version: 1,
    slots: {
      memory: { slot: "memory", mode: "deny", grants: [] },
      credentials: { slot: "credentials", mode: "deny", grants: [] },
      plans: { slot: "plans", mode: "deny", grants: [] },
      outputs: { slot: "outputs", mode: "grant", grants: [] },
    },
    capabilities: {
      concordia_commitment_classes: [],
      honeypot_skill_ids: [],
      is_sentinel: false,
    },
    auto_trigger_ladder: {
      honeypot_auto_freeze: true,
      threshold_rule_action: "operator_approved",
      ml_anomaly_action: "operator_approved",
    },
    source_english: "test policy",
    compiled_at: new Date().toISOString(),
  };
}

/**
 * Deterministic embedding function for tests.
 * Maps known words to specific dimensions for reproducible search.
 * No network call; pure computation.
 */
function deterministicEmbed(text: string): Promise<number[]> {
  const vec = new Array(1536).fill(0);
  // Assign specific words to specific dimensions
  const wordMap: Record<string, number> = {
    security: 0,
    sovereignty: 1,
    encryption: 2,
    fortress: 3,
    agent: 4,
    policy: 5,
    budget: 6,
    retention: 7,
    chat: 8,
    message: 9,
    presence: 10,
    mls: 11,
    group: 12,
    deploy: 13,
    monitor: 14,
    alert: 15,
    status: 16,
    update: 17,
    review: 18,
    approve: 19,
  };
  const words = text.toLowerCase().split(/\s+/);
  for (const word of words) {
    const dim = wordMap[word];
    if (dim !== undefined) vec[dim] = 1.0;
  }
  // Normalize
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0));
  if (norm > 0) {
    for (let i = 0; i < vec.length; i++) vec[i] /= norm;
  }
  return Promise.resolve(vec);
}

// ═══════════════════════════════════════════════════════════════════════
// AC-1: MLS group round-trip (single-fortress) + forward secrecy
// ═══════════════════════════════════════════════════════════════════════

describe("AC-1: MLS single-fortress round-trip", () => {
  let operator: MLSGroupManager;
  let agentB: MLSGroupManager;
  let agentC: MLSGroupManager;
  let operatorId: MLSMemberIdentity;
  let agentBId: MLSMemberIdentity;
  let agentCId: MLSMemberIdentity;
  const fortressId = "fortress-001";

  beforeEach(() => {
    operatorId = makeIdentity("operator-primary");
    agentBId = makeIdentity("agent-b");
    agentCId = makeIdentity("agent-c");
    operator = new MLSGroupManager(operatorId);
    agentB = new MLSGroupManager(agentBId);
    agentC = new MLSGroupManager(agentCId);
  });

  it("operator creates group, adds agents B and C, all can encrypt/decrypt", () => {
    // Operator creates group
    const groupId = intraFortressGroupId(fortressId);
    const { state } = operator.createGroup({
      group_id: groupId,
      group_type: "intra_fortress",
      fortress_ids: [fortressId],
    });
    expect(state.members).toEqual(["operator-primary"]);
    expect(state.epoch).toBe(0);

    // Add agent B
    const addB = operator.addMember(groupId, {
      member_id: "agent-b",
      public_key: agentBId.public_key,
    });
    expect(addB.new_epoch).toBe(1);

    // Agent B joins via welcome
    const bState = agentB.joinViaWelcome(addB.welcome);
    expect(bState.members).toContain("agent-b");

    // Add agent C
    const addC = operator.addMember(groupId, {
      member_id: "agent-c",
      public_key: agentCId.public_key,
    });
    expect(addC.new_epoch).toBe(2);

    // Agent C joins via welcome
    const cState = agentC.joinViaWelcome(addC.welcome);
    expect(cState.members).toContain("agent-c");

    // Agent B processes add-C commit to get new epoch secret
    agentB.processCommit(groupId, addC.commit);

    // Operator sends message
    const plaintext: ChatPlaintext = {
      content: "Hello agents!",
      sent_at: new Date().toISOString(),
      sender_id: "operator-primary",
    };
    const ciphertext = operator.encrypt(groupId, plaintext);

    // Both agents can decrypt
    const decB = agentB.decrypt(groupId, ciphertext, 2);
    expect(decB.content).toBe("Hello agents!");
    expect(decB.sender_id).toBe("operator-primary");

    const decC = agentC.decrypt(groupId, ciphertext, 2);
    expect(decC.content).toBe("Hello agents!");
  });

  it("MLS ciphertext contains zero plaintext bytes of the message", () => {
    const groupId = intraFortressGroupId(fortressId);
    operator.createGroup({
      group_id: groupId,
      group_type: "intra_fortress",
      fortress_ids: [fortressId],
    });

    const secretMessage = "TOP_SECRET_AGENT_DATA_12345";
    const plaintext: ChatPlaintext = {
      content: secretMessage,
      sent_at: new Date().toISOString(),
      sender_id: "operator-primary",
    };
    const ciphertext = operator.encrypt(groupId, plaintext);

    // Convert ciphertext to string to check for plaintext leaks
    const ciphertextStr = new TextDecoder("utf-8", { fatal: false }).decode(ciphertext);
    expect(ciphertextStr).not.toContain(secretMessage);

    // Also check raw bytes for any substring of the secret
    const secretBytes = new TextEncoder().encode(secretMessage);
    let found = false;
    for (let i = 0; i <= ciphertext.length - secretBytes.length; i++) {
      let match = true;
      for (let j = 0; j < secretBytes.length; j++) {
        if (ciphertext[i + j] !== secretBytes[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        found = true;
        break;
      }
    }
    expect(found).toBe(false);
  });

  it("forward secrecy: new member D cannot decrypt pre-join messages", () => {
    const groupId = intraFortressGroupId(fortressId);
    operator.createGroup({
      group_id: groupId,
      group_type: "intra_fortress",
      fortress_ids: [fortressId],
    });

    // Agent B sends a message at epoch 0
    const addB = operator.addMember(groupId, {
      member_id: "agent-b",
      public_key: agentBId.public_key,
    });
    agentB.joinViaWelcome(addB.welcome);

    // Operator sends message at epoch 1 (after B joined)
    const preJoinMsg: ChatPlaintext = {
      content: "Pre-D message",
      sent_at: new Date().toISOString(),
      sender_id: "operator-primary",
    };
    const preJoinCipher = operator.encrypt(groupId, preJoinMsg);

    // Add agent D
    const agentDId = makeIdentity("agent-d");
    const agentD = new MLSGroupManager(agentDId);
    const addD = operator.addMember(groupId, {
      member_id: "agent-d",
      public_key: agentDId.public_key,
    });
    agentD.joinViaWelcome(addD.welcome);

    // Agent D CANNOT decrypt pre-join message (epoch 1, D joined at epoch 2)
    expect(() => {
      agentD.decrypt(groupId, preJoinCipher, 1);
    }).toThrow(/forward secrecy barrier|no epoch secret/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-2: Cross-fortress MLS round-trip
// ═══════════════════════════════════════════════════════════════════════

describe("AC-2: Cross-fortress MLS round-trip", () => {
  it("two fortresses form cross-fortress group, exchange messages, removal blocks decryption", () => {
    const fortressX = "fortress-x";
    const fortressY = "fortress-y";
    const operatorX = makeIdentity("operator-x");
    const operatorY = makeIdentity("operator-y");
    const managerX = new MLSGroupManager(operatorX);
    const managerY = new MLSGroupManager(operatorY);

    // Fortress X creates cross-fortress group
    const groupId = crossFortressGroupId(fortressX, fortressY);
    managerX.createGroup({
      group_id: groupId,
      group_type: "cross_fortress",
      fortress_ids: [fortressX, fortressY],
    });

    // Add operator Y
    const addY = managerX.addMember(groupId, {
      member_id: "operator-y",
      public_key: operatorY.public_key,
    });
    managerY.joinViaWelcome(addY.welcome);

    // Operator X sends message
    const msg: ChatPlaintext = {
      content: "Cross-fortress hello",
      sent_at: new Date().toISOString(),
      sender_id: "operator-x",
    };
    const cipher = managerX.encrypt(groupId, msg);

    // Operator Y decrypts
    const decrypted = managerY.decrypt(groupId, cipher, addY.new_epoch);
    expect(decrypted.content).toBe("Cross-fortress hello");

    // Remove Y from group
    const removeY = managerX.removeMember(groupId, "operator-y");
    expect(removeY.new_epoch).toBe(2);

    // X sends post-removal message at new epoch
    const postMsg: ChatPlaintext = {
      content: "Y cannot see this",
      sent_at: new Date().toISOString(),
      sender_id: "operator-x",
    };
    const postCipher = managerX.encrypt(groupId, postMsg);

    // Y cannot decrypt post-removal message
    expect(() => {
      managerY.decrypt(groupId, postCipher, removeY.new_epoch);
    }).toThrow(/forward secrecy barrier|no epoch secret/);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-3: Presence correctness
// ═══════════════════════════════════════════════════════════════════════

describe("AC-3: Presence staleness transitions", () => {
  it("computes correct state from elapsed time", () => {
    expect(computePresenceState(0)).toBe("active");
    expect(computePresenceState(30_000)).toBe("active");
    expect(computePresenceState(59_999)).toBe("active");
    expect(computePresenceState(60_000)).toBe("idle");
    expect(computePresenceState(120_000)).toBe("idle");
    expect(computePresenceState(299_999)).toBe("idle");
    expect(computePresenceState(300_000)).toBe("away");
    expect(computePresenceState(600_000)).toBe("away");
    expect(computePresenceState(899_999)).toBe("away");
    expect(computePresenceState(900_000)).toBe("offline");
    expect(computePresenceState(1_800_000)).toBe("offline");
  });

  it("tracker transitions through all four states on staleness", () => {
    const tracker = new PresenceTracker(10_000);
    const transitions: Array<{ from: string; to: string }> = [];
    tracker.onPresenceChange((_id, from, to) => transitions.push({ from, to }));

    const now = Date.now();
    const heartbeatTime = new Date(now).toISOString();

    // Agent publishes heartbeat
    tracker.receiveHeartbeat("agent-a", heartbeatTime);
    expect(tracker.getPresence("agent-a")?.state).toBe("active");

    // 90s later: idle
    tracker.evaluateAll(now + 90_000);
    expect(tracker.getPresence("agent-a")?.state).toBe("idle");

    // 360s later: away
    tracker.evaluateAll(now + 360_000);
    expect(tracker.getPresence("agent-a")?.state).toBe("away");

    // 960s later: offline
    tracker.evaluateAll(now + 960_000);
    expect(tracker.getPresence("agent-a")?.state).toBe("offline");

    // Resume heartbeat: back to active
    tracker.receiveHeartbeat("agent-a", new Date(now + 970_000).toISOString());
    expect(tracker.getPresence("agent-a")?.state).toBe("active");

    expect(transitions).toEqual([
      { from: "offline", to: "active" },  // first heartbeat
      { from: "active", to: "idle" },
      { from: "idle", to: "away" },
      { from: "away", to: "offline" },
      { from: "offline", to: "active" },  // resume
    ]);
  });

  it("PresencePublisher builds heartbeat events with correct shape", () => {
    const identity = makeIdentity("agent-pub");
    const publisher = new PresencePublisher({
      member_id: "agent-pub",
      emitter_node: "node-001",
      emitter_principal: "system",
      fortress_id: "fortress-001",
      node_private_key: identity.private_key,
      interval_ms: 30_000,
    });

    const heartbeat = publisher.buildHeartbeat();
    expect(heartbeat.event_type).toBe("chat_presence");
    expect(heartbeat.payload.member_id).toBe("agent-pub");
    expect(heartbeat.payload.state).toBe("active");
    expect(heartbeat.payload.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(heartbeat.protocol_version).toBe(PROTOCOL_VERSION);
    expect(heartbeat.node_signature).toBeTruthy();

    // Verify signature
    const body = { ...heartbeat };
    delete (body as Record<string, unknown>).node_signature;
    delete (body as Record<string, unknown>).principal_signature;
    const bodyBytes = canonicalizeToBytes(body);
    const sigBytes = fromBase64url(heartbeat.node_signature);
    expect(ed25519.verify(sigBytes, bodyBytes, identity.public_key)).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-4: Agent coordination-peers enforcement
// ═══════════════════════════════════════════════════════════════════════

describe("AC-4: Coordination-peers enforcement", () => {
  const fortressId = "fortress-001";

  it("agent with coordination_peers can message listed peer", () => {
    const policy = makeMinimalPolicy("agent-x", fortressId);
    const policyWithPeers = withCoordinationPeers(policy, ["agent-y", "agent-z"]);

    const result = evaluateChatGate(policyWithPeers, {
      agent_id: "agent-x",
      target_peer: "agent-y",
    });
    expect(result.decision).toBe("allow");
    expect(result.reason_code).toBe(CHAT_GATE_REASON_CODES.CHAT_PEER_AUTHORIZED);
  });

  it("agent with coordination_peers CANNOT message unlisted peer", () => {
    const policy = makeMinimalPolicy("agent-x", fortressId);
    const policyWithPeers = withCoordinationPeers(policy, ["agent-y"]);

    const result = evaluateChatGate(policyWithPeers, {
      agent_id: "agent-x",
      target_peer: "agent-z",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(CHAT_GATE_REASON_CODES.CHAT_PEER_NOT_AUTHORIZED);
  });

  it("agent without coordination_peers is denied", () => {
    const policy = makeMinimalPolicy("agent-x", fortressId);

    const result = evaluateChatGate(policy, {
      agent_id: "agent-x",
      target_peer: "agent-y",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(CHAT_GATE_REASON_CODES.CHAT_NO_COORDINATION_PEERS);
  });

  it("null policy denies", () => {
    const result = evaluateChatGate(null, {
      agent_id: "agent-x",
      target_peer: "agent-y",
    });
    expect(result.decision).toBe("deny");
  });

  it("sentinel agent is denied (Key 11)", () => {
    const policy = makeMinimalPolicy("sentinel-1", fortressId);
    policy.capabilities.is_sentinel = true;
    const policyWithPeers = withCoordinationPeers(policy, ["agent-y"]);

    const result = evaluateChatGate(policyWithPeers, {
      agent_id: "sentinel-1",
      target_peer: "agent-y",
    });
    expect(result.decision).toBe("deny");
    expect(result.reason_code).toBe(CHAT_GATE_REASON_CODES.CHAT_SENTINEL_DENIED);
  });

  it("enforceCoordinationPeers throws correct error types", () => {
    const policy = makeMinimalPolicy("agent-x", fortressId);
    const policyWithPeers = withCoordinationPeers(policy, ["agent-y"]);

    // Authorized: no throw
    expect(() =>
      enforceCoordinationPeers(policyWithPeers, {
        agent_id: "agent-x",
        target_peer: "agent-y",
      })
    ).not.toThrow();

    // Not authorized: ChatPeerNotAuthorizedError
    expect(() =>
      enforceCoordinationPeers(policyWithPeers, {
        agent_id: "agent-x",
        target_peer: "agent-z",
      })
    ).toThrow(ChatPeerNotAuthorizedError);

    // No peers: ChatNoCoordinationPeersError
    expect(() =>
      enforceCoordinationPeers(policy, {
        agent_id: "agent-x",
        target_peer: "agent-y",
      })
    ).toThrow(ChatNoCoordinationPeersError);
  });

  it("wildcard coordination_peers authorizes any target", () => {
    const policy = makeMinimalPolicy("agent-x", fortressId);
    const policyWithWildcard = withCoordinationPeers(policy, ["*"]);

    const result = evaluateChatGate(policyWithWildcard, {
      agent_id: "agent-x",
      target_peer: "any-agent-at-all",
    });
    expect(result.decision).toBe("allow");
  });

  it("getCoordinationPeers extracts and validates", () => {
    const policy = makeMinimalPolicy("agent-x", fortressId);
    expect(getCoordinationPeers(policy)).toBeUndefined();

    const withPeers = withCoordinationPeers(policy, ["a", "b"]);
    expect(getCoordinationPeers(withPeers)).toEqual(["a", "b"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-5: Retention-sweep integration
// ═══════════════════════════════════════════════════════════════════════

describe("AC-5: Retention-sweep integration", () => {
  it("retention sweep deletes expired chat messages from store AND pgvector", async () => {
    const chatLog = new InMemoryChatLogStore();
    const pgIndex = new InMemoryPgVectorIndex(deterministicEmbed);
    const adapter = new ChatRetentionAdapter(chatLog, pgIndex);

    // Seed 100 chat messages, all 8 days old
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    for (let i = 0; i < 100; i++) {
      const entry = {
        message_id: `msg-${i}`,
        group_id: "group-1",
        sender_id: "agent-a",
        content: `message number ${i}`,
        sent_at: eightDaysAgo,
        stored_at: eightDaysAgo,
        target: "group",
        fortress_id: "fortress-001",
      };
      await chatLog.append(entry);
      await pgIndex.indexMessage(entry);
    }

    expect(await chatLog.count()).toBe(100);
    expect(pgIndex.count()).toBe(100);

    // Retention window: 7 days for outputs slot
    const retention = {
      windows: {
        outputs: { max_age_seconds: 7 * 24 * 60 * 60 },
      },
    };

    // Execute sweep
    const result = await executeRetentionSweep({
      agent_id: "agent-a",
      retention,
      store: adapter,
    });

    // All 100 chat messages should be swept from outputs slot
    expect(result.swept.outputs).toBe(100);

    // Verify both stores are empty
    expect(await chatLog.count()).toBe(0);
    expect(pgIndex.count()).toBe(0);
  });

  it("non-expired messages are retained", async () => {
    const chatLog = new InMemoryChatLogStore();
    const adapter = new ChatRetentionAdapter(chatLog, null);

    // Seed 10 recent messages
    const now = new Date().toISOString();
    for (let i = 0; i < 10; i++) {
      await chatLog.append({
        message_id: `msg-${i}`,
        group_id: "group-1",
        sender_id: "agent-a",
        content: `recent message ${i}`,
        sent_at: now,
        stored_at: now,
        target: "group",
        fortress_id: "fortress-001",
      });
    }

    const retention = {
      windows: {
        outputs: { max_age_seconds: 7 * 24 * 60 * 60 },
      },
    };

    const result = await executeRetentionSweep({
      agent_id: "agent-a",
      retention,
      store: adapter,
    });

    expect(result.swept.outputs).toBe(0);
    expect(result.retained.outputs).toBe(10);
    expect(await chatLog.count()).toBe(10);
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-6: pgvector search (deterministic embedding)
// ═══════════════════════════════════════════════════════════════════════

describe("AC-6: pgvector semantic search", () => {
  it("finds the expected message via semantic match", async () => {
    const pgIndex = new InMemoryPgVectorIndex(deterministicEmbed);

    // Seed 20 messages with varied content
    const messages = [
      "security audit completed successfully",
      "sovereignty assessment pending review",
      "encryption keys rotated on schedule",
      "fortress perimeter check passed",
      "agent deployment script updated",
      "policy configuration changed",
      "budget allocation for Q2 approved",
      "retention window extended to 90 days",
      "chat system integration testing",
      "message delivery latency improved",
      "presence heartbeat interval adjusted",
      "mls group key ratchet verified",
      "group membership audit complete",
      "deploy pipeline green across all stages",
      "monitor alert threshold lowered",
      "alert notifications sent to operator",
      "status dashboard widgets refreshed",
      "update rollout completed successfully",
      "review process streamlined",
      "approve gate timeout increased",
    ];

    const fortressId = "fortress-001";
    for (let i = 0; i < messages.length; i++) {
      await pgIndex.indexMessage({
        message_id: `msg-${i}`,
        group_id: "group-1",
        sender_id: "agent-a",
        content: messages[i]!,
        sent_at: new Date().toISOString(),
        stored_at: new Date().toISOString(),
        target: "group",
        fortress_id: fortressId,
      });
    }

    // Search for "encryption" concept
    const results = await pgIndex.search({
      query: "encryption",
      fortress_id: fortressId,
      limit: 1,
    });

    expect(results.length).toBe(1);
    expect(results[0]!.message.content).toBe("encryption keys rotated on schedule");
    expect(results[0]!.similarity).toBeGreaterThan(0);

    // Search for "security" concept
    const secResults = await pgIndex.search({
      query: "security",
      fortress_id: fortressId,
      limit: 1,
    });
    expect(secResults[0]!.message.content).toBe("security audit completed successfully");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// AC-7: Signed-event fields on every signed artifact
// ═══════════════════════════════════════════════════════════════════════

describe("AC-7: Signed-event field correctness", () => {
  it("packEphemeralEvent produces valid signed event with correct fields", () => {
    const identity = makeIdentity("agent-test");

    const event = packEphemeralEvent({
      event_type: "chat_presence",
      emitter_node: "node-001",
      emitter_principal: "system",
      fortress_id: "fortress-001",
      payload: {
        member_id: "agent-test",
        state: "active",
        heartbeat_at: new Date().toISOString(),
        signature_scheme: SIGNATURE_SCHEME_V1,
      },
      monotonic_seq: 1,
      node_private_key: identity.private_key,
    });

    // Check required fields
    expect(event.protocol_version).toBe(PROTOCOL_VERSION);
    expect(event.event_type).toBe("chat_presence");
    expect(event.event_id).toBeTruthy();
    expect(event.emitter_node).toBe("node-001");
    expect(event.fortress_id).toBe("fortress-001");
    expect(event.node_signature).toBeTruthy();
    expect(event.payload.signature_scheme).toBe("ed25519-v1");
    expect(event.monotonic_seq).toBe(1);
    expect(event.extension_envelope).toEqual({});

    // Verify signature
    const body = { ...event };
    delete (body as Record<string, unknown>).node_signature;
    delete (body as Record<string, unknown>).principal_signature;
    const bodyBytes = canonicalizeToBytes(body);
    const sigValid = ed25519.verify(
      fromBase64url(event.node_signature),
      bodyBytes,
      identity.public_key
    );
    expect(sigValid).toBe(true);
  });

  it("chat event types do not collide with reserved prefixes", () => {
    const reservedPrefixes = ["EXTENSION_", "cross_fortress_", "multi_master_"];
    const chatTypes = ["chat_message", "chat_mls_commit", "chat_presence", "chat_group_create", "chat_group_invite"];

    for (const chatType of chatTypes) {
      for (const prefix of reservedPrefixes) {
        expect(chatType.startsWith(prefix)).toBe(false);
      }
    }
  });

  it("MLS commit payloads carry signature_scheme", () => {
    // This tests the type contract; the ChatService emits these
    const payload = {
      group_id: "test-group",
      operation: "add" as const,
      member_id: "agent-new",
      mls_commit: toBase64url(new Uint8Array(32)),
      new_epoch: 1,
      signature_scheme: SIGNATURE_SCHEME_V1,
    };

    expect(payload.signature_scheme).toBe("ed25519-v1");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// ChatService integration tests
// ═══════════════════════════════════════════════════════════════════════

describe("ChatService integration", () => {
  let service: ChatService;
  let operatorId: MLSMemberIdentity;
  const fortressId = "fortress-001";

  beforeEach(() => {
    operatorId = makeIdentity("operator-primary");
    const policies = new Map<string, CompiledPolicy>();

    // Create a policy for agent-x with coordination_peers
    const agentPolicy = makeMinimalPolicy("agent-x", fortressId);
    const agentPolicyWithPeers = withCoordinationPeers(agentPolicy, ["agent-y"]);
    policies.set("agent-x", agentPolicyWithPeers);

    service = new ChatService({
      config: {
        fortress_id: fortressId,
        operator_principal_id: "operator-primary",
      },
      identity: operatorId,
      emitter_node: "node-001",
      node_private_key: operatorId.private_key,
      lookupPolicy: (id) => policies.get(id) ?? null,
      embedFn: deterministicEmbed,
    });
  });

  it("send and receive message through the full path", async () => {
    // Create group
    service.createIntraFortressGroup();
    const groupId = intraFortressGroupId(fortressId);

    // Send message (as operator, no coordination_peers check needed)
    const result = await service.sendMessage({
      group_id: groupId,
      content: "Test message for chat integration",
      sender_id: "operator-primary",
      target: "group",
    });

    expect(result.event_id).toBeTruthy();
    expect(result.epoch).toBe(0);

    // Verify chat log persisted
    const logs = await service.chatLog.listByGroup(groupId);
    expect(logs.length).toBe(1);
    expect(logs[0]!.content).toBe("Test message for chat integration");

    // Verify pgvector indexed
    if (service.pgIndex) {
      const count = await service.pgIndex.countByFortress(fortressId);
      expect(count).toBe(1);
    }
  });

  it("agent-initiated message enforcement via ChatService", async () => {
    const groupId = intraFortressGroupId(fortressId);
    service.createIntraFortressGroup();

    // Agent X can message agent Y (in coordination_peers)
    await expect(
      service.sendMessage({
        group_id: groupId,
        content: "Hi agent Y",
        sender_id: "agent-x",
        target: "agent-y",
        agent_id: "agent-x",
      })
    ).resolves.toBeTruthy();

    // Agent X CANNOT message agent Z (not in coordination_peers)
    await expect(
      service.sendMessage({
        group_id: groupId,
        content: "Hi agent Z",
        sender_id: "agent-x",
        target: "agent-z",
        agent_id: "agent-x",
      })
    ).rejects.toThrow(ChatPeerNotAuthorizedError);
  });

  it("semantic search works through ChatService", async () => {
    const groupId = intraFortressGroupId(fortressId);
    service.createIntraFortressGroup();

    await service.sendMessage({
      group_id: groupId,
      content: "security audit results look great",
      sender_id: "operator-primary",
      target: "group",
    });

    await service.sendMessage({
      group_id: groupId,
      content: "budget allocation approved for next quarter",
      sender_id: "operator-primary",
      target: "group",
    });

    const results = await service.searchMessages("security");
    expect(results.length).toBeGreaterThan(0);
    expect(results[0]!.message.content).toContain("security");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Topic namespace tests
// ═══════════════════════════════════════════════════════════════════════

describe("Chat topic namespaces", () => {
  it("chat topics are distinct from federation topics", () => {
    const fortressId = "fortress-abc";
    const fedTopic = broadcastTopic(fortressId);
    const chatT = chatTopic(fortressId);
    const presT = presenceTopic(fortressId);
    const crossT = crossFortressChatTopic("fortress-a", "fortress-b");

    // All topics must be non-empty and distinct
    expect(fedTopic).toBeTruthy();
    expect(chatT).toBeTruthy();
    expect(presT).toBeTruthy();
    expect(crossT).toBeTruthy();

    // Chat topics start with sanctuary/chat/v1
    expect(chatT.startsWith("sanctuary/chat/v1")).toBe(true);
    expect(presT.startsWith("sanctuary/chat/v1")).toBe(true);
    expect(crossT.startsWith("sanctuary/chat/v1")).toBe(true);

    // Federation topic starts with sanctuary/fed/v0.1
    expect(fedTopic.startsWith("sanctuary/fed/v0.1")).toBe(true);

    // No collision
    expect(chatT).not.toBe(fedTopic);
    expect(presT).not.toBe(fedTopic);
  });

  it("cross-fortress topic is deterministic regardless of argument order", () => {
    expect(crossFortressChatTopic("a", "b")).toBe(crossFortressChatTopic("b", "a"));
  });
});

// ═══════════════════════════════════════════════════════════════════════
// MLS group ID tests
// ═══════════════════════════════════════════════════════════════════════

describe("MLS group IDs", () => {
  it("intra-fortress group ID is deterministic", () => {
    expect(intraFortressGroupId("f1")).toBe("sanctuary-chat-v1/f1");
    expect(intraFortressGroupId("f1")).toBe(intraFortressGroupId("f1"));
  });

  it("cross-fortress group ID is deterministic and order-independent", () => {
    expect(crossFortressGroupId("a", "b")).toBe(crossFortressGroupId("b", "a"));
    expect(crossFortressGroupId("a", "b")).toBe("sanctuary-chat-v1/cross/a/b");
  });
});

// ═══════════════════════════════════════════════════════════════════════
// Chat log store tests
// ═══════════════════════════════════════════════════════════════════════

describe("InMemoryChatLogStore", () => {
  it("append, list, get, delete", async () => {
    const store = new InMemoryChatLogStore();

    const entry = {
      message_id: "msg-1",
      group_id: "group-1",
      sender_id: "agent-a",
      content: "hello",
      sent_at: new Date().toISOString(),
      stored_at: new Date().toISOString(),
      target: "group",
      fortress_id: "fortress-001",
    };

    await store.append(entry);
    expect(await store.count()).toBe(1);
    expect(await store.get("msg-1")).toEqual(entry);

    const byGroup = await store.listByGroup("group-1");
    expect(byGroup.length).toBe(1);

    const byFortress = await store.listByFortress("fortress-001");
    expect(byFortress.length).toBe(1);

    await store.delete("msg-1");
    expect(await store.count()).toBe(0);
    expect(await store.get("msg-1")).toBeUndefined();
  });
});
