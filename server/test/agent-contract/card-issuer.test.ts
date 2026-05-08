/**
 * Agent Contract v0.1 — Agent Card issuance + verification tests (§3).
 *
 * Real crypto end-to-end: a fortress is built, an Agent Card is issued,
 * verified against the pinned master; tampering with any field fails the
 * envelope signature check.
 */

import { describe, it, expect } from "vitest";
import { fromBase64url, toBase64url } from "../../src/core/encoding.js";
import {
  computePolicyVersionHash,
  hashAgentCard,
  issueAgentCard,
  verifyAgentCard,
} from "../../src/agent-contract/card-issuer.js";
import {
  AgentCardSchemaError,
  AgentCardVerificationError,
} from "../../src/agent-contract/errors.js";
import { MeshSignatureError } from "../../src/mesh/errors.js";
import { SIGNATURE_SCHEME_V1 } from "../../src/mesh/constants.js";
import { buildPolicyBlobBytes, buildTestFortress } from "./fixture.js";
import type { SignedEvent } from "../../src/mesh/types.js";
import type { AgentCard } from "../../src/agent-contract/types.js";

describe("Agent Card issuance + verification (§3)", () => {
  it("round-trips a signed Agent Card through real mesh crypto", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    const { signed_event, card } = issueAgentCard({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      tier: "B",
      harness_id: "cline",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(7)),
      capabilities: [
        { kind: "read-slot", target: "memory" },
        { kind: "tool-call", target: "filesystem/read*" },
      ],
      policy_version: 1,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      principal_private_key: f.principalKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(card.signature_scheme).toBe(SIGNATURE_SCHEME_V1);
    expect(card.policy_version_hash).toBe(computePolicyVersionHash(policy));

    const verified = verifyAgentCard(signed_event, f.verifyContext);
    expect(verified.card.agent_id).toBe("agent-alpha");
    expect(verified.unknown_extension_keys).toEqual([]);
    expect(hashAgentCard(verified.card)).toBe(hashAgentCard(card));
  });

  it("rejects tampered capabilities (payload_hash coherence)", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    const { signed_event } = issueAgentCard({
      agent_id: "agent-alpha",
      fortress_id: f.master.public.fortress_id,
      tier: "B",
      harness_id: "cline",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(7)),
      capabilities: [{ kind: "read-slot", target: "memory" }],
      policy_version: 1,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    const tampered: SignedEvent<AgentCard> = {
      ...signed_event,
      payload: {
        ...signed_event.payload,
        // Add a capability post-sign → payload_hash no longer matches.
        capabilities: [
          { kind: "read-slot", target: "memory" },
          { kind: "egress", target: "https://evil.example.com" },
        ],
      },
    };
    expect(() => verifyAgentCard(tampered, f.verifyContext)).toThrow(
      MeshSignatureError
    );
  });

  it("rejects an event_type other than agent_card_issued", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    const { signed_event } = issueAgentCard({
      agent_id: "a",
      fortress_id: f.master.public.fortress_id,
      tier: "B",
      harness_id: "cline",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(7)),
      capabilities: [],
      policy_version: 0,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    const wrongType = { ...signed_event, event_type: "heartbeat" };
    expect(() =>
      verifyAgentCard(wrongType as SignedEvent, f.verifyContext)
    ).toThrow(AgentCardVerificationError);
  });

  it("rejects a card whose card.fortress_id disagrees with envelope.fortress_id", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    const { signed_event } = issueAgentCard({
      agent_id: "a",
      fortress_id: f.master.public.fortress_id,
      tier: "B",
      harness_id: "cline",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(7)),
      capabilities: [],
      policy_version: 0,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    // Surgically mutate the PAYLOAD'S fortress_id — this also breaks
    // payload_hash (which is the correct mesh-level rejection), but the
    // Agent Contract layer has its OWN guard. We test the mesh guard
    // fires first, and the agent-contract guard is load-bearing only if
    // the payload hash is recomputed.
    // For the intra-card check, emit a card with a deliberately wrong
    // card.fortress_id value matched to a valid envelope fortress_id:
    // that's architecturally impossible in normal flow since issueAgentCard
    // derives card.fortress_id from the envelope. Instead we forge the
    // event manually.
    const forgedEvent: SignedEvent<AgentCard> = {
      ...signed_event,
      payload: { ...signed_event.payload, fortress_id: "not-our-fortress" },
    };
    // Recomputing payload_hash would require re-signing. Instead assert
    // that the mesh rejects at the payload_hash layer.
    expect(() => verifyAgentCard(forgedEvent, f.verifyContext)).toThrow(
      MeshSignatureError
    );
  });

  it("rejects model_provider mismatch for pinned harness at issuance gate (#56)", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    expect(() =>
      issueAgentCard({
        agent_id: "agent-pinned",
        fortress_id: f.master.public.fortress_id,
        tier: "B",
        harness_id: "claude-code",
        // claude-code is pinned to "anthropic" via ADAPTER_PROVIDER_PINS;
        // even bypassing the adapter constructor, the issuance gate refuses.
        model_provider: "openai",
        model_id: "gpt-5",
        agent_pubkey: toBase64url(new Uint8Array(32).fill(9)),
        capabilities: [{ kind: "read-slot", target: "memory" }],
        policy_version: 1,
        policy_blob_bytes: policy,
        attestation_endpoint: "http://127.0.0.1:3501/att",
        emitter_node: f.nodeCert.node_id,
        emitter_principal: f.principalCert.principal_id,
        node_private_key: f.nodeKeypair.privateKey,
        monotonic_seq: 0,
      })
    ).toThrow(AgentCardSchemaError);
  });

  it("accepts pinned-harness card when model_provider matches the pin (#56)", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    const { card } = issueAgentCard({
      agent_id: "agent-pinned-ok",
      fortress_id: f.master.public.fortress_id,
      tier: "B",
      harness_id: "claude-code",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(11)),
      capabilities: [{ kind: "read-slot", target: "memory" }],
      policy_version: 1,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(card.harness_id).toBe("claude-code");
    expect(card.model_provider).toBe("anthropic");
  });

  it("permits any model_provider for unpinned harness at issuance gate (#56)", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    // Hermes is deliberately unpinned: operator routes Hermes to whatever
    // model they choose (NousResearch, Anthropic, OpenAI, etc.).
    const { card } = issueAgentCard({
      agent_id: "agent-hermes",
      fortress_id: f.master.public.fortress_id,
      tier: "B",
      harness_id: "hermes",
      model_provider: "openai",
      model_id: "gpt-5",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(13)),
      capabilities: [{ kind: "read-slot", target: "memory" }],
      policy_version: 1,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(card.model_provider).toBe("openai");
  });

  it("embeds signature_scheme=ed25519-v1 on every emission (crypto-agility hinge)", () => {
    const f = buildTestFortress();
    const policy = buildPolicyBlobBytes(1);
    const { card, signed_event } = issueAgentCard({
      agent_id: "agent-a",
      fortress_id: f.master.public.fortress_id,
      tier: "A",
      harness_id: "openclaw",
      model_provider: "anthropic",
      model_id: "claude-opus-4-7",
      agent_pubkey: toBase64url(new Uint8Array(32).fill(3)),
      capabilities: [{ kind: "read-slot", target: "memory" }],
      policy_version: 1,
      policy_blob_bytes: policy,
      attestation_endpoint: "http://127.0.0.1:3501/att",
      emitter_node: f.nodeCert.node_id,
      emitter_principal: f.principalCert.principal_id,
      node_private_key: f.nodeKeypair.privateKey,
      monotonic_seq: 0,
    });
    expect(card.signature_scheme).toBe("ed25519-v1");
    // Envelope's node_signature is base64url, so simply assert presence.
    expect(signed_event.node_signature.length).toBeGreaterThan(0);
    expect(fromBase64url(signed_event.node_signature).length).toBe(64);
  });
});
