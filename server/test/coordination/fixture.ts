/**
 * Coordination test fixture.
 *
 * Builds:
 *   - Two agent signers (sender + recipient) with raw Ed25519 keypairs.
 *   - One operator signer (used for policy_gate denials).
 *   - A `CoordinationKeyResolver` covering all three.
 *   - A `LocalCoordinator` wired to a real `MemoryStorage` + real `AuditLog`
 *     so signing, persistence, and audit emission run end-to-end.
 *
 * No crypto is mocked. Every signature is a real Ed25519 signature over
 * canonical JSON.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { randomBytes } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  type CoordinationKeyResolver,
  type CoordinationSigner,
  HandoffStore,
  LocalCoordinator,
  type CoordinationPolicyGate,
} from "../../src/coordination/index.js";

export interface AgentFixture {
  agent_id: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  signer: CoordinationSigner;
}

export function buildAgent(agent_id: string): AgentFixture {
  const { publicKey, privateKey } = generateKeypair();
  const signer: CoordinationSigner = {
    identity_id: agent_id,
    publicKey,
    sign: (payload) => ed25519.sign(payload, privateKey),
  };
  return { agent_id, publicKey, privateKey, signer };
}

export interface OperatorFixture {
  identity_id: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  signer: CoordinationSigner;
}

export function buildOperator(identity_id = "operator-root"): OperatorFixture {
  const { publicKey, privateKey } = generateKeypair();
  const signer: CoordinationSigner = {
    identity_id,
    publicKey,
    sign: (payload) => ed25519.sign(payload, privateKey),
  };
  return { identity_id, publicKey, privateKey, signer };
}

export interface CoordinationFixture {
  sender: AgentFixture;
  recipient: AgentFixture;
  thirdParty: AgentFixture;
  operator: OperatorFixture;
  keyResolver: CoordinationKeyResolver;
  storage: MemoryStorage;
  auditLog: AuditLog;
  store: HandoffStore;
  coordinator: LocalCoordinator;
}

export interface BuildFixtureOptions {
  policyGate?: CoordinationPolicyGate;
}

export function buildCoordinationFixture(
  options: BuildFixtureOptions = {},
): CoordinationFixture {
  const sender = buildAgent("agent-sender");
  const recipient = buildAgent("agent-recipient");
  const thirdParty = buildAgent("agent-third");
  const operator = buildOperator();
  const masterKey = randomBytes(32);
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new HandoffStore(storage, masterKey);

  const keyResolver: CoordinationKeyResolver = {
    lookupAgentPublicKey(agent_id: string): Uint8Array | undefined {
      if (agent_id === sender.agent_id) return sender.publicKey;
      if (agent_id === recipient.agent_id) return recipient.publicKey;
      if (agent_id === thirdParty.agent_id) return thirdParty.publicKey;
      return undefined;
    },
    lookupOperatorPublicKey(identity_id: string): Uint8Array | undefined {
      return identity_id === operator.identity_id
        ? operator.publicKey
        : undefined;
    },
  };

  const coordinator = new LocalCoordinator({
    store,
    auditLog,
    keyResolver,
    policyGate: options.policyGate,
  });

  return {
    sender,
    recipient,
    thirdParty,
    operator,
    keyResolver,
    storage,
    auditLog,
    store,
    coordinator,
  };
}
