/**
 * Sanctuary Chat v1.0 — Chat Service
 *
 * Orchestrator that wires encrypted chat groups, presence, coordination-peers
 * gate, chat log persistence, and pgvector indexing into a unified surface.
 *
 * The chat service is the entry point for:
 * - Creating intra-fortress and cross-fortress encrypted groups
 * - Sending/receiving AES-256-GCM encrypted messages (per-epoch keys)
 * - Publishing/tracking presence
 * - Enforcing coordination-peers policy on agent-initiated sends
 * - Persisting chat logs and indexing them for retrieval
 *
 * WP-MVP-7: Q2 architecture walkthrough.
 */

import { SIGNATURE_SCHEME_V1 } from "../mesh/constants.js";
import { packSignedEvent } from "../mesh/envelope.js";
import type { CompiledPolicy } from "../policy-engine/types.js";
import { ChatLogStore, InMemoryChatLogStore } from "./chat-log.js";
import { enforceCoordinationPeers } from "./coordination-gate.js";
import {
  MLSGroupManager,
  type MLSMemberIdentity,
  intraFortressGroupId,
  crossFortressGroupId,
} from "./mls-group.js";
import { PresenceTracker, PresencePublisher } from "./presence.js";
import type {
  ChatConfig,
  ChatLogEntry,
  ChatMessagePayload,
  ChatPlaintext,
  MLSGroupState,
  ChatSearchResult,
} from "./types.js";
import { toBase64url } from "../core/encoding.js";
import { InMemoryPgVectorIndex, type EmbedFn } from "./pgvector-index.js";

// ═══════════════════════════════════════════════════════════════════════
// Chat Service
// ═══════════════════════════════════════════════════════════════════════

export interface ChatServiceParams {
  config: ChatConfig;
  identity: MLSMemberIdentity;
  /** Node ID for signed-event emissions. */
  emitter_node: string;
  /** Node's Ed25519 private key for signing. */
  node_private_key: Uint8Array;
  /** Policy lookup: agent_id -> compiled policy. */
  lookupPolicy: (agentId: string) => CompiledPolicy | null;
  /** Optional chat log store (defaults to in-memory). */
  chatLogStore?: ChatLogStore;
  /** Optional pgvector index (defaults to in-memory). */
  pgVectorIndex?: InMemoryPgVectorIndex;
  /** Optional embedding function. */
  embedFn?: EmbedFn;
}

export class ChatService {
  readonly config: ChatConfig;
  readonly mlsManager: MLSGroupManager;
  readonly presenceTracker: PresenceTracker;
  readonly presencePublisher: PresencePublisher;
  readonly chatLog: ChatLogStore;
  readonly pgIndex: InMemoryPgVectorIndex | null;

  private lookupPolicy: (agentId: string) => CompiledPolicy | null;
  private emitterNode: string;
  private nodePrivateKey: Uint8Array;
  private seqCounter = 0;

  constructor(params: ChatServiceParams) {
    this.config = params.config;
    this.mlsManager = new MLSGroupManager(params.identity);
    this.presenceTracker = new PresenceTracker();
    this.presencePublisher = new PresencePublisher({
      member_id: params.identity.member_id,
      emitter_node: params.emitter_node,
      emitter_principal: params.config.operator_principal_id,
      fortress_id: params.config.fortress_id,
      node_private_key: params.node_private_key,
      interval_ms: params.config.presence_heartbeat_interval_ms,
    });
    this.chatLog = params.chatLogStore ?? new InMemoryChatLogStore();
    this.lookupPolicy = params.lookupPolicy;
    this.emitterNode = params.emitter_node;
    this.nodePrivateKey = params.node_private_key;

    // Set up pgvector index if embedding function provided
    if (params.pgVectorIndex) {
      this.pgIndex = params.pgVectorIndex;
    } else if (params.embedFn) {
      this.pgIndex = new InMemoryPgVectorIndex(params.embedFn);
    } else {
      this.pgIndex = null;
    }
  }

  private nextSeq(): number {
    return ++this.seqCounter;
  }

  // ═══════════════════════════════════════════════════════════════════
  // Group management
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Create an intra-fortress encrypted chat group.
   * Operator + her wrapped agents form the default group.
   */
  createIntraFortressGroup(): {
    state: MLSGroupState;
    groupInfo: Uint8Array;
  } {
    const groupId = intraFortressGroupId(this.config.fortress_id);
    const result = this.mlsManager.createGroup({
      group_id: groupId,
      group_type: "intra_fortress",
      fortress_ids: [this.config.fortress_id],
    });
    return { state: result.state, groupInfo: result.group_info };
  }

  /**
   * Create a cross-fortress encrypted chat group with another fortress.
   */
  createCrossFortressGroup(otherFortressId: string): {
    state: MLSGroupState;
    groupInfo: Uint8Array;
  } {
    const groupId = crossFortressGroupId(
      this.config.fortress_id,
      otherFortressId
    );
    const result = this.mlsManager.createGroup({
      group_id: groupId,
      group_type: "cross_fortress",
      fortress_ids: [this.config.fortress_id, otherFortressId],
    });
    return { state: result.state, groupInfo: result.group_info };
  }

  /**
   * Add an agent to a group. Operator-only operation.
   * Returns the commit and Welcome for distributing to the new member.
   */
  addMember(
    groupId: string,
    member: { member_id: string; public_key: Uint8Array }
  ): { commit: Uint8Array; welcome: Uint8Array; new_epoch: number } {
    return this.mlsManager.addMember(groupId, member);
  }

  /**
   * Remove a member from a group. Operator-only operation.
   */
  removeMember(
    groupId: string,
    memberId: string
  ): { commit: Uint8Array; new_epoch: number } {
    return this.mlsManager.removeMember(groupId, memberId);
  }

  /**
   * Join a group via a Welcome message (for agents being added).
   */
  joinGroup(welcomeBytes: Uint8Array): MLSGroupState {
    return this.mlsManager.joinViaWelcome(welcomeBytes);
  }

  // ═══════════════════════════════════════════════════════════════════
  // Sending messages
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Send a message to a group. Handles:
   * 1. Coordination-peers enforcement (for agent senders)
   * 2. AES-256-GCM encryption at current epoch
   * 3. Chat log persistence
   * 4. pgvector indexing
   *
   * Returns the signed event wrapping the encrypted ciphertext.
   */
  async sendMessage(params: {
    group_id: string;
    content: string;
    sender_id: string;
    target: string | "group";
    /** If sender is an agent, its agent_id for policy lookup. Null for operator. */
    agent_id?: string;
  }): Promise<{
    event_id: string;
    mls_ciphertext: Uint8Array;
    epoch: number;
  }> {
    // Step 1: Coordination-peers enforcement for agent senders
    if (params.agent_id && params.target !== "group") {
      const policy = this.lookupPolicy(params.agent_id);
      enforceCoordinationPeers(policy, {
        agent_id: params.agent_id,
        target_peer: params.target,
      });
    }

    // Step 2: MLS encryption
    const plaintext: ChatPlaintext = {
      content: params.content,
      sent_at: new Date().toISOString(),
      sender_id: params.sender_id,
    };

    const groupState = this.mlsManager.getGroupState(params.group_id);
    if (!groupState) {
      throw new Error(`group ${params.group_id} not found`);
    }

    const ciphertext = this.mlsManager.encrypt(params.group_id, plaintext);

    // Step 3: Build signed event
    const payload: ChatMessagePayload = {
      group_id: params.group_id,
      mls_epoch: groupState.epoch,
      mls_ciphertext: toBase64url(ciphertext),
      sender_id: params.sender_id,
      target: params.target,
      signature_scheme: SIGNATURE_SCHEME_V1,
    };

    const event = packSignedEvent<ChatMessagePayload>({
      event_type: "chat_message" as string,
      emitter_node: this.emitterNode,
      emitter_principal: this.config.operator_principal_id,
      fortress_id: this.config.fortress_id,
      payload,
      monotonic_seq: this.nextSeq(),
      node_private_key: this.nodePrivateKey,
    });

    // Step 4: Persist to chat log
    const logEntry: ChatLogEntry = {
      message_id: event.event_id,
      group_id: params.group_id,
      sender_id: params.sender_id,
      content: params.content,
      sent_at: plaintext.sent_at,
      stored_at: new Date().toISOString(),
      target: params.target,
      fortress_id: this.config.fortress_id,
    };
    await this.chatLog.append(logEntry);

    // Step 5: pgvector indexing (async, non-blocking)
    if (this.pgIndex) {
      await this.pgIndex.indexMessage(logEntry);
    }

    return {
      event_id: event.event_id,
      mls_ciphertext: ciphertext,
      epoch: groupState.epoch,
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  // Receiving messages
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Receive and decrypt an encrypted chat message.
   * Persists the decrypted message to the chat log and pgvector.
   */
  async receiveMessage(
    eventId: string,
    groupId: string,
    ciphertext: Uint8Array,
    epoch: number,
    senderId: string,
    target: string
  ): Promise<ChatPlaintext> {
    const plaintext = this.mlsManager.decrypt(groupId, ciphertext, epoch);

    // Persist
    const logEntry: ChatLogEntry = {
      message_id: eventId,
      group_id: groupId,
      sender_id: senderId,
      content: plaintext.content,
      sent_at: plaintext.sent_at,
      stored_at: new Date().toISOString(),
      target,
      fortress_id: this.config.fortress_id,
    };
    await this.chatLog.append(logEntry);

    if (this.pgIndex) {
      await this.pgIndex.indexMessage(logEntry);
    }

    return plaintext;
  }

  // ═══════════════════════════════════════════════════════════════════
  // Search
  // ═══════════════════════════════════════════════════════════════════

  /**
   * Semantic search over chat messages using pgvector.
   */
  async searchMessages(query: string, limit?: number): Promise<ChatSearchResult[]> {
    if (!this.pgIndex) return [];
    return this.pgIndex.search({
      query,
      fortress_id: this.config.fortress_id,
      limit,
    });
  }

  // ═══════════════════════════════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════════════════════════════

  /** Start the chat service (presence tracking + publishing). */
  start(publishFn: (event: unknown) => void): void {
    this.presenceTracker.start();
    this.presencePublisher.start(publishFn as (event: unknown) => void);
  }

  /** Stop the chat service. */
  stop(): void {
    this.presenceTracker.stop();
    this.presencePublisher.stop();
  }
}
