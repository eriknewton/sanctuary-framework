/**
 * Sanctuary Chat v1.0 — Error Types
 *
 * Structured errors for chat operations. Machine-readable codes for
 * downstream consumers (console, audit, policy engine).
 */

/** Base class for all chat errors. */
export class ChatError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ChatError";
    this.code = code;
  }
}

/** Agent attempted to send a message to a peer not in its coordination_peers list. */
export class ChatPeerNotAuthorizedError extends ChatError {
  readonly agent_id: string;
  readonly target_peer: string;
  constructor(agent_id: string, target_peer: string) {
    super(
      "chat_peer_not_authorized",
      `agent ${agent_id} is not authorized to message peer ${target_peer} (not in coordination_peers)`
    );
    this.name = "ChatPeerNotAuthorizedError";
    this.agent_id = agent_id;
    this.target_peer = target_peer;
  }
}

/** Agent has no coordination_peers extension in its pinned policy. */
export class ChatNoCoordinationPeersError extends ChatError {
  readonly agent_id: string;
  constructor(agent_id: string) {
    super(
      "chat_no_coordination_peers",
      `agent ${agent_id} has no coordination_peers in pinned policy; agent-initiated chat denied`
    );
    this.name = "ChatNoCoordinationPeersError";
    this.agent_id = agent_id;
  }
}

/** Group operation failed. */
export class MLSGroupError extends ChatError {
  constructor(message: string) {
    super("mls_group_error", message);
    this.name = "MLSGroupError";
  }
}

/** Decryption failed (member not in group or forward secrecy barrier). */
export class MLSDecryptionError extends ChatError {
  constructor(message: string) {
    super("mls_decryption_error", message);
    this.name = "MLSDecryptionError";
  }
}

/** Cross-fortress group bootstrap handshake failed. */
export class CrossFortressBootstrapError extends ChatError {
  constructor(message: string) {
    super("cross_fortress_bootstrap_error", message);
    this.name = "CrossFortressBootstrapError";
  }
}

/** Presence heartbeat validation failure. */
export class PresenceValidationError extends ChatError {
  constructor(message: string) {
    super("presence_validation_error", message);
    this.name = "PresenceValidationError";
  }
}

/** pgvector index operation failed. */
export class ChatIndexError extends ChatError {
  constructor(message: string) {
    super("chat_index_error", message);
    this.name = "ChatIndexError";
  }
}
