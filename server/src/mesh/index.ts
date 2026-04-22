/**
 * Sanctuary Federation Protocol v0.1 — Public Surface
 *
 * Intra-fortress mesh protocol: single console speaks to every node in one operator's
 * mesh as a single sovereign fabric. Three node modes (local, operator_cloud,
 * sovereign_tee). Six v0.1 message classes plus three RPC shapes.
 *
 * This is distinct from server/src/federation/ (MCP-to-MCP peer federation with
 * SHR exchange and handshake-based trust). The mesh module is intra-operator;
 * the federation module is inter-instance. They do not share types.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md
 * Hard-gate walkthrough: Review/Sanctuary/Federation_V0.1_Hard_Gate_Walkthrough_2026-04-21.md
 */

export * from "./constants.js";
export * from "./errors.js";
export * from "./types.js";
export * from "./trust-root.js";
export * from "./envelope.js";
export * from "./audit-batch.js";
export * from "./router.js";
export * from "./in-memory-transport.js";
export { canonicalize, canonicalizeToBytes } from "./canonical-json.js";
export * from "./guardian/index.js";
export * from "./failure-modes/index.js";
export * from "./recovery-flows/index.js";
export {
  Libp2pMeshTransport,
  AGENT_STATE_TRANSFER_PROTOCOL,
  ALL_STREAM_PROTOCOLS,
  SYNC_PROTOCOL,
  UNICAST_PROTOCOL,
  applyLibp2pConfigDefaults,
  broadcastTopic,
  libp2pPrivateKeyFromSanctuarySeed,
  peerIdFromSanctuaryPubkey,
  peerIdFromSanctuarySeed,
  LIBP2P_TRANSPORT_DEFAULTS,
  type Libp2pMeshTransportParams,
  type Libp2pTransportConfig,
  type StreamProtocol,
} from "./libp2p-transport/index.js";
