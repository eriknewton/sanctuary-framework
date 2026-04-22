/**
 * Sanctuary Federation Protocol v0.1 — libp2p MeshTransport (public barrel).
 *
 * See `transport.ts` for the main entry point `Libp2pMeshTransport.start(...)`.
 * See `config.ts` for the operator-facing configuration type.
 *
 * Non-dependency: this module imports libp2p + @chainsafe + @libp2p/* from
 * npm. It does NOT import Concordia or Verascore.
 */

export {
  Libp2pMeshTransport,
  type Libp2pMeshTransportParams,
} from "./transport.js";
export {
  applyLibp2pConfigDefaults,
  LIBP2P_TRANSPORT_DEFAULTS,
  type Libp2pTransportConfig,
} from "./config.js";
export {
  libp2pPrivateKeyFromSanctuarySeed,
  peerIdFromSanctuaryPubkey,
  peerIdFromSanctuarySeed,
} from "./peer-id.js";
export {
  AGENT_STATE_TRANSFER_PROTOCOL,
  ALL_STREAM_PROTOCOLS,
  SYNC_PROTOCOL,
  UNICAST_PROTOCOL,
  broadcastTopic,
  type StreamProtocol,
} from "./protocols.js";
