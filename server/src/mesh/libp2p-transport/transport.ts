/**
 * Sanctuary Federation Protocol v0.1 — libp2p MeshTransport adapter.
 *
 * Implements the same `MeshTransport` interface PR #29 shipped on top of
 * `InMemoryTransport`, now backed by real TCP sockets + Noise session-layer
 * encryption + gossipsub broadcast + direct streams for unicast.
 *
 * Hard rules enforced here (spawn prompt §5 / §7.1):
 *
 *   1. peer-id = Ed25519 public key of the node's NodeIdentityCertificate.
 *      We pass the seed through `libp2pPrivateKeyFromSanctuarySeed` into libp2p
 *      as the node's static keypair, so the Noise handshake proves possession
 *      of that key to remote peers. A peer presenting any other peer-id is
 *      rejected pre-application-layer.
 *
 *   2. `SignedEvent<T>` JSON goes on the wire as-is — Noise wraps it at the
 *      session layer; the application layer verifies signatures again
 *      independently via `verifySignedEvent` at dispatch time.
 *
 *   3. `signature_scheme: "ed25519-v1"` mandatory on every signed emission —
 *      the transport does not mint events, but it refuses to emit any payload
 *      that does not already carry a node_signature (defense in depth).
 *
 *   4. Non-dependency: Sanctuary ↛ Concordia. No Concordia imports.
 *
 * Discovery (§11 picks): mDNS (LAN), Kademlia DHT (internet-scale), and
 * operator-configured static peers. All three funnel through the same libp2p
 * peerStore; the application-layer roster (NodeRoster from PR #30) is the
 * authoritative membership record.
 *
 * Spec: Federation_Protocol_V0.1_Spec_2026-04-21.md §2 (transport keys), §4
 * (wire format), §11 (stack pick).
 */

import { createLibp2p, type Libp2p } from "libp2p";
import { noise } from "@chainsafe/libp2p-noise";
import { yamux } from "@chainsafe/libp2p-yamux";
import { tcp } from "@libp2p/tcp";
import { mdns } from "@libp2p/mdns";
import { kadDHT } from "@libp2p/kad-dht";
import { identify } from "@libp2p/identify";
import { gossipsub, type GossipSub } from "@chainsafe/libp2p-gossipsub";
import { multiaddr, type Multiaddr } from "@multiformats/multiaddr";
import { peerIdFromString } from "@libp2p/peer-id";
import type { PeerId, Stream } from "@libp2p/interface";
import { pipe } from "it-pipe";
import * as lp from "it-length-prefixed";
import { fromString as u8FromString, toString as u8ToString } from "uint8arrays";

import type {
  EventHandler,
  MeshTransport,
  MessageSerialized,
  UnicastHandler,
} from "../in-memory-transport.js";
import type { SignedEvent } from "../types.js";
import {
  applyLibp2pConfigDefaults,
  type Libp2pTransportConfig,
} from "./config.js";
import {
  libp2pPrivateKeyFromSanctuarySeed,
  peerIdFromSanctuaryPubkey,
} from "./peer-id.js";
import {
  ALL_STREAM_PROTOCOLS,
  AGENT_STATE_TRANSFER_PROTOCOL,
  SYNC_PROTOCOL,
  UNICAST_PROTOCOL,
  broadcastTopic,
} from "./protocols.js";

/**
 * libp2p service map exposed to application code. Gossipsub is the only
 * service the transport publishes; identify/dht are registered but not
 * surfaced.
 */
interface TransportServices extends Record<string, unknown> {
  pubsub: GossipSub;
  identify: ReturnType<ReturnType<typeof identify>>;
}

/**
 * Constructor arguments. The transport does NOT generate the Ed25519 seed —
 * it is handed the per-node seed unwrapped from the `NodeKeyStore` (Q8
 * cocoon binding) by the lifecycle orchestrator. This keeps key material
 * on one path through the system.
 */
export interface Libp2pMeshTransportParams {
  /** 32-byte Ed25519 private-key seed for this node (matches NodeIdentityCertificate.node_pubkey). */
  ed25519_seed: Uint8Array;
  /** Fortress this transport serves — scopes gossipsub topic names. */
  fortress_id: string;
  /** Operator-facing config (listen addrs, discovery, static peers). */
  config: Libp2pTransportConfig;
}

/**
 * The libp2p MeshTransport.
 *
 * Usage:
 *   const transport = await Libp2pMeshTransport.start(params);
 *   ... hand transport to MeshNode as MeshTransport ...
 *   await transport.stop();
 *
 * The returned object satisfies `MeshTransport` exactly — same broadcast /
 * unicast / subscribe / subscribeUnicast signatures that `InMemoryTransport`
 * ships. Call-site code does not know which transport it has.
 */
export class Libp2pMeshTransport implements MeshTransport {
  private constructor(
    private readonly libp2p: Libp2p<TransportServices>,
    private readonly pubsub: GossipSub,
    private readonly fortressId: string,
    private readonly broadcastHandlers: Set<EventHandler>,
    private readonly unicastHandlers: Set<UnicastHandler>,
    /**
     * Sanctuary node_id (128-bit hex) → libp2p PeerId.
     * Populated by `registerPeer`; looked up during `unicast`.
     */
    private readonly nodeIdToPeerId: Map<string, PeerId>,
    /**
     * Inverse direction for convenience in tests / callers that only know
     * a peer by libp2p id and want the Sanctuary nodeId back.
     */
    private readonly peerIdToNodeId: Map<string, string>
  ) {}

  /**
   * Boot the libp2p stack and start the transport. Listens on the configured
   * multiaddrs, dials static peers, subscribes to the fortress gossipsub
   * topic, registers direct-stream protocol handlers.
   */
  static async start(
    params: Libp2pMeshTransportParams
  ): Promise<Libp2pMeshTransport> {
    const cfg = applyLibp2pConfigDefaults(params.config);
    const privateKey = await libp2pPrivateKeyFromSanctuarySeed(
      params.ed25519_seed
    );

    const broadcastHandlers = new Set<EventHandler>();
    const unicastHandlers = new Set<UnicastHandler>();
    const nodeIdToPeerId = new Map<string, PeerId>();
    const peerIdToNodeId = new Map<string, string>();

    // Build libp2p with our locked stack (§11 picks).
    const services: Record<string, (components: unknown) => unknown> = {
      pubsub: gossipsub({
        // Strict-sign — gossipsub enforces per-message signatures at the libp2p
        // layer, on top of our app-level node_signature. Two defenses.
        emitSelf: false,
        allowPublishToZeroTopicPeers: true,
      }) as unknown as (components: unknown) => unknown,
      identify: identify() as unknown as (components: unknown) => unknown,
    };
    if (cfg.dht) {
      services.dht = kadDHT({
        // v0.1 opt-in. Kademlia is off by default — see config.ts for
        // why (presence leak to the wider swarm).
        clientMode: false,
      }) as unknown as (components: unknown) => unknown;
    }

    const peerDiscovery: Array<(components: unknown) => unknown> = [];
    if (cfg.mdns) {
      peerDiscovery.push(mdns() as unknown as (c: unknown) => unknown);
    }

    // libp2p's createLibp2p has a deeply-generic signature keyed on internal
    // Components types. Our service factory builders (gossipsub/identify/
    // mdns/kadDHT) all satisfy the shape structurally but don't widen cleanly
    // into the generic bound. Cast at the call boundary — the runtime shape
    // is exactly what libp2p expects.
    const node = (await (createLibp2p as unknown as (
      opts: unknown
    ) => Promise<Libp2p<TransportServices>>)({
      privateKey,
      addresses: {
        listen: cfg.listen,
        ...(cfg.announce.length > 0 ? { announce: cfg.announce } : {}),
      },
      transports: [tcp()],
      connectionEncrypters: [noise()],
      streamMuxers: [yamux()],
      peerDiscovery: peerDiscovery.length > 0 ? peerDiscovery : undefined,
      services,
      connectionManager: {
        // The spawn prompt explicitly forbids rate-limiting / flow-control
        // heuristics; the app layer handles refusal. We set very permissive
        // defaults so two pilot nodes on a LAN do not throttle each other.
        maxConnections: 128,
      },
    }));

    const pubsub = node.services.pubsub;
    const topic = broadcastTopic(params.fortress_id);

    // Subscribe to the fortress topic and fan gossipsub messages into the
    // MeshTransport EventHandler callbacks.
    pubsub.subscribe(topic);
    pubsub.addEventListener("message", (evt) => {
      const msg = evt.detail;
      if (msg.topic !== topic) return;
      let parsed: SignedEvent;
      let wire: string;
      try {
        wire = u8ToString(msg.data, "utf8");
        parsed = JSON.parse(wire) as SignedEvent;
      } catch {
        // Malformed wire bytes — gossipsub signature passed but application
        // payload didn't parse. Drop silently; peers sending garbage will be
        // scored down by gossipsub over time.
        return;
      }
      for (const h of broadcastHandlers) {
        try {
          h(parsed, wire);
        } catch {
          // Handlers must be exception-safe; swallow and continue fan-out so
          // one misbehaving handler can't break the others.
        }
      }
    });

    // Register direct-stream handlers for all protocols. Each protocol's
    // inbound stream carries one length-prefixed JSON payload; we pipe it
    // to the unicast handler set.
    const ownNodeIdLookup = (): string => {
      // The transport itself does not know its Sanctuary node_id — the
      // lifecycle orchestrator owns that. For the unicast handler signature
      // (to, message), the receiver side passes its OWN node_id in via the
      // ownNodeIdRef set below, so the handler on the receiver knows "this
      // arrived addressed to me". Until a node_id is registered, falls back
      // to the libp2p peer id as a stable string.
      return ownNodeIdRef.value ?? node.peerId.toString();
    };
    const ownNodeIdRef: { value: string | undefined } = { value: undefined };

    for (const protocol of ALL_STREAM_PROTOCOLS) {
      await node.handle(protocol, async ({ stream }) => {
        try {
          await consumeLengthPrefixedJson(stream, (message) => {
            const addressee = ownNodeIdLookup();
            for (const h of unicastHandlers) {
              try {
                h(addressee, message);
              } catch {
                // Exception-safe fan-out; see broadcast comment above.
              }
            }
          });
        } finally {
          await closeStreamSafe(stream);
        }
      });
    }

    // Dial static peers. Failures are swallowed rather than thrown — a
    // static peer being offline at startup must not prevent the transport
    // from starting for the rest of the mesh. We do however `await` the
    // initial dial attempt so that when a test calls `start()` and the
    // static peers ARE reachable, the peer is already connected on return.
    // This matters for tests that assert on peer state immediately after
    // start; production operators can tolerate the initial dial being
    // async, but it costs nothing to be deterministic here.
    for (const addrStr of cfg.static_peers) {
      let ma: Multiaddr;
      try {
        ma = multiaddr(addrStr);
      } catch {
        continue;
      }
      try {
        await node.dial(ma);
      } catch (e) {
        // Peer not reachable on first attempt — libp2p's connection
        // manager will autodial when it becomes reachable; mdns / dht may
        // also fill in. Do not throw.
        if (process.env.SANCTUARY_LIBP2P_DEBUG === "1") {
          // SAFETY: no structured logger module is wired in server/src/ yet; until one lands, raw stderr is the runtime warning channel for this site.
          console.error(
            `Libp2pMeshTransport: static-peer dial failed: ${addrStr} — ${(e as Error).message}`
          );
        }
      }
    }

    const t = new Libp2pMeshTransport(
      node,
      pubsub,
      params.fortress_id,
      broadcastHandlers,
      unicastHandlers,
      nodeIdToPeerId,
      peerIdToNodeId
    );
    // Expose the ref so `setOwnNodeId` can update the addressee value the
    // unicast handler reads. Ref-in-closure keeps the transport instance
    // immutable post-construction.
    (t as unknown as { _ownNodeIdRef: typeof ownNodeIdRef })._ownNodeIdRef =
      ownNodeIdRef;
    return t;
  }

  /**
   * Declare the Sanctuary node_id this transport instance is serving. The
   * unicast handler reports this id back through the `to` argument of its
   * callback so the MeshNode's existing "is this addressed to me?" filter
   * (see mesh-node.ts:188) works identically to the in-memory case.
   */
  setOwnNodeId(nodeId: string): void {
    const ref = (this as unknown as {
      _ownNodeIdRef: { value: string | undefined };
    })._ownNodeIdRef;
    ref.value = nodeId;
  }

  /**
   * Register a Sanctuary node_id → Ed25519-pubkey mapping so `unicast(nodeId, ...)`
   * can resolve the libp2p peer to dial. Called by the lifecycle orchestrator
   * whenever a NodeIdentityCertificate is accepted into the roster.
   *
   * @param nodeId          Sanctuary 128-bit node_id (hex).
   * @param pubkeyBase64url Ed25519 public key from the node-identity-cert.
   * @param multiaddrs      Optional pre-known multiaddrs for dial-hint; the
   *                        transport adds them to the libp2p peerStore.
   */
  async registerPeer(
    nodeId: string,
    pubkeyBase64url: string,
    multiaddrs: string[] = []
  ): Promise<void> {
    const peerId = peerIdFromSanctuaryPubkey(pubkeyBase64url);
    this.nodeIdToPeerId.set(nodeId, peerId);
    this.peerIdToNodeId.set(peerId.toString(), nodeId);
    if (multiaddrs.length > 0) {
      const mas: Multiaddr[] = [];
      for (const s of multiaddrs) {
        try {
          mas.push(multiaddr(s));
        } catch {
          // Skip bad multiaddrs; we already have peer-id pinning so an
          // unreachable address is at worst a slow-dial, not a security issue.
        }
      }
      if (mas.length > 0) {
        await this.libp2p.peerStore.merge(peerId, { multiaddrs: mas });
      }
    }
  }

  /**
   * Return the libp2p peer-id this transport presents during Noise handshake.
   * Useful for tests (assert peer-id matches pubkey) and for assembling the
   * static-peer multiaddr strings operators hand to each other.
   */
  peerId(): PeerId {
    return this.libp2p.peerId;
  }

  /**
   * Return all multiaddrs this node is listening on. Callers build the
   * static-peer string by appending `/p2p/<peer-id>`.
   */
  listenAddresses(): Multiaddr[] {
    return this.libp2p.getMultiaddrs();
  }

  // ═══════════════════════════════════════════════════════════════════════
  // MeshTransport contract
  // ═══════════════════════════════════════════════════════════════════════

  async broadcast(evt: SignedEvent): Promise<void> {
    // Defense-in-depth: refuse to fan out a payload that lacks a node_signature.
    // This catches programmer errors more than attacks (spec already requires
    // signature at packSignedEvent time), but the cost is ~zero.
    if (!evt.node_signature) {
      throw new Error(
        "Libp2pMeshTransport.broadcast: refuses to publish unsigned SignedEvent"
      );
    }
    const topic = broadcastTopic(this.fortressId);
    const bytes = u8FromString(JSON.stringify(evt), "utf8");
    await this.pubsub.publish(topic, bytes);
  }

  async unicast(
    toNodeId: string,
    message: MessageSerialized
  ): Promise<void> {
    const peerId = this.nodeIdToPeerId.get(toNodeId);
    if (!peerId) {
      throw new Error(
        `Libp2pMeshTransport.unicast: unknown target node_id ${toNodeId} — call registerPeer first`
      );
    }
    const protocol = selectStreamProtocol(message);
    const stream = await this.libp2p.dialProtocol(peerId, protocol);
    try {
      await sendLengthPrefixedJson(stream, message);
    } finally {
      await closeStreamSafe(stream);
    }
  }

  subscribe(handler: EventHandler): () => void {
    this.broadcastHandlers.add(handler);
    return () => this.broadcastHandlers.delete(handler);
  }

  subscribeUnicast(handler: UnicastHandler): () => void {
    this.unicastHandlers.add(handler);
    return () => this.unicastHandlers.delete(handler);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Lifecycle
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Stop the libp2p stack. Idempotent — calling twice is safe.
   */
  async stop(): Promise<void> {
    try {
      await this.libp2p.stop();
    } catch {
      // Best-effort shutdown — some libp2p teardown paths throw on already-
      // stopped transports; absorbing is safer than letting a shutdown
      // error mask a real test failure.
    }
  }

  /**
   * Low-level escape hatch. Tests use this to assert on peer-count,
   * connection state, dial against a multiaddr. Production code should
   * not reach into the underlying libp2p.
   */
  _libp2p(): Libp2p<TransportServices> {
    return this.libp2p;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════════

/**
 * Pick the stream protocol for a given unicast payload.
 *
 * The current MeshTransport contract (in-memory-transport.ts) makes unicast
 * a generic string channel; application code discriminates by parsing the
 * JSON envelope's `kind` field. We mirror that by sniffing the envelope
 * shape here so sync and agent-state-transfer ride their dedicated
 * protocols (enables separate flow-control + per-protocol rate limits at
 * v1.x without touching the transport surface).
 */
function selectStreamProtocol(message: MessageSerialized): string {
  try {
    const parsed = JSON.parse(message) as { kind?: string };
    if (parsed.kind === "agent_state_transfer") {
      return AGENT_STATE_TRANSFER_PROTOCOL;
    }
    if (
      parsed.kind === "policy_bundle" ||
      parsed.kind === "locator_table" ||
      parsed.kind === "audit_range"
    ) {
      return SYNC_PROTOCOL;
    }
  } catch {
    // Non-JSON or unexpected shape — fall through to the generic unicast.
  }
  return UNICAST_PROTOCOL;
}

/**
 * Send a single length-prefixed JSON frame and half-close write.
 */
async function sendLengthPrefixedJson(
  stream: Stream,
  json: string
): Promise<void> {
  const bytes = u8FromString(json, "utf8");
  await pipe(
    (async function* () {
      yield bytes;
    })(),
    (source) => lp.encode(source),
    stream.sink
  );
}

/**
 * Read all length-prefixed frames off a stream, calling `onMessage` for each.
 * For our usage, there is exactly one message per stream (unicast is
 * message-oriented), but the decoder is length-prefixed so future v1.x
 * multi-message streams work without re-handshaking.
 */
async function consumeLengthPrefixedJson(
  stream: Stream,
  onMessage: (message: string) => void
): Promise<void> {
  await pipe(stream.source, (source) => lp.decode(source), async (source) => {
    for await (const frame of source) {
      const bytes = frame.subarray();
      const text = u8ToString(bytes, "utf8");
      onMessage(text);
    }
  });
}

async function closeStreamSafe(stream: Stream): Promise<void> {
  try {
    await stream.close();
  } catch {
    // Already-closed / reset streams throw on close; swallowing is safe —
    // the libp2p muxer guarantees resource reclamation regardless.
  }
}

// Keep the symbol referenced for typecheck users who import from the barrel;
// it is not otherwise called here but provides the direct-stream protocol
// constants at public API level.
export { peerIdFromString };
