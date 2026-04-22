/**
 * Sanctuary Federation Protocol v0.1 — libp2p Transport Configuration.
 *
 * Spec: Review/Sanctuary/Federation_Protocol_V0.1_Spec_2026-04-21.md (§2 transport keys,
 * §4 message classes, §11 libp2p stack pick).
 * Spawn prompt: Review/Sanctuary/WP_MVP_3_Followup_2_Libp2p_Adapter_Spawn_Prompt_2026-04-21.md
 *
 * No secret material belongs here. Per-node Ed25519 private keys live in the
 * NodeKeyStore (cocoon-wrapped); this config only references listen/static-peer
 * multiaddrs and discovery toggles.
 */

/**
 * Minimal configuration for the libp2p adapter. A sovereign operator edits this
 * in their fortress config directory; the lifecycle orchestrator passes it in
 * at MeshNode construction.
 */
export interface Libp2pTransportConfig {
  /**
   * Multiaddrs this node listens on.
   * Common shapes:
   *   - "/ip4/0.0.0.0/tcp/0" — let the kernel pick a port (tests, mDNS LAN)
   *   - "/ip4/0.0.0.0/tcp/4001" — pinned port (production static-peer mesh)
   *
   * Omit or pass [] to run a transport that only dials outbound (not recommended
   * for a mesh node; an always-dialer can never receive gossipsub fan-out).
   */
  listen: string[];

  /**
   * Operator-configured static peers — the always-works fallback and the only
   * thing a paranoid operator uses. Format: full libp2p multiaddr with
   * /p2p/<peer-id> suffix, so the transport can enforce peer-id pinning
   * pre-handshake. Example:
   *   "/ip4/10.0.0.7/tcp/4001/p2p/12D3KooW..."
   *
   * Empty by default; mDNS + DHT handle discovery if enabled.
   */
  static_peers?: string[];

  /**
   * Enable mDNS peer discovery on the local network.
   *
   * mDNS is explicitly LAN-only — it will never discover peers across the
   * internet. Safe default for single-fortress / Drew's office. Set false for
   * internet-only fortresses where mDNS traffic is noise.
   *
   * Default: true.
   */
  mdns?: boolean;

  /**
   * Enable Kademlia DHT peer discovery + content routing.
   *
   * Kademlia supports internet-scale mesh. Disable for air-gapped or
   * single-LAN deployments where the DHT chatter is wasted bandwidth.
   *
   * Default: false (opt-in — Drew's pilot will be LAN-mDNS, and DHT exposes
   * presence metadata the paranoid operator may not want on the wire).
   */
  dht?: boolean;

  /**
   * Announce multiaddrs this node advertises to peers for dial-back. Useful
   * when running behind a NAT or a known public IP but listening on 0.0.0.0.
   * Optional — libp2p infers from listen addresses when empty.
   */
  announce?: string[];
}

/**
 * Defaults applied to a partial config. Splat a user-supplied config over this
 * to get the runtime shape.
 */
export const LIBP2P_TRANSPORT_DEFAULTS: Required<
  Pick<Libp2pTransportConfig, "mdns" | "dht" | "static_peers" | "announce">
> = {
  mdns: true,
  dht: false,
  static_peers: [],
  announce: [],
};

export function applyLibp2pConfigDefaults(
  input: Libp2pTransportConfig
): Required<Libp2pTransportConfig> {
  return {
    listen: input.listen ?? [],
    static_peers: input.static_peers ?? LIBP2P_TRANSPORT_DEFAULTS.static_peers,
    mdns: input.mdns ?? LIBP2P_TRANSPORT_DEFAULTS.mdns,
    dht: input.dht ?? LIBP2P_TRANSPORT_DEFAULTS.dht,
    announce: input.announce ?? LIBP2P_TRANSPORT_DEFAULTS.announce,
  };
}
