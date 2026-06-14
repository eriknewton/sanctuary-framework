import { describe, it, expect, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { Libp2pMeshTransport } from "../../src/mesh/libp2p-transport/index.js";

/**
 * Regression coverage for the kad-dht v15 -> v16 upgrade (CVE GHSA-32mq-hpph-xfvr).
 *
 * kad-dht@16 split @libp2p/ping out into a required service capability. Before
 * the fix, a node started with `dht: true` threw at startup:
 *   UnmetServiceDependenciesError: Service "@libp2p/kad-dht" required
 *   capability "@libp2p/ping" but it was not provided by any component.
 *
 * The existing libp2p-transport suite only ever starts nodes with `dht: false`
 * (the shipped default), so this break was invisible to it. This test exercises
 * the opt-in DHT path explicitly so a future kad-dht bump that re-breaks the
 * service wiring fails loudly.
 */
const toStop: Libp2pMeshTransport[] = [];
afterEach(async () => {
  for (const t of toStop.splice(0)) {
    try {
      await t.stop();
    } catch {
      // ignore teardown errors
    }
  }
});

describe("libp2p-transport: dht-enabled startup", () => {
  it("starts and stops a node with the Kademlia DHT enabled (server mode)", async () => {
    const seed = randomBytes(32);
    const transport = await Libp2pMeshTransport.start({
      ed25519_seed: seed,
      fortress_id: "dht-startup-fortress",
      config: {
        listen: ["/ip4/127.0.0.1/tcp/0"],
        mdns: false,
        dht: true,
        static_peers: [],
      },
    });
    toStop.push(transport);
    expect(transport).toBeDefined();

    // Clean stop must also succeed with the DHT + ping services wired in.
    await transport.stop();
    toStop.pop();
  });
});
