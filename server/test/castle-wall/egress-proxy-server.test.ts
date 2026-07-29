/**
 * Integration test for the Castle Wall egress proxy server.
 *
 * Tests the full HTTP CONNECT flow through the running server, simulating
 * what the vsock egress bridge does: make a TCP connection to the proxy
 * and send HTTP CONNECT requests.
 *
 * The VM/vsock boundary is mocked — the test connects directly via TCP
 * (exactly as the bridge's connectToProxy() does).
 */
import http from "node:http";
import net from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { CASTLE_WALL_SCHEMA_VERSION_V1 } from "../../src/castle-wall/constants.js";
import {
  createCastleWallEgressProxyServer,
  type EgressProxyDecision,
} from "../../src/castle-wall/egress-proxy.js";
import type { AllowlistRule } from "../../src/castle-wall/allowlist/schema.js";

const ALLOWED_HOST = "allowed.test";
const DENIED_HOST = "denied.test";
const UPSTREAM_PORT_PLACEHOLDER = 9999;

function makeRule(host: string, port: number): AllowlistRule {
  return {
    id: `rule-${host}`,
    schema_version: CASTLE_WALL_SCHEMA_VERSION_V1,
    created_at: new Date().toISOString(),
    match: { host, port, protocol: "tcp" },
    scope: {},
    disposition: "allow",
  };
}

function connectAndSend(
  proxyPort: number,
  authority: string,
): Promise<{ statusCode: number; statusMessage: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(proxyPort, "127.0.0.1", () => {
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`,
      );
    });
    let response = "";
    socket.on("data", (chunk) => {
      response += chunk.toString();
      // Parse the first line of the HTTP response
      const firstLine = response.split("\r\n")[0];
      if (firstLine) {
        const parts = firstLine.split(" ");
        const statusCode = parseInt(parts[1] ?? "0", 10);
        const statusMessage = parts.slice(2).join(" ");
        socket.destroy();
        resolve({ statusCode, statusMessage });
      }
    });
    socket.on("error", reject);
    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error("timeout"));
    });
  });
}

describe("castle-wall/egress-proxy server integration", () => {
  let proxyServer: http.Server;
  let proxyPort: number;
  let upstreamServer: net.Server;
  let upstreamPort: number;
  const decisions: Array<{ authority: string; decision: EgressProxyDecision }> =
    [];

  beforeAll(async () => {
    // Start a local TCP echo server as the "upstream" destination.
    upstreamServer = net.createServer((socket) => {
      socket.pipe(socket);
    });
    await new Promise<void>((resolve) => {
      upstreamServer.listen(0, "127.0.0.1", () => resolve());
    });
    const upstreamAddr = upstreamServer.address() as net.AddressInfo;
    upstreamPort = upstreamAddr.port;

    // Start the egress proxy with:
    //   - Allow allowed.test:<upstreamPort>
    //   - Deny everything else
    //   - Resolver returns 127.0.0.1 for allowed.test (local upstream)
    //   - isRoutable override to accept 127.0.0.1 (testing only)
    proxyServer = createCastleWallEgressProxyServer({
      rules: [makeRule(ALLOWED_HOST, upstreamPort)],
      resolver: {
        async resolve(): Promise<string[]> {
          return ["127.0.0.1"];
        },
      },
      isRoutable: () => true,
      onDecision: (authority, decision) => {
        decisions.push({ authority, decision });
      },
    });

    await new Promise<void>((resolve) => {
      proxyServer.listen(0, "127.0.0.1", () => resolve());
    });
    const proxyAddr = proxyServer.address() as net.AddressInfo;
    proxyPort = proxyAddr.port;
  });

  afterAll(async () => {
    proxyServer?.close();
    upstreamServer?.close();
  });

  it("blocks a DENIED host with 403", async () => {
    const result = await connectAndSend(
      proxyPort,
      `${DENIED_HOST}:${UPSTREAM_PORT_PLACEHOLDER}`,
    );
    expect(result.statusCode).toBe(403);
  });

  it("allows an ALLOWED host and pipes to upstream (200)", async () => {
    const result = await connectAndSend(
      proxyPort,
      `${ALLOWED_HOST}:${upstreamPort}`,
    );
    expect(result.statusCode).toBe(200);
  });

  it("logs decisions via onDecision callback", () => {
    // The two tests above should have logged decisions
    const denied = decisions.find(
      (d) => d.decision.disposition === "deny",
    );
    const allowed = decisions.find(
      (d) => d.decision.disposition === "allow",
    );
    expect(denied).toBeDefined();
    expect(allowed).toBeDefined();
    expect(denied!.decision.disposition).toBe("deny");
    expect(allowed!.decision.disposition).toBe("allow");
  });

  it("blocks a host allowed on the wrong port with 403", async () => {
    const result = await connectAndSend(
      proxyPort,
      `${ALLOWED_HOST}:443`,
    );
    expect(result.statusCode).toBe(403);
  });

  it("survives a client reset during the async decision window (no process-killing uncaughtException)", async () => {
    // Regression (same hazard and fix as egress-gate/gate-server): the party
    // on the client socket can RST while decideEgressProxyConnect performs
    // DNS resolution; a listener-less 'error' event would crash the whole
    // proxy process. A dedicated server with a slow resolver widens the
    // decision window deterministically.
    const slowServer = createCastleWallEgressProxyServer({
      rules: [makeRule(ALLOWED_HOST, upstreamPort)],
      resolver: {
        resolve: () =>
          new Promise<string[]>((resolve) =>
            setTimeout(() => resolve(["127.0.0.1"]), 150),
          ),
      },
      isRoutable: () => true,
    });
    await new Promise<void>((resolve) => {
      slowServer.listen(0, "127.0.0.1", () => resolve());
    });
    const slowPort = (slowServer.address() as net.AddressInfo).port;
    try {
      await new Promise<void>((resolve) => {
        const socket = net.connect(slowPort, "127.0.0.1", () => {
          socket.write(
            `CONNECT ${ALLOWED_HOST}:${upstreamPort} HTTP/1.1\r\nHost: x\r\n\r\n`,
          );
          setTimeout(() => {
            socket.resetAndDestroy();
            resolve();
          }, 50);
        });
        socket.on("error", () => {});
      });
      // Let the in-flight handler run past the await with the dead client.
      await new Promise((r) => setTimeout(r, 300));
      // The proxy survived: a fresh CONNECT still tunnels.
      const result = await connectAndSend(
        slowPort,
        `${ALLOWED_HOST}:${upstreamPort}`,
      );
      expect(result.statusCode).toBe(200);
    } finally {
      await new Promise<void>((r) => slowServer.close(() => r()));
    }
  });
});
