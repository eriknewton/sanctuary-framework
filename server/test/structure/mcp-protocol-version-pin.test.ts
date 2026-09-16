// fail-before-exempt: forward drift guard, not a fix verification — the negotiated protocolVersion is already correct today and there is no defect commit to diff against; the assertion exists so a future SDK bump is loud instead of silent (2026-09-15 MCP drift audit).

/**
 * MCP protocol version pin (2026-09-15 MCP drift audit).
 *
 * Sanctuary's src/router.ts never sets `protocolVersion` itself — the MCP
 * SDK's Server/Client negotiate it from `LATEST_PROTOCOL_VERSION`, a
 * constant that lives inside @modelcontextprotocol/sdk. This test starts
 * the real, shipped `createServer()` in-process, connects it to a real SDK
 * `Client` over a linked in-memory transport pair (the same construction
 * test/principal-policy/router-gate-denial-opacity.test.ts uses), and
 * asserts the version the two sides actually negotiate over the wire — not
 * a value read out of Sanctuary source.
 */
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { LATEST_PROTOCOL_VERSION } from "@modelcontextprotocol/sdk/types.js";
import { createServer } from "../../src/router.js";

describe("MCP protocol version pin", () => {
  it("negotiates the pinned protocolVersion against the shipped in-process server", async () => {
    const server = createServer([]);
    const client = new Client({
      name: "protocol-version-pin-test",
      version: "1.0.0",
    });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    // The SDK Client's connect() negotiates protocolVersion internally but
    // discards it once connect() returns — it stores serverCapabilities and
    // serverVersion, not the version string itself — so it is captured here
    // off the wire instead: the actual JSON-RPC initialize response the
    // shipped server transport sends back.
    let negotiatedProtocolVersion: string | undefined;
    const originalSend = serverTransport.send.bind(serverTransport);
    serverTransport.send = async (message, options) => {
      const result = (message as { result?: unknown }).result;
      if (result && typeof result === "object" && "protocolVersion" in result) {
        negotiatedProtocolVersion = (
          result as { protocolVersion: string }
        ).protocolVersion;
      }
      return originalSend(message, options);
    };

    await server.connect(serverTransport);
    await client.connect(clientTransport);

    // The advertised revision comes from @modelcontextprotocol/sdk's
    // LATEST_PROTOCOL_VERSION, not from Sanctuary code; a silent SDK bump
    // would change what every client negotiates with nothing failing, so
    // the pin is here (2026-09-15 MCP drift audit).
    expect(negotiatedProtocolVersion).toBe("2025-11-25");
    expect(LATEST_PROTOCOL_VERSION).toBe("2025-11-25");

    await client.close();
    await server.close();
  });
});
