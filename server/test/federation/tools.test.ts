/**
 * Federation Tools tests
 *
 * Covers: list/register/remove peers, handshake verification gate,
 * trust evaluation, federation status aggregation.
 * Not covered: real handshake protocol, network I/O.
 */

import { describe, it, expect } from "vitest";
import { createFederationTools } from "../../src/federation/tools.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import type { HandshakeResult } from "../../src/handshake/types.js";

function setup() {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  const handshakeResults = new Map<string, HandshakeResult>();
  const { tools, registry } = createFederationTools(auditLog, handshakeResults);
  const findTool = (name: string) => tools.find(t => t.name === name)!;
  return { tools, registry, handshakeResults, findTool };
}

function makeHandshakeResult(peerId: string, verified: boolean): HandshakeResult {
  return {
    peer_id: peerId,
    verified,
    peer_public_key: "mock-pk",
    sovereignty_level: verified ? "full" : "minimal",
    completed_at: new Date().toISOString(),
    shr: null as any,
  } as HandshakeResult;
}

describe("Federation Tools", () => {
  describe("federation_peers — list", () => {
    it("returns empty list initially", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({ action: "list" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.peers).toEqual([]);
      expect(parsed.total).toBe(0);
    });
  });

  describe("federation_peers — register", () => {
    it("requires peer_id and peer_did", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({ action: "register" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBeDefined();
    });

    it("rejects if no completed handshake", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: "unknown-peer",
        peer_did: "did:key:xyz",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toContain("No completed handshake");
    });

    it("rejects unverified handshake", async () => {
      const { findTool, handshakeResults } = setup();
      handshakeResults.set("peer-1", makeHandshakeResult("peer-1", false));

      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: "peer-1",
        peer_did: "did:key:abc",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toContain("not verified");
    });

    it("registers peer with verified handshake", async () => {
      const { findTool, handshakeResults } = setup();
      handshakeResults.set("peer-1", makeHandshakeResult("peer-1", true));

      const result = await findTool("federation_peers").handler({
        action: "register",
        peer_id: "peer-1",
        peer_did: "did:key:abc",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.registered).toBe(true);
    });
  });

  describe("federation_peers — remove", () => {
    it("requires peer_id", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({ action: "remove" });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.error).toBeDefined();
    });

    it("returns removed: false for unknown peer", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_peers").handler({
        action: "remove",
        peer_id: "nonexistent",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.removed).toBe(false);
    });
  });

  describe("federation_status", () => {
    it("returns summary with zero peers", async () => {
      const { findTool } = setup();
      const result = await findTool("federation_status").handler({});
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.total_peers).toBe(0);
      expect(parsed.federation_ready).toBe(false);
    });
  });

  describe("federation_trust_evaluate", () => {
    it("evaluates trust for a peer", async () => {
      const { findTool, handshakeResults } = setup();
      handshakeResults.set("peer-1", makeHandshakeResult("peer-1", true));

      // Register the peer first
      await findTool("federation_peers").handler({
        action: "register",
        peer_id: "peer-1",
        peer_did: "did:key:abc",
      });

      const result = await findTool("federation_trust_evaluate").handler({
        peer_id: "peer-1",
      });
      const parsed = JSON.parse(result.content[0].text);
      expect(parsed.trust_level).toBeDefined();
    });
  });
});
