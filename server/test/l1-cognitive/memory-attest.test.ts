/**
 * Memory Attestation — Tests
 *
 * Tests for the memory_attest tool: Ed25519-signed attestations
 * for memory operations across any MCP-compatible memory provider.
 */

import { describe, it, expect, beforeEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, verify } from "../../src/core/identity.js";
import { fromBase64url, stringToBytes, toBase64url } from "../../src/core/encoding.js";
import { hash, hashToString } from "../../src/core/hashing.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { IdentityManager } from "../../src/l1-cognitive/tools.js";
import { createMemoryAttestTools } from "../../src/l1-cognitive/memory-attest.js";
import type { ToolDefinition } from "../../src/router.js";

// ─── Test Helpers ────────────────────────────────────────────────────────

function parseResult(result: { content: Array<{ type: string; text: string }> }): Record<string, unknown> {
  return JSON.parse(result.content[0]!.text);
}

// ─── Tests ───────────────────────────────────────────────────────────────

describe("memory_attest tool", () => {
  let masterKey: Uint8Array;
  let storage: MemoryStorage;
  let identityManager: IdentityManager;
  let auditLog: AuditLog;
  let tool: ToolDefinition;

  beforeEach(async () => {
    masterKey = generateRandomKey(32);
    storage = new MemoryStorage();
    identityManager = new IdentityManager(storage, masterKey);
    auditLog = new AuditLog(storage, masterKey);

    // Create and save a default identity
    const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
    const { storedIdentity } = createIdentity("test-agent", identityEncKey, "passphrase");
    await identityManager.save(storedIdentity);

    // Create tool
    const { tools } = createMemoryAttestTools(identityManager, masterKey, auditLog);
    tool = tools[0]!;
  });

  it("has correct name and schema", () => {
    expect(tool.name).toBe("memory_attest");
    expect(tool.inputSchema.required).toEqual(["operation", "provider", "content_hash"]);
  });

  // ── Happy Path ───────────────────────────────────────────────────────

  describe("store operation", () => {
    it("creates a signed attestation for a store operation", async () => {
      const contentHash = hashToString(stringToBytes("test memory content"));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const parsed = parseResult(result);
      expect(parsed.attestation_id).toBeDefined();
      expect(parsed.signature).toBeDefined();
      expect(parsed.public_key).toBeDefined();
      expect(parsed.payload).toBeDefined();

      const payload = parsed.payload as Record<string, unknown>;
      expect(payload.version).toBe(1);
      expect(payload.operation).toBe("store");
      expect(payload.provider).toBe("mem0");
      expect(payload.content_hash).toBe(contentHash);
      expect(payload.timestamp).toBeDefined();
      expect(payload.identity_id).toBeDefined();
      expect(payload.identity_did).toMatch(/^did:key:/);
    });
  });

  describe("all valid operations", () => {
    it.each(["store", "retrieve", "update", "delete", "search"] as const)(
      "accepts '%s' operation",
      async (operation) => {
        const contentHash = hashToString(stringToBytes(`content-${operation}`));

        const result = await tool.handler({
          operation,
          provider: "mem0",
          content_hash: contentHash,
        });

        const parsed = parseResult(result);
        expect(parsed.attestation_id).toBeDefined();
        const payload = parsed.payload as Record<string, unknown>;
        expect(payload.operation).toBe(operation);
      }
    );
  });

  // ── Signature Verification ───────────────────────────────────────────

  describe("Ed25519 signature", () => {
    it("produces a verifiable signature over the payload", async () => {
      const contentHash = hashToString(stringToBytes("verifiable content"));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const parsed = parseResult(result);
      const payloadBytes = stringToBytes(JSON.stringify(parsed.payload));
      const signature = fromBase64url(parsed.signature as string);
      const publicKey = fromBase64url(parsed.public_key as string);

      const isValid = verify(payloadBytes, signature, publicKey);
      expect(isValid).toBe(true);
    });

    it("signature fails if payload is tampered", async () => {
      const contentHash = hashToString(stringToBytes("tamper test"));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const parsed = parseResult(result);
      const tamperedPayload = { ...(parsed.payload as Record<string, unknown>), operation: "delete" };
      const payloadBytes = stringToBytes(JSON.stringify(tamperedPayload));
      const signature = fromBase64url(parsed.signature as string);
      const publicKey = fromBase64url(parsed.public_key as string);

      const isValid = verify(payloadBytes, signature, publicKey);
      expect(isValid).toBe(false);
    });
  });

  // ── Content Hash (not content) ───────────────────────────────────────

  describe("content hash privacy", () => {
    it("stores content hash, never raw content", async () => {
      const rawContent = "sensitive memory: my social security number is 123-45-6789";
      const contentHash = hashToString(stringToBytes(rawContent));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const resultText = result.content[0]!.text;
      // Raw content must never appear in the attestation
      expect(resultText).not.toContain("sensitive memory");
      expect(resultText).not.toContain("123-45-6789");
      // But the hash should be present
      expect(resultText).toContain(contentHash);
    });
  });

  // ── Metadata ─────────────────────────────────────────────────────────

  describe("optional metadata", () => {
    it("includes metadata when provided", async () => {
      const contentHash = hashToString(stringToBytes("metadata test"));

      const result = await tool.handler({
        operation: "retrieve",
        provider: "zep",
        content_hash: contentHash,
        memory_id: "mem-12345",
        user_id: "erik-newton",
        agent_id: "newton-agent",
        session_id: "session-abc",
        scope: "user",
      });

      const parsed = parseResult(result);
      const payload = parsed.payload as Record<string, unknown>;
      expect(payload.memory_id).toBe("mem-12345");
      expect(payload.provider).toBe("zep");

      const metadata = payload.metadata as Record<string, unknown>;
      expect(metadata.user_id).toBe("erik-newton");
      expect(metadata.agent_id).toBe("newton-agent");
      expect(metadata.session_id).toBe("session-abc");
      expect(metadata.scope).toBe("user");
    });

    it("omits metadata fields not provided", async () => {
      const contentHash = hashToString(stringToBytes("minimal test"));

      const result = await tool.handler({
        operation: "search",
        provider: "letta",
        content_hash: contentHash,
      });

      const parsed = parseResult(result);
      const payload = parsed.payload as Record<string, unknown>;
      const metadata = payload.metadata as Record<string, unknown>;
      expect(metadata.user_id).toBeUndefined();
      expect(metadata.agent_id).toBeUndefined();
      expect(metadata.session_id).toBeUndefined();
      expect(metadata.scope).toBeUndefined();
    });
  });

  // ── Audit Trail ──────────────────────────────────────────────────────

  describe("audit logging", () => {
    it("creates an audit entry for each attestation", async () => {
      const contentHash = hashToString(stringToBytes("audit test"));

      await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const { entries } = await auditLog.query({});
      const memoryEntries = entries.filter((e) => e.operation === "memory_store");
      expect(memoryEntries.length).toBe(1);
      expect(memoryEntries[0]!.layer).toBe("l1");
      expect(memoryEntries[0]!.result).toBe("success");
      expect(memoryEntries[0]!.details).toMatchObject({
        provider: "mem0",
        content_hash: contentHash,
      });
    });

    it("uses the correct operation name in audit", async () => {
      const contentHash = hashToString(stringToBytes("delete audit"));

      await tool.handler({
        operation: "delete",
        provider: "mem0",
        content_hash: contentHash,
      });

      const { entries } = await auditLog.query({});
      const deleteEntries = entries.filter((e) => e.operation === "memory_delete");
      expect(deleteEntries.length).toBe(1);
    });
  });

  // ── Deterministic Attestation ID ─────────────────────────────────────

  describe("attestation ID", () => {
    it("generates a non-empty attestation ID", async () => {
      const contentHash = hashToString(stringToBytes("id test"));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const parsed = parseResult(result);
      expect(typeof parsed.attestation_id).toBe("string");
      expect((parsed.attestation_id as string).length).toBeGreaterThan(0);
    });
  });

  // ── Provider Agnosticism ─────────────────────────────────────────────

  describe("provider agnosticism", () => {
    it.each(["mem0", "zep", "letta", "graphiti", "custom-provider"])(
      "works with provider '%s'",
      async (provider) => {
        const contentHash = hashToString(stringToBytes(`${provider} content`));

        const result = await tool.handler({
          operation: "store",
          provider,
          content_hash: contentHash,
        });

        const parsed = parseResult(result);
        const payload = parsed.payload as Record<string, unknown>;
        expect(payload.provider).toBe(provider);
      }
    );
  });

  // ── Validation ───────────────────────────────────────────────────────

  describe("input validation", () => {
    it("rejects invalid operation", async () => {
      const result = await tool.handler({
        operation: "invalid_op",
        provider: "mem0",
        content_hash: "abc123",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("Invalid operation");
    });

    it("rejects empty provider", async () => {
      const result = await tool.handler({
        operation: "store",
        provider: "",
        content_hash: "abc123",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("Provider name is required");
    });

    it("rejects provider exceeding 128 chars", async () => {
      const result = await tool.handler({
        operation: "store",
        provider: "a".repeat(129),
        content_hash: "abc123",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("128 character limit");
    });

    it("rejects empty content hash", async () => {
      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: "",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("Content hash is required");
    });

    it("rejects content hash exceeding 128 chars", async () => {
      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: "a".repeat(129),
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("128 character limit");
    });

    it("rejects invalid scope", async () => {
      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: "abc123",
        scope: "invalid_scope",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("Invalid scope");
    });

    it("rejects when no identity exists", async () => {
      // Create a fresh manager with no identities
      const freshManager = new IdentityManager(new MemoryStorage(), masterKey);
      await freshManager.load();
      const { tools } = createMemoryAttestTools(freshManager, masterKey, auditLog);
      const freshTool = tools[0]!;

      const result = await freshTool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: "abc123",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("No default identity");
    });

    it("rejects when specified identity_id not found", async () => {
      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: "abc123",
        identity_id: "nonexistent-identity",
      });

      const parsed = parseResult(result);
      expect(parsed.error).toContain("Identity not found");
    });
  });

  // ── Multi-identity ───────────────────────────────────────────────────

  describe("identity selection", () => {
    it("uses primary identity by default", async () => {
      const contentHash = hashToString(stringToBytes("default identity"));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
      });

      const parsed = parseResult(result);
      const payload = parsed.payload as Record<string, unknown>;
      const defaultIdentity = identityManager.getDefault();
      expect(payload.identity_id).toBe(defaultIdentity!.identity_id);
    });

    it("uses specified identity when identity_id provided", async () => {
      // Create a second identity
      const identityEncKey = derivePurposeKey(masterKey, "identity-encryption");
      const { storedIdentity: secondIdentity } = createIdentity(
        "second-agent",
        identityEncKey,
        "passphrase"
      );
      await identityManager.save(secondIdentity);

      const contentHash = hashToString(stringToBytes("specific identity"));

      const result = await tool.handler({
        operation: "store",
        provider: "mem0",
        content_hash: contentHash,
        identity_id: secondIdentity.identity_id,
      });

      const parsed = parseResult(result);
      const payload = parsed.payload as Record<string, unknown>;
      expect(payload.identity_id).toBe(secondIdentity.identity_id);
      expect(parsed.public_key).toBe(secondIdentity.public_key);
    });
  });

  // ── Scope Validation ─────────────────────────────────────────────────

  describe("valid scopes", () => {
    it.each(["user", "agent", "session", "app"] as const)(
      "accepts scope '%s'",
      async (scope) => {
        const contentHash = hashToString(stringToBytes(`scope-${scope}`));

        const result = await tool.handler({
          operation: "store",
          provider: "mem0",
          content_hash: contentHash,
          scope,
        });

        const parsed = parseResult(result);
        const payload = parsed.payload as Record<string, unknown>;
        const metadata = payload.metadata as Record<string, unknown>;
        expect(metadata.scope).toBe(scope);
      }
    );
  });
});
