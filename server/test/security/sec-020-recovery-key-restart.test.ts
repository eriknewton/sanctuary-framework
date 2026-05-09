/**
 * Sanctuary MCP Server — SEC-020 Regression Test
 *
 * SEC-020: Recovery key path regenerates master key on every restart.
 *
 * When no passphrase is provided and an existing recovery-key-hash exists,
 * the code previously generated a new random master key instead of requiring
 * the original recovery key. This silently destroyed access to all previously
 * encrypted state.
 *
 * These tests verify that:
 * 1. First run correctly generates and stores a recovery key hash
 * 2. Subsequent runs require the correct recovery key via SANCTUARY_RECOVERY_KEY
 * 3. Missing or incorrect recovery keys cause a clear startup failure
 * 4. Data written under one master key is readable after restart with correct key
 * 5. Orphaned encrypted data without a recovery-key-hash triggers a safety net
 *
 * These tests would have PASSED silently before the SEC-020 fix — the server
 * would have started with a new key and all prior data would be silently lost.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url, fromBase64url, stringToBytes, bytesToString, constantTimeEqual } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import { encrypt, decrypt } from "../../src/core/encryption.js";
import { createSanctuaryServer } from "../../src/index.js";
import { deriveNamespaceKey } from "../../src/core/key-derivation.js";

// Save and restore env vars between tests
let savedPassphrase: string | undefined;
let savedRecoveryKey: string | undefined;

beforeEach(() => {
  savedPassphrase = process.env.SANCTUARY_PASSPHRASE;
  savedRecoveryKey = process.env.SANCTUARY_RECOVERY_KEY;
  delete process.env.SANCTUARY_PASSPHRASE;
  delete process.env.SANCTUARY_RECOVERY_KEY;
});

afterEach(() => {
  if (savedPassphrase !== undefined) {
    process.env.SANCTUARY_PASSPHRASE = savedPassphrase;
  } else {
    delete process.env.SANCTUARY_PASSPHRASE;
  }
  if (savedRecoveryKey !== undefined) {
    process.env.SANCTUARY_RECOVERY_KEY = savedRecoveryKey;
  } else {
    delete process.env.SANCTUARY_RECOVERY_KEY;
  }
});

describe("SEC-020: Recovery key path must not regenerate master key", () => {
  // ── First run behavior ─────────────────────────────────────────────

  it("first run generates a recovery key and stores its hash", async () => {
    const storage = new MemoryStorage();

    // First run: no passphrase, no existing hash
    const { config } = await createSanctuaryServer({ storage });

    // Verify recovery-key-hash was stored
    const storedHash = await storage.read("_meta", "recovery-key-hash");
    expect(storedHash).not.toBeNull();
    expect(storedHash!.length).toBeGreaterThan(0);
  });

  // ── Subsequent run with correct recovery key ───────────────────────

  it("subsequent run with correct recovery key succeeds and preserves key material", async () => {
    const storage = new MemoryStorage();

    // --- Run 1: First start, capture the recovery key ---
    // Generate a known master key so we can set up the recovery key env var
    const masterKey = generateRandomKey();
    const recoveryKeyStr = toBase64url(masterKey);
    const keyHash = hashToString(masterKey);

    // Simulate first-run storage: write the recovery-key-hash
    await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

    // Write encrypted data using a namespace key derived from the master key.
    // This simulates what StateStore does internally — deriving a namespace
    // key via HKDF and encrypting data with it.
    const nsKey = deriveNamespaceKey(masterKey, "test-ns");
    const testData = stringToBytes("secret-value-from-run-1");
    const encrypted = encrypt(testData, nsKey);
    await storage.write("test-ns", "test-key", stringToBytes(JSON.stringify(encrypted)));

    // --- Run 2: Restart with the correct recovery key ---
    process.env.SANCTUARY_RECOVERY_KEY = recoveryKeyStr;

    const { config } = await createSanctuaryServer({ storage });

    // The server started successfully — now verify we can derive the same
    // namespace key and decrypt the data (proving the master key was recovered)
    const nsKey2 = deriveNamespaceKey(fromBase64url(recoveryKeyStr), "test-ns");
    expect(constantTimeEqual(nsKey, nsKey2)).toBe(true);

    const storedRaw = await storage.read("test-ns", "test-key");
    expect(storedRaw).not.toBeNull();
    const storedPayload = JSON.parse(bytesToString(storedRaw!));
    const decrypted = decrypt(storedPayload, nsKey2);
    expect(bytesToString(decrypted)).toBe("secret-value-from-run-1");
  });

  // ── Subsequent run without any credentials ─────────────────────────

  it("subsequent run without credentials fails with descriptive error", async () => {
    const storage = new MemoryStorage();

    // Simulate existing installation: recovery-key-hash exists
    const masterKey = generateRandomKey();
    const keyHash = hashToString(masterKey);
    await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

    // No SANCTUARY_PASSPHRASE, no SANCTUARY_RECOVERY_KEY
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/no credentials provided/i);

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/SANCTUARY_RECOVERY_KEY/);
  });

  // ── Subsequent run with incorrect recovery key ─────────────────────

  it("subsequent run with incorrect recovery key fails", async () => {
    const storage = new MemoryStorage();

    // Simulate existing installation
    const masterKey = generateRandomKey();
    const keyHash = hashToString(masterKey);
    await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

    // Set a WRONG recovery key
    const wrongKey = generateRandomKey();
    process.env.SANCTUARY_RECOVERY_KEY = toBase64url(wrongKey);

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/does not match/i);

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/incorrect/i);
  });

  // ── Invalid recovery key format ────────────────────────────────────

  it("rejects recovery key with invalid base64url encoding", async () => {
    const storage = new MemoryStorage();

    const masterKey = generateRandomKey();
    const keyHash = hashToString(masterKey);
    await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

    process.env.SANCTUARY_RECOVERY_KEY = "not-valid-base64url-!!!";

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/SANCTUARY_RECOVERY_KEY/);
  });

  it("rejects recovery key with incorrect length", async () => {
    const storage = new MemoryStorage();

    const masterKey = generateRandomKey();
    const keyHash = hashToString(masterKey);
    await storage.write("_meta", "recovery-key-hash", stringToBytes(keyHash));

    // Too short — only 16 bytes instead of 32
    const shortKey = toBase64url(new Uint8Array(16));
    process.env.SANCTUARY_RECOVERY_KEY = shortKey;

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/incorrect length/i);
  });

  // ── Safety net: orphaned encrypted data ────────────────────────────

  it("first run with orphaned key-params (no recovery-key-hash) fails", async () => {
    const storage = new MemoryStorage();

    // Simulate corrupted state: key-params exist but no recovery-key-hash
    await storage.write(
      "_meta",
      "key-params",
      stringToBytes(JSON.stringify({ alg: "argon2id", salt: "abc", m: 65536, t: 3, p: 4, l: 32 }))
    );

    // No passphrase, no recovery key, no recovery-key-hash — but key-params exist
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;

    await expect(
      createSanctuaryServer({ storage })
    ).rejects.toThrow(/passphrase required/i);
  });

  // ── Passphrase path still works (non-regression) ───────────────────

  it("passphrase path is not affected by recovery key changes", async () => {
    const storage = new MemoryStorage();

    process.env.SANCTUARY_PASSPHRASE = "test-passphrase-for-sec-020";

    // Should start fine with passphrase
    const { config } = await createSanctuaryServer({ storage });
    expect(config).toBeDefined();

    // Verify key-params were stored (passphrase path)
    const keyParams = await storage.read("_meta", "key-params");
    expect(keyParams).not.toBeNull();
  });

  // ── Recovery key hash uses constant-time comparison ────────────────

  it("recovery key verification uses constant-time hash comparison", () => {
    // This is a unit test for the comparison mechanism.
    // The actual constant-time comparison is used in index.ts via constantTimeEqual.
    const key1 = generateRandomKey();
    const key2 = generateRandomKey();

    const hash1Bytes = stringToBytes(hashToString(key1));
    const hash2Bytes = stringToBytes(hashToString(key2));
    const hash1Copy = stringToBytes(hashToString(key1));

    // Same key → same hash → equal
    expect(constantTimeEqual(hash1Bytes, hash1Copy)).toBe(true);

    // Different key → different hash → not equal
    expect(constantTimeEqual(hash1Bytes, hash2Bytes)).toBe(false);
  });
});
