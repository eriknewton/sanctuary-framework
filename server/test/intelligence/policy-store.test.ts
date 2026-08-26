/**
 * Intelligence Substrate Config Store — Encrypted Persistence Tests
 *
 * Verifies:
 *   - default config is returned on first load (no on-disk record)
 *   - save -> load round-trip preserves the SubstrateConfig shape
 *   - on-disk payload is encrypted (raw bytes do NOT contain plaintext)
 *   - corrupt persisted record falls back to defaults cleanly
 *   - future-version persisted record falls back to defaults cleanly
 *   - clear() removes the record and subsequent load returns defaults
 */

import { describe, it, expect, vi } from "vitest";
import {
  IntelligenceConfigStore,
  INTELLIGENCE_NAMESPACE,
  SUBSTRATE_CONFIG_KEY,
} from "../../src/intelligence/policy-store.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { stringToBytes, bytesToString } from "../../src/core/encoding.js";

describe("Intelligence Substrate Config Store", () => {
  it("returns the default config on first load (no record)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    const outcome = await store.load();

    expect(outcome.kind).toBe("default");
    expect(outcome.config.version).toBe(1);
    expect(outcome.config.perSurface.concierge).toBe("local");
    expect(outcome.config.fallback["sentinel-scoring"]).toBe("conservative-deny");
  });

  it("save -> load round-trip preserves SubstrateConfig shape", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    const config = buildDefaultConfig();
    config.perSurface.concierge = "venice";
    config.veniceApiKey = "test-venice-key";
    config.frontierConfig = { anthropic: "test-anthropic-key" };
    await store.save(config);

    const outcome = await store.load();

    expect(outcome.kind).toBe("loaded");
    expect(outcome.config.perSurface.concierge).toBe("venice");
    expect(outcome.config.veniceApiKey).toBe("test-venice-key");
    expect(outcome.config.frontierConfig.anthropic).toBe("test-anthropic-key");
  });

  it("save stamps updatedAt with the current ISO8601 timestamp", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    const before = new Date().toISOString();
    const config = buildDefaultConfig();
    await store.save(config);
    const after = new Date().toISOString();

    const outcome = await store.load();
    expect(outcome.kind).toBe("loaded");
    expect(outcome.config.updatedAt >= before).toBe(true);
    expect(outcome.config.updatedAt <= after).toBe(true);
  });

  it("uses the durable storage primitive for the authoritative config when available", async () => {
    const base = new MemoryStorage();
    const write = vi.fn((...args: Parameters<MemoryStorage["write"]>) =>
      base.write(...args));
    const writeDurable = vi.fn((...args: Parameters<MemoryStorage["write"]>) =>
      base.write(...args));
    const storage = {
      write,
      writeDurable,
      read: (...args: Parameters<MemoryStorage["read"]>) => base.read(...args),
      delete: (...args: Parameters<MemoryStorage["delete"]>) => base.delete(...args),
      list: (...args: Parameters<MemoryStorage["list"]>) => base.list(...args),
      exists: (...args: Parameters<MemoryStorage["exists"]>) => base.exists(...args),
      totalSize: () => base.totalSize(),
      listNamespaces: () => base.listNamespaces(),
      namespacePath: () => "/in-memory-fixture",
    };
    const store = new IntelligenceConfigStore(storage, generateRandomKey());

    await store.save(buildDefaultConfig());

    expect(writeDurable).toHaveBeenCalledOnce();
    expect(write).not.toHaveBeenCalled();
  });

  it("on-disk payload is encrypted (no plaintext API key on disk)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    const config = buildDefaultConfig();
    config.veniceApiKey = "totally-secret-venice-key-nobody-must-see";
    config.frontierConfig = { anthropic: "totally-secret-anthropic-key-nobody-must-see" };
    await store.save(config);

    const raw = await storage.read(INTELLIGENCE_NAMESPACE, SUBSTRATE_CONFIG_KEY);
    expect(raw).not.toBeNull();
    const onDisk = bytesToString(raw!);
    expect(onDisk).not.toContain("totally-secret-venice-key");
    expect(onDisk).not.toContain("totally-secret-anthropic-key");
  });

  it("corrupt persisted record falls back to default config", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    // Write garbage bytes that won't decrypt cleanly.
    await storage.write(
      INTELLIGENCE_NAMESPACE,
      SUBSTRATE_CONFIG_KEY,
      stringToBytes("{\"v\":1,\"alg\":\"aes-256-gcm\",\"iv\":\"AAAA\",\"ct\":\"AAAA\",\"ts\":\"2026-04-29T00:00:00Z\"}")
    );

    const outcome = await store.load();
    expect(outcome.kind).toBe("corrupt");
    expect(outcome.config.version).toBe(1);
  });

  it("future-version persisted record falls back to default config", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    // Save a v2-shaped record manually so load() sees a future version.
    const futureConfig = { ...buildDefaultConfig(), version: 99 } as unknown;
    const otherStore = new IntelligenceConfigStore(storage, masterKey);
    // Bypass save() typing by using the actual encryption path.
    await otherStore.save(futureConfig as ReturnType<typeof buildDefaultConfig>);

    const outcome = await store.load();
    expect(outcome.kind).toBe("version-too-new");
    if (outcome.kind === "version-too-new") {
      expect(outcome.persistedVersion).toBe(99);
      expect(outcome.config.version).toBe(1);
    }
  });

  it("clear() removes the record; subsequent load returns defaults", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const store = new IntelligenceConfigStore(storage, masterKey);

    const config = buildDefaultConfig();
    config.perSurface.concierge = "venice";
    await store.save(config);

    const before = await store.load();
    expect(before.kind).toBe("loaded");

    await store.clear();

    const after = await store.load();
    expect(after.kind).toBe("default");
    expect(after.config.perSurface.concierge).toBe("local");
  });

  it("two separate fortresses with different master keys cannot read each other's config", async () => {
    const storage = new MemoryStorage();
    const fortressA = new IntelligenceConfigStore(storage, generateRandomKey());
    const fortressB = new IntelligenceConfigStore(storage, generateRandomKey());

    const config = buildDefaultConfig();
    config.veniceApiKey = "fortress-A-key";
    await fortressA.save(config);

    const outcome = await fortressB.load();
    expect(outcome.kind).toBe("corrupt");
    // Defaults applied; A's key not surfaced through B.
    expect(outcome.config.veniceApiKey).toBeUndefined();
  });
});
