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

// fail-before-exempt: hosted-CI fixture correction replaces a root-anchored fake lock path with an isolated temp directory; it intentionally changes no production behavior.

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, vi } from "vitest";
import {
  IntelligenceConfigStore,
  INTELLIGENCE_NAMESPACE,
  SUBSTRATE_CONFIG_KEY,
  classifyLocalIntelligenceState,
  probeDurableRecordPresence,
} from "../../src/intelligence/policy-store.js";
import { buildDefaultConfig } from "../../src/intelligence/defaults.js";
import type { LocalIntegrityStateV2 } from "../../src/intelligence/model-manifest-v2.js";
import type { SubstrateConfigV2 } from "../../src/intelligence/types.js";
import { q5eIntegrityState } from "./q5e-fixtures.js";
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
    const root = await mkdtemp(join(tmpdir(), "sanctuary-policy-store-"));
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
      namespacePath: (namespace: string) => join(root, namespace),
    };
    const store = new IntelligenceConfigStore(storage, generateRandomKey());
    try {
      await store.save(buildDefaultConfig());

      expect(writeDurable).toHaveBeenCalledOnce();
      expect(write).not.toHaveBeenCalled();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
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

/**
 * The operator-facing classification of a durable-record load (R2-F3).
 *
 * These assert the two properties the diagnostic depends on: it never reports a
 * state the SELECTOR would refuse to honor, and it never turns an indeterminate
 * read into a positive claim about the record.
 */
describe("classifyLocalIntelligenceState", () => {
  const armedState = (root = "/var/lib/ollama/models") => q5eIntegrityState(root);
  const v2Config = (state: LocalIntegrityStateV2): SubstrateConfigV2 => ({
    ...buildDefaultConfig(),
    version: 2,
    localIntegrityState: state,
  });

  it("reports armed for a V2 record that carries verified bindings", () => {
    const report = classifyLocalIntelligenceState({
      kind: "loaded",
      config: v2Config(armedState()),
    });
    expect(report.state).toBe("armed");
    expect(report.bindings.length).toBeGreaterThan(0);
    expect(report.remedy).toBeNull();
  });

  it("refuses to call a V2 record with no verified binding armed", () => {
    // `gatedLocalHandle` refuses EVERY local surface whose binding is missing
    // from a V2 record, so "armed" here would be the report contradicting the
    // runtime it is supposed to describe.
    const report = classifyLocalIntelligenceState({
      kind: "loaded",
      config: v2Config({ ...armedState(), bindings: {} }),
    });
    expect(report.state).toBe("integrity_state_invalid");
    expect(report.bindings).toEqual([]);
    expect(report.manifest_version).toBeNull();
    expect(report.detail).toContain("no verified model binding");
  });

  it("offers no remedy for a record that failed Q5 integrity validation", () => {
    // Both candidate verbs refuse this state: config-reset by design, and
    // re-provisioning because every config write reads the durable record
    // through loadAuthoritative(), which throws on exactly this record.
    const report = classifyLocalIntelligenceState({
      kind: "integrity-state-invalid",
      reason: "binding_mismatch",
      config: buildDefaultConfig(),
    });
    expect(report.state).toBe("integrity_state_invalid");
    expect(report.remedy).toBeNull();
    expect(report.detail).toContain("no in-product recovery");
  });

  it("reports a failed record read as indeterminate, never as absent", () => {
    const report = classifyLocalIntelligenceState({ kind: "read-failed" });
    expect(report.state).toBe("storage_unreadable");
    expect(report.detail).toContain("indeterminate");
    // The absent wording is a positive claim and must not appear here.
    expect(report.detail).not.toContain("no durable local-intelligence config record exists");
  });
});

describe("probeDurableRecordPresence", () => {
  it("answers absent and present without a master key", async () => {
    const storage = new MemoryStorage();
    // No key is passed anywhere in this test: presence is a property of the
    // bytes, which is why a diagnostic can settle it before resolving any
    // fortress credential.
    expect(await probeDurableRecordPresence(storage)).toBe("absent");
    await new IntelligenceConfigStore(storage, generateRandomKey())
      .save(buildDefaultConfig());
    expect(await probeDurableRecordPresence(storage)).toBe("present");
  });

  it("keeps a failed read distinct from an absent record", async () => {
    const storage = new MemoryStorage();
    vi.spyOn(storage, "read").mockImplementation(async () => {
      const error = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
      error.code = "EACCES";
      throw error;
    });
    // Reporting "absent" here would be a positive claim built on a failure.
    expect(await probeDurableRecordPresence(storage)).toBe("unreadable");
    vi.restoreAllMocks();
  });
});

describe("IntelligenceConfigStore.loadForDiagnostics", () => {
  /** A storage whose reads fail the way an unreadable fortress directory does. */
  function eaccesStorage(): MemoryStorage {
    const storage = new MemoryStorage();
    vi.spyOn(storage, "read").mockImplementation(async () => {
      const error = new Error("EACCES: permission denied, open '/fortress/state/_intelligence/substrate-config.enc'") as NodeJS.ErrnoException;
      error.code = "EACCES";
      throw error;
    });
    return storage;
  }

  it("reports read-failed where load() reports a fresh fortress", async () => {
    const masterKey = generateRandomKey();
    const storage = eaccesStorage();
    const store = new IntelligenceConfigStore(storage, masterKey);
    // The boot path's swallow is deliberate and stays; the diagnostic read is
    // the one that must not launder a read failure into "no record exists".
    expect((await store.load()).kind).toBe("default");
    expect((await store.loadForDiagnostics()).kind).toBe("read-failed");
    vi.restoreAllMocks();
  });

  it("agrees with load() on an absent record and on a readable one", async () => {
    const storage = new MemoryStorage();
    const store = new IntelligenceConfigStore(storage, generateRandomKey());
    expect((await store.loadForDiagnostics()).kind).toBe("default");
    await store.save(buildDefaultConfig());
    expect((await store.loadForDiagnostics()).kind).toBe("loaded");
  });
});
