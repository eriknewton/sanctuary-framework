/**
 * Sanctuary MCP Server — SEC-019 Regression Test
 *
 * SEC-019: Config silently accepts unimplemented features.
 *
 * This test verifies that the config parser rejects unimplemented feature
 * values at load time with clear error messages, preventing a false sense
 * of security when features are configured but not active.
 *
 * These tests would have passed silently before the SEC-019 fix — the
 * config would have been accepted without error.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { loadConfig, validateConfig, defaultConfig } from "../../src/config.js";

// Each test gets an isolated temp directory for config files
let tempDir: string;

beforeEach(async () => {
  tempDir = join(tmpdir(), `sanctuary-sec019-${randomBytes(8).toString("hex")}`);
  await mkdir(tempDir, { recursive: true });
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

async function writeConfigAndLoad(partial: Record<string, unknown>): Promise<void> {
  const configPath = join(tempDir, "sanctuary.json");
  await writeFile(configPath, JSON.stringify(partial));
  await loadConfig(configPath);
}

describe("SEC-019: Reject unimplemented config features", () => {
  // --- Unimplemented proof_system values ---

  it("rejects proof_system: groth16", async () => {
    await expect(
      writeConfigAndLoad({ disclosure: { proof_system: "groth16" } })
    ).rejects.toThrow(/unimplemented/i);
    await expect(
      writeConfigAndLoad({ disclosure: { proof_system: "groth16" } })
    ).rejects.toThrow(/disclosure\.proof_system/);
    await expect(
      writeConfigAndLoad({ disclosure: { proof_system: "groth16" } })
    ).rejects.toThrow(/groth16/);
  });

  it("rejects proof_system: plonk", async () => {
    await expect(
      writeConfigAndLoad({ disclosure: { proof_system: "plonk" } })
    ).rejects.toThrow(/unimplemented/i);
    await expect(
      writeConfigAndLoad({ disclosure: { proof_system: "plonk" } })
    ).rejects.toThrow(/plonk/);
  });

  // --- Unimplemented key_protection values ---

  it("rejects key_protection: hardware-key", async () => {
    await expect(
      writeConfigAndLoad({ state: { key_protection: "hardware-key" } })
    ).rejects.toThrow(/unimplemented/i);
    await expect(
      writeConfigAndLoad({ state: { key_protection: "hardware-key" } })
    ).rejects.toThrow(/state\.key_protection/);
    await expect(
      writeConfigAndLoad({ state: { key_protection: "hardware-key" } })
    ).rejects.toThrow(/hardware-key/);
  });

  // --- Unimplemented environment values ---

  it("rejects environment: tee", async () => {
    await expect(
      writeConfigAndLoad({ execution: { environment: "tee" } })
    ).rejects.toThrow(/unimplemented/i);
    await expect(
      writeConfigAndLoad({ execution: { environment: "tee" } })
    ).rejects.toThrow(/execution\.environment/);
    await expect(
      writeConfigAndLoad({ execution: { environment: "tee" } })
    ).rejects.toThrow(/tee/);
  });

  // --- Unimplemented disclosure.default_policy values ---

  it("rejects disclosure.default_policy: withhold-all", async () => {
    await expect(
      writeConfigAndLoad({ disclosure: { default_policy: "withhold-all" } })
    ).rejects.toThrow(/unimplemented/i);
    await expect(
      writeConfigAndLoad({ disclosure: { default_policy: "withhold-all" } })
    ).rejects.toThrow(/disclosure\.default_policy/);
    await expect(
      writeConfigAndLoad({ disclosure: { default_policy: "withhold-all" } })
    ).rejects.toThrow(/withhold-all/);
  });

  it("accepts disclosure.default_policy: minimum-necessary", async () => {
    await expect(
      writeConfigAndLoad({ disclosure: { default_policy: "minimum-necessary" } })
    ).resolves.not.toThrow();
  });

  // --- Unimplemented reputation.mode values ---

  it("rejects reputation.mode: service-mediated", async () => {
    await expect(
      writeConfigAndLoad({ reputation: { mode: "service-mediated" } })
    ).rejects.toThrow(/unimplemented/i);
    await expect(
      writeConfigAndLoad({ reputation: { mode: "service-mediated" } })
    ).rejects.toThrow(/reputation\.mode/);
    await expect(
      writeConfigAndLoad({ reputation: { mode: "service-mediated" } })
    ).rejects.toThrow(/service-mediated/);
  });

  it("accepts reputation.mode: self-custodied", async () => {
    await expect(
      writeConfigAndLoad({ reputation: { mode: "self-custodied" } })
    ).resolves.not.toThrow();
  });

  // --- Multiple unimplemented features in a single config ---

  it("reports all unimplemented features when multiple are present", async () => {
    await expect(
      writeConfigAndLoad({
        state: { key_protection: "hardware-key" },
        execution: { environment: "tee" },
        disclosure: { proof_system: "groth16" },
      })
    ).rejects.toThrow(/hardware-key/);
    await expect(
      writeConfigAndLoad({
        state: { key_protection: "hardware-key" },
        execution: { environment: "tee" },
        disclosure: { proof_system: "groth16" },
      })
    ).rejects.toThrow(/tee/);
    await expect(
      writeConfigAndLoad({
        state: { key_protection: "hardware-key" },
        execution: { environment: "tee" },
        disclosure: { proof_system: "groth16" },
      })
    ).rejects.toThrow(/groth16/);
  });

  // --- Implemented values must be accepted ---

  it("accepts proof_system: commitment-only", async () => {
    await expect(
      writeConfigAndLoad({ disclosure: { proof_system: "commitment-only" } })
    ).resolves.not.toThrow();
  });

  it("accepts key_protection: passphrase", async () => {
    await expect(
      writeConfigAndLoad({ state: { key_protection: "passphrase" } })
    ).resolves.not.toThrow();
  });

  it("accepts key_protection: none", async () => {
    await expect(
      writeConfigAndLoad({ state: { key_protection: "none" } })
    ).resolves.not.toThrow();
  });

  it("accepts environment: local-process", async () => {
    await expect(
      writeConfigAndLoad({ execution: { environment: "local-process" } })
    ).resolves.not.toThrow();
  });

  it("accepts environment: docker", async () => {
    await expect(
      writeConfigAndLoad({ execution: { environment: "docker" } })
    ).resolves.not.toThrow();
  });

  it("accepts default config (no overrides)", async () => {
    // loadConfig with a non-existent file falls back to defaults
    const nonExistentPath = join(tempDir, "no-such-file.json");
    await expect(loadConfig(nonExistentPath)).resolves.not.toThrow();
  });

  // --- validateConfig unit tests ---

  it("validateConfig passes for default config", () => {
    expect(() => validateConfig(defaultConfig())).not.toThrow();
  });

  it("validateConfig throws for unimplemented proof_system", () => {
    const config = defaultConfig();
    (config.disclosure as { proof_system: string }).proof_system = "groth16";
    expect(() => validateConfig(config)).toThrow(/unimplemented/i);
  });
});
