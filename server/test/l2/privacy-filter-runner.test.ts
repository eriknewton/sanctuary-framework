import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  applyConfiguredPrivacyFilter,
  OPF_STDOUT_MAX_BYTES,
  PrivacyFilterRuntimeError,
  runOpenAIPrivacyFilter,
  type PrivacyFilterRuntimeConfig,
} from "../../src/l2-operational/privacy-filter-runner.js";
import { PrivacyPlaceholderVault } from "../../src/l2-operational/privacy-filter.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";

describe("privacy filter runtime runner", () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-opf-"));
  });

  afterEach(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it("invokes an opf-compatible command and adapts spans into placeholders", async () => {
    const command = await writeOpfCommand(
      JSON.stringify({
        schema_version: 1,
        text: "Contact jane@example.com",
        detected_spans: [
          {
            label: "private_email",
            start: 8,
            end: 24,
            text: "jane@example.com",
          },
        ],
      })
    );
    const vault = new PrivacyPlaceholderVault(new MemoryStorage(), generateRandomKey());

    const result = await applyConfiguredPrivacyFilter(
      { prompt: "Contact jane@example.com" },
      vault,
      "policy-a",
      opfConfig(command)
    );

    expect(result.value).toEqual({ prompt: "Contact EMAIL_1" });
    expect(result.mode).toBe("opf");
    expect(result.findings).toEqual([
      {
        path: "$.prompt",
        class: "email",
        action: "placeholder",
        placeholder: "EMAIL_1",
      },
    ]);
    await expect(vault.resolvePlaceholder("EMAIL_1", "policy-a")).resolves.toBe(
      "jane@example.com"
    );
  });

  it("falls back to the built-in placeholder filter when opf fails in fallback mode", async () => {
    const vault = new PrivacyPlaceholderVault(new MemoryStorage(), generateRandomKey());

    const result = await applyConfiguredPrivacyFilter(
      { prompt: "Contact jane@example.com" },
      vault,
      "policy-a",
      opfConfig(join(tempDir, "missing-opf"), "fallback")
    );

    expect(result.value).toEqual({ prompt: "Contact EMAIL_1" });
    expect(result.mode).toBe("local");
    expect(result.fallback_from).toBe("opf");
    expect(result.findings[0]).toMatchObject({
      path: "$.prompt",
      class: "email",
      action: "placeholder",
      placeholder: "EMAIL_1",
    });
  });

  it("throws a runtime error when opf fails in closed mode", async () => {
    const vault = new PrivacyPlaceholderVault(new MemoryStorage(), generateRandomKey());

    await expect(
      applyConfiguredPrivacyFilter(
        "Contact jane@example.com",
        vault,
        "policy-a",
        opfConfig(join(tempDir, "missing-opf"), "closed")
      )
    ).rejects.toBeInstanceOf(PrivacyFilterRuntimeError);
  });

  it("rejects malformed opf JSON output", async () => {
    const command = await writeOpfCommand("{not json");

    await expect(runOpenAIPrivacyFilter("hello", opfConfig(command))).rejects.toThrow(
      /invalid JSON/
    );
  });

  it("can be disabled without storing findings", async () => {
    const vault = new PrivacyPlaceholderVault(new MemoryStorage(), generateRandomKey());

    const result = await applyConfiguredPrivacyFilter(
      "Contact jane@example.com",
      vault,
      "policy-a",
      {
        mode: "off",
        fail_mode: "closed",
        command: "opf",
        timeout_ms: 500,
      }
    );

    expect(result).toEqual({
      value: "Contact jane@example.com",
      findings: [],
      mode: "off",
    });
    await expect(vault.resolvePlaceholder("EMAIL_1", "policy-a")).resolves.toBeNull();
  });

  it("rejects oversized OPF stdout before JSON.parse (#6)", async () => {
    // Emit a payload just over the 10 MB cap. Using zero-padding keeps the
    // test cheap on memory (no JSON tree growth) while exercising the
    // pre-parse byte-length guard.
    const command = join(tempDir, "mock-opf-oversized.mjs");
    const oversized = OPF_STDOUT_MAX_BYTES + 1;
    await writeFile(
      command,
      [
        "#!/usr/bin/env node",
        "process.stdin.resume();",
        `process.stdout.write("0".repeat(${oversized}));`,
        "",
      ].join("\n"),
      { mode: 0o700 }
    );
    await chmod(command, 0o700);

    await expect(
      runOpenAIPrivacyFilter("hello", opfConfig(command))
    ).rejects.toThrow(/exceeded.*10000000.*cap/i);
  });

  async function writeOpfCommand(stdout: string): Promise<string> {
    const command = join(tempDir, "mock-opf.mjs");
    await writeFile(
      command,
      [
        "#!/usr/bin/env node",
        "process.stdin.resume();",
        `process.stdout.write(${JSON.stringify(stdout)});`,
        "",
      ].join("\n"),
      { mode: 0o700 }
    );
    await chmod(command, 0o700);
    return command;
  }
});

function opfConfig(
  command: string,
  failMode: PrivacyFilterRuntimeConfig["fail_mode"] = "closed"
): PrivacyFilterRuntimeConfig {
  return {
    mode: "opf",
    fail_mode: failMode,
    command,
    timeout_ms: 500,
  };
}
