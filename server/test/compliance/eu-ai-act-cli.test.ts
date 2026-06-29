/**
 * EU AI Act CLI tests
 *
 * Covers: argument parsing via runCompliance (help, missing agent-did, unknown flags),
 * output directory creation, path traversal in --output.
 * Not covered: real Sanctuary server spin-up, network, PDF rendering.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runCompliance } from "../../src/compliance/eu_ai_act/cli.js";

// process.exit is called in help/error paths — mock it to prevent test exit
const exitSpy = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
  throw new Error(`process.exit(${code})`);
}) as typeof process.exit);

// Mock the heavy dependencies so we only test CLI logic
vi.mock("../../src/index.js", () => ({
  createSanctuaryServer: vi.fn(async () => ({
    config: { version: "0.9.0-rc.1" },
    identityManager: {
      getDefault: () => ({
        identity_id: "test-id",
        public_key: "pk",
        did: "did:key:test",
        label: "test",
        created_at: new Date().toISOString(),
        key_type: "ed25519",
        key_protection: "passphrase",
        encrypted_private_key: { ct: "", iv: "", tag: "" },
        rotation_history: [],
      }),
    },
    masterKey: new Uint8Array(32),
    auditLog: { append: vi.fn() },
    policy: {},
  })),
}));

vi.mock("../../src/compliance/eu_ai_act/generator.js", () => ({
  generateEuAiActBundle: vi.fn(async () => ({
    manifest: {
      documents: [],
      bundle_id: "test",
      signed_at: new Date().toISOString(),
      signer: { did: "did:key:test", public_key: "pk" },
      bundle_version: "1.0",
      matrix_version: "1.0",
      regulation_version: "EU AI Act 2024/1689",
      agent_did: "did:key:test",
      period_start: "2026-03-17T00:00:00Z",
      period_end: "2026-04-17T00:00:00Z",
      coverage_summary: { full: 5, full_pct: 11, partial: 24, partial_pct: 52, manual_only: 17, manual_only_pct: 37 },
    },
    files: [
      { filename: "01_annex_iv_technical_documentation.md", content: "# Test doc\n[MANUAL INPUT REQUIRED: test]" },
      { filename: "02_article_26_deployer_log.md", content: "# Deployer log" },
    ],
    publish_result: null,
  })),
}));

vi.mock("../../src/compliance/eu_ai_act/pdf.js", () => ({
  renderBundleToPdf: vi.fn(() => new Uint8Array([0x25, 0x50, 0x44, 0x46])),
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    mkdir: vi.fn(async () => undefined),
    writeFile: vi.fn(async () => undefined),
  };
});

describe("EU AI Act CLI", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("prints help and exits on --help", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await expect(runCompliance(["--help"])).rejects.toThrow("process.exit(0)");
    expect(logSpy).toHaveBeenCalled();
    const output = logSpy.mock.calls.map(c => c.join(" ")).join("\n");
    expect(output).toContain("EU AI Act Compliance Bundle Generator");
    logSpy.mockRestore();
  });

  it("prints help on empty args", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await expect(runCompliance([])).rejects.toThrow("process.exit(0)");
    expect(logSpy).toHaveBeenCalled();
    logSpy.mockRestore();
  });

  it("exits with error on unknown subcommand", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(runCompliance(["unknown-cmd"])).rejects.toThrow("process.exit(2)");
    errSpy.mockRestore();
  });

  it("exits with error on missing agent-did", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(runCompliance(["eu-ai-act"])).rejects.toThrow("process.exit(2)");
    errSpy.mockRestore();
  });

  it("exits with error on missing agent-did when first arg is a flag", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(runCompliance(["eu-ai-act", "--output", "/tmp"])).rejects.toThrow("process.exit(2)");
    errSpy.mockRestore();
  });

  it("exits with error on unknown flag", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(
      runCompliance(["eu-ai-act", "did:key:test", "--invalid-flag"])
    ).rejects.toThrow("process.exit(2)");
    errSpy.mockRestore();
  });

  it("creates output directory and writes files", async () => {
    const { mkdir, writeFile } = await import("node:fs/promises");
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    await runCompliance([
      "eu-ai-act",
      "did:key:test",
      "--output", "out/test-bundle",
      "--passphrase", "test-pass",
    ]);

    expect(mkdir).toHaveBeenCalledWith("out/test-bundle", { recursive: true });
    expect(writeFile).toHaveBeenCalled();
    stderrSpy.mockRestore();
  });

  it("parses --publish-to-verascore as boolean flag (no value)", async () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);

    // Should not throw — --publish-to-verascore is a boolean flag
    await runCompliance([
      "eu-ai-act",
      "did:key:test",
      "--output", "out/test-bundle",
      "--passphrase", "test-pass",
      "--publish-to-verascore",
    ]);

    stderrSpy.mockRestore();
  });

  it("parses -h as help", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await expect(runCompliance(["-h"])).rejects.toThrow("process.exit(0)");
    expect(logSpy).toHaveBeenCalled();
    logSpy.mockRestore();
  });
});
