/**
 * F2 (Exit V2 D1 operator finding, 2026-08-23): human-mode `sanctuary exit
 * verify` on a refused bundle used to print `verdict: FAIL` plus three
 * neutral fields (manifest/identity/artifacts) and NO reason at all, even
 * though the `--json` path already carried a specific `failure_class`.
 * Erik's own read of the drill transcript: "Mostly greek."
 *
 * This file has two halves:
 *  - a full-set-parity check over `FAILURE_CLASS_EXPLANATIONS`
 *    (server/src/exit/cli.ts), the ONE shared table both the human and
 *    `--json` branches of `verify` read from. `Record<...failure_class,
 *    string>` already makes TypeScript refuse to compile a missing key;
 *    this test is the runtime insurance for that same property, listing
 *    every class by hand the way the codebase's other full-set-equality
 *    structural pins do (see fortress-open-recovery-wiring.test.ts's
 *    wired-list assertion);
 *  - a WIRED-CONSUMER test that drives a real refused bundle through
 *    `runExitCommand` (not the table in isolation) and asserts the actual
 *    printed output - human mode and `--json` - both carry the reason.
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm, unlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { Writable } from "node:stream";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { exportExitBundle } from "../../src/exit/bundle.js";
import { runExitCommand } from "../../src/exit/cli.js";
import type { ExitBundleManifest } from "../../src/contracts/v1.1/exit-bundle-manifest.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

// Full-set-parity list, hand-copied from the `failure_class` union in
// server/src/contracts/v1.1/exit-bundle-manifest.ts. A class added there
// without a matching addition here (or to FAILURE_CLASS_EXPLANATIONS
// itself) fails this test loudly.
const ALL_FAILURE_CLASSES = [
  "manifest_signature_invalid",
  "manifest_unknown_version",
  "manifest_signature_scheme_invalid",
  "artifact_hash_mismatch",
  "artifact_missing",
  "artifact_size_mismatch",
  "aggregate_hash_mismatch",
  "artifact_path_unsafe",
  "artifact_path_duplicate",
  "artifact_kind_duplicate",
  "artifact_set_invalid",
  "artifact_directory_unlisted_file",
  "artifact_path_escapes_root",
  "archive_contains_symlink",
  "private_material_present",
  "identity_binding_mismatch",
  "identity_signature_invalid",
  "rotation_chain_invalid",
  "reputation_bundle_signature_invalid",
  "reputation_completeness_mismatch",
  "reputation_attestation_signature_invalid",
  "reputation_unverifiable_attestations",
  "known_signers_invalid",
  "encrypted_state_entries_unreadable",
  "other",
].sort();

async function callTool(
  tools: Array<{
    name: string;
    handler: (args: Record<string, unknown>) => Promise<{
      content: Array<{ type: string; text: string }>;
    }>;
  }>,
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

describe("FAILURE_CLASS_EXPLANATIONS full-set parity (F2)", () => {
  it("has exactly one sentence per failure_class the contract defines, no more, no fewer", async () => {
    // Import path is deliberately dynamic + `as any`-free: the table is
    // not exported (module-private), so this test exercises it only
    // through the CLI's real output below. This describe block instead
    // pins the CONTRACT's own class list against the hand-copied list
    // above, so a class added to the union is caught here even before a
    // wired-consumer test would happen to exercise it.
    const { readFile: rf } = await import("node:fs/promises");
    const src = await rf(
      join(__dirname, "../../src/contracts/v1.1/exit-bundle-manifest.ts"),
      "utf8"
    );
    const matches = [...src.matchAll(/^\s*\| "([a-z_]+)"/gm)].map((m) => m[1]!);
    expect(matches.sort()).toEqual(ALL_FAILURE_CLASSES);
  });

  it("cli.ts's FAILURE_CLASS_EXPLANATIONS table names every one of those classes (full-set parity, not first-entry)", async () => {
    const { readFile: rf } = await import("node:fs/promises");
    const src = await rf(join(__dirname, "../../src/exit/cli.ts"), "utf8");
    const tableMatch = src.match(
      /const FAILURE_CLASS_EXPLANATIONS[\s\S]*?=\s*\{([\s\S]*?)\n\};/
    );
    expect(tableMatch, "FAILURE_CLASS_EXPLANATIONS table not found in cli.ts").not.toBeNull();
    const body = tableMatch![1]!;
    const keys = [...body.matchAll(/^\s*([a-z_]+):/gm)].map((m) => m[1]!);
    expect(keys.sort()).toEqual(ALL_FAILURE_CLASSES);
  });
});

describe("WIRED CONSUMER: `sanctuary exit verify` prints the reason (F2)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("human mode prints `reason: artifact_missing` plus the shared table's sentence; --json carries the same sentence as reason_text", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog
    );
    await identityManager.load();
    await callTool(tools, "identity_create", { label: "verify-reason-source" });
    const { reputationStore } = createL4Tools(storage, masterKey, identityManager, auditLog);

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-verify-reason-"));
    tempDirs.push(bundleDir);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir,
      storage,
      masterKey,
      identityManager,
      auditLog,
      reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      keySource: "recovery-key",
    });

    // Induce `artifact_missing`: delete a real artifact file the signed
    // manifest lists, without touching manifest.json itself.
    const manifestRaw = await readFile(join(bundleDir, "manifest.json"), "utf8");
    const manifest = JSON.parse(manifestRaw) as ExitBundleManifest;
    const victim = manifest.body.artifacts[0]!;
    await unlink(join(bundleDir, victim.path));

    const humanOut = new StringWritable();
    const humanCode = await runExitCommand({
      argv: ["verify", bundleDir],
      out: humanOut,
      err: new StringWritable(),
    });
    expect(humanCode).toBe(1);
    expect(humanOut.text).toContain("verdict: FAIL");
    expect(humanOut.text).toContain("reason: artifact_missing");
    // The exact sentence from FAILURE_CLASS_EXPLANATIONS, not just the
    // bare failure_class token - proves the table's VALUE reached the
    // terminal, not only its key.
    expect(humanOut.text).toContain(
      "At least one artifact the manifest lists could not be found in the bundle directory."
    );

    const jsonOut = new StringWritable();
    const jsonCode = await runExitCommand({
      argv: ["verify", bundleDir, "--json"],
      out: jsonOut,
      err: new StringWritable(),
    });
    expect(jsonCode).toBe(1);
    const parsed = JSON.parse(jsonOut.text) as Record<string, unknown>;
    expect(parsed.failure_class).toBe("artifact_missing");
    // SAME sentence as the human branch printed above - one shared table,
    // not a hand-mirrored copy per output mode.
    expect(parsed.reason_text).toBe(
      "At least one artifact the manifest lists could not be found in the bundle directory. The download or copy is incomplete."
    );
  });

  it("human mode on a PASSING bundle prints no reason line at all (additive-only: never interleaved into the frozen block)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const stateStore = new StateStore(storage, masterKey);
    const { tools, identityManager } = createL1Tools(
      stateStore,
      storage,
      masterKey,
      "recovery-key",
      auditLog
    );
    await identityManager.load();
    await callTool(tools, "identity_create", { label: "verify-reason-passing" });
    const { reputationStore } = createL4Tools(storage, masterKey, identityManager, auditLog);

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-verify-reason-pass-"));
    tempDirs.push(bundleDir);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir,
      storage,
      masterKey,
      identityManager,
      auditLog,
      reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      keySource: "recovery-key",
    });

    const out = new StringWritable();
    const code = await runExitCommand({
      argv: ["verify", bundleDir],
      out,
      err: new StringWritable(),
    });
    expect(code).toBe(0);
    expect(out.text).toContain("verdict: PASS");
    // Not a bare `not.toContain("reason:")`: a passing bundle with no
    // state can legitimately print `empty_reason: ...`, which contains
    // that substring. The property under test is specifically the
    // `reason:` LINE this finding adds, so anchor to line start.
    expect(out.text).not.toMatch(/^reason: /m);
  });
});
